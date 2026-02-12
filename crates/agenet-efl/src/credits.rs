use agenet_types::{AgenetError, AgentId};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::sync::Arc;

/// Credit transaction type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditTxType {
    Mint,
    Burn,
}

impl std::fmt::Display for CreditTxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreditTxType::Mint => write!(f, "mint"),
            CreditTxType::Burn => write!(f, "burn"),
        }
    }
}

/// A credit transaction record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreditTransaction {
    pub id: i64,
    pub agent_id: String,
    pub amount: i64,
    pub tx_type: String,
    pub reason: String,
    pub timestamp: i64,
}

/// Credit ledger backed by SQLite.
#[derive(Clone)]
pub struct CreditLedger {
    pool: Arc<SqlitePool>,
}

/// Burn cost rules.
#[derive(Clone, Debug)]
pub struct BurnPolicy {
    /// Credits for a standard post (alternative to PoW).
    pub post_cost: i64,
    /// Credits per MB for large artifacts.
    pub artifact_per_mb: i64,
    /// Artifact size threshold in bytes before cost applies.
    pub artifact_threshold: u64,
    /// Credits for priority routing flag.
    pub priority_cost: i64,
}

impl Default for BurnPolicy {
    fn default() -> Self {
        Self {
            post_cost: 1,
            artifact_per_mb: 3,
            artifact_threshold: 10 * 1024 * 1024, // 10MB
            priority_cost: 5,
        }
    }
}

impl CreditLedger {
    /// Open or create the credit ledger database.
    pub async fn open(db_path: &str) -> Result<Self, AgenetError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect(&format!("sqlite:{db_path}?mode=rwc"))
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        let ledger = Self {
            pool: Arc::new(pool),
        };
        ledger.migrate().await?;
        Ok(ledger)
    }

    /// Open an in-memory ledger (for testing).
    pub async fn open_memory() -> Result<Self, AgenetError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        let ledger = Self {
            pool: Arc::new(pool),
        };
        ledger.migrate().await?;
        Ok(ledger)
    }

    async fn migrate(&self) -> Result<(), AgenetError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS credit_balances (
                agent_id TEXT PRIMARY KEY,
                balance INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS credit_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                tx_type TEXT NOT NULL,
                reason TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            )",
        )
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_credit_tx_agent ON credit_transactions(agent_id)",
        )
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        Ok(())
    }

    /// Mint credits for an agent (provisioning from external payment).
    pub async fn mint(&self, agent_id: &AgentId, amount: i64, reason: &str) -> Result<i64, AgenetError> {
        if amount <= 0 {
            return Err(AgenetError::Unauthorized("mint amount must be positive".into()));
        }

        let agent_hex = agent_id.to_hex();
        let now = chrono::Utc::now().timestamp();

        // Upsert balance
        sqlx::query(
            "INSERT INTO credit_balances (agent_id, balance) VALUES (?, ?)
             ON CONFLICT(agent_id) DO UPDATE SET balance = balance + ?",
        )
        .bind(&agent_hex)
        .bind(amount)
        .bind(amount)
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        // Record transaction
        sqlx::query(
            "INSERT INTO credit_transactions (agent_id, amount, tx_type, reason, timestamp)
             VALUES (?, ?, 'mint', ?, ?)",
        )
        .bind(&agent_hex)
        .bind(amount)
        .bind(reason)
        .bind(now)
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        self.balance(agent_id).await
    }

    /// Burn credits from an agent. Fails if insufficient balance.
    pub async fn burn(&self, agent_id: &AgentId, amount: i64, reason: &str) -> Result<i64, AgenetError> {
        if amount <= 0 {
            return Err(AgenetError::Unauthorized("burn amount must be positive".into()));
        }

        let agent_hex = agent_id.to_hex();
        let now = chrono::Utc::now().timestamp();

        // Check balance
        let current = self.balance(agent_id).await?;
        if current < amount {
            return Err(AgenetError::InsufficientCredits);
        }

        // Deduct
        sqlx::query("UPDATE credit_balances SET balance = balance - ? WHERE agent_id = ?")
            .bind(amount)
            .bind(&agent_hex)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        // Record
        sqlx::query(
            "INSERT INTO credit_transactions (agent_id, amount, tx_type, reason, timestamp)
             VALUES (?, ?, 'burn', ?, ?)",
        )
        .bind(&agent_hex)
        .bind(amount)
        .bind(reason)
        .bind(now)
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        self.balance(agent_id).await
    }

    /// Get current balance for an agent.
    pub async fn balance(&self, agent_id: &AgentId) -> Result<i64, AgenetError> {
        let agent_hex = agent_id.to_hex();
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT balance FROM credit_balances WHERE agent_id = ?")
                .bind(&agent_hex)
                .fetch_optional(self.pool.as_ref())
                .await
                .map_err(|e| AgenetError::Storage(e.to_string()))?;

        Ok(row.map(|(b,)| b).unwrap_or(0))
    }

    /// Get transaction history for an agent.
    pub async fn transactions(
        &self,
        agent_id: &AgentId,
        limit: i64,
    ) -> Result<Vec<CreditTransaction>, AgenetError> {
        let agent_hex = agent_id.to_hex();
        let rows: Vec<(i64, String, i64, String, String, i64)> = sqlx::query_as(
            "SELECT id, agent_id, amount, tx_type, reason, timestamp
             FROM credit_transactions WHERE agent_id = ?
             ORDER BY id DESC LIMIT ?",
        )
        .bind(&agent_hex)
        .bind(limit)
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|(id, agent_id, amount, tx_type, reason, timestamp)| CreditTransaction {
                id,
                agent_id,
                amount,
                tx_type,
                reason,
                timestamp,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_ledger() -> CreditLedger {
        CreditLedger::open_memory().await.unwrap()
    }

    fn test_agent() -> AgentId {
        AgentId::from_public_key(&[42u8; 32])
    }

    #[tokio::test]
    async fn mint_credits() {
        let ledger = test_ledger().await;
        let agent = test_agent();
        let balance = ledger.mint(&agent, 100, "initial provision").await.unwrap();
        assert_eq!(balance, 100);
    }

    #[tokio::test]
    async fn mint_accumulates() {
        let ledger = test_ledger().await;
        let agent = test_agent();
        ledger.mint(&agent, 50, "first").await.unwrap();
        let balance = ledger.mint(&agent, 30, "second").await.unwrap();
        assert_eq!(balance, 80);
    }

    #[tokio::test]
    async fn burn_credits() {
        let ledger = test_ledger().await;
        let agent = test_agent();
        ledger.mint(&agent, 100, "provision").await.unwrap();
        let balance = ledger.burn(&agent, 25, "post to topic").await.unwrap();
        assert_eq!(balance, 75);
    }

    #[tokio::test]
    async fn burn_insufficient_fails() {
        let ledger = test_ledger().await;
        let agent = test_agent();
        ledger.mint(&agent, 10, "provision").await.unwrap();
        let result = ledger.burn(&agent, 50, "too much").await;
        assert!(matches!(result, Err(AgenetError::InsufficientCredits)));
    }

    #[tokio::test]
    async fn burn_zero_balance_fails() {
        let ledger = test_ledger().await;
        let agent = test_agent();
        let result = ledger.burn(&agent, 1, "no balance").await;
        assert!(matches!(result, Err(AgenetError::InsufficientCredits)));
    }

    #[tokio::test]
    async fn balance_unknown_agent_is_zero() {
        let ledger = test_ledger().await;
        let agent = test_agent();
        let balance = ledger.balance(&agent).await.unwrap();
        assert_eq!(balance, 0);
    }

    #[tokio::test]
    async fn transaction_history() {
        let ledger = test_ledger().await;
        let agent = test_agent();
        ledger.mint(&agent, 100, "provision").await.unwrap();
        ledger.burn(&agent, 25, "post").await.unwrap();
        ledger.burn(&agent, 5, "priority").await.unwrap();

        let txs = ledger.transactions(&agent, 10).await.unwrap();
        assert_eq!(txs.len(), 3);
        assert_eq!(txs[0].tx_type, "burn");
        assert_eq!(txs[0].reason, "priority");
    }

    #[tokio::test]
    async fn mint_negative_fails() {
        let ledger = test_ledger().await;
        let agent = test_agent();
        assert!(ledger.mint(&agent, -10, "bad").await.is_err());
    }

    #[tokio::test]
    async fn credits_not_transferable() {
        let ledger = test_ledger().await;
        let alice = AgentId::from_public_key(&[1u8; 32]);
        let bob = AgentId::from_public_key(&[2u8; 32]);
        ledger.mint(&alice, 100, "provision").await.unwrap();
        // Bob has nothing — no transfer mechanism exists
        assert_eq!(ledger.balance(&bob).await.unwrap(), 0);
        assert_eq!(ledger.balance(&alice).await.unwrap(), 100);
    }
}
