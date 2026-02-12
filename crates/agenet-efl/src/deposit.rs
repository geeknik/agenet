use agenet_types::{AgenetError, AgentId};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::sync::Arc;

/// Violation type that triggers deposit burns.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationType {
    ProvenSpam,
    InvalidObjectInjection,
    PolicyViolation,
    ReplayAttack,
}

impl std::fmt::Display for ViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViolationType::ProvenSpam => write!(f, "proven_spam"),
            ViolationType::InvalidObjectInjection => write!(f, "invalid_object_injection"),
            ViolationType::PolicyViolation => write!(f, "policy_violation"),
            ViolationType::ReplayAttack => write!(f, "replay_attack"),
        }
    }
}

/// Burn amount configuration per violation type.
#[derive(Clone, Debug)]
pub struct ViolationPenalties {
    pub proven_spam: i64,
    pub invalid_object: i64,
    pub policy_violation: i64,
    pub replay_attack: i64,
}

impl Default for ViolationPenalties {
    fn default() -> Self {
        Self {
            proven_spam: 100,
            invalid_object: 200,
            policy_violation: 50,
            replay_attack: 150,
        }
    }
}

impl ViolationPenalties {
    pub fn penalty_for(&self, violation: &ViolationType) -> i64 {
        match violation {
            ViolationType::ProvenSpam => self.proven_spam,
            ViolationType::InvalidObjectInjection => self.invalid_object,
            ViolationType::PolicyViolation => self.policy_violation,
            ViolationType::ReplayAttack => self.replay_attack,
        }
    }
}

/// A deposit record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositRecord {
    pub agent_id: String,
    pub deposited: i64,
    pub burned: i64,
    pub status: String,
}

/// Deposited liability escrow for enterprise nodes.
///
/// No token, no market, pure escrow liability.
/// Misbehavior triggers automated burn. Good standing returns deposit.
#[derive(Clone)]
pub struct DepositEscrow {
    pool: Arc<SqlitePool>,
    penalties: ViolationPenalties,
}

impl DepositEscrow {
    pub async fn open(db_path: &str, penalties: ViolationPenalties) -> Result<Self, AgenetError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect(&format!("sqlite:{db_path}?mode=rwc"))
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        let escrow = Self {
            pool: Arc::new(pool),
            penalties,
        };
        escrow.migrate().await?;
        Ok(escrow)
    }

    pub async fn open_memory(penalties: ViolationPenalties) -> Result<Self, AgenetError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        let escrow = Self {
            pool: Arc::new(pool),
            penalties,
        };
        escrow.migrate().await?;
        Ok(escrow)
    }

    async fn migrate(&self) -> Result<(), AgenetError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS deposits (
                agent_id TEXT PRIMARY KEY,
                deposited INTEGER NOT NULL DEFAULT 0,
                burned INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active'
            )",
        )
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS violation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                violation_type TEXT NOT NULL,
                penalty INTEGER NOT NULL,
                timestamp INTEGER NOT NULL
            )",
        )
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        Ok(())
    }

    /// Lock a deposit for an enterprise agent.
    pub async fn lock_deposit(&self, agent_id: &AgentId, amount: i64) -> Result<(), AgenetError> {
        if amount <= 0 {
            return Err(AgenetError::Unauthorized("deposit must be positive".into()));
        }
        let agent_hex = agent_id.to_hex();
        sqlx::query(
            "INSERT INTO deposits (agent_id, deposited, burned, status) VALUES (?, ?, 0, 'active')
             ON CONFLICT(agent_id) DO UPDATE SET deposited = deposited + ?, status = 'active'",
        )
        .bind(&agent_hex)
        .bind(amount)
        .bind(amount)
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        Ok(())
    }

    /// Record a violation and burn from the deposit.
    pub async fn record_violation(
        &self,
        agent_id: &AgentId,
        violation: ViolationType,
    ) -> Result<i64, AgenetError> {
        let penalty = self.penalties.penalty_for(&violation);
        let agent_hex = agent_id.to_hex();
        let now = chrono::Utc::now().timestamp();

        // Check deposit exists
        let record = self.get_deposit(agent_id).await?;
        if record.is_none() {
            return Err(AgenetError::NotFound(format!("no deposit for {agent_hex}")));
        }
        let record = record.unwrap();

        let remaining = record.deposited - record.burned;
        let actual_burn = penalty.min(remaining);

        // Burn
        sqlx::query("UPDATE deposits SET burned = burned + ? WHERE agent_id = ?")
            .bind(actual_burn)
            .bind(&agent_hex)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        // If fully burned, mark as suspended
        if record.deposited <= record.burned + actual_burn {
            sqlx::query("UPDATE deposits SET status = 'suspended' WHERE agent_id = ?")
                .bind(&agent_hex)
                .execute(self.pool.as_ref())
                .await
                .map_err(|e| AgenetError::Storage(e.to_string()))?;
        }

        // Log violation
        sqlx::query(
            "INSERT INTO violation_log (agent_id, violation_type, penalty, timestamp)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&agent_hex)
        .bind(violation.to_string())
        .bind(actual_burn)
        .bind(now)
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        Ok(actual_burn)
    }

    /// Get deposit record for an agent.
    pub async fn get_deposit(&self, agent_id: &AgentId) -> Result<Option<DepositRecord>, AgenetError> {
        let agent_hex = agent_id.to_hex();
        let row: Option<(String, i64, i64, String)> = sqlx::query_as(
            "SELECT agent_id, deposited, burned, status FROM deposits WHERE agent_id = ?",
        )
        .bind(&agent_hex)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        Ok(row.map(|(agent_id, deposited, burned, status)| DepositRecord {
            agent_id,
            deposited,
            burned,
            status,
        }))
    }

    /// Refund remaining deposit for a good-standing agent.
    pub async fn refund(&self, agent_id: &AgentId) -> Result<i64, AgenetError> {
        let record = self.get_deposit(agent_id).await?;
        match record {
            Some(r) if r.status == "active" => {
                let refund = r.deposited - r.burned;
                let agent_hex = agent_id.to_hex();
                sqlx::query(
                    "UPDATE deposits SET deposited = 0, burned = 0, status = 'refunded' WHERE agent_id = ?",
                )
                .bind(&agent_hex)
                .execute(self.pool.as_ref())
                .await
                .map_err(|e| AgenetError::Storage(e.to_string()))?;

                Ok(refund)
            }
            Some(r) => Err(AgenetError::Unauthorized(format!(
                "cannot refund: account status is {}",
                r.status
            ))),
            None => Err(AgenetError::NotFound("no deposit found".into())),
        }
    }

    /// Check if an agent is in good standing (has active deposit, not suspended).
    pub async fn is_good_standing(&self, agent_id: &AgentId) -> Result<bool, AgenetError> {
        match self.get_deposit(agent_id).await? {
            Some(r) => Ok(r.status == "active"),
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_escrow() -> DepositEscrow {
        DepositEscrow::open_memory(ViolationPenalties::default())
            .await
            .unwrap()
    }

    fn test_agent() -> AgentId {
        AgentId::from_public_key(&[42u8; 32])
    }

    #[tokio::test]
    async fn lock_and_query_deposit() {
        let escrow = test_escrow().await;
        let agent = test_agent();
        escrow.lock_deposit(&agent, 1000).await.unwrap();

        let record = escrow.get_deposit(&agent).await.unwrap().unwrap();
        assert_eq!(record.deposited, 1000);
        assert_eq!(record.burned, 0);
        assert_eq!(record.status, "active");
    }

    #[tokio::test]
    async fn lock_accumulates() {
        let escrow = test_escrow().await;
        let agent = test_agent();
        escrow.lock_deposit(&agent, 500).await.unwrap();
        escrow.lock_deposit(&agent, 300).await.unwrap();

        let record = escrow.get_deposit(&agent).await.unwrap().unwrap();
        assert_eq!(record.deposited, 800);
    }

    #[tokio::test]
    async fn violation_burns_deposit() {
        let escrow = test_escrow().await;
        let agent = test_agent();
        escrow.lock_deposit(&agent, 1000).await.unwrap();

        let burned = escrow
            .record_violation(&agent, ViolationType::ProvenSpam)
            .await
            .unwrap();
        assert_eq!(burned, 100);

        let record = escrow.get_deposit(&agent).await.unwrap().unwrap();
        assert_eq!(record.burned, 100);
        assert_eq!(record.status, "active");
    }

    #[tokio::test]
    async fn violation_exhausts_deposit() {
        let escrow = test_escrow().await;
        let agent = test_agent();
        escrow.lock_deposit(&agent, 150).await.unwrap();

        // InvalidObjectInjection costs 200, but only 150 remains
        let burned = escrow
            .record_violation(&agent, ViolationType::InvalidObjectInjection)
            .await
            .unwrap();
        assert_eq!(burned, 150);

        let record = escrow.get_deposit(&agent).await.unwrap().unwrap();
        assert_eq!(record.status, "suspended");
    }

    #[tokio::test]
    async fn refund_good_standing() {
        let escrow = test_escrow().await;
        let agent = test_agent();
        escrow.lock_deposit(&agent, 1000).await.unwrap();

        // Small violation
        escrow
            .record_violation(&agent, ViolationType::PolicyViolation)
            .await
            .unwrap();

        let refund = escrow.refund(&agent).await.unwrap();
        assert_eq!(refund, 950); // 1000 - 50

        let record = escrow.get_deposit(&agent).await.unwrap().unwrap();
        assert_eq!(record.status, "refunded");
    }

    #[tokio::test]
    async fn refund_suspended_fails() {
        let escrow = test_escrow().await;
        let agent = test_agent();
        escrow.lock_deposit(&agent, 100).await.unwrap();

        // Exhaust deposit
        escrow
            .record_violation(&agent, ViolationType::InvalidObjectInjection)
            .await
            .unwrap();

        assert!(escrow.refund(&agent).await.is_err());
    }

    #[tokio::test]
    async fn good_standing_check() {
        let escrow = test_escrow().await;
        let agent = test_agent();
        let unknown = AgentId::from_public_key(&[99u8; 32]);

        assert!(!escrow.is_good_standing(&agent).await.unwrap());
        assert!(!escrow.is_good_standing(&unknown).await.unwrap());

        escrow.lock_deposit(&agent, 500).await.unwrap();
        assert!(escrow.is_good_standing(&agent).await.unwrap());
    }

    #[tokio::test]
    async fn violation_no_deposit_fails() {
        let escrow = test_escrow().await;
        let agent = test_agent();
        assert!(escrow
            .record_violation(&agent, ViolationType::ProvenSpam)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn negative_deposit_fails() {
        let escrow = test_escrow().await;
        let agent = test_agent();
        assert!(escrow.lock_deposit(&agent, -100).await.is_err());
    }
}
