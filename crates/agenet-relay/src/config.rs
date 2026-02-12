use std::net::SocketAddr;

/// Relay server configuration.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Address to bind the HTTP server to.
    pub bind_addr: SocketAddr,
    /// SQLite database path for object storage.
    pub db_path: String,
    /// SQLite database path for credit ledger.
    pub credit_db_path: String,
    /// SQLite database path for deposit escrow (None = deposits disabled).
    pub deposit_db_path: Option<String>,
    /// Default PoW difficulty for topics without explicit policy.
    pub default_pow_difficulty: u32,
    /// PoW challenge TTL in seconds.
    pub pow_challenge_ttl: i64,
    /// Rate tracker sliding window in seconds.
    pub rate_window_seconds: i64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind_addr: ([127, 0, 0, 1], 9600).into(),
            db_path: "agenet-relay.db".to_string(),
            credit_db_path: "agenet-credits.db".to_string(),
            deposit_db_path: Some("agenet-deposits.db".to_string()),
            default_pow_difficulty: 20,
            pow_challenge_ttl: 300,
            rate_window_seconds: 60,
        }
    }
}
