use std::net::SocketAddr;

/// Relay server configuration.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Address to bind the HTTP server to.
    pub bind_addr: SocketAddr,
    /// SQLite database path.
    pub db_path: String,
    /// Default PoW difficulty for topics without explicit policy.
    pub default_pow_difficulty: u32,
    /// PoW challenge TTL in seconds.
    pub pow_challenge_ttl: i64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind_addr: ([127, 0, 0, 1], 9600).into(),
            db_path: "agenet-relay.db".to_string(),
            default_pow_difficulty: 20,
            pow_challenge_ttl: 300,
        }
    }
}
