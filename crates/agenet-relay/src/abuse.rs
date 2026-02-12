use agenet_types::AgentId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Token-bucket rate limiter keyed by IP or AgentId.
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    config: RateLimitConfig,
}

#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum tokens (burst capacity).
    pub max_tokens: u32,
    /// Tokens replenished per second.
    pub refill_rate: f64,
    /// Tokens consumed per request.
    pub cost: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_tokens: 60,
            refill_rate: 10.0,
            cost: 1,
        }
    }
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: u32) -> Self {
        Self {
            tokens: max_tokens as f64,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self, cost: u32, max_tokens: u32, refill_rate: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_rate).min(max_tokens as f64);
        self.last_refill = now;

        if self.tokens >= cost as f64 {
            self.tokens -= cost as f64;
            true
        } else {
            false
        }
    }
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Check if a request from this key is allowed.
    /// Returns true if allowed, false if rate-limited.
    pub fn check(&self, key: &str) -> bool {
        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(self.config.max_tokens));
        bucket.try_consume(self.config.cost, self.config.max_tokens, self.config.refill_rate)
    }

    /// Check rate limit by IP address.
    pub fn check_ip(&self, ip: &str) -> bool {
        self.check(&format!("ip:{ip}"))
    }

    /// Check rate limit by AgentId.
    pub fn check_agent(&self, agent_id: &AgentId) -> bool {
        self.check(&format!("agent:{}", agent_id.to_hex()))
    }

    /// Evict stale buckets (idle for more than `max_idle_seconds`).
    pub fn evict_stale(&self, max_idle_seconds: f64) {
        let now = Instant::now();
        self.buckets.write().unwrap().retain(|_, bucket| {
            now.duration_since(bucket.last_refill).as_secs_f64() < max_idle_seconds
        });
    }
}

/// TTL enforcer for objects — rejects expired objects, tracks for eviction.
pub struct TtlEnforcer;

impl TtlEnforcer {
    /// Check if an object's TTL is valid (not expired).
    /// Returns Ok(()) if valid or no TTL set, Err if expired.
    pub fn check(ttl: Option<i64>, timestamp: i64) -> Result<(), &'static str> {
        if let Some(ttl) = ttl {
            let expires_at = timestamp + ttl;
            let now = chrono::Utc::now().timestamp();
            if now > expires_at {
                return Err("object TTL expired");
            }
        }
        Ok(())
    }
}

/// Replay detection using nonce + timestamp windows.
#[derive(Clone)]
pub struct ReplayDetector {
    /// Set of (nonce_hash, timestamp) pairs seen recently.
    seen: Arc<RwLock<HashMap<String, i64>>>,
    /// Maximum age of entries to keep (seconds).
    window: i64,
}

impl ReplayDetector {
    pub fn new(window_seconds: i64) -> Self {
        Self {
            seen: Arc::new(RwLock::new(HashMap::new())),
            window: window_seconds,
        }
    }

    /// Check if this object hash has been seen before.
    /// Returns true if it's new (not a replay), false if replay detected.
    pub fn check_and_record(&self, object_hash: &str, timestamp: i64) -> bool {
        let mut seen = self.seen.write().unwrap();
        if seen.contains_key(object_hash) {
            return false; // replay
        }
        seen.insert(object_hash.to_string(), timestamp);
        true
    }

    /// Evict entries older than the window.
    pub fn evict(&self) {
        let cutoff = chrono::Utc::now().timestamp() - self.window;
        self.seen.write().unwrap().retain(|_, &mut ts| ts > cutoff);
    }
}

/// Credit burn escalation — increase costs when abuse is detected.
#[derive(Clone, Debug)]
pub struct BurnEscalation {
    /// Base burn cost.
    pub base_cost: i64,
    /// Multiplier per abuse flag.
    pub abuse_multiplier: f64,
    /// Maximum burn cost (cap).
    pub max_cost: i64,
}

impl Default for BurnEscalation {
    fn default() -> Self {
        Self {
            base_cost: 1,
            abuse_multiplier: 2.0,
            max_cost: 100,
        }
    }
}

impl BurnEscalation {
    /// Calculate the burn cost given the number of abuse flags.
    pub fn cost(&self, abuse_flags: u32) -> i64 {
        let cost = self.base_cost as f64 * self.abuse_multiplier.powi(abuse_flags as i32);
        (cost as i64).min(self.max_cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_allows_normal_traffic() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_tokens: 10,
            refill_rate: 10.0,
            cost: 1,
        });
        // Should allow 10 requests immediately (burst)
        for i in 0..10 {
            assert!(limiter.check("test"), "request {i} should be allowed");
        }
    }

    #[test]
    fn rate_limiter_rejects_burst() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_tokens: 5,
            refill_rate: 1.0,
            cost: 1,
        });
        for _ in 0..5 {
            assert!(limiter.check("test"));
        }
        // 6th should be rejected
        assert!(!limiter.check("test"));
    }

    #[test]
    fn rate_limiter_separate_keys() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_tokens: 2,
            refill_rate: 1.0,
            cost: 1,
        });
        assert!(limiter.check("key-a"));
        assert!(limiter.check("key-a"));
        assert!(!limiter.check("key-a"));
        // Different key still has tokens
        assert!(limiter.check("key-b"));
    }

    #[test]
    fn rate_limiter_ip_and_agent() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        assert!(limiter.check_ip("192.168.1.1"));
        let agent_id = AgentId::from_public_key(&[1u8; 32]);
        assert!(limiter.check_agent(&agent_id));
    }

    #[test]
    fn ttl_enforcer_no_ttl() {
        assert!(TtlEnforcer::check(None, 0).is_ok());
    }

    #[test]
    fn ttl_enforcer_valid() {
        let now = chrono::Utc::now().timestamp();
        assert!(TtlEnforcer::check(Some(3600), now).is_ok());
    }

    #[test]
    fn ttl_enforcer_expired() {
        let old_timestamp = chrono::Utc::now().timestamp() - 7200;
        assert!(TtlEnforcer::check(Some(3600), old_timestamp).is_err());
    }

    #[test]
    fn replay_detector_allows_new() {
        let detector = ReplayDetector::new(300);
        assert!(detector.check_and_record("hash-1", 1000));
        assert!(detector.check_and_record("hash-2", 1001));
    }

    #[test]
    fn replay_detector_blocks_replay() {
        let detector = ReplayDetector::new(300);
        assert!(detector.check_and_record("hash-1", 1000));
        assert!(!detector.check_and_record("hash-1", 1000)); // replay
    }

    #[test]
    fn replay_detector_eviction() {
        let detector = ReplayDetector::new(1); // 1 second window
        let old_ts = chrono::Utc::now().timestamp() - 10;
        detector.check_and_record("old-hash", old_ts);
        detector.evict();
        // After eviction, should be accepted again
        assert!(detector.check_and_record("old-hash", chrono::Utc::now().timestamp()));
    }

    #[test]
    fn burn_escalation_no_abuse() {
        let esc = BurnEscalation::default();
        assert_eq!(esc.cost(0), 1);
    }

    #[test]
    fn burn_escalation_increases() {
        let esc = BurnEscalation::default();
        assert_eq!(esc.cost(1), 2);
        assert_eq!(esc.cost(2), 4);
        assert_eq!(esc.cost(3), 8);
    }

    #[test]
    fn burn_escalation_capped() {
        let esc = BurnEscalation {
            base_cost: 1,
            abuse_multiplier: 2.0,
            max_cost: 50,
        };
        assert_eq!(esc.cost(10), 50); // 2^10 = 1024, capped at 50
    }
}
