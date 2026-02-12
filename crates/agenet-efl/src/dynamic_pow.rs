use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Tracks per-topic message rates for difficulty adjustment.
#[derive(Clone)]
pub struct TopicRateTracker {
    /// topic -> list of submission timestamps (sliding window)
    windows: Arc<RwLock<HashMap<String, Vec<i64>>>>,
    window_seconds: i64,
}

impl TopicRateTracker {
    pub fn new(window_seconds: i64) -> Self {
        Self {
            windows: Arc::new(RwLock::new(HashMap::new())),
            window_seconds,
        }
    }

    /// Record an object submission for a topic.
    pub fn record(&self, topic: &str) {
        let now = chrono::Utc::now().timestamp();
        let mut windows = self.windows.write().unwrap();
        let entries = windows.entry(topic.to_string()).or_default();
        entries.push(now);
        // Prune old entries
        let cutoff = now - self.window_seconds;
        entries.retain(|&t| t > cutoff);
    }

    /// Get objects-per-minute for a topic.
    pub fn rate_per_minute(&self, topic: &str) -> f64 {
        let now = chrono::Utc::now().timestamp();
        let cutoff = now - self.window_seconds;
        let windows = self.windows.read().unwrap();
        match windows.get(topic) {
            Some(entries) => {
                let count = entries.iter().filter(|&&t| t > cutoff).count();
                (count as f64 / self.window_seconds as f64) * 60.0
            }
            None => 0.0,
        }
    }
}

/// Agent reputation snapshot for PoW difficulty calculation.
pub struct AgentReputation {
    pub attestation_count: u32,
    pub abuse_flags: u32,
}

/// Configuration for dynamic difficulty adjustment.
#[derive(Clone, Debug)]
pub struct DifficultyConfig {
    /// Base difficulty (leading zero bits) for all topics.
    pub base_difficulty: u32,
    /// Minimum difficulty floor.
    pub min_difficulty: u32,
    /// Maximum difficulty ceiling.
    pub max_difficulty: u32,
    /// Messages/minute threshold above which difficulty starts increasing.
    pub congestion_threshold: f64,
    /// Difficulty increase per 10x congestion above threshold.
    pub congestion_scale: u32,
    /// Difficulty reduction per N attestations (reputation discount).
    pub attestation_discount_per: u32,
    /// How many attestations for 1 difficulty reduction.
    pub attestations_per_discount: u32,
    /// Extra difficulty per abuse flag.
    pub abuse_penalty: u32,
}

impl Default for DifficultyConfig {
    fn default() -> Self {
        Self {
            base_difficulty: 20,
            min_difficulty: 16,
            max_difficulty: 28,
            congestion_threshold: 100.0,
            congestion_scale: 2,
            attestation_discount_per: 1,
            attestations_per_discount: 5,
            abuse_penalty: 4,
        }
    }
}

/// Calculate dynamic PoW difficulty for a given context.
pub fn difficulty_for(
    config: &DifficultyConfig,
    topic_rate: f64,
    reputation: &AgentReputation,
) -> u32 {
    let mut difficulty = config.base_difficulty;

    // Congestion increase: +congestion_scale for each 10x over threshold
    if topic_rate > config.congestion_threshold {
        let ratio = topic_rate / config.congestion_threshold;
        let log_factor = ratio.log10().ceil() as u32;
        difficulty += log_factor * config.congestion_scale;
    }

    // Reputation discount
    let discount =
        (reputation.attestation_count / config.attestations_per_discount) * config.attestation_discount_per;
    difficulty = difficulty.saturating_sub(discount);

    // Abuse penalty
    difficulty += reputation.abuse_flags * config.abuse_penalty;

    // Clamp to bounds
    difficulty.clamp(config.min_difficulty, config.max_difficulty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_difficulty_no_congestion() {
        let config = DifficultyConfig::default();
        let rep = AgentReputation {
            attestation_count: 0,
            abuse_flags: 0,
        };
        assert_eq!(difficulty_for(&config, 0.0, &rep), 20);
    }

    #[test]
    fn congestion_increases_difficulty() {
        let config = DifficultyConfig::default();
        let rep = AgentReputation {
            attestation_count: 0,
            abuse_flags: 0,
        };
        // 1000 msg/min = 10x over threshold of 100
        let d = difficulty_for(&config, 1000.0, &rep);
        assert!(d > 20, "expected > 20, got {d}");
    }

    #[test]
    fn reputation_reduces_difficulty() {
        let config = DifficultyConfig::default();
        let rep = AgentReputation {
            attestation_count: 15, // 15/5 = 3 discounts
            abuse_flags: 0,
        };
        let d = difficulty_for(&config, 0.0, &rep);
        assert_eq!(d, 17); // 20 - 3 = 17
    }

    #[test]
    fn abuse_increases_difficulty() {
        let config = DifficultyConfig::default();
        let rep = AgentReputation {
            attestation_count: 0,
            abuse_flags: 2,
        };
        let d = difficulty_for(&config, 0.0, &rep);
        assert_eq!(d, 28); // 20 + 2*4 = 28 (capped)
    }

    #[test]
    fn difficulty_clamped_to_bounds() {
        let config = DifficultyConfig::default();
        // Very high reputation
        let rep = AgentReputation {
            attestation_count: 100,
            abuse_flags: 0,
        };
        let d = difficulty_for(&config, 0.0, &rep);
        assert_eq!(d, config.min_difficulty);

        // Very high abuse
        let rep2 = AgentReputation {
            attestation_count: 0,
            abuse_flags: 10,
        };
        let d2 = difficulty_for(&config, 10000.0, &rep2);
        assert_eq!(d2, config.max_difficulty);
    }

    #[test]
    fn combined_factors() {
        let config = DifficultyConfig::default();
        // Moderate congestion + good reputation
        let rep = AgentReputation {
            attestation_count: 10, // -2 discount
            abuse_flags: 0,
        };
        // 1000 msg/min -> +2 from congestion
        let d = difficulty_for(&config, 1000.0, &rep);
        assert_eq!(d, 20); // 20 + 2 - 2 = 20
    }

    #[test]
    fn rate_tracker() {
        let tracker = TopicRateTracker::new(60);
        for _ in 0..10 {
            tracker.record("test-topic");
        }
        let rate = tracker.rate_per_minute("test-topic");
        assert!((rate - 10.0).abs() < 1.0, "expected ~10/min, got {rate}");
    }

    #[test]
    fn rate_tracker_empty_topic() {
        let tracker = TopicRateTracker::new(60);
        assert_eq!(tracker.rate_per_minute("nonexistent"), 0.0);
    }
}
