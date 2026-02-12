use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Per-topic policy requirements enforced by the relay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TopicPolicy {
    pub topic: String,
    /// Minimum PoW difficulty required (0 = no PoW required).
    pub min_pow: u32,
    /// Minimum positive attestations the author must have.
    pub min_reputation_attestations: u32,
    /// Maximum payload size in bytes (0 = unlimited).
    pub max_payload_bytes: usize,
    /// Whether PoW can be substituted with credit burn.
    pub allow_credit_substitution: bool,
    /// Minimum trust graph depth (unique attesters in chain, 0 = no requirement).
    pub min_trust_depth: u32,
}

impl Default for TopicPolicy {
    fn default() -> Self {
        Self {
            topic: String::new(),
            min_pow: 0,
            min_reputation_attestations: 0,
            max_payload_bytes: 0,
            allow_credit_substitution: true,
            min_trust_depth: 0,
        }
    }
}

/// Registry of per-topic policies.
#[derive(Clone, Default)]
pub struct PolicyRegistry {
    policies: Arc<RwLock<HashMap<String, TopicPolicy>>>,
    /// Default policy for topics without explicit policy.
    default_policy: TopicPolicy,
}

impl PolicyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default(default_policy: TopicPolicy) -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            default_policy,
        }
    }

    /// Register or update a topic policy.
    pub fn set(&self, policy: TopicPolicy) {
        self.policies
            .write()
            .unwrap()
            .insert(policy.topic.clone(), policy);
    }

    /// Get the effective policy for a topic (falls back to default).
    pub fn get(&self, topic: &str) -> TopicPolicy {
        self.policies
            .read()
            .unwrap()
            .get(topic)
            .cloned()
            .unwrap_or_else(|| {
                let mut p = self.default_policy.clone();
                p.topic = topic.to_string();
                p
            })
    }

    /// Ingest a Policy object's payload and register it.
    pub fn ingest_from_payload(&self, payload: &serde_json::Value) {
        let topic = match payload.get("topic").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => return,
        };

        let requirements = match payload.get("requirements") {
            Some(r) => r,
            None => return,
        };

        let min_pow = requirements
            .get("min_pow")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let min_reputation = requirements
            .get("min_reputation_attestations")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let max_size = requirements
            .get("artifact_max_size_mb")
            .and_then(|v| v.as_u64())
            .map(|mb| (mb as usize) * 1024 * 1024)
            .unwrap_or(0);

        let min_trust_depth = requirements
            .get("min_trust_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        self.set(TopicPolicy {
            topic,
            min_pow,
            min_reputation_attestations: min_reputation,
            max_payload_bytes: max_size,
            allow_credit_substitution: true,
            min_trust_depth,
        });
    }

    /// List all registered topic policies.
    pub fn list(&self) -> Vec<TopicPolicy> {
        self.policies.read().unwrap().values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_policy_for_unknown_topic() {
        let registry = PolicyRegistry::new();
        let policy = registry.get("unknown");
        assert_eq!(policy.min_pow, 0);
        assert_eq!(policy.min_reputation_attestations, 0);
    }

    #[test]
    fn set_and_get_policy() {
        let registry = PolicyRegistry::new();
        registry.set(TopicPolicy {
            topic: "CVE-Research".into(),
            min_pow: 20,
            min_reputation_attestations: 3,
            max_payload_bytes: 50 * 1024 * 1024,
            allow_credit_substitution: true,
            min_trust_depth: 0,
        });
        let policy = registry.get("CVE-Research");
        assert_eq!(policy.min_pow, 20);
        assert_eq!(policy.min_reputation_attestations, 3);
    }

    #[test]
    fn ingest_from_policy_payload() {
        let registry = PolicyRegistry::new();
        let payload = json!({
            "topic": "security",
            "requirements": {
                "min_pow": 22,
                "min_reputation_attestations": 5,
                "artifact_max_size_mb": 100
            }
        });
        registry.ingest_from_payload(&payload);

        let policy = registry.get("security");
        assert_eq!(policy.min_pow, 22);
        assert_eq!(policy.min_reputation_attestations, 5);
        assert_eq!(policy.max_payload_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn custom_default_policy() {
        let registry = PolicyRegistry::with_default(TopicPolicy {
            topic: String::new(),
            min_pow: 16,
            min_reputation_attestations: 1,
            max_payload_bytes: 10 * 1024 * 1024,
            allow_credit_substitution: true,
            min_trust_depth: 0,
        });
        let policy = registry.get("any-topic");
        assert_eq!(policy.min_pow, 16);
        assert_eq!(policy.min_reputation_attestations, 1);
    }

    #[test]
    fn list_policies() {
        let registry = PolicyRegistry::new();
        registry.set(TopicPolicy {
            topic: "a".into(),
            ..Default::default()
        });
        registry.set(TopicPolicy {
            topic: "b".into(),
            ..Default::default()
        });
        assert_eq!(registry.list().len(), 2);
    }
}
