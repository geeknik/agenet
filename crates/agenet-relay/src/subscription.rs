use agenet_object::Object;
use agenet_types::SchemaId;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Subscription filter sent by clients over WebSocket.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub author_trust_set: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_lt: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
}

impl SubscriptionFilter {
    /// Check if an object matches this filter.
    pub fn matches(&self, object: &Object) -> bool {
        if let Some(ref schema) = self.schema {
            if object.schema.name() != SchemaId(schema.clone()).name() {
                return false;
            }
        }
        if !self.tags.is_empty() && !self.tags.iter().any(|t| object.tags.contains(t)) {
            return false;
        }
        if !self.author_trust_set.is_empty() {
            let author_hex = object.author.to_hex();
            if !self.author_trust_set.contains(&author_hex) {
                return false;
            }
        }
        if let Some(ttl_lt) = self.ttl_lt {
            if let Some(ttl) = object.ttl {
                if ttl >= ttl_lt {
                    return false;
                }
            }
        }
        if let Some(ref topic) = self.topic {
            match &object.topic {
                Some(obj_topic) if obj_topic == topic => {}
                _ => return false,
            }
        }
        true
    }
}

/// Fan-out hub for broadcasting new objects to subscribers.
#[derive(Clone)]
pub struct SubscriptionHub {
    sender: broadcast::Sender<Object>,
}

impl SubscriptionHub {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Broadcast a new object to all subscribers.
    pub fn broadcast(&self, object: &Object) {
        // Ignore error (no receivers is fine)
        let _ = self.sender.send(object.clone());
    }

    /// Get a new receiver for subscribing.
    pub fn subscribe(&self) -> broadcast::Receiver<Object> {
        self.sender.subscribe()
    }
}

impl Default for SubscriptionHub {
    fn default() -> Self {
        Self::new(4096)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_serde_roundtrip() {
        let filter = SubscriptionFilter {
            schema: Some("Claim@1.0.0".into()),
            tags: vec!["CVE-2026".into()],
            author_trust_set: vec![],
            ttl_lt: Some(604800),
            topic: Some("security".into()),
        };
        let json = serde_json::to_string(&filter).unwrap();
        let filter2: SubscriptionFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(filter2.schema, filter.schema);
        assert_eq!(filter2.ttl_lt, filter.ttl_lt);
    }

    fn make_test_object(
        schema: &str,
        topic: Option<&str>,
        tags: Vec<String>,
        ttl: Option<i64>,
    ) -> Object {
        use agenet_identity::AgentKeypair;
        use serde_json::json;
        let kp = AgentKeypair::generate();
        let mut builder = agenet_object::ObjectBuilder::new(
            SchemaId(format!("{schema}@1.0.0")),
            json!({"statement": "test"}),
        )
        .tags(tags);
        if let Some(t) = topic {
            builder = builder.topic(t);
        }
        if let Some(ttl_val) = ttl {
            builder = builder.ttl(ttl_val);
        }
        builder.sign(&kp)
    }

    #[test]
    fn matches_empty_filter_accepts_all() {
        let filter = SubscriptionFilter {
            schema: None,
            tags: vec![],
            author_trust_set: vec![],
            ttl_lt: None,
            topic: None,
        };
        let obj = make_test_object("Claim", Some("any-topic"), vec!["tag1".into()], None);
        assert!(filter.matches(&obj));
    }

    #[test]
    fn matches_schema_filter() {
        let filter = SubscriptionFilter {
            schema: Some("Claim@1.0.0".into()),
            tags: vec![],
            author_trust_set: vec![],
            ttl_lt: None,
            topic: None,
        };
        let matching = make_test_object("Claim", None, vec![], None);
        let non_matching = make_test_object("Message", None, vec![], None);
        assert!(filter.matches(&matching));
        assert!(!filter.matches(&non_matching));
    }

    #[test]
    fn matches_tag_filter_or_semantics() {
        let filter = SubscriptionFilter {
            schema: None,
            tags: vec!["security".into(), "cve".into()],
            author_trust_set: vec![],
            ttl_lt: None,
            topic: None,
        };
        // Has "security" — matches (OR)
        let obj1 = make_test_object("Claim", None, vec!["security".into()], None);
        assert!(filter.matches(&obj1));

        // Has "cve" — matches
        let obj2 = make_test_object("Claim", None, vec!["cve".into()], None);
        assert!(filter.matches(&obj2));

        // Has neither — no match
        let obj3 = make_test_object("Claim", None, vec!["unrelated".into()], None);
        assert!(!filter.matches(&obj3));

        // Has no tags — no match
        let obj4 = make_test_object("Claim", None, vec![], None);
        assert!(!filter.matches(&obj4));
    }

    #[test]
    fn matches_author_trust_set() {
        use agenet_identity::AgentKeypair;
        use serde_json::json;

        let trusted_kp = AgentKeypair::generate();
        let untrusted_kp = AgentKeypair::generate();

        let filter = SubscriptionFilter {
            schema: None,
            tags: vec![],
            author_trust_set: vec![trusted_kp.agent_id().to_hex()],
            ttl_lt: None,
            topic: None,
        };

        let trusted_obj = agenet_object::ObjectBuilder::new(
            SchemaId("Claim@1.0.0".into()),
            json!({"statement": "test"}),
        )
        .sign(&trusted_kp);

        let untrusted_obj = agenet_object::ObjectBuilder::new(
            SchemaId("Claim@1.0.0".into()),
            json!({"statement": "test"}),
        )
        .sign(&untrusted_kp);

        assert!(filter.matches(&trusted_obj));
        assert!(!filter.matches(&untrusted_obj));
    }

    #[test]
    fn matches_ttl_filter() {
        let filter = SubscriptionFilter {
            schema: None,
            tags: vec![],
            author_trust_set: vec![],
            ttl_lt: Some(3600), // Want objects with TTL < 1 hour
            topic: None,
        };
        // TTL 1800 (30 min) < 3600 — matches
        let obj_short_ttl = make_test_object("Claim", None, vec![], Some(1800));
        assert!(filter.matches(&obj_short_ttl));

        // TTL 7200 (2 hours) >= 3600 — no match
        let obj_long_ttl = make_test_object("Claim", None, vec![], Some(7200));
        assert!(!filter.matches(&obj_long_ttl));

        // No TTL set — passes (filter only applies when TTL exists)
        let obj_no_ttl = make_test_object("Claim", None, vec![], None);
        assert!(filter.matches(&obj_no_ttl));
    }

    #[test]
    fn matches_topic_filter() {
        let filter = SubscriptionFilter {
            schema: None,
            tags: vec![],
            author_trust_set: vec![],
            ttl_lt: None,
            topic: Some("security".into()),
        };
        let obj_match = make_test_object("Claim", Some("security"), vec![], None);
        let obj_wrong = make_test_object("Claim", Some("other"), vec![], None);
        let obj_none = make_test_object("Claim", None, vec![], None);
        assert!(filter.matches(&obj_match));
        assert!(!filter.matches(&obj_wrong));
        assert!(!filter.matches(&obj_none));
    }

    #[test]
    fn matches_combined_filters() {
        let filter = SubscriptionFilter {
            schema: Some("Claim@1.0.0".into()),
            tags: vec!["security".into()],
            author_trust_set: vec![],
            ttl_lt: None,
            topic: Some("security-alerts".into()),
        };
        // Matches all criteria
        let obj_match = make_test_object("Claim", Some("security-alerts"), vec!["security".into()], None);
        assert!(filter.matches(&obj_match));

        // Wrong schema
        let obj_wrong_schema = make_test_object("Message", Some("security-alerts"), vec!["security".into()], None);
        assert!(!filter.matches(&obj_wrong_schema));

        // Wrong tag
        let obj_wrong_tag = make_test_object("Claim", Some("security-alerts"), vec!["fun".into()], None);
        assert!(!filter.matches(&obj_wrong_tag));
    }

    #[test]
    fn hub_broadcast_and_receive() {
        let hub = SubscriptionHub::new(16);
        let mut rx = hub.subscribe();

        let obj = make_test_object("Claim", Some("test"), vec![], None);
        hub.broadcast(&obj);

        let received = rx.try_recv().unwrap();
        assert_eq!(received.schema, obj.schema);
    }
}
