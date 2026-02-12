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
}
