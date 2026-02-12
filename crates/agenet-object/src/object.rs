use agenet_identity::AgentKeypair;
use agenet_types::{AgentId, AgenetError, ObjectHash, PowProof, SchemaId, Timestamp};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{canonicalize, content_hash};

/// A signed, content-addressed AGENET object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Object {
    pub schema: SchemaId,
    pub author: AgentId,
    pub timestamp: Timestamp,
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<ObjectHash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pow_proof: Option<PowProof>,
    /// Hex-encoded Ed25519 public key of the author (for self-authenticating verification).
    pub author_pubkey: String,
    /// Hex-encoded Ed25519 signature over the canonicalized object (sans signature/pubkey fields).
    pub signature: String,
}

/// The object fields without signature, used for canonicalization and hashing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawObject {
    pub schema: SchemaId,
    pub author: AgentId,
    pub timestamp: Timestamp,
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<ObjectHash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pow_proof: Option<PowProof>,
}

impl Object {
    /// Extract the signable (unsigned) portion of this object.
    pub fn raw(&self) -> RawObject {
        RawObject {
            schema: self.schema.clone(),
            author: self.author.clone(),
            timestamp: self.timestamp,
            payload: self.payload.clone(),
            topic: self.topic.clone(),
            ttl: self.ttl,
            references: self.references.clone(),
            capabilities: self.capabilities.clone(),
            tags: self.tags.clone(),
            pow_proof: self.pow_proof.clone(),
        }
    }

    /// Compute the canonical JSON of the unsigned portion.
    pub fn canonical_bytes(&self) -> String {
        let raw_value = serde_json::to_value(self.raw()).expect("RawObject must serialize");
        canonicalize(&raw_value)
    }

    /// Compute the content-addressed hash.
    pub fn hash(&self) -> ObjectHash {
        content_hash(&self.canonical_bytes())
    }

    /// Verify the Ed25519 signature given the author's public key.
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), AgenetError> {
        let sig_bytes =
            hex::decode(&self.signature).map_err(|_| AgenetError::InvalidSignature)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AgenetError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_arr);
        let canonical = self.canonical_bytes();
        let verifying_key =
            VerifyingKey::from_bytes(public_key).map_err(|_| AgenetError::InvalidSignature)?;
        verifying_key
            .verify(canonical.as_bytes(), &signature)
            .map_err(|_| AgenetError::InvalidSignature)
    }

    /// Self-authenticating verification: verify author == SHA-256(author_pubkey) AND signature is valid.
    pub fn verify_self(&self) -> Result<(), AgenetError> {
        let pubkey_bytes: [u8; 32] = hex::decode(&self.author_pubkey)
            .map_err(|_| AgenetError::InvalidSignature)?
            .try_into()
            .map_err(|_| AgenetError::InvalidSignature)?;

        // Verify author matches public key
        let expected_author = AgentId::from_public_key(&pubkey_bytes);
        if expected_author != self.author {
            return Err(AgenetError::InvalidSignature);
        }

        // Verify cryptographic signature
        self.verify(&pubkey_bytes)
    }
}

impl RawObject {
    /// Compute canonical JSON for this unsigned object.
    pub fn canonical_bytes(&self) -> String {
        let value = serde_json::to_value(self).expect("RawObject must serialize");
        canonicalize(&value)
    }

    /// Compute content hash.
    pub fn hash(&self) -> ObjectHash {
        content_hash(&self.canonical_bytes())
    }
}

/// Builder for constructing and signing objects.
pub struct ObjectBuilder {
    schema: SchemaId,
    payload: Value,
    topic: Option<String>,
    ttl: Option<Timestamp>,
    references: Vec<ObjectHash>,
    capabilities: Vec<String>,
    tags: Vec<String>,
    pow_proof: Option<PowProof>,
    timestamp: Option<Timestamp>,
}

impl ObjectBuilder {
    pub fn new(schema: SchemaId, payload: Value) -> Self {
        Self {
            schema,
            payload,
            topic: None,
            ttl: None,
            references: Vec::new(),
            capabilities: Vec::new(),
            tags: Vec::new(),
            pow_proof: None,
            timestamp: None,
        }
    }

    pub fn topic(mut self, topic: impl Into<String>) -> Self {
        self.topic = Some(topic.into());
        self
    }

    pub fn ttl(mut self, ttl: Timestamp) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn references(mut self, refs: Vec<ObjectHash>) -> Self {
        self.references = refs;
        self
    }

    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn capabilities(mut self, caps: Vec<String>) -> Self {
        self.capabilities = caps;
        self
    }

    pub fn pow_proof(mut self, proof: PowProof) -> Self {
        self.pow_proof = Some(proof);
        self
    }

    pub fn timestamp(mut self, ts: Timestamp) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// Sign and produce the final Object.
    pub fn sign(self, keypair: &AgentKeypair) -> Object {
        let now = self
            .timestamp
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        let raw = RawObject {
            schema: self.schema,
            author: keypair.agent_id(),
            timestamp: now,
            payload: self.payload,
            topic: self.topic,
            ttl: self.ttl,
            references: self.references,
            capabilities: self.capabilities,
            tags: self.tags,
            pow_proof: self.pow_proof,
        };

        let canonical = raw.canonical_bytes();
        let signature = keypair.sign(canonical.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());

        Object {
            schema: raw.schema,
            author: raw.author,
            timestamp: raw.timestamp,
            payload: raw.payload,
            topic: raw.topic,
            ttl: raw.ttl,
            references: raw.references,
            capabilities: raw.capabilities,
            tags: raw.tags,
            pow_proof: raw.pow_proof,
            author_pubkey: hex::encode(keypair.public_key_bytes()),
            signature: sig_hex,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_keypair() -> AgentKeypair {
        AgentKeypair::generate()
    }

    #[test]
    fn build_sign_verify() {
        let kp = test_keypair();
        let obj = ObjectBuilder::new(
            SchemaId::new("Claim", "1.0.0"),
            json!({"statement": "test claim"}),
        )
        .topic("test-topic")
        .tags(vec!["test".into()])
        .sign(&kp);

        assert!(obj.verify(&kp.public_key_bytes()).is_ok());
        assert!(obj.verify_self().is_ok());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let kp = test_keypair();
        let mut obj = ObjectBuilder::new(
            SchemaId::new("Claim", "1.0.0"),
            json!({"statement": "original"}),
        )
        .sign(&kp);

        // Tamper with payload
        obj.payload = json!({"statement": "tampered"});
        assert!(obj.verify(&kp.public_key_bytes()).is_err());
        assert!(obj.verify_self().is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp1 = test_keypair();
        let kp2 = test_keypair();
        let obj = ObjectBuilder::new(SchemaId::new("Claim", "1.0.0"), json!({"x": 1})).sign(&kp1);

        assert!(obj.verify(&kp2.public_key_bytes()).is_err());
    }

    #[test]
    fn verify_self_rejects_mismatched_pubkey() {
        let kp1 = test_keypair();
        let kp2 = test_keypair();
        let mut obj = ObjectBuilder::new(SchemaId::new("Claim", "1.0.0"), json!({"x": 1})).sign(&kp1);

        // Replace pubkey with different key — author won't match
        obj.author_pubkey = hex::encode(kp2.public_key_bytes());
        assert!(obj.verify_self().is_err());
    }

    #[test]
    fn content_addressing_deterministic() {
        let kp = test_keypair();
        let obj = ObjectBuilder::new(SchemaId::new("Message", "1.0.0"), json!({"body": "hello"}))
            .sign(&kp);

        let hash1 = obj.hash();
        let hash2 = obj.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn serde_roundtrip() {
        let kp = test_keypair();
        let obj = ObjectBuilder::new(SchemaId::new("Claim", "1.0.0"), json!({"data": 42}))
            .topic("roundtrip")
            .sign(&kp);

        let json = serde_json::to_string(&obj).unwrap();
        let obj2: Object = serde_json::from_str(&json).unwrap();
        assert_eq!(obj.hash(), obj2.hash());
        assert!(obj2.verify_self().is_ok());
    }

    #[test]
    fn builder_capabilities() {
        let kp = test_keypair();
        let obj = ObjectBuilder::new(SchemaId::new("Claim", "1.0.0"), json!({"statement": "test"}))
            .capabilities(vec!["read:topic:security".into(), "write:topic:security".into()])
            .sign(&kp);

        assert_eq!(obj.capabilities.len(), 2);
        assert_eq!(obj.capabilities[0], "read:topic:security");
        assert_eq!(obj.capabilities[1], "write:topic:security");
        assert!(obj.verify_self().is_ok());
    }

    #[test]
    fn builder_references() {
        let kp = test_keypair();
        let ref_hash = ObjectHash::from_hex(&"ab".repeat(32)).unwrap();
        let obj = ObjectBuilder::new(SchemaId::new("Claim", "1.0.0"), json!({"statement": "test"}))
            .references(vec![ref_hash.clone()])
            .sign(&kp);

        assert_eq!(obj.references.len(), 1);
        assert_eq!(obj.references[0], ref_hash);
        assert!(obj.verify_self().is_ok());
    }

    #[test]
    fn builder_ttl() {
        let kp = test_keypair();
        let obj = ObjectBuilder::new(SchemaId::new("Claim", "1.0.0"), json!({"statement": "ephemeral"}))
            .ttl(3600)
            .sign(&kp);

        assert_eq!(obj.ttl, Some(3600));
        assert!(obj.verify_self().is_ok());
    }

    #[test]
    fn builder_all_fields() {
        let kp = test_keypair();
        let ref_hash = ObjectHash::from_hex(&"cd".repeat(32)).unwrap();
        let obj = ObjectBuilder::new(SchemaId::new("Claim", "1.0.0"), json!({"statement": "full"}))
            .topic("full-test")
            .ttl(7200)
            .tags(vec!["tag1".into(), "tag2".into()])
            .capabilities(vec!["cap1".into()])
            .references(vec![ref_hash.clone()])
            .timestamp(1700000000)
            .sign(&kp);

        assert_eq!(obj.topic, Some("full-test".into()));
        assert_eq!(obj.ttl, Some(7200));
        assert_eq!(obj.tags, vec!["tag1", "tag2"]);
        assert_eq!(obj.capabilities, vec!["cap1"]);
        assert_eq!(obj.references, vec![ref_hash]);
        assert_eq!(obj.timestamp, 1700000000);
        assert!(obj.verify_self().is_ok());

        // Serde roundtrip preserves everything
        let json = serde_json::to_string(&obj).unwrap();
        let obj2: Object = serde_json::from_str(&json).unwrap();
        assert_eq!(obj.hash(), obj2.hash());
        assert_eq!(obj2.capabilities, obj.capabilities);
        assert_eq!(obj2.references, obj.references);
    }
}
