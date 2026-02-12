use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Agent identity — SHA-256 of the agent's Ed25519 public key.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl AgentId {
    pub fn from_public_key(pubkey_bytes: &[u8; 32]) -> Self {
        let hash = Sha256::digest(pubkey_bytes);
        Self(hash.into())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentId({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Content-addressed object hash — SHA-256 of the canonicalized object (sans signature).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectHash(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl ObjectHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for ObjectHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectHash({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for ObjectHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Unix epoch timestamp in seconds.
pub type Timestamp = i64;

/// Schema identifier with version, e.g. "Claim@1.0.0".
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaId(pub String);

impl SchemaId {
    pub fn new(name: &str, version: &str) -> Self {
        Self(format!("{name}@{version}"))
    }

    pub fn name(&self) -> &str {
        self.0.split('@').next().unwrap_or(&self.0)
    }

    pub fn version(&self) -> Option<&str> {
        self.0.split('@').nth(1)
    }
}

impl fmt::Display for SchemaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Proof-of-work proof attached to objects.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowProof {
    pub nonce: String,
    pub counter: u64,
    pub result_hash: String,
    pub difficulty: u32,
}

/// Topic identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TopicId(pub String);

impl fmt::Display for TopicId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Common error types.
#[derive(Debug, thiserror::Error)]
pub enum AgenetError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid proof-of-work")]
    InvalidPow,
    #[error("pow challenge expired")]
    PowExpired,
    #[error("unknown schema: {0}")]
    UnknownSchema(String),
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),
    #[error("object not found: {0}")]
    NotFound(String),
    #[error("duplicate object: {0}")]
    Duplicate(String),
    #[error("insufficient credits")]
    InsufficientCredits,
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Serde helper for fixed-size byte arrays as hex strings.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_from_public_key() {
        let pubkey = [42u8; 32];
        let id = AgentId::from_public_key(&pubkey);
        assert_eq!(id.0.len(), 32);
        // Deterministic: same key -> same id
        let id2 = AgentId::from_public_key(&pubkey);
        assert_eq!(id, id2);
    }

    #[test]
    fn agent_id_hex_roundtrip() {
        let pubkey = [7u8; 32];
        let id = AgentId::from_public_key(&pubkey);
        let hex_str = id.to_hex();
        let id2 = AgentId::from_hex(&hex_str).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn object_hash_hex_roundtrip() {
        let hash = ObjectHash([0xab; 32]);
        let hex_str = hash.to_hex();
        let hash2 = ObjectHash::from_hex(&hex_str).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn schema_id_parsing() {
        let schema = SchemaId::new("Claim", "1.0.0");
        assert_eq!(schema.name(), "Claim");
        assert_eq!(schema.version(), Some("1.0.0"));
        assert_eq!(schema.to_string(), "Claim@1.0.0");
    }

    #[test]
    fn agent_id_serde_roundtrip() {
        let id = AgentId::from_public_key(&[99u8; 32]);
        let json = serde_json::to_string(&id).unwrap();
        let id2: AgentId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }
}
