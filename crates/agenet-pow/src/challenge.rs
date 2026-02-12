use agenet_types::{AgenetError, Timestamp};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A PoW challenge issued by a relay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowChallenge {
    pub nonce: String,
    pub difficulty: u32,
    pub expires: Timestamp,
}

impl PowChallenge {
    /// Generate a new challenge with random nonce.
    pub fn new(difficulty: u32, ttl_seconds: i64) -> Self {
        let mut rng = rand::thread_rng();
        let nonce_bytes: [u8; 16] = rng.gen();
        let nonce = hex::encode(nonce_bytes);
        let expires = chrono::Utc::now().timestamp() + ttl_seconds;
        Self {
            nonce,
            difficulty,
            expires,
        }
    }

    /// Check if this challenge has expired.
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() > self.expires
    }
}

/// In-memory store for issued challenges (one-use, TTL-evicted).
#[derive(Clone, Default)]
pub struct ChallengeStore {
    challenges: Arc<RwLock<HashMap<String, PowChallenge>>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a new challenge and store it.
    pub fn issue(&self, difficulty: u32, ttl_seconds: i64) -> PowChallenge {
        let challenge = PowChallenge::new(difficulty, ttl_seconds);
        self.challenges
            .write()
            .unwrap()
            .insert(challenge.nonce.clone(), challenge.clone());
        challenge
    }

    /// Consume a challenge (one-use). Returns the challenge if valid.
    pub fn consume(&self, nonce: &str) -> Result<PowChallenge, AgenetError> {
        let mut store = self.challenges.write().unwrap();
        let challenge = store.remove(nonce).ok_or(AgenetError::InvalidPow)?;
        if challenge.is_expired() {
            return Err(AgenetError::PowExpired);
        }
        Ok(challenge)
    }

    /// Evict expired challenges.
    pub fn evict_expired(&self) {
        let now = chrono::Utc::now().timestamp();
        self.challenges
            .write()
            .unwrap()
            .retain(|_, c| c.expires > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_generation() {
        let c = PowChallenge::new(20, 300);
        assert_eq!(c.difficulty, 20);
        assert!(!c.is_expired());
        assert_eq!(c.nonce.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn store_issue_and_consume() {
        let store = ChallengeStore::new();
        let challenge = store.issue(20, 300);
        let consumed = store.consume(&challenge.nonce).unwrap();
        assert_eq!(consumed.nonce, challenge.nonce);
        // Second consume should fail (one-use)
        assert!(store.consume(&challenge.nonce).is_err());
    }
}
