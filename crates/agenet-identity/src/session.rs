use agenet_types::{AgenetError, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::AgentKeypair;

/// An ephemeral session key derived from the agent's identity key.
///
/// Session keys are short-lived, rotated frequently, and used for
/// E2EE session negotiation instead of exposing the long-lived identity key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionKey {
    /// Unique session ID (hex-encoded SHA-256 of the session public key).
    pub session_id: String,
    /// The ephemeral X25519 public key for this session (hex-encoded).
    pub x25519_pubkey: String,
    /// When this session key was created (unix timestamp).
    pub created: Timestamp,
    /// When this session key expires (unix timestamp).
    pub expires: Timestamp,
}

/// Internal representation with the secret half.
struct SessionKeyPair {
    session_id: String,
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
    created: Timestamp,
    expires: Timestamp,
}

/// Manages rotating session keys for an agent.
///
/// Session keys are ephemeral X25519 keys derived from random entropy
/// (not from the identity key) for forward secrecy. Each session key
/// has a bounded lifetime and is automatically cleaned up on expiry.
pub struct SessionKeyManager {
    /// The agent's identity keypair (for signing session announcements).
    identity: AgentKeypair,
    /// Active session keys, keyed by session_id.
    sessions: Arc<RwLock<HashMap<String, SessionKeyPair>>>,
    /// Default session TTL in seconds.
    default_ttl: i64,
}

impl SessionKeyManager {
    /// Create a new session key manager for an agent.
    pub fn new(identity: AgentKeypair, default_ttl: i64) -> Self {
        Self {
            identity,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
        }
    }

    /// Generate a new ephemeral session key.
    pub fn rotate(&self) -> SessionKey {
        self.rotate_with_ttl(self.default_ttl)
    }

    /// Generate a new session key with a specific TTL.
    pub fn rotate_with_ttl(&self, ttl_seconds: i64) -> SessionKey {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let public = x25519_dalek::PublicKey::from(&secret);
        let pubkey_bytes = public.as_bytes();
        let session_id = hex::encode(Sha256::digest(pubkey_bytes));
        let now = chrono::Utc::now().timestamp();
        let expires = now + ttl_seconds;

        let pair = SessionKeyPair {
            session_id: session_id.clone(),
            secret,
            public,
            created: now,
            expires,
        };

        self.sessions
            .write()
            .unwrap()
            .insert(session_id.clone(), pair);

        SessionKey {
            session_id,
            x25519_pubkey: hex::encode(pubkey_bytes),
            created: now,
            expires,
        }
    }

    /// Perform DH key exchange using a session key.
    pub fn exchange(
        &self,
        session_id: &str,
        peer_x25519_pubkey: &x25519_dalek::PublicKey,
    ) -> Result<[u8; 32], AgenetError> {
        let sessions = self.sessions.read().unwrap();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| AgenetError::NotFound(format!("session {session_id}")))?;

        let now = chrono::Utc::now().timestamp();
        if now > session.expires {
            return Err(AgenetError::Unauthorized("session key expired".into()));
        }

        let shared = session.secret.diffie_hellman(peer_x25519_pubkey);
        Ok(*shared.as_bytes())
    }

    /// Get the public portion of a session key.
    pub fn get_session(&self, session_id: &str) -> Option<SessionKey> {
        let sessions = self.sessions.read().unwrap();
        sessions.get(session_id).map(|s| SessionKey {
            session_id: s.session_id.clone(),
            x25519_pubkey: hex::encode(s.public.as_bytes()),
            created: s.created,
            expires: s.expires,
        })
    }

    /// List all active (non-expired) session keys.
    pub fn active_sessions(&self) -> Vec<SessionKey> {
        let now = chrono::Utc::now().timestamp();
        let sessions = self.sessions.read().unwrap();
        sessions
            .values()
            .filter(|s| s.expires > now)
            .map(|s| SessionKey {
                session_id: s.session_id.clone(),
                x25519_pubkey: hex::encode(s.public.as_bytes()),
                created: s.created,
                expires: s.expires,
            })
            .collect()
    }

    /// Remove expired session keys.
    pub fn cleanup(&self) -> usize {
        let now = chrono::Utc::now().timestamp();
        let mut sessions = self.sessions.write().unwrap();
        let before = sessions.len();
        sessions.retain(|_, s| s.expires > now);
        before - sessions.len()
    }

    /// Revoke a specific session key.
    pub fn revoke(&self, session_id: &str) -> bool {
        self.sessions
            .write()
            .unwrap()
            .remove(session_id)
            .is_some()
    }

    /// Total number of session keys (including expired).
    pub fn count(&self) -> usize {
        self.sessions.read().unwrap().len()
    }

    /// Access the identity keypair.
    pub fn identity(&self) -> &AgentKeypair {
        &self.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> SessionKeyManager {
        let kp = AgentKeypair::generate();
        SessionKeyManager::new(kp, 3600) // 1 hour default
    }

    #[test]
    fn rotate_creates_session() {
        let mgr = make_manager();
        assert_eq!(mgr.count(), 0);

        let session = mgr.rotate();
        assert_eq!(mgr.count(), 1);
        assert!(!session.session_id.is_empty());
        assert!(!session.x25519_pubkey.is_empty());
        assert!(session.expires > session.created);
    }

    #[test]
    fn multiple_rotations() {
        let mgr = make_manager();
        let s1 = mgr.rotate();
        let s2 = mgr.rotate();
        let s3 = mgr.rotate();

        assert_eq!(mgr.count(), 3);
        assert_ne!(s1.session_id, s2.session_id);
        assert_ne!(s2.session_id, s3.session_id);
    }

    #[test]
    fn exchange_succeeds() {
        let alice_mgr = make_manager();
        let bob_mgr = make_manager();

        let alice_session = alice_mgr.rotate();
        let bob_session = bob_mgr.rotate();

        let alice_pub_bytes: [u8; 32] = hex::decode(&alice_session.x25519_pubkey)
            .unwrap()
            .try_into()
            .unwrap();
        let bob_pub_bytes: [u8; 32] = hex::decode(&bob_session.x25519_pubkey)
            .unwrap()
            .try_into()
            .unwrap();

        let alice_pub = x25519_dalek::PublicKey::from(alice_pub_bytes);
        let bob_pub = x25519_dalek::PublicKey::from(bob_pub_bytes);

        let shared_a = alice_mgr
            .exchange(&alice_session.session_id, &bob_pub)
            .unwrap();
        let shared_b = bob_mgr
            .exchange(&bob_session.session_id, &alice_pub)
            .unwrap();

        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn expired_session_rejected() {
        let mgr = SessionKeyManager::new(AgentKeypair::generate(), 3600);
        // Create session with 0 TTL (already expired)
        let session = mgr.rotate_with_ttl(-1);
        let peer = AgentKeypair::generate();
        let peer_pub = peer.x25519_public_key();

        assert!(mgr.exchange(&session.session_id, &peer_pub).is_err());
    }

    #[test]
    fn unknown_session_rejected() {
        let mgr = make_manager();
        let peer = AgentKeypair::generate();
        let peer_pub = peer.x25519_public_key();

        assert!(mgr.exchange("nonexistent", &peer_pub).is_err());
    }

    #[test]
    fn revoke_session() {
        let mgr = make_manager();
        let session = mgr.rotate();
        assert_eq!(mgr.count(), 1);

        assert!(mgr.revoke(&session.session_id));
        assert_eq!(mgr.count(), 0);
        assert!(!mgr.revoke(&session.session_id)); // already gone
    }

    #[test]
    fn cleanup_expired() {
        let mgr = SessionKeyManager::new(AgentKeypair::generate(), 3600);
        mgr.rotate(); // valid
        mgr.rotate_with_ttl(-1); // expired
        mgr.rotate_with_ttl(-1); // expired

        assert_eq!(mgr.count(), 3);
        let removed = mgr.cleanup();
        assert_eq!(removed, 2);
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn active_sessions_excludes_expired() {
        let mgr = SessionKeyManager::new(AgentKeypair::generate(), 3600);
        mgr.rotate(); // valid
        mgr.rotate_with_ttl(-1); // expired

        let active = mgr.active_sessions();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn get_session() {
        let mgr = make_manager();
        let session = mgr.rotate();

        let retrieved = mgr.get_session(&session.session_id).unwrap();
        assert_eq!(retrieved.session_id, session.session_id);
        assert_eq!(retrieved.x25519_pubkey, session.x25519_pubkey);

        assert!(mgr.get_session("nonexistent").is_none());
    }

    #[test]
    fn session_key_serde() {
        let mgr = make_manager();
        let session = mgr.rotate();

        let json = serde_json::to_string(&session).unwrap();
        let session2: SessionKey = serde_json::from_str(&json).unwrap();
        assert_eq!(session2.session_id, session.session_id);
        assert_eq!(session2.x25519_pubkey, session.x25519_pubkey);
    }
}
