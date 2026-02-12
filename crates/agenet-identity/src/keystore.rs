use agenet_types::AgentId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::AgentKeypair;

/// Trait for storing and retrieving agent keypairs.
pub trait KeyStore: Send + Sync {
    /// Store a keypair, returns the AgentId.
    fn store(&self, keypair: AgentKeypair) -> AgentId;

    /// Retrieve a keypair by AgentId.
    fn get(&self, id: &AgentId) -> Option<AgentKeypair>;

    /// Look up an Ed25519 public key by AgentId.
    fn public_key(&self, id: &AgentId) -> Option<[u8; 32]>;

    /// List all stored AgentIds.
    fn list(&self) -> Vec<AgentId>;
}

/// In-memory key store (for testing and single-process relays).
#[derive(Clone, Default)]
pub struct MemoryKeyStore {
    keys: Arc<RwLock<HashMap<AgentId, AgentKeypair>>>,
    pubkeys: Arc<RwLock<HashMap<AgentId, [u8; 32]>>>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register just a public key (for verifying remote agents).
    pub fn register_public_key(&self, agent_id: AgentId, pubkey: [u8; 32]) {
        self.pubkeys.write().unwrap().insert(agent_id, pubkey);
    }
}

impl KeyStore for MemoryKeyStore {
    fn store(&self, keypair: AgentKeypair) -> AgentId {
        let id = keypair.agent_id();
        let pubkey = keypair.public_key_bytes();
        self.keys.write().unwrap().insert(id.clone(), keypair);
        self.pubkeys.write().unwrap().insert(id.clone(), pubkey);
        id
    }

    fn get(&self, id: &AgentId) -> Option<AgentKeypair> {
        self.keys.read().unwrap().get(id).cloned()
    }

    fn public_key(&self, id: &AgentId) -> Option<[u8; 32]> {
        self.pubkeys.read().unwrap().get(id).copied()
    }

    fn list(&self) -> Vec<AgentId> {
        self.keys.read().unwrap().keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_retrieve() {
        let store = MemoryKeyStore::new();
        let kp = AgentKeypair::generate();
        let id = store.store(kp.clone());

        let retrieved = store.get(&id).unwrap();
        assert_eq!(retrieved.agent_id(), id);
    }

    #[test]
    fn list_keys() {
        let store = MemoryKeyStore::new();
        let kp1 = AgentKeypair::generate();
        let kp2 = AgentKeypair::generate();
        store.store(kp1);
        store.store(kp2);

        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn public_key_lookup() {
        let store = MemoryKeyStore::new();
        let kp = AgentKeypair::generate();
        let pubkey = kp.public_key_bytes();
        let id = store.store(kp);

        assert_eq!(store.public_key(&id), Some(pubkey));
    }
}
