use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A Merkle tree for verifiable append-only topic logs.
///
/// Each appended object hash extends the tree. The root can be published
/// at intervals. Clients verify inclusion via Merkle proofs.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Leaf hashes in insertion order.
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Append a leaf (object hash) to the tree.
    pub fn append(&mut self, hash: [u8; 32]) {
        self.leaves.push(hash);
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Compute the Merkle root.
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        if self.leaves.len() == 1 {
            return self.leaves[0];
        }
        compute_root(&self.leaves)
    }

    /// Generate an inclusion proof for the leaf at `index`.
    /// Returns a list of (sibling_hash, is_right) pairs from leaf to root.
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut proof_nodes = Vec::new();
        let mut level = self.leaves.clone();
        let mut idx = index;

        while level.len() > 1 {
            // Pad to even
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }

            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let is_right = idx % 2 == 0;

            proof_nodes.push(ProofNode {
                hash: level[sibling_idx],
                is_right,
            });

            // Move up
            let mut next_level = Vec::new();
            for pair in level.chunks(2) {
                next_level.push(hash_pair(&pair[0], &pair[1]));
            }
            level = next_level;
            idx /= 2;
        }

        Some(MerkleProof {
            leaf_index: index,
            leaf_hash: self.leaves[index],
            nodes: proof_nodes,
            root: self.root(),
        })
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// A Merkle inclusion proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    #[serde(with = "hex_bytes_32")]
    pub leaf_hash: [u8; 32],
    pub nodes: Vec<ProofNode>,
    #[serde(with = "hex_bytes_32")]
    pub root: [u8; 32],
}

impl MerkleProof {
    /// Verify this proof against a claimed root.
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        if self.root != *expected_root {
            return false;
        }

        let mut current = self.leaf_hash;
        for node in &self.nodes {
            if node.is_right {
                // sibling is on the right
                current = hash_pair(&current, &node.hash);
            } else {
                // sibling is on the left
                current = hash_pair(&node.hash, &current);
            }
        }

        current == *expected_root
    }
}

/// A node in a Merkle proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProofNode {
    #[serde(with = "hex_bytes_32")]
    pub hash: [u8; 32],
    /// True if the current node is on the left (sibling is right).
    pub is_right: bool,
}

/// Hash two nodes together.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute root from leaves.
fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}

/// Per-topic Merkle tree registry.
#[derive(Clone, Default)]
pub struct TopicMerkleStore {
    trees: Arc<RwLock<HashMap<String, MerkleTree>>>,
}

impl TopicMerkleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an object hash to a topic's Merkle tree.
    pub fn append(&self, topic: &str, hash: [u8; 32]) {
        self.trees
            .write()
            .unwrap()
            .entry(topic.to_string())
            .or_default()
            .append(hash);
    }

    /// Get the current Merkle root for a topic.
    pub fn root(&self, topic: &str) -> Option<[u8; 32]> {
        let trees = self.trees.read().unwrap();
        trees.get(topic).map(|t| t.root())
    }

    /// Generate an inclusion proof for an object at a given index in a topic.
    pub fn proof(&self, topic: &str, index: usize) -> Option<MerkleProof> {
        let trees = self.trees.read().unwrap();
        trees.get(topic).and_then(|t| t.proof(index))
    }

    /// Get the number of leaves in a topic's tree.
    pub fn len(&self, topic: &str) -> usize {
        let trees = self.trees.read().unwrap();
        trees.get(topic).map(|t| t.len()).unwrap_or(0)
    }
}

mod hex_bytes_32 {
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

    fn hash_of(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    #[test]
    fn empty_tree() {
        let tree = MerkleTree::new();
        assert_eq!(tree.root(), [0u8; 32]);
        assert!(tree.is_empty());
    }

    #[test]
    fn single_leaf() {
        let mut tree = MerkleTree::new();
        let leaf = hash_of(b"hello");
        tree.append(leaf);
        assert_eq!(tree.root(), leaf);
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn two_leaves() {
        let mut tree = MerkleTree::new();
        let a = hash_of(b"a");
        let b = hash_of(b"b");
        tree.append(a);
        tree.append(b);
        let expected_root = hash_pair(&a, &b);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn root_deterministic() {
        let mut t1 = MerkleTree::new();
        let mut t2 = MerkleTree::new();
        for i in 0..10u8 {
            let h = hash_of(&[i]);
            t1.append(h);
            t2.append(h);
        }
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn root_changes_with_new_leaf() {
        let mut tree = MerkleTree::new();
        tree.append(hash_of(b"a"));
        tree.append(hash_of(b"b"));
        let root1 = tree.root();
        tree.append(hash_of(b"c"));
        let root2 = tree.root();
        assert_ne!(root1, root2);
    }

    #[test]
    fn proof_single_leaf() {
        let mut tree = MerkleTree::new();
        tree.append(hash_of(b"only"));
        let proof = tree.proof(0).unwrap();
        assert!(proof.verify(&tree.root()));
    }

    #[test]
    fn proof_two_leaves() {
        let mut tree = MerkleTree::new();
        tree.append(hash_of(b"a"));
        tree.append(hash_of(b"b"));
        let root = tree.root();

        let proof0 = tree.proof(0).unwrap();
        assert!(proof0.verify(&root));

        let proof1 = tree.proof(1).unwrap();
        assert!(proof1.verify(&root));
    }

    #[test]
    fn proof_many_leaves() {
        let mut tree = MerkleTree::new();
        for i in 0..17u8 {
            tree.append(hash_of(&[i]));
        }
        let root = tree.root();

        // Verify every leaf
        for i in 0..17 {
            let proof = tree.proof(i).unwrap();
            assert!(proof.verify(&root), "proof failed for leaf {i}");
        }
    }

    #[test]
    fn proof_out_of_bounds() {
        let mut tree = MerkleTree::new();
        tree.append(hash_of(b"x"));
        assert!(tree.proof(1).is_none());
    }

    #[test]
    fn proof_rejects_wrong_root() {
        let mut tree = MerkleTree::new();
        tree.append(hash_of(b"a"));
        tree.append(hash_of(b"b"));
        let proof = tree.proof(0).unwrap();
        let wrong_root = [0xffu8; 32];
        assert!(!proof.verify(&wrong_root));
    }

    #[test]
    fn topic_merkle_store() {
        let store = TopicMerkleStore::new();
        store.append("topic-a", hash_of(b"obj1"));
        store.append("topic-a", hash_of(b"obj2"));
        store.append("topic-b", hash_of(b"obj3"));

        assert_eq!(store.len("topic-a"), 2);
        assert_eq!(store.len("topic-b"), 1);
        assert!(store.root("topic-a").is_some());
        assert!(store.root("nonexistent").is_none());

        let proof = store.proof("topic-a", 0).unwrap();
        assert!(proof.verify(&store.root("topic-a").unwrap()));
    }

    #[test]
    fn proof_serde_roundtrip() {
        let mut tree = MerkleTree::new();
        tree.append(hash_of(b"a"));
        tree.append(hash_of(b"b"));
        tree.append(hash_of(b"c"));
        let proof = tree.proof(1).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let proof2: MerkleProof = serde_json::from_str(&json).unwrap();
        assert!(proof2.verify(&tree.root()));
    }
}
