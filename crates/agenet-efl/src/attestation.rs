use agenet_identity::AgentKeypair;
use agenet_types::{AgentId, AgenetError, ObjectHash};
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

/// Attestation claim types.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttestationClaim {
    Trustworthy,
    DomainExpert(String),
    ReliableData,
    GoodActor,
    Malicious,
    Spammer,
}

/// A signed attestation: one agent vouches for another.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    pub attester: AgentId,
    pub attester_pubkey: String,
    pub attestee: AgentId,
    pub claim: AttestationClaim,
    pub evidence_refs: Vec<ObjectHash>,
    pub timestamp: i64,
    pub signature: String,
}

impl Attestation {
    /// Create and sign a new attestation.
    pub fn create(
        attester: &AgentKeypair,
        attestee: AgentId,
        claim: AttestationClaim,
        evidence_refs: Vec<ObjectHash>,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();
        let attester_pubkey = hex::encode(attester.public_key_bytes());
        let signable = Self::signable_content(
            &attester.agent_id(),
            &attestee,
            &claim,
            &evidence_refs,
            now,
        );
        let sig = attester.sign(signable.as_bytes());

        Self {
            attester: attester.agent_id(),
            attester_pubkey,
            attestee,
            claim,
            evidence_refs,
            timestamp: now,
            signature: hex::encode(sig.to_bytes()),
        }
    }

    /// Verify this attestation's signature.
    pub fn verify(&self) -> Result<(), AgenetError> {
        let pubkey_bytes: [u8; 32] = hex::decode(&self.attester_pubkey)
            .map_err(|_| AgenetError::InvalidSignature)?
            .try_into()
            .map_err(|_| AgenetError::InvalidSignature)?;

        // Verify attester ID matches pubkey
        let expected_id = AgentId::from_public_key(&pubkey_bytes);
        if expected_id != self.attester {
            return Err(AgenetError::InvalidSignature);
        }

        let signable = Self::signable_content(
            &self.attester,
            &self.attestee,
            &self.claim,
            &self.evidence_refs,
            self.timestamp,
        );
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| AgenetError::InvalidSignature)?
            .try_into()
            .map_err(|_| AgenetError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let verifying_key =
            VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| AgenetError::InvalidSignature)?;
        verifying_key
            .verify(signable.as_bytes(), &signature)
            .map_err(|_| AgenetError::InvalidSignature)
    }

    fn signable_content(
        attester: &AgentId,
        attestee: &AgentId,
        claim: &AttestationClaim,
        evidence_refs: &[ObjectHash],
        timestamp: i64,
    ) -> String {
        let claim_json = serde_json::to_string(claim).unwrap();
        let refs: Vec<String> = evidence_refs.iter().map(|r| r.to_hex()).collect();
        let refs_str = refs.join(",");
        format!("attestation:{attester}:{attestee}:{claim_json}:{refs_str}:{timestamp}")
    }
}

/// In-memory attestation graph for trust path queries.
#[derive(Clone, Default)]
pub struct AttestationGraph {
    /// attester -> [(attestee, claim)]
    outgoing: Arc<RwLock<HashMap<AgentId, Vec<Attestation>>>>,
    /// attestee -> [(attester, claim)]
    incoming: Arc<RwLock<HashMap<AgentId, Vec<Attestation>>>>,
}

impl AttestationGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an attestation relationship directly (e.g., from a verified Attestation object).
    pub fn record(&self, attester: AgentId, attestee: AgentId, claim: AttestationClaim) {
        let attestation = Attestation {
            attester: attester.clone(),
            attester_pubkey: String::new(), // Not needed for graph queries
            attestee: attestee.clone(),
            claim,
            evidence_refs: vec![],
            timestamp: chrono::Utc::now().timestamp(),
            signature: String::new(), // Already verified at the object level
        };
        self.add(attestation);
    }

    /// Add a verified attestation to the graph.
    pub fn add(&self, attestation: Attestation) {
        self.outgoing
            .write()
            .unwrap()
            .entry(attestation.attester.clone())
            .or_default()
            .push(attestation.clone());
        self.incoming
            .write()
            .unwrap()
            .entry(attestation.attestee.clone())
            .or_default()
            .push(attestation);
    }

    /// Get all attestations about an agent.
    pub fn attestations_for(&self, agent_id: &AgentId) -> Vec<Attestation> {
        self.incoming
            .read()
            .unwrap()
            .get(agent_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all attestations made by an agent.
    pub fn attestations_by(&self, agent_id: &AgentId) -> Vec<Attestation> {
        self.outgoing
            .read()
            .unwrap()
            .get(agent_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Count positive attestations for an agent (for reputation scoring).
    pub fn positive_attestation_count(&self, agent_id: &AgentId) -> u32 {
        self.attestations_for(agent_id)
            .iter()
            .filter(|a| matches!(a.claim, AttestationClaim::Trustworthy | AttestationClaim::DomainExpert(_) | AttestationClaim::ReliableData | AttestationClaim::GoodActor))
            .count() as u32
    }

    /// Count negative attestations (abuse flags).
    pub fn negative_attestation_count(&self, agent_id: &AgentId) -> u32 {
        self.attestations_for(agent_id)
            .iter()
            .filter(|a| matches!(a.claim, AttestationClaim::Malicious | AttestationClaim::Spammer))
            .count() as u32
    }

    /// Find a trust path from `from` to `to` via positive attestations (BFS).
    /// Returns None if no path exists within max_depth.
    pub fn trust_path(
        &self,
        from: &AgentId,
        to: &AgentId,
        max_depth: usize,
    ) -> Option<Vec<AgentId>> {
        if from == to {
            return Some(vec![from.clone()]);
        }

        let outgoing = self.outgoing.read().unwrap();
        let mut visited = HashSet::new();
        let mut queue: VecDeque<(AgentId, Vec<AgentId>)> = VecDeque::new();
        queue.push_back((from.clone(), vec![from.clone()]));
        visited.insert(from.clone());

        while let Some((current, path)) = queue.pop_front() {
            if path.len() > max_depth {
                continue;
            }

            if let Some(attestations) = outgoing.get(&current) {
                for att in attestations {
                    if matches!(
                        att.claim,
                        AttestationClaim::Trustworthy
                            | AttestationClaim::DomainExpert(_)
                            | AttestationClaim::ReliableData
                            | AttestationClaim::GoodActor
                    ) && !visited.contains(&att.attestee)
                    {
                        let mut new_path = path.clone();
                        new_path.push(att.attestee.clone());

                        if att.attestee == *to {
                            return Some(new_path);
                        }

                        visited.insert(att.attestee.clone());
                        queue.push_back((att.attestee.clone(), new_path));
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify_attestation() {
        let attester = AgentKeypair::generate();
        let attestee = AgentKeypair::generate();
        let att = Attestation::create(
            &attester,
            attestee.agent_id(),
            AttestationClaim::Trustworthy,
            vec![],
        );
        assert!(att.verify().is_ok());
    }

    #[test]
    fn tampered_attestation_rejected() {
        let attester = AgentKeypair::generate();
        let attestee = AgentKeypair::generate();
        let mut att = Attestation::create(
            &attester,
            attestee.agent_id(),
            AttestationClaim::Trustworthy,
            vec![],
        );
        att.claim = AttestationClaim::DomainExpert("hacking".into());
        assert!(att.verify().is_err());
    }

    #[test]
    fn graph_add_and_query() {
        let graph = AttestationGraph::new();
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();

        let att = Attestation::create(
            &alice,
            bob.agent_id(),
            AttestationClaim::Trustworthy,
            vec![],
        );
        graph.add(att);

        assert_eq!(graph.attestations_for(&bob.agent_id()).len(), 1);
        assert_eq!(graph.attestations_by(&alice.agent_id()).len(), 1);
        assert_eq!(graph.positive_attestation_count(&bob.agent_id()), 1);
    }

    #[test]
    fn trust_path_direct() {
        let graph = AttestationGraph::new();
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();

        graph.add(Attestation::create(
            &alice,
            bob.agent_id(),
            AttestationClaim::Trustworthy,
            vec![],
        ));

        let path = graph.trust_path(&alice.agent_id(), &bob.agent_id(), 3);
        assert!(path.is_some());
        let path = path.unwrap();
        assert_eq!(path.len(), 2);
        assert_eq!(path[0], alice.agent_id());
        assert_eq!(path[1], bob.agent_id());
    }

    #[test]
    fn trust_path_transitive() {
        let graph = AttestationGraph::new();
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();
        let carol = AgentKeypair::generate();

        graph.add(Attestation::create(
            &alice,
            bob.agent_id(),
            AttestationClaim::Trustworthy,
            vec![],
        ));
        graph.add(Attestation::create(
            &bob,
            carol.agent_id(),
            AttestationClaim::ReliableData,
            vec![],
        ));

        let path = graph.trust_path(&alice.agent_id(), &carol.agent_id(), 5);
        assert!(path.is_some());
        assert_eq!(path.unwrap().len(), 3);
    }

    #[test]
    fn trust_path_none_when_no_connection() {
        let graph = AttestationGraph::new();
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();
        let carol = AgentKeypair::generate();

        graph.add(Attestation::create(
            &alice,
            bob.agent_id(),
            AttestationClaim::Trustworthy,
            vec![],
        ));
        // No path from alice to carol
        assert!(graph
            .trust_path(&alice.agent_id(), &carol.agent_id(), 5)
            .is_none());
    }

    #[test]
    fn trust_path_ignores_negative() {
        let graph = AttestationGraph::new();
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();

        // Negative attestation only
        graph.add(Attestation::create(
            &alice,
            bob.agent_id(),
            AttestationClaim::Malicious,
            vec![],
        ));

        assert!(graph
            .trust_path(&alice.agent_id(), &bob.agent_id(), 3)
            .is_none());
    }

    #[test]
    fn negative_attestation_count() {
        let graph = AttestationGraph::new();
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();
        let carol = AgentKeypair::generate();

        graph.add(Attestation::create(
            &alice,
            bob.agent_id(),
            AttestationClaim::Spammer,
            vec![],
        ));
        graph.add(Attestation::create(
            &carol,
            bob.agent_id(),
            AttestationClaim::Malicious,
            vec![],
        ));
        graph.add(Attestation::create(
            &alice,
            bob.agent_id(),
            AttestationClaim::Trustworthy, // mixed signals
            vec![],
        ));

        assert_eq!(graph.negative_attestation_count(&bob.agent_id()), 2);
        assert_eq!(graph.positive_attestation_count(&bob.agent_id()), 1);
    }

    #[test]
    fn attestation_serde_roundtrip() {
        let attester = AgentKeypair::generate();
        let attestee = AgentKeypair::generate();
        let att = Attestation::create(
            &attester,
            attestee.agent_id(),
            AttestationClaim::DomainExpert("cryptography".into()),
            vec![],
        );
        let json = serde_json::to_string(&att).unwrap();
        let att2: Attestation = serde_json::from_str(&json).unwrap();
        assert!(att2.verify().is_ok());
        assert_eq!(att2.attester, att.attester);
    }
}
