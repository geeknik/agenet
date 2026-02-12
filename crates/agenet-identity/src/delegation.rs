use agenet_types::{AgentId, AgenetError, Timestamp};
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AgentKeypair;

/// A scope restriction on a delegated key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegationScope {
    /// Full authority — same as parent.
    Full,
    /// Restricted to specific topics.
    Topics(Vec<String>),
    /// Restricted to specific schemas.
    Schemas(Vec<String>),
    /// Restricted to specific operations.
    Operations(Vec<String>),
}

/// A delegation certificate: parent signs child key with scope restrictions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegationCert {
    /// The parent (delegator) agent ID.
    pub parent: AgentId,
    /// The parent's public key bytes.
    pub parent_pubkey: String,
    /// The child (delegatee) public key bytes.
    pub child_pubkey: String,
    /// What the child is allowed to do.
    pub scope: DelegationScope,
    /// When this delegation was created.
    pub created: Timestamp,
    /// When this delegation expires (0 = never).
    pub expires: Timestamp,
    /// Parent's signature over the canonical cert content.
    pub signature: String,
}

impl DelegationCert {
    /// Create and sign a delegation from parent to child.
    pub fn create(
        parent: &AgentKeypair,
        child_pubkey: &[u8; 32],
        scope: DelegationScope,
        expires: Timestamp,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();
        let parent_pubkey_hex = hex::encode(parent.public_key_bytes());
        let child_pubkey_hex = hex::encode(child_pubkey);

        let signable = Self::signable_content(
            &parent.agent_id(),
            &parent_pubkey_hex,
            &child_pubkey_hex,
            &scope,
            now,
            expires,
        );

        let signature = parent.sign(signable.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());

        Self {
            parent: parent.agent_id(),
            parent_pubkey: parent_pubkey_hex,
            child_pubkey: child_pubkey_hex,
            scope,
            created: now,
            expires,
            signature: sig_hex,
        }
    }

    /// Verify this delegation certificate.
    pub fn verify(&self) -> Result<(), AgenetError> {
        let parent_bytes: [u8; 32] = hex::decode(&self.parent_pubkey)
            .map_err(|_| AgenetError::InvalidSignature)?
            .try_into()
            .map_err(|_| AgenetError::InvalidSignature)?;

        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| AgenetError::InvalidSignature)?
            .try_into()
            .map_err(|_| AgenetError::InvalidSignature)?;

        // Verify parent AgentId matches parent pubkey
        let expected_id = AgentId::from_public_key(&parent_bytes);
        if expected_id != self.parent {
            return Err(AgenetError::InvalidSignature);
        }

        // Check expiry
        if self.expires > 0 && chrono::Utc::now().timestamp() > self.expires {
            return Err(AgenetError::Unauthorized("delegation expired".into()));
        }

        let signable = Self::signable_content(
            &self.parent,
            &self.parent_pubkey,
            &self.child_pubkey,
            &self.scope,
            self.created,
            self.expires,
        );

        let verifying_key =
            VerifyingKey::from_bytes(&parent_bytes).map_err(|_| AgenetError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(signable.as_bytes(), &signature)
            .map_err(|_| AgenetError::InvalidSignature)
    }

    /// Check if an operation is permitted under this delegation's scope.
    pub fn permits_topic(&self, topic: &str) -> bool {
        match &self.scope {
            DelegationScope::Full => true,
            DelegationScope::Topics(topics) => topics.iter().any(|t| t == topic),
            _ => false,
        }
    }

    pub fn permits_schema(&self, schema: &str) -> bool {
        match &self.scope {
            DelegationScope::Full => true,
            DelegationScope::Schemas(schemas) => schemas.iter().any(|s| s == schema),
            _ => false,
        }
    }

    fn signable_content(
        parent: &AgentId,
        parent_pubkey: &str,
        child_pubkey: &str,
        scope: &DelegationScope,
        created: Timestamp,
        expires: Timestamp,
    ) -> String {
        let scope_json = serde_json::to_string(scope).unwrap();
        format!("delegation:{parent}:{parent_pubkey}:{child_pubkey}:{scope_json}:{created}:{expires}")
    }
}

/// A capability token: a signed assertion granting specific permissions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Unique hash identifier for this capability.
    pub id: String,
    /// Who issued this capability.
    pub issuer: AgentId,
    /// Who this capability is granted to.
    pub grantee: AgentId,
    /// What actions are permitted.
    pub permissions: Vec<Permission>,
    /// When this was created.
    pub created: Timestamp,
    /// When this expires (0 = never).
    pub expires: Timestamp,
    /// Issuer's signature.
    pub signature: String,
}

/// A specific permission granted by a capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    /// Post objects to a specific topic.
    PostToTopic(String),
    /// Read objects from a specific topic.
    ReadTopic(String),
    /// Post objects with a specific schema.
    UseSchema(String),
    /// Set policy on a topic.
    ManageTopic(String),
    /// Mint capabilities for others (delegation of capability).
    MintCapabilities,
}

impl CapabilityToken {
    pub fn create(
        issuer: &AgentKeypair,
        grantee: AgentId,
        permissions: Vec<Permission>,
        expires: Timestamp,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();
        let signable =
            Self::signable_content(&issuer.agent_id(), &grantee, &permissions, now, expires);
        let signature = issuer.sign(signable.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());
        let id = hex::encode(Sha256::digest(signable.as_bytes()));

        Self {
            id,
            issuer: issuer.agent_id(),
            grantee,
            permissions,
            created: now,
            expires,
            signature: sig_hex,
        }
    }

    pub fn verify(&self, issuer_pubkey: &[u8; 32]) -> Result<(), AgenetError> {
        // Check expiry
        if self.expires > 0 && chrono::Utc::now().timestamp() > self.expires {
            return Err(AgenetError::Unauthorized("capability expired".into()));
        }

        let signable = Self::signable_content(
            &self.issuer,
            &self.grantee,
            &self.permissions,
            self.created,
            self.expires,
        );

        let verifying_key =
            VerifyingKey::from_bytes(issuer_pubkey).map_err(|_| AgenetError::InvalidSignature)?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| AgenetError::InvalidSignature)?
            .try_into()
            .map_err(|_| AgenetError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(signable.as_bytes(), &signature)
            .map_err(|_| AgenetError::InvalidSignature)
    }

    pub fn has_permission(&self, perm: &Permission) -> bool {
        self.permissions.contains(perm)
    }

    fn signable_content(
        issuer: &AgentId,
        grantee: &AgentId,
        permissions: &[Permission],
        created: Timestamp,
        expires: Timestamp,
    ) -> String {
        let perms_json = serde_json::to_string(permissions).unwrap();
        format!("capability:{issuer}:{grantee}:{perms_json}:{created}:{expires}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_create_and_verify() {
        let parent = AgentKeypair::generate();
        let child = AgentKeypair::generate();
        let cert = DelegationCert::create(
            &parent,
            &child.public_key_bytes(),
            DelegationScope::Full,
            0,
        );
        assert!(cert.verify().is_ok());
    }

    #[test]
    fn delegation_scoped_to_topics() {
        let parent = AgentKeypair::generate();
        let child = AgentKeypair::generate();
        let cert = DelegationCert::create(
            &parent,
            &child.public_key_bytes(),
            DelegationScope::Topics(vec!["security".into(), "research".into()]),
            0,
        );
        assert!(cert.verify().is_ok());
        assert!(cert.permits_topic("security"));
        assert!(cert.permits_topic("research"));
        assert!(!cert.permits_topic("random"));
    }

    #[test]
    fn delegation_tampered_signature_rejected() {
        let parent = AgentKeypair::generate();
        let child = AgentKeypair::generate();
        let mut cert = DelegationCert::create(
            &parent,
            &child.public_key_bytes(),
            DelegationScope::Full,
            0,
        );
        // Tamper
        cert.scope = DelegationScope::Topics(vec!["hacked".into()]);
        assert!(cert.verify().is_err());
    }

    #[test]
    fn delegation_wrong_parent_rejected() {
        let parent = AgentKeypair::generate();
        let impostor = AgentKeypair::generate();
        let child = AgentKeypair::generate();
        let mut cert = DelegationCert::create(
            &parent,
            &child.public_key_bytes(),
            DelegationScope::Full,
            0,
        );
        // Swap parent pubkey
        cert.parent_pubkey = hex::encode(impostor.public_key_bytes());
        assert!(cert.verify().is_err());
    }

    #[test]
    fn capability_create_and_verify() {
        let issuer = AgentKeypair::generate();
        let grantee = AgentKeypair::generate();
        let cap = CapabilityToken::create(
            &issuer,
            grantee.agent_id(),
            vec![
                Permission::PostToTopic("CVE-Research".into()),
                Permission::ReadTopic("CVE-Research".into()),
            ],
            0,
        );
        assert!(cap.verify(&issuer.public_key_bytes()).is_ok());
        assert!(cap.has_permission(&Permission::PostToTopic("CVE-Research".into())));
        assert!(!cap.has_permission(&Permission::MintCapabilities));
    }

    #[test]
    fn capability_wrong_key_rejected() {
        let issuer = AgentKeypair::generate();
        let impostor = AgentKeypair::generate();
        let grantee = AgentKeypair::generate();
        let cap = CapabilityToken::create(
            &issuer,
            grantee.agent_id(),
            vec![Permission::MintCapabilities],
            0,
        );
        assert!(cap.verify(&impostor.public_key_bytes()).is_err());
    }

    #[test]
    fn capability_tampered_rejected() {
        let issuer = AgentKeypair::generate();
        let grantee = AgentKeypair::generate();
        let mut cap = CapabilityToken::create(
            &issuer,
            grantee.agent_id(),
            vec![Permission::ReadTopic("safe".into())],
            0,
        );
        cap.permissions = vec![Permission::MintCapabilities]; // escalate
        assert!(cap.verify(&issuer.public_key_bytes()).is_err());
    }

    #[test]
    fn delegation_serde_roundtrip() {
        let parent = AgentKeypair::generate();
        let child = AgentKeypair::generate();
        let cert = DelegationCert::create(
            &parent,
            &child.public_key_bytes(),
            DelegationScope::Schemas(vec!["Claim".into()]),
            0,
        );
        let json = serde_json::to_string(&cert).unwrap();
        let cert2: DelegationCert = serde_json::from_str(&json).unwrap();
        assert!(cert2.verify().is_ok());
        assert_eq!(cert2.parent, cert.parent);
    }
}
