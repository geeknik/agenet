use agenet_types::AgentId;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// An agent's Ed25519 identity keypair.
#[derive(Clone)]
pub struct AgentKeypair {
    signing_key: SigningKey,
}

impl AgentKeypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let mut csprng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Restore from raw secret key bytes.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        Self { signing_key }
    }

    /// Raw secret key bytes.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    /// Ed25519 public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Derive AgentId = SHA-256(public_key).
    pub fn agent_id(&self) -> AgentId {
        AgentId::from_public_key(&self.public_key_bytes())
    }

    /// Sign arbitrary bytes.
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature against this keypair's public key.
    pub fn verify(&self, message: &[u8], signature: &ed25519_dalek::Signature) -> bool {
        self.verifying_key().verify(message, signature).is_ok()
    }

    /// Derive X25519 static secret for key exchange (E2EE sessions).
    pub fn x25519_static_secret(&self) -> x25519_dalek::StaticSecret {
        // Derive X25519 secret from Ed25519 secret via SHA-256
        // This is a standard derivation path (similar to libsodium's crypto_sign_ed25519_sk_to_curve25519)
        let hash = Sha256::digest(self.signing_key.as_bytes());
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&hash);
        // Clamp per X25519 spec
        key_bytes[0] &= 248;
        key_bytes[31] &= 127;
        key_bytes[31] |= 64;
        x25519_dalek::StaticSecret::from(key_bytes)
    }

    /// Derive X25519 public key from identity.
    pub fn x25519_public_key(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(&self.x25519_static_secret())
    }
}

/// Verify a signature given a public key, message, and signature.
pub fn verify_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &ed25519_dalek::Signature,
) -> Result<(), agenet_types::AgenetError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| agenet_types::AgenetError::InvalidSignature)?;
    verifying_key
        .verify(message, signature)
        .map_err(|_| agenet_types::AgenetError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_derive_agent_id() {
        let kp = AgentKeypair::generate();
        let id = kp.agent_id();
        // AgentId is deterministic for same pubkey
        let id2 = AgentId::from_public_key(&kp.public_key_bytes());
        assert_eq!(id, id2);
    }

    #[test]
    fn sign_and_verify() {
        let kp = AgentKeypair::generate();
        let msg = b"hello agenet";
        let sig = kp.sign(msg);
        assert!(kp.verify(msg, &sig));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let kp = AgentKeypair::generate();
        let sig = kp.sign(b"correct");
        assert!(!kp.verify(b"wrong", &sig));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp1 = AgentKeypair::generate();
        let kp2 = AgentKeypair::generate();
        let sig = kp1.sign(b"message");
        assert!(!kp2.verify(b"message", &sig));
    }

    #[test]
    fn secret_bytes_roundtrip() {
        let kp = AgentKeypair::generate();
        let secret = *kp.secret_bytes();
        let kp2 = AgentKeypair::from_bytes(&secret);
        assert_eq!(kp.public_key_bytes(), kp2.public_key_bytes());
        assert_eq!(kp.agent_id(), kp2.agent_id());
    }

    #[test]
    fn x25519_key_exchange() {
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();

        let alice_secret = alice.x25519_static_secret();
        let bob_public = bob.x25519_public_key();
        let shared_a = alice_secret.diffie_hellman(&bob_public);

        let bob_secret = bob.x25519_static_secret();
        let alice_public = alice.x25519_public_key();
        let shared_b = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    }

    #[test]
    fn verify_signature_standalone() {
        let kp = AgentKeypair::generate();
        let msg = b"standalone verify";
        let sig = kp.sign(msg);
        assert!(verify_signature(&kp.public_key_bytes(), msg, &sig).is_ok());
    }
}
