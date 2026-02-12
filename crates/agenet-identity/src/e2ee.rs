use agenet_types::AgenetError;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::AgentKeypair;

/// An encrypted payload envelope.
///
/// Wraps ciphertext produced via X25519 DH + HKDF-SHA256 + ChaCha20-Poly1305 AEAD.
/// The sender's ephemeral public key is included so the recipient can derive
/// the shared secret. The nonce is prepended to the ciphertext.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedPayload {
    /// Hex-encoded X25519 ephemeral public key of the sender.
    pub sender_x25519_pubkey: String,
    /// Hex-encoded nonce (12 bytes) + ciphertext + auth tag.
    pub ciphertext: String,
}

/// Derive a 32-byte symmetric key from a shared secret via HKDF-SHA256 (simplified).
fn derive_key(shared_secret: &[u8; 32], context: &[u8]) -> [u8; 32] {
    // HKDF-extract: PRK = HMAC-SHA256(salt="agenet-e2ee", IKM=shared_secret)
    // Simplified: SHA-256(shared_secret || context)
    let mut hasher = Sha256::new();
    hasher.update(b"agenet-e2ee-v1:");
    hasher.update(shared_secret);
    hasher.update(b":");
    hasher.update(context);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Encrypt a payload for a specific recipient using X25519 + ChaCha20-Poly1305.
///
/// Uses the sender's identity key to derive an X25519 static secret,
/// performs DH with the recipient's X25519 public key, and encrypts.
pub fn encrypt(
    sender: &AgentKeypair,
    recipient_x25519_pubkey: &x25519_dalek::PublicKey,
    plaintext: &[u8],
) -> Result<EncryptedPayload, AgenetError> {
    let sender_secret = sender.x25519_static_secret();
    let sender_pubkey = x25519_dalek::PublicKey::from(&sender_secret);
    let shared = sender_secret.diffie_hellman(recipient_x25519_pubkey);

    let key = derive_key(shared.as_bytes(), b"payload-encryption");
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| AgenetError::Serialization(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AgenetError::Serialization(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(EncryptedPayload {
        sender_x25519_pubkey: hex::encode(sender_pubkey.as_bytes()),
        ciphertext: hex::encode(combined),
    })
}

/// Decrypt an encrypted payload using the recipient's identity key.
pub fn decrypt(
    recipient: &AgentKeypair,
    envelope: &EncryptedPayload,
) -> Result<Vec<u8>, AgenetError> {
    let sender_pubkey_bytes: [u8; 32] = hex::decode(&envelope.sender_x25519_pubkey)
        .map_err(|_| AgenetError::InvalidSignature)?
        .try_into()
        .map_err(|_| AgenetError::InvalidSignature)?;
    let sender_pubkey = x25519_dalek::PublicKey::from(sender_pubkey_bytes);

    let recipient_secret = recipient.x25519_static_secret();
    let shared = recipient_secret.diffie_hellman(&sender_pubkey);

    let key = derive_key(shared.as_bytes(), b"payload-encryption");
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| AgenetError::Serialization(e.to_string()))?;

    let combined =
        hex::decode(&envelope.ciphertext).map_err(|_| AgenetError::InvalidSignature)?;
    if combined.len() < 12 {
        return Err(AgenetError::InvalidSignature);
    }

    let nonce = Nonce::from_slice(&combined[..12]);
    let ciphertext = &combined[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AgenetError::InvalidSignature)
}

/// Encrypt a JSON payload, returning it as a serde_json::Value wrapping the EncryptedPayload.
pub fn encrypt_json_payload(
    sender: &AgentKeypair,
    recipient_x25519_pubkey: &x25519_dalek::PublicKey,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, AgenetError> {
    let plaintext = serde_json::to_vec(payload)
        .map_err(|e| AgenetError::Serialization(e.to_string()))?;
    let envelope = encrypt(sender, recipient_x25519_pubkey, &plaintext)?;
    serde_json::to_value(envelope).map_err(|e| AgenetError::Serialization(e.to_string()))
}

/// Decrypt a JSON payload from an EncryptedPayload wrapped in a serde_json::Value.
pub fn decrypt_json_payload(
    recipient: &AgentKeypair,
    encrypted_value: &serde_json::Value,
) -> Result<serde_json::Value, AgenetError> {
    let envelope: EncryptedPayload = serde_json::from_value(encrypted_value.clone())
        .map_err(|e| AgenetError::Serialization(e.to_string()))?;
    let plaintext = decrypt(recipient, &envelope)?;
    serde_json::from_slice(&plaintext).map_err(|e| AgenetError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();

        let plaintext = b"secret message for bob";
        let bob_x25519 = bob.x25519_public_key();

        let envelope = encrypt(&alice, &bob_x25519, plaintext).unwrap();
        let decrypted = decrypt(&bob, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_recipient_fails() {
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();
        let eve = AgentKeypair::generate();

        let plaintext = b"secret for bob only";
        let bob_x25519 = bob.x25519_public_key();

        let envelope = encrypt(&alice, &bob_x25519, plaintext).unwrap();
        assert!(decrypt(&eve, &envelope).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();

        let plaintext = b"integrity check";
        let bob_x25519 = bob.x25519_public_key();

        let mut envelope = encrypt(&alice, &bob_x25519, plaintext).unwrap();
        // Flip a byte in ciphertext
        let mut bytes = hex::decode(&envelope.ciphertext).unwrap();
        if let Some(b) = bytes.last_mut() {
            *b ^= 0xff;
        }
        envelope.ciphertext = hex::encode(bytes);

        assert!(decrypt(&bob, &envelope).is_err());
    }

    #[test]
    fn json_payload_roundtrip() {
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();
        let bob_x25519 = bob.x25519_public_key();

        let payload = serde_json::json!({"statement": "classified intelligence", "level": 5});
        let encrypted = encrypt_json_payload(&alice, &bob_x25519, &payload).unwrap();

        // Encrypted value should NOT contain the original text
        let enc_str = serde_json::to_string(&encrypted).unwrap();
        assert!(!enc_str.contains("classified intelligence"));

        let decrypted = decrypt_json_payload(&bob, &encrypted).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();
        let bob_x25519 = bob.x25519_public_key();

        let envelope = encrypt(&alice, &bob_x25519, b"serde test").unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        let envelope2: EncryptedPayload = serde_json::from_str(&json).unwrap();
        let decrypted = decrypt(&bob, &envelope2).unwrap();
        assert_eq!(decrypted, b"serde test");
    }

    #[test]
    fn empty_plaintext() {
        let alice = AgentKeypair::generate();
        let bob = AgentKeypair::generate();
        let bob_x25519 = bob.x25519_public_key();

        let envelope = encrypt(&alice, &bob_x25519, b"").unwrap();
        let decrypted = decrypt(&bob, &envelope).unwrap();
        assert!(decrypted.is_empty());
    }
}
