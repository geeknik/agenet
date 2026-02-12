use agenet_types::{AgenetError, PowProof};
use sha2::{Digest, Sha256};

/// Verify a PoW proof in O(1) — single hash computation.
pub fn verify(proof: &PowProof, object_hash: &str) -> Result<(), AgenetError> {
    let input = format!("{}{}{}", proof.nonce, object_hash, proof.counter);
    let hash = Sha256::digest(input.as_bytes());
    let hash_bytes: [u8; 32] = hash.into();
    let result_hex = hex::encode(hash_bytes);

    // Verify the claimed result hash matches
    if result_hex != proof.result_hash {
        return Err(AgenetError::InvalidPow);
    }

    // Verify difficulty requirement
    let target = target_from_difficulty(proof.difficulty);
    if !is_below_target(&hash_bytes, &target) {
        return Err(AgenetError::InvalidPow);
    }

    Ok(())
}

fn target_from_difficulty(difficulty: u32) -> [u8; 32] {
    let mut target = [0xffu8; 32];
    let full_bytes = (difficulty / 8) as usize;
    let remaining_bits = difficulty % 8;

    for byte in target.iter_mut().take(full_bytes) {
        *byte = 0;
    }
    if full_bytes < 32 && remaining_bits > 0 {
        target[full_bytes] = 0xff >> remaining_bits;
    }
    target
}

fn is_below_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in 0..32 {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver;

    #[test]
    fn verify_valid_proof() {
        let proof = solver::solve("testnonce", "testhash", 8);
        assert!(verify(&proof, "testhash").is_ok());
    }

    #[test]
    fn verify_rejects_wrong_object_hash() {
        let proof = solver::solve("testnonce", "testhash", 8);
        assert!(verify(&proof, "wronghash").is_err());
    }

    #[test]
    fn verify_rejects_tampered_counter() {
        let mut proof = solver::solve("testnonce", "testhash", 8);
        proof.counter += 1; // tamper
        // result_hash no longer matches
        assert!(verify(&proof, "testhash").is_err());
    }

    #[test]
    fn verify_rejects_tampered_result_hash() {
        let mut proof = solver::solve("testnonce", "testhash", 8);
        proof.result_hash = "0000000000000000000000000000000000000000000000000000000000000000".into();
        assert!(verify(&proof, "testhash").is_err());
    }
}
