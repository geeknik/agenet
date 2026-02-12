use agenet_types::PowProof;
use sha2::{Digest, Sha256};

/// Solve a PoW challenge: find counter such that SHA256(nonce || object_hash || counter) has
/// `difficulty` leading zero bits.
pub fn solve(nonce: &str, object_hash: &str, difficulty: u32) -> PowProof {
    let target = target_from_difficulty(difficulty);
    let mut counter: u64 = 0;

    loop {
        let input = format!("{nonce}{object_hash}{counter}");
        let hash = Sha256::digest(input.as_bytes());
        let hash_bytes: [u8; 32] = hash.into();

        if is_below_target(&hash_bytes, &target) {
            return PowProof {
                nonce: nonce.to_string(),
                counter,
                result_hash: hex::encode(hash_bytes),
                difficulty,
            };
        }
        counter += 1;
    }
}

/// Compute the target value from difficulty (number of leading zero bits).
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

/// Check if hash is below target (lexicographic byte comparison).
fn is_below_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in 0..32 {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    true // equal counts as valid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_low_difficulty() {
        let proof = solve("testnonce", "testhash", 4);
        assert_eq!(proof.difficulty, 4);
        assert_eq!(proof.nonce, "testnonce");
        // Verify the result hash has 4 leading zero bits (first nibble is 0)
        assert!(
            proof.result_hash.starts_with('0'),
            "hash should start with 0: {}",
            proof.result_hash
        );
    }

    #[test]
    fn target_from_difficulty_8() {
        let target = target_from_difficulty(8);
        assert_eq!(target[0], 0x00);
        assert_eq!(target[1], 0xff);
    }

    #[test]
    fn target_from_difficulty_12() {
        let target = target_from_difficulty(12);
        assert_eq!(target[0], 0x00);
        assert_eq!(target[1], 0x0f);
        assert_eq!(target[2], 0xff);
    }

    #[test]
    fn is_below_target_works() {
        let target = target_from_difficulty(8);
        let good = [0u8; 32]; // all zeros, definitely below
        let bad = [0xff; 32]; // all ones, definitely above
        assert!(is_below_target(&good, &target));
        assert!(!is_below_target(&bad, &target));
    }
}
