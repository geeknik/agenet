use serde_json::Value;
use sha2::{Digest, Sha256};

use agenet_types::ObjectHash;

/// Produce a deterministic canonical JSON representation.
///
/// Rules:
/// - Object keys sorted lexicographically
/// - No trailing whitespace
/// - No unnecessary whitespace (compact format)
/// - Numbers in their canonical form
/// - Null values included
pub fn canonicalize(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap(),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize).collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let pairs: Vec<String> = keys
                .iter()
                .map(|k| {
                    let key = serde_json::to_string(*k).unwrap();
                    let val = canonicalize(map.get(*k).unwrap());
                    format!("{key}:{val}")
                })
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

/// Compute the content hash of a canonicalized JSON value.
pub fn content_hash(canonical_json: &str) -> ObjectHash {
    let hash = Sha256::digest(canonical_json.as_bytes());
    ObjectHash(hash.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_sorted() {
        let val = json!({"z": 1, "a": 2, "m": 3});
        let canonical = canonicalize(&val);
        assert_eq!(canonical, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn nested_objects_sorted() {
        let val = json!({"b": {"z": 1, "a": 2}, "a": 0});
        let canonical = canonicalize(&val);
        assert_eq!(canonical, r#"{"a":0,"b":{"a":2,"z":1}}"#);
    }

    #[test]
    fn arrays_preserve_order() {
        let val = json!([3, 1, 2]);
        let canonical = canonicalize(&val);
        assert_eq!(canonical, "[3,1,2]");
    }

    #[test]
    fn strings_escaped() {
        let val = json!({"key": "value with \"quotes\""});
        let canonical = canonicalize(&val);
        assert_eq!(canonical, r#"{"key":"value with \"quotes\""}"#);
    }

    #[test]
    fn identical_objects_same_hash() {
        let a = json!({"z": 1, "a": 2});
        let b = json!({"a": 2, "z": 1});
        let hash_a = content_hash(&canonicalize(&a));
        let hash_b = content_hash(&canonicalize(&b));
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn different_objects_different_hash() {
        let a = json!({"a": 1});
        let b = json!({"a": 2});
        let hash_a = content_hash(&canonicalize(&a));
        let hash_b = content_hash(&canonicalize(&b));
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn null_and_bool() {
        assert_eq!(canonicalize(&json!(null)), "null");
        assert_eq!(canonicalize(&json!(true)), "true");
        assert_eq!(canonicalize(&json!(false)), "false");
    }
}
