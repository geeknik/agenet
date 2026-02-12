use agenet_types::{AgenetError, SchemaId};
use serde_json::Value;
use std::collections::HashMap;

/// Validates that an object's payload conforms to its declared schema.
pub type ValidatorFn = Box<dyn Fn(&Value) -> Result<(), String> + Send + Sync>;

/// Registry of known schemas and their validators.
pub struct SchemaRegistry {
    validators: HashMap<String, ValidatorFn>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            validators: HashMap::new(),
        };
        registry.register_defaults();
        registry
    }

    /// Register a schema validator.
    pub fn register(&mut self, schema_name: &str, validator: ValidatorFn) {
        self.validators.insert(schema_name.to_string(), validator);
    }

    /// Validate an object's payload against its schema.
    pub fn validate(&self, schema: &SchemaId, payload: &Value) -> Result<(), AgenetError> {
        let name = schema.name();
        match self.validators.get(name) {
            Some(validator) => validator(payload).map_err(AgenetError::SchemaValidation),
            None => Err(AgenetError::UnknownSchema(schema.to_string())),
        }
    }

    /// Check if a schema is registered.
    pub fn is_known(&self, schema: &SchemaId) -> bool {
        self.validators.contains_key(schema.name())
    }

    fn register_defaults(&mut self) {
        // Message: must have "body" string field
        self.register(
            "Message",
            Box::new(|payload| {
                payload
                    .get("body")
                    .and_then(|v| v.as_str())
                    .map(|_| ())
                    .ok_or_else(|| "Message requires 'body' string field".to_string())
            }),
        );

        // Claim: must have "statement" string field
        self.register(
            "Claim",
            Box::new(|payload| {
                payload
                    .get("statement")
                    .and_then(|v| v.as_str())
                    .map(|_| ())
                    .ok_or_else(|| "Claim requires 'statement' string field".to_string())
            }),
        );

        // Evidence: must have "claim_ref" and "data"
        self.register(
            "Evidence",
            Box::new(|payload| {
                if payload.get("claim_ref").is_none() {
                    return Err("Evidence requires 'claim_ref' field".to_string());
                }
                if payload.get("data").is_none() {
                    return Err("Evidence requires 'data' field".to_string());
                }
                Ok(())
            }),
        );

        // Artifact: must have "content_type" and either "data" or "url"
        self.register(
            "Artifact",
            Box::new(|payload| {
                if payload.get("content_type").is_none() {
                    return Err("Artifact requires 'content_type' field".to_string());
                }
                if payload.get("data").is_none() && payload.get("url").is_none() {
                    return Err("Artifact requires 'data' or 'url' field".to_string());
                }
                Ok(())
            }),
        );

        // Policy: must have "topic" and "requirements"
        self.register(
            "Policy",
            Box::new(|payload| {
                if payload.get("topic").is_none() {
                    return Err("Policy requires 'topic' field".to_string());
                }
                if payload.get("requirements").is_none() {
                    return Err("Policy requires 'requirements' field".to_string());
                }
                Ok(())
            }),
        );

        // Attestation: must have "attestee" and "claim"
        self.register(
            "Attestation",
            Box::new(|payload| {
                if payload.get("attestee").is_none() {
                    return Err("Attestation requires 'attestee' field".to_string());
                }
                if payload.get("claim").is_none() {
                    return Err("Attestation requires 'claim' field".to_string());
                }
                Ok(())
            }),
        );

        // Task: must have "description" and "status"
        self.register(
            "Task",
            Box::new(|payload| {
                if payload.get("description").is_none() {
                    return Err("Task requires 'description' field".to_string());
                }
                if payload.get("status").is_none() {
                    return Err("Task requires 'status' field".to_string());
                }
                Ok(())
            }),
        );

        // ReputationEvent: must have "subject" and "event_type"
        self.register(
            "ReputationEvent",
            Box::new(|payload| {
                if payload.get("subject").is_none() {
                    return Err("ReputationEvent requires 'subject' field".to_string());
                }
                if payload.get("event_type").is_none() {
                    return Err("ReputationEvent requires 'event_type' field".to_string());
                }
                Ok(())
            }),
        );
    }
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function using default registry.
pub fn validate_schema(schema: &SchemaId, payload: &Value) -> Result<(), AgenetError> {
    let registry = SchemaRegistry::new();
    registry.validate(schema, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid_message() {
        let registry = SchemaRegistry::new();
        let schema = SchemaId::new("Message", "1.0.0");
        assert!(registry.validate(&schema, &json!({"body": "hello"})).is_ok());
    }

    #[test]
    fn invalid_message_missing_body() {
        let registry = SchemaRegistry::new();
        let schema = SchemaId::new("Message", "1.0.0");
        assert!(registry.validate(&schema, &json!({"text": "hello"})).is_err());
    }

    #[test]
    fn valid_claim() {
        let registry = SchemaRegistry::new();
        let schema = SchemaId::new("Claim", "1.0.0");
        assert!(registry
            .validate(&schema, &json!({"statement": "the sky is blue"}))
            .is_ok());
    }

    #[test]
    fn valid_policy() {
        let registry = SchemaRegistry::new();
        let schema = SchemaId::new("Policy", "1.0.0");
        assert!(registry
            .validate(
                &schema,
                &json!({"topic": "CVE-Research", "requirements": {"min_pow": 20}})
            )
            .is_ok());
    }

    #[test]
    fn unknown_schema_rejected() {
        let registry = SchemaRegistry::new();
        let schema = SchemaId::new("Unknown", "1.0.0");
        assert!(matches!(
            registry.validate(&schema, &json!({})),
            Err(AgenetError::UnknownSchema(_))
        ));
    }

    #[test]
    fn all_default_schemas_registered() {
        let registry = SchemaRegistry::new();
        let schemas = [
            "Message",
            "Claim",
            "Evidence",
            "Artifact",
            "Policy",
            "Attestation",
            "Task",
            "ReputationEvent",
        ];
        for name in schemas {
            assert!(
                registry.is_known(&SchemaId::new(name, "1.0.0")),
                "schema {name} not registered"
            );
        }
    }
}
