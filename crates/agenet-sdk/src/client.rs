use agenet_identity::AgentKeypair;
use agenet_object::{Object, ObjectBuilder};
use agenet_pow::PowChallenge;
use agenet_types::{AgentId, AgenetError, ObjectHash, PowProof, SchemaId};
use serde_json::Value;

/// The primary programmatic interface for agents interacting with AGENET relays.
///
/// No CLI, no GUI, no human UX. Agents consume this directly.
pub struct AgentClient {
    keypair: AgentKeypair,
    relay_url: String,
    http: reqwest::Client,
}

impl AgentClient {
    /// Create a new agent client.
    pub fn new(keypair: AgentKeypair, relay_url: impl Into<String>) -> Self {
        Self {
            keypair,
            relay_url: relay_url.into(),
            http: reqwest::Client::new(),
        }
    }

    /// This agent's identity.
    pub fn agent_id(&self) -> AgentId {
        self.keypair.agent_id()
    }

    /// Submit a signed object to the relay.
    pub async fn submit_object(
        &self,
        schema: SchemaId,
        payload: Value,
        topic: Option<&str>,
        tags: Vec<String>,
        pow_proof: Option<PowProof>,
    ) -> Result<ObjectHash, AgenetError> {
        let mut builder = ObjectBuilder::new(schema, payload).tags(tags);
        if let Some(t) = topic {
            builder = builder.topic(t);
        }
        if let Some(proof) = pow_proof {
            builder = builder.pow_proof(proof);
        }
        let object = builder.sign(&self.keypair);
        self.post_object(&object).await
    }

    /// Post a pre-built object.
    pub async fn post_object(&self, object: &Object) -> Result<ObjectHash, AgenetError> {
        let url = format!("{}/objects", self.relay_url);
        let resp = self
            .http
            .post(&url)
            .json(object)
            .send()
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        if resp.status().is_success() {
            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| AgenetError::Serialization(e.to_string()))?;
            let hash_hex = body["hash"]
                .as_str()
                .ok_or_else(|| AgenetError::Serialization("missing hash in response".into()))?;
            ObjectHash::from_hex(hash_hex)
                .map_err(|e| AgenetError::Serialization(e.to_string()))
        } else {
            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| AgenetError::Serialization(e.to_string()))?;
            let detail = body["detail"].as_str().unwrap_or("unknown error");
            Err(AgenetError::Unauthorized(detail.to_string()))
        }
    }

    /// Retrieve an object by content hash.
    pub async fn get_object(&self, hash: &ObjectHash) -> Result<Object, AgenetError> {
        let url = format!("{}/objects/{}", self.relay_url, hash.to_hex());
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        if resp.status().is_success() {
            resp.json::<Object>()
                .await
                .map_err(|e| AgenetError::Serialization(e.to_string()))
        } else {
            Err(AgenetError::NotFound(hash.to_hex()))
        }
    }

    /// Request a PoW challenge for a topic.
    pub async fn get_challenge(
        &self,
        topic: Option<&str>,
    ) -> Result<PowChallenge, AgenetError> {
        let mut url = format!("{}/pow/challenge", self.relay_url);
        if let Some(t) = topic {
            url = format!("{url}?topic={t}");
        }
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        resp.json::<PowChallenge>()
            .await
            .map_err(|e| AgenetError::Serialization(e.to_string()))
    }

    /// Solve a PoW challenge for an object.
    pub fn solve_pow(&self, challenge: &PowChallenge, object_hash: &str) -> PowProof {
        agenet_pow::solve(&challenge.nonce, object_hash, challenge.difficulty)
    }

    /// Convenience: get challenge, build object, solve PoW, submit.
    pub async fn submit_with_pow(
        &self,
        schema: SchemaId,
        payload: Value,
        topic: &str,
        tags: Vec<String>,
    ) -> Result<ObjectHash, AgenetError> {
        // Build the object first to get its hash
        let object = ObjectBuilder::new(schema.clone(), payload.clone())
            .topic(topic)
            .tags(tags.clone())
            .sign(&self.keypair);
        let object_hash = object.hash().to_hex();

        // Get challenge and solve
        let challenge = self.get_challenge(Some(topic)).await?;
        let proof = self.solve_pow(&challenge, &object_hash);

        // Rebuild with PoW proof
        self.submit_object(schema, payload, Some(topic), tags, Some(proof))
            .await
    }

    /// Get topic log entries.
    pub async fn topic_log(
        &self,
        topic: &str,
        after: Option<i64>,
        limit: Option<i64>,
    ) -> Result<Vec<TopicLogEntry>, AgenetError> {
        let mut url = format!("{}/topics/{}/log", self.relay_url, topic);
        let mut params = Vec::new();
        if let Some(a) = after {
            params.push(format!("after={a}"));
        }
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        resp.json::<Vec<TopicLogEntry>>()
            .await
            .map_err(|e| AgenetError::Serialization(e.to_string()))
    }

    /// Access the underlying keypair.
    pub fn keypair(&self) -> &AgentKeypair {
        &self.keypair
    }
}

/// A topic log entry returned by the relay.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TopicLogEntry {
    pub seq: i64,
    pub object_hash: String,
}
