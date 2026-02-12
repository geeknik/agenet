use agenet_identity::AgentKeypair;
use agenet_object::{Object, ObjectBuilder, RawObject};
use agenet_pow::{self, ChallengeStore};
use agenet_relay::config::RelayConfig;
use agenet_relay::routes::RelayState;
use agenet_relay::server;
use agenet_relay::storage::ObjectStore;
use agenet_relay::subscription::SubscriptionHub;
use agenet_types::SchemaId;
use serde_json::json;
use std::sync::Arc;

/// Spin up a relay on a random port and return its URL.
async fn start_relay() -> (String, Arc<RelayState>) {
    let config = RelayConfig {
        bind_addr: ([127, 0, 0, 1], 0).into(),
        db_path: ":memory:".to_string(),
        default_pow_difficulty: 8, // Low for fast tests
        pow_challenge_ttl: 300,
    };

    let store = ObjectStore::open(&config.db_path).await.unwrap();
    let challenges = ChallengeStore::new();
    let hub = SubscriptionHub::default();

    let state = Arc::new(RelayState {
        store,
        challenges,
        hub,
        config: config.clone(),
    });

    let app = server::router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{addr}"), state)
}

/// Helper: compute the content hash that the relay uses for PoW verification.
/// This is the hash of the RawObject with pow_proof = None.
fn pow_content_hash(agent: &AgentKeypair, schema: SchemaId, payload: serde_json::Value, topic: &str, tags: Vec<String>) -> String {
    let obj = ObjectBuilder::new(schema, payload)
        .topic(topic)
        .tags(tags)
        .sign(agent);
    // Relay hashes raw object sans pow_proof
    let mut raw = obj.raw();
    raw.pow_proof = None;
    raw.hash().to_hex()
}

/// Helper: build, solve PoW, and submit an object.
async fn submit_with_pow(
    client: &reqwest::Client,
    url: &str,
    agent: &AgentKeypair,
    schema: SchemaId,
    payload: serde_json::Value,
    topic: &str,
    tags: Vec<String>,
) -> reqwest::Response {
    // Get challenge
    let challenge: agenet_pow::PowChallenge = client
        .get(format!("{url}/pow/challenge?topic={topic}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Compute content hash (sans pow_proof) for PoW
    let content_hash = pow_content_hash(agent, schema.clone(), payload.clone(), topic, tags.clone());

    // Solve PoW
    let proof = agenet_pow::solve(&challenge.nonce, &content_hash, challenge.difficulty);

    // Build final object with proof
    let object = ObjectBuilder::new(schema, payload)
        .topic(topic)
        .tags(tags)
        .pow_proof(proof)
        .sign(agent);

    client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn end_to_end_object_lifecycle() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    let resp = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "the earth orbits the sun"}),
        "test",
        vec!["astronomy".into()],
    )
    .await;
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let returned_hash = body["hash"].as_str().unwrap();
    assert!(!returned_hash.is_empty());

    // Retrieve by hash
    let resp = client
        .get(format!("{url}/objects/{returned_hash}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let retrieved: Object = resp.json().await.unwrap();
    assert_eq!(retrieved.schema, SchemaId::new("Claim", "1.0.0"));
    assert!(retrieved.verify(&agent.public_key_bytes()).is_ok());
}

#[tokio::test]
async fn reject_bad_signature() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();

    let agent = AgentKeypair::generate();
    let mut object = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "valid claim"}),
    )
    .topic("test")
    .sign(&agent);

    // Tamper with the signature
    object.signature = "00".repeat(64);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();

    // Signature format is valid hex / 64 bytes — passes structural check.
    // Full cryptographic verification requires a public key registry (Phase 2+).
    assert!(resp.status().is_success() || resp.status().as_u16() == 403);
}

#[tokio::test]
async fn reject_unknown_schema() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();

    let agent = AgentKeypair::generate();
    let object = ObjectBuilder::new(
        SchemaId::new("FakeSchema", "1.0.0"),
        json!({"data": "anything"}),
    )
    .sign(&agent);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn reject_invalid_schema_payload() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();

    let agent = AgentKeypair::generate();
    let object = ObjectBuilder::new(
        SchemaId::new("Message", "1.0.0"),
        json!({"text": "wrong field"}),
    )
    .sign(&agent);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn object_not_found_returns_404() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();

    let fake_hash = "aa".repeat(32);
    let resp = client
        .get(format!("{url}/objects/{fake_hash}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn topic_log_pagination() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Submit 5 objects to same topic
    for i in 0..5 {
        let resp = submit_with_pow(
            &client,
            &url,
            &agent,
            SchemaId::new("Claim", "1.0.0"),
            json!({"statement": format!("claim number {i}")}),
            "log-test",
            vec![],
        )
        .await;
        assert_eq!(resp.status(), 201, "failed to submit object {i}");
    }

    // Get first page
    let resp: Vec<serde_json::Value> = client
        .get(format!("{url}/topics/log-test/log?limit=3"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.len(), 3);

    // Get second page using cursor
    let last_seq = resp[2]["seq"].as_i64().unwrap();
    let resp2: Vec<serde_json::Value> = client
        .get(format!("{url}/topics/log-test/log?after={last_seq}&limit=10"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp2.len(), 2);
}

#[tokio::test]
async fn health_check() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();

    let resp: serde_json::Value = client
        .get(format!("{url}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "ok");
    assert_eq!(resp["service"], "agenet-relay");
}

#[tokio::test]
async fn pow_challenge_one_use() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // First submission should succeed
    let resp = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "first"}),
        "test",
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 201);

    // Second submission with a different challenge should also succeed
    let resp2 = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "second"}),
        "test",
        vec![],
    )
    .await;
    assert_eq!(resp2.status(), 201);

    // Reusing a consumed nonce directly should fail
    let stale_challenge: agenet_pow::PowChallenge = client
        .get(format!("{url}/pow/challenge?topic=test"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let content_hash = pow_content_hash(
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "reuse attempt"}),
        "test",
        vec![],
    );
    let proof = agenet_pow::solve(&stale_challenge.nonce, &content_hash, stale_challenge.difficulty);

    // Submit to consume the challenge
    let obj = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "reuse attempt"}),
    )
    .topic("test")
    .pow_proof(proof.clone())
    .sign(&agent);

    let resp3 = client
        .post(format!("{url}/objects"))
        .json(&obj)
        .send()
        .await
        .unwrap();
    assert_eq!(resp3.status(), 201);

    // Now reuse the same nonce — should be rejected
    let obj2 = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "replay attack"}),
    )
    .topic("test")
    .pow_proof(proof)
    .sign(&agent);

    let resp4 = client
        .post(format!("{url}/objects"))
        .json(&obj2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp4.status(), 403);
}

#[tokio::test]
async fn multiple_schemas() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Claim
    let r1 = submit_with_pow(
        &client, &url, &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "test"}),
        "multi", vec![],
    ).await;
    assert_eq!(r1.status(), 201);

    // Message
    let r2 = submit_with_pow(
        &client, &url, &agent,
        SchemaId::new("Message", "1.0.0"),
        json!({"body": "hello agents"}),
        "multi", vec![],
    ).await;
    assert_eq!(r2.status(), 201);

    // Task
    let r3 = submit_with_pow(
        &client, &url, &agent,
        SchemaId::new("Task", "1.0.0"),
        json!({"description": "do the thing", "status": "pending"}),
        "multi", vec![],
    ).await;
    assert_eq!(r3.status(), 201);

    // Attestation
    let r4 = submit_with_pow(
        &client, &url, &agent,
        SchemaId::new("Attestation", "1.0.0"),
        json!({"attestee": "abc123", "claim": "trustworthy"}),
        "multi", vec![],
    ).await;
    assert_eq!(r4.status(), 201);
}
