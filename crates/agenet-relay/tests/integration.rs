use agenet_efl::attestation::AttestationGraph;
use agenet_efl::credits::{BurnPolicy, CreditLedger};
use agenet_efl::dynamic_pow::{DifficultyConfig, TopicRateTracker};
use agenet_identity::AgentKeypair;
use agenet_object::{Object, ObjectBuilder};
use agenet_pow::{self, ChallengeStore};
use agenet_relay::abuse::{BurnEscalation, RateLimitConfig, RateLimiter, ReplayDetector};
use agenet_relay::config::RelayConfig;
use agenet_relay::merkle::TopicMerkleStore;
use agenet_relay::policy::PolicyRegistry;
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
        credit_db_path: ":memory:".to_string(),
        deposit_db_path: None,
        default_pow_difficulty: 8, // Low for fast tests
        pow_challenge_ttl: 300,
        rate_window_seconds: 60,
    };

    let store = ObjectStore::open(&config.db_path).await.unwrap();
    let challenges = ChallengeStore::new();
    let hub = SubscriptionHub::default();
    let merkle = TopicMerkleStore::new();
    let rate_limiter = RateLimiter::new(RateLimitConfig {
        max_tokens: 1000,
        refill_rate: 100.0,
        cost: 1,
    });
    let replay_detector = ReplayDetector::new(300);
    let credits = CreditLedger::open_memory().await.unwrap();
    let burn_policy = BurnPolicy::default();
    let attestations = AttestationGraph::new();
    let rate_tracker = TopicRateTracker::new(60);
    let difficulty_config = DifficultyConfig {
        base_difficulty: config.default_pow_difficulty,
        min_difficulty: 4,  // Low floor for fast tests
        max_difficulty: 12, // Low ceiling for fast tests
        ..Default::default()
    };
    let policies = PolicyRegistry::new();

    let state = Arc::new(RelayState {
        store,
        challenges,
        hub,
        config: config.clone(),
        merkle,
        rate_limiter,
        replay_detector,
        credits,
        burn_policy,
        attestations,
        rate_tracker,
        difficulty_config,
        policies,
        deposits: None,
        burn_escalation: BurnEscalation::default(),
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
/// Uses a pinned timestamp so the hash matches the final signed object.
fn pow_content_hash(
    agent: &AgentKeypair,
    schema: SchemaId,
    payload: serde_json::Value,
    topic: &str,
    tags: Vec<String>,
    pinned_ts: i64,
) -> String {
    let obj = ObjectBuilder::new(schema, payload)
        .topic(topic)
        .tags(tags)
        .timestamp(pinned_ts)
        .sign(agent);
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
    let challenge: agenet_pow::PowChallenge = client
        .get(format!("{url}/pow/challenge?topic={topic}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Pin the timestamp so content hash matches between PoW solve and final object
    let pinned_ts = chrono::Utc::now().timestamp();

    let content_hash = pow_content_hash(agent, schema.clone(), payload.clone(), topic, tags.clone(), pinned_ts);
    let proof = agenet_pow::solve(&challenge.nonce, &content_hash, challenge.difficulty);

    let object = ObjectBuilder::new(schema, payload)
        .topic(topic)
        .tags(tags)
        .timestamp(pinned_ts)
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
    assert!(retrieved.verify_self().is_ok());
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

    // Tamper with the signature — verify_self() will fail
    object.signature = "00".repeat(64);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
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

    let resp: Vec<serde_json::Value> = client
        .get(format!("{url}/topics/log-test/log?limit=3"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.len(), 3);

    let last_seq = resp[2]["seq"].as_i64().unwrap();
    let resp2: Vec<serde_json::Value> = client
        .get(format!(
            "{url}/topics/log-test/log?after={last_seq}&limit=10"
        ))
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

    // Reusing a consumed nonce should fail
    let stale_challenge: agenet_pow::PowChallenge = client
        .get(format!("{url}/pow/challenge?topic=test"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let pinned_ts = chrono::Utc::now().timestamp();
    let content_hash = pow_content_hash(
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "reuse attempt"}),
        "test",
        vec![],
        pinned_ts,
    );
    let proof = agenet_pow::solve(
        &stale_challenge.nonce,
        &content_hash,
        stale_challenge.difficulty,
    );

    // Consume the challenge
    let obj = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "reuse attempt"}),
    )
    .topic("test")
    .timestamp(pinned_ts)
    .pow_proof(proof.clone())
    .sign(&agent);

    let resp3 = client
        .post(format!("{url}/objects"))
        .json(&obj)
        .send()
        .await
        .unwrap();
    assert_eq!(resp3.status(), 201);

    // Reuse same nonce — rejected
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

    let r1 = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "test"}),
        "multi",
        vec![],
    )
    .await;
    assert_eq!(r1.status(), 201);

    let r2 = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Message", "1.0.0"),
        json!({"body": "hello agents"}),
        "multi",
        vec![],
    )
    .await;
    assert_eq!(r2.status(), 201);

    let r3 = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Task", "1.0.0"),
        json!({"description": "do the thing", "status": "pending"}),
        "multi",
        vec![],
    )
    .await;
    assert_eq!(r3.status(), 201);

    let r4 = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Attestation", "1.0.0"),
        json!({"attestee": "abc123", "claim": "trustworthy"}),
        "multi",
        vec![],
    )
    .await;
    assert_eq!(r4.status(), 201);
}

// --- New integration tests for EFL features ---

#[tokio::test]
async fn credit_mint_and_balance() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();
    let agent_hex = agent.agent_id().to_hex();

    // Check initial balance is 0
    let resp: serde_json::Value = client
        .get(format!("{url}/credits/{agent_hex}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["balance"], 0);

    // Mint credits
    let resp: serde_json::Value = client
        .post(format!("{url}/capabilities/mint"))
        .json(&json!({
            "agent_id": agent_hex,
            "amount": 100,
            "reason": "initial provision"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["balance"], 100);

    // Verify balance
    let resp: serde_json::Value = client
        .get(format!("{url}/credits/{agent_hex}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["balance"], 100);
}

#[tokio::test]
async fn topic_policy_enforcement() {
    let (url, state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Set a policy requiring PoW difficulty >= 16
    state.policies.set(agenet_relay::policy::TopicPolicy {
        topic: "restricted".into(),
        min_pow: 16,
        min_reputation_attestations: 0,
        max_payload_bytes: 0,
        allow_credit_substitution: false,
    });

    // Submit without PoW to restricted topic — should fail
    let object = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "should fail"}),
    )
    .topic("restricted")
    .sign(&agent);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Submit with PoW to restricted topic — should succeed
    let resp2 = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "should succeed"}),
        "restricted",
        vec![],
    )
    .await;
    assert_eq!(resp2.status(), 201);
}

#[tokio::test]
async fn credit_substitution_for_pow() {
    let (url, state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();
    let agent_hex = agent.agent_id().to_hex();

    // Set a policy requiring PoW but allowing credit substitution
    state.policies.set(agenet_relay::policy::TopicPolicy {
        topic: "credit-sub".into(),
        min_pow: 8,
        min_reputation_attestations: 0,
        max_payload_bytes: 0,
        allow_credit_substitution: true,
    });

    // Mint credits for the agent
    state
        .credits
        .mint(&agent.agent_id(), 50, "test provision")
        .await
        .unwrap();

    // Submit without PoW — should burn credits
    let object = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "paid with credits"}),
    )
    .topic("credit-sub")
    .sign(&agent);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Verify credits were burned
    let resp: serde_json::Value = client
        .get(format!("{url}/credits/{agent_hex}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["balance"], 49); // 50 - 1 (default post_cost)
}

#[tokio::test]
async fn dynamic_pow_challenge() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();

    // Get challenge without topic/agent context — should get base difficulty
    let challenge: agenet_pow::PowChallenge = client
        .get(format!("{url}/pow/challenge"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(challenge.difficulty >= 8); // base_difficulty from config
}

#[tokio::test]
async fn topic_policy_query() {
    let (url, state) = start_relay().await;
    let client = reqwest::Client::new();

    state.policies.set(agenet_relay::policy::TopicPolicy {
        topic: "my-topic".into(),
        min_pow: 22,
        min_reputation_attestations: 5,
        max_payload_bytes: 1024 * 1024,
        allow_credit_substitution: true,
    });

    let resp: serde_json::Value = client
        .get(format!("{url}/topics/my-topic/policy"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["min_pow"], 22);
    assert_eq!(resp["min_reputation_attestations"], 5);
}

#[tokio::test]
async fn merkle_root_and_proof() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Submit objects to build Merkle tree
    for i in 0..3 {
        let resp = submit_with_pow(
            &client,
            &url,
            &agent,
            SchemaId::new("Claim", "1.0.0"),
            json!({"statement": format!("merkle test {i}")}),
            "merkle-topic",
            vec![],
        )
        .await;
        assert_eq!(resp.status(), 201);
    }

    // Get Merkle root
    let root_resp: serde_json::Value = client
        .get(format!("{url}/topics/merkle-topic/merkle-root"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(root_resp["leaves"], 3);
    assert!(root_resp["root"].is_string());

    // Get inclusion proof for index 0
    let proof_resp = client
        .get(format!("{url}/topics/merkle-topic/proof/0"))
        .send()
        .await
        .unwrap();
    assert_eq!(proof_resp.status(), 200);
}

#[tokio::test]
async fn topic_compaction() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Submit objects to build a log
    for i in 0..5 {
        let resp = submit_with_pow(
            &client,
            &url,
            &agent,
            SchemaId::new("Claim", "1.0.0"),
            json!({"statement": format!("compact test {i}")}),
            "compact-topic",
            vec![],
        )
        .await;
        assert_eq!(resp.status(), 201, "failed to submit object {i}");
    }

    // Verify 5 entries in log
    let log: Vec<serde_json::Value> = client
        .get(format!("{url}/topics/compact-topic/log?limit=100"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(log.len(), 5);

    // Compact up to seq 3
    let compact_resp: serde_json::Value = client
        .post(format!("{url}/topics/compact-topic/compact"))
        .json(&json!({"up_to_seq": 3}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(compact_resp["pruned_entries"], 3);

    // Only 2 entries remaining in log
    let log2: Vec<serde_json::Value> = client
        .get(format!("{url}/topics/compact-topic/log?limit=100"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(log2.len(), 2);

    // Snapshot should exist
    let snapshot: serde_json::Value = client
        .get(format!("{url}/topics/compact-topic/snapshot"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(snapshot["snapshot_seq"], 3);
    assert_eq!(snapshot["object_count"], 3);
}

#[tokio::test]
async fn deposit_endpoints() {
    // Start relay WITH deposits enabled
    use agenet_efl::deposit::{DepositEscrow, ViolationPenalties};

    let config = RelayConfig {
        bind_addr: ([127, 0, 0, 1], 0).into(),
        db_path: ":memory:".to_string(),
        credit_db_path: ":memory:".to_string(),
        deposit_db_path: None,
        default_pow_difficulty: 8,
        pow_challenge_ttl: 300,
        rate_window_seconds: 60,
    };

    let store = ObjectStore::open(&config.db_path).await.unwrap();
    let deposits = DepositEscrow::open_memory(ViolationPenalties::default())
        .await
        .unwrap();

    let state = Arc::new(RelayState {
        store,
        challenges: ChallengeStore::new(),
        hub: SubscriptionHub::default(),
        config: config.clone(),
        merkle: TopicMerkleStore::new(),
        rate_limiter: RateLimiter::new(RateLimitConfig {
            max_tokens: 1000,
            refill_rate: 100.0,
            cost: 1,
        }),
        replay_detector: ReplayDetector::new(300),
        credits: CreditLedger::open_memory().await.unwrap(),
        burn_policy: BurnPolicy::default(),
        attestations: AttestationGraph::new(),
        rate_tracker: TopicRateTracker::new(60),
        difficulty_config: DifficultyConfig {
            base_difficulty: config.default_pow_difficulty,
            min_difficulty: 4,
            max_difficulty: 12,
            ..Default::default()
        },
        policies: PolicyRegistry::new(),
        deposits: Some(deposits),
        burn_escalation: BurnEscalation::default(),
    });

    let app = server::router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let url = format!("http://{addr}");
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();
    let agent_hex = agent.agent_id().to_hex();

    // Lock deposit
    let resp: serde_json::Value = client
        .post(format!("{url}/deposits/lock"))
        .json(&json!({"agent_id": agent_hex, "amount": 500}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["deposited"], 500);

    // Query deposit
    let resp: serde_json::Value = client
        .get(format!("{url}/deposits/{agent_hex}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["deposited"], 500);
    assert_eq!(resp["remaining"], 500);
    assert_eq!(resp["status"], "active");
}
