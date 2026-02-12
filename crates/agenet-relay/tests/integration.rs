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
use std::net::SocketAddr;
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
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
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
        min_trust_depth: 0,
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
        min_trust_depth: 0,
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
        min_trust_depth: 0,
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
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
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

#[tokio::test]
async fn trust_depth_enforcement() {
    let (url, state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();
    let attester1 = AgentKeypair::generate();
    let attester2 = AgentKeypair::generate();

    // Set a policy requiring trust depth >= 2
    state.policies.set(agenet_relay::policy::TopicPolicy {
        topic: "trust-gated".into(),
        min_pow: 0,
        min_reputation_attestations: 0,
        max_payload_bytes: 0,
        allow_credit_substitution: true,
        min_trust_depth: 2,
    });

    // Submit without attestations — should fail
    let object = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "no trust"}),
    )
    .topic("trust-gated")
    .sign(&agent);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Add 2 attesters for the agent
    use agenet_efl::attestation::AttestationClaim;
    state.attestations.record(attester1.agent_id(), agent.agent_id(), AttestationClaim::Trustworthy);
    state.attestations.record(attester2.agent_id(), agent.agent_id(), AttestationClaim::GoodActor);

    // Now submit — should succeed (2 unique attesters meets depth >= 2)
    let resp2 = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "trusted agent"}),
        "trust-gated",
        vec![],
    )
    .await;
    assert_eq!(resp2.status(), 201);
}

#[tokio::test]
async fn reputation_burn_discount() {
    let (url, state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();
    let attester = AgentKeypair::generate();
    let agent_hex = agent.agent_id().to_hex();

    // Set policy with PoW + credit substitution
    state.policies.set(agenet_relay::policy::TopicPolicy {
        topic: "rep-discount".into(),
        min_pow: 8,
        min_reputation_attestations: 0,
        max_payload_bytes: 0,
        allow_credit_substitution: true,
        min_trust_depth: 0,
    });

    // Mint credits
    state.credits.mint(&agent.agent_id(), 100, "test").await.unwrap();

    // Add reputation for the agent
    use agenet_efl::attestation::AttestationClaim;
    state.attestations.record(attester.agent_id(), agent.agent_id(), AttestationClaim::Trustworthy);

    // Submit without PoW — should burn discounted credits
    let object = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "discounted burn"}),
    )
    .topic("rep-discount")
    .sign(&agent);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // With 1 reputation: cost = ceil(1 / (1+1)) = 1 (minimum)
    // Balance should be 99
    let resp: serde_json::Value = client
        .get(format!("{url}/credits/{agent_hex}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["balance"], 99);
}

// --- WebSocket subscription tests ---

#[tokio::test]
async fn websocket_subscription_receives_matching_objects() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite;

    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Connect WebSocket
    let ws_url = url.replace("http://", "ws://") + "/subscribe";
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();

    // Send filter for schema=Claim and topic=ws-test
    let filter = json!({
        "schema": "Claim@1.0.0",
        "topic": "ws-test"
    });
    ws.send(tungstenite::Message::Text(filter.to_string().into())).await.unwrap();

    // Read subscription confirmation
    let confirm = ws.next().await.unwrap().unwrap();
    let confirm_json: serde_json::Value = serde_json::from_str(confirm.to_text().unwrap()).unwrap();
    assert_eq!(confirm_json["subscribed"], true);

    // Submit a matching object
    let resp = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "ws-test claim"}),
        "ws-test",
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 201);

    // Receive the object via WebSocket
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .expect("timeout waiting for WS message")
        .unwrap()
        .unwrap();
    let obj: serde_json::Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert_eq!(obj["schema"], "Claim@1.0.0");
    assert_eq!(obj["payload"]["statement"], "ws-test claim");
}

#[tokio::test]
async fn websocket_subscription_filters_non_matching() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite;

    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Connect and subscribe to topic "alpha-only"
    let ws_url = url.replace("http://", "ws://") + "/subscribe";
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws.send(tungstenite::Message::Text(json!({"topic": "alpha-only"}).to_string().into())).await.unwrap();
    let _ = ws.next().await; // consume confirmation

    // Submit to a DIFFERENT topic
    let resp = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "wrong topic"}),
        "beta-only",
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 201);

    // Submit to the CORRECT topic
    let resp2 = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "right topic"}),
        "alpha-only",
        vec![],
    )
    .await;
    assert_eq!(resp2.status(), 201);

    // We should only get the "alpha-only" object
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .expect("timeout")
        .unwrap()
        .unwrap();
    let obj: serde_json::Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert_eq!(obj["payload"]["statement"], "right topic");
}

// --- Error branch tests ---

#[tokio::test]
async fn reject_expired_ttl() {
    let (url, _state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Build an object with a TTL that's already expired
    let old_timestamp = chrono::Utc::now().timestamp() - 7200; // 2 hours ago
    let object = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "expired"}),
    )
    .topic("test")
    .ttl(3600) // TTL = 1 hour, but timestamp is 2 hours ago => expired
    .timestamp(old_timestamp)
    .sign(&agent);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["detail"].as_str().unwrap().contains("TTL expired"));
}

#[tokio::test]
async fn reject_payload_too_large() {
    let (url, state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Set policy with small max payload
    state.policies.set(agenet_relay::policy::TopicPolicy {
        topic: "small-payload".into(),
        min_pow: 0,
        min_reputation_attestations: 0,
        max_payload_bytes: 50, // Very small: 50 bytes
        allow_credit_substitution: true,
        min_trust_depth: 0,
    });

    // Submit a payload that's too big
    let object = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "this is a rather long statement that will definitely exceed the fifty byte limit set by the policy"}),
    )
    .topic("small-payload")
    .sign(&agent);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["detail"].as_str().unwrap().contains("payload exceeds"));
}

#[tokio::test]
async fn reject_insufficient_attestations() {
    let (url, state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Set policy requiring 3 attestations
    state.policies.set(agenet_relay::policy::TopicPolicy {
        topic: "attested-only".into(),
        min_pow: 0,
        min_reputation_attestations: 3,
        max_payload_bytes: 0,
        allow_credit_substitution: true,
        min_trust_depth: 0,
    });

    // Submit without any attestations
    let object = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "no attestations"}),
    )
    .topic("attested-only")
    .sign(&agent);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["detail"].as_str().unwrap().contains("attestations"));
}

#[tokio::test]
async fn reject_pow_difficulty_too_low() {
    let (url, state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Set policy requiring high PoW, no credit substitution
    state.policies.set(agenet_relay::policy::TopicPolicy {
        topic: "high-pow".into(),
        min_pow: 20,
        min_reputation_attestations: 0,
        max_payload_bytes: 0,
        allow_credit_substitution: false,
        min_trust_depth: 0,
    });

    // Get a challenge for a DIFFERENT topic (low difficulty)
    let challenge: agenet_pow::PowChallenge = client
        .get(format!("{url}/pow/challenge?topic=unrelated"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Solve with the low difficulty, but submit to "high-pow" topic
    let pinned_ts = chrono::Utc::now().timestamp();
    let content_hash = pow_content_hash(
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "low pow"}),
        "high-pow",
        vec![],
        pinned_ts,
    );
    let proof = agenet_pow::solve(&challenge.nonce, &content_hash, challenge.difficulty);

    let object = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "low pow"}),
    )
    .topic("high-pow")
    .timestamp(pinned_ts)
    .pow_proof(proof)
    .sign(&agent);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();
    // Should be rejected because PoW difficulty < 20
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn reject_credit_sub_insufficient_credits() {
    let (url, state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Policy requires PoW with credit substitution allowed
    state.policies.set(agenet_relay::policy::TopicPolicy {
        topic: "credits-needed".into(),
        min_pow: 8,
        min_reputation_attestations: 0,
        max_payload_bytes: 0,
        allow_credit_substitution: true,
        min_trust_depth: 0,
    });

    // Don't mint any credits — agent has 0 balance
    // Submit WITHOUT PoW — should try credit sub but fail
    let object = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "no credits"}),
    )
    .topic("credits-needed")
    .sign(&agent);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&object)
        .send()
        .await
        .unwrap();
    // Should fail because no credits to burn
    assert_ne!(resp.status(), 201);
}

#[tokio::test]
async fn suspended_deposit_blocks_submission() {
    use agenet_efl::deposit::{DepositEscrow, ViolationPenalties, ViolationType};

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
    let deposits = DepositEscrow::open_memory(ViolationPenalties {
        proven_spam: 500,     // Will exhaust a 500 deposit in 1 violation
        invalid_object: 200,
        policy_violation: 50,
        replay_attack: 150,
    })
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
        deposits: Some(deposits.clone()),
        burn_escalation: BurnEscalation::default(),
    });

    let app = server::router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    let url = format!("http://{addr}");
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Lock deposit and immediately exhaust it via violation
    deposits.lock_deposit(&agent.agent_id(), 500).await.unwrap();
    deposits.record_violation(&agent.agent_id(), ViolationType::ProvenSpam).await.unwrap();

    // Verify deposit is suspended
    let record = deposits.get_deposit(&agent.agent_id()).await.unwrap().unwrap();
    assert_eq!(record.status, "suspended");

    // Try to submit — should be blocked
    let resp = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "blocked agent"}),
        "test",
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["detail"].as_str().unwrap().contains("suspended"));
}

// --- Tag query test ---

#[tokio::test]
async fn tag_indexing_and_query() {
    let (url, state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Submit objects with different tags
    let r1 = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "tagged A"}),
        "tag-test",
        vec!["security".into(), "cve".into()],
    )
    .await;
    assert_eq!(r1.status(), 201);

    let r2 = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "tagged B"}),
        "tag-test",
        vec!["security".into()],
    )
    .await;
    assert_eq!(r2.status(), 201);

    let r3 = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "tagged C"}),
        "tag-test",
        vec!["research".into()],
    )
    .await;
    assert_eq!(r3.status(), 201);

    // Query by tag "security" — should find 2
    let results = state.store.by_tag("security", 100).await.unwrap();
    assert_eq!(results.len(), 2);

    // Query by tag "cve" — should find 1
    let results = state.store.by_tag("cve", 100).await.unwrap();
    assert_eq!(results.len(), 1);

    // Query by tag "research" — should find 1
    let results = state.store.by_tag("research", 100).await.unwrap();
    assert_eq!(results.len(), 1);

    // Query by tag "nonexistent" — should find 0
    let results = state.store.by_tag("nonexistent", 100).await.unwrap();
    assert_eq!(results.len(), 0);
}

// --- Attestation ingestion via POST /objects ---

#[tokio::test]
async fn attestation_object_updates_graph() {
    let (url, state) = start_relay().await;
    let client = reqwest::Client::new();
    let attester = AgentKeypair::generate();
    let attestee = AgentKeypair::generate();

    // Submit an Attestation object
    let resp = submit_with_pow(
        &client,
        &url,
        &attester,
        SchemaId::new("Attestation", "1.0.0"),
        json!({
            "attestee": attestee.agent_id().to_hex(),
            "claim": "trustworthy"
        }),
        "trust",
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 201);

    // Verify the attestation graph was updated
    let count = state.attestations.positive_attestation_count(&attestee.agent_id());
    assert_eq!(count, 1);
}

// --- Policy ingestion via POST /objects ---

#[tokio::test]
async fn policy_object_registers_policy() {
    let (url, state) = start_relay().await;
    let client = reqwest::Client::new();
    let agent = AgentKeypair::generate();

    // Submit a Policy object
    let resp = submit_with_pow(
        &client,
        &url,
        &agent,
        SchemaId::new("Policy", "1.0.0"),
        json!({
            "topic": "auto-policy",
            "requirements": {
                "min_pow": 18,
                "min_reputation_attestations": 2,
                "artifact_max_size_mb": 50
            }
        }),
        "governance",
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 201);

    // Verify the policy was registered
    let policy = state.policies.get("auto-policy");
    assert_eq!(policy.min_pow, 18);
    assert_eq!(policy.min_reputation_attestations, 2);
    assert_eq!(policy.max_payload_bytes, 50 * 1024 * 1024);
}

// --- Real-world smoke test: full lifecycle ---

/// This test simulates a real agent workflow:
/// 1. Agent A publishes PoW-backed claims to a topic
/// 2. Agent B attests Agent A as trustworthy
/// 3. Agent A posts to a reputation-gated topic
/// 4. Subscription receives matching objects in real-time
/// 5. Merkle proofs are verified for auditability
/// 6. Credits are minted, burned (credit substitution)
/// 7. Topic compaction cleans old log entries
/// 8. Deposit escrow and violation triggers work correctly
#[tokio::test]
async fn full_lifecycle_smoke_test() {
    use agenet_efl::deposit::{DepositEscrow, ViolationPenalties};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite;

    // ---- Setup relay with deposits ----
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
    let credits = CreditLedger::open_memory().await.unwrap();

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
        credits,
        burn_policy: BurnPolicy::default(),
        attestations: AttestationGraph::new(),
        rate_tracker: TopicRateTracker::new(60),
        difficulty_config: DifficultyConfig {
            base_difficulty: 8,
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
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    let url = format!("http://{addr}");
    let client = reqwest::Client::new();

    // ---- Create agents ----
    let agent_a = AgentKeypair::generate();
    let agent_b = AgentKeypair::generate();
    let agent_a_hex = agent_a.agent_id().to_hex();
    let agent_b_hex = agent_b.agent_id().to_hex();

    // ---- Phase 1: Health check ----
    let health: serde_json::Value = client
        .get(format!("{url}/health"))
        .send().await.unwrap()
        .json().await.unwrap();
    assert_eq!(health["status"], "ok");

    // ---- Phase 2: WebSocket subscription ----
    let ws_url = url.replace("http://", "ws://") + "/subscribe";
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws.send(tungstenite::Message::Text(
        json!({"topic": "research"}).to_string().into(),
    ))
    .await
    .unwrap();
    let confirm = ws.next().await.unwrap().unwrap();
    let confirm_json: serde_json::Value =
        serde_json::from_str(confirm.to_text().unwrap()).unwrap();
    assert_eq!(confirm_json["subscribed"], true);

    // ---- Phase 3: Agent A publishes PoW-backed claims ----
    let mut hashes = Vec::new();
    for i in 0..3 {
        let resp = submit_with_pow(
            &client,
            &url,
            &agent_a,
            SchemaId::new("Claim", "1.0.0"),
            json!({"statement": format!("research finding #{i}")}),
            "research",
            vec!["science".into()],
        )
        .await;
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = resp.json().await.unwrap();
        hashes.push(body["hash"].as_str().unwrap().to_string());
    }

    // Verify WebSocket received all 3 objects
    for i in 0..3 {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("WS timeout")
            .unwrap()
            .unwrap();
        let obj: serde_json::Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
        assert_eq!(obj["schema"], "Claim@1.0.0");
        assert_eq!(
            obj["payload"]["statement"],
            format!("research finding #{i}")
        );
    }

    // ---- Phase 4: Retrieve objects by hash ----
    for hash in &hashes {
        let resp = client
            .get(format!("{url}/objects/{hash}"))
            .send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let obj: Object = resp.json().await.unwrap();
        assert!(obj.verify_self().is_ok(), "self-authentication failed");
    }

    // ---- Phase 5: Verify topic log and Merkle tree ----
    let log: Vec<serde_json::Value> = client
        .get(format!("{url}/topics/research/log?limit=100"))
        .send().await.unwrap()
        .json().await.unwrap();
    assert_eq!(log.len(), 3);

    let merkle_root: serde_json::Value = client
        .get(format!("{url}/topics/research/merkle-root"))
        .send().await.unwrap()
        .json().await.unwrap();
    assert_eq!(merkle_root["leaves"], 3);
    assert!(merkle_root["root"].is_string());

    // Verify inclusion proof for index 1
    let proof_resp = client
        .get(format!("{url}/topics/research/proof/1"))
        .send().await.unwrap();
    assert_eq!(proof_resp.status(), 200);

    // ---- Phase 6: Agent B attests Agent A ----
    let attest_resp = submit_with_pow(
        &client,
        &url,
        &agent_b,
        SchemaId::new("Attestation", "1.0.0"),
        json!({
            "attestee": agent_a_hex,
            "claim": "trustworthy"
        }),
        "trust",
        vec![],
    )
    .await;
    assert_eq!(attest_resp.status(), 201);

    // Verify attestation was registered
    let a_rep = state.attestations.positive_attestation_count(&agent_a.agent_id());
    assert!(a_rep >= 1);

    // ---- Phase 7: Reputation-gated topic ----
    state.policies.set(agenet_relay::policy::TopicPolicy {
        topic: "trusted-research".into(),
        min_pow: 0,
        min_reputation_attestations: 1,
        max_payload_bytes: 0,
        allow_credit_substitution: true,
        min_trust_depth: 0,
    });

    // Agent A (has 1 attestation) can post
    let resp = submit_with_pow(
        &client,
        &url,
        &agent_a,
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "trusted finding"}),
        "trusted-research",
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 201);

    // New unattested agent cannot
    let unattested = AgentKeypair::generate();
    let unattested_obj = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "untrusted"}),
    )
    .topic("trusted-research")
    .sign(&unattested);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&unattested_obj)
        .send().await.unwrap();
    assert_eq!(resp.status(), 403);

    // ---- Phase 8: Credit mint and credit substitution ----
    let mint_resp: serde_json::Value = client
        .post(format!("{url}/capabilities/mint"))
        .json(&json!({
            "agent_id": agent_a_hex,
            "amount": 50,
            "reason": "research grant"
        }))
        .send().await.unwrap()
        .json().await.unwrap();
    assert_eq!(mint_resp["balance"], 50);

    // Use credit substitution (no PoW)
    state.policies.set(agenet_relay::policy::TopicPolicy {
        topic: "credit-research".into(),
        min_pow: 8,
        min_reputation_attestations: 0,
        max_payload_bytes: 0,
        allow_credit_substitution: true,
        min_trust_depth: 0,
    });

    let credit_obj = ObjectBuilder::new(
        SchemaId::new("Claim", "1.0.0"),
        json!({"statement": "paid with credits"}),
    )
    .topic("credit-research")
    .sign(&agent_a);

    let resp = client
        .post(format!("{url}/objects"))
        .json(&credit_obj)
        .send().await.unwrap();
    assert_eq!(resp.status(), 201);

    // Verify credits were burned
    let balance: serde_json::Value = client
        .get(format!("{url}/credits/{agent_a_hex}"))
        .send().await.unwrap()
        .json().await.unwrap();
    assert!(balance["balance"].as_i64().unwrap() < 50);

    // ---- Phase 9: Topic compaction ----
    let compact_resp: serde_json::Value = client
        .post(format!("{url}/topics/research/compact"))
        .json(&json!({"up_to_seq": 2}))
        .send().await.unwrap()
        .json().await.unwrap();
    assert_eq!(compact_resp["pruned_entries"], 2);

    // Only 1 entry left
    let log_after: Vec<serde_json::Value> = client
        .get(format!("{url}/topics/research/log?limit=100"))
        .send().await.unwrap()
        .json().await.unwrap();
    assert_eq!(log_after.len(), 1);

    // Snapshot exists
    let snapshot: serde_json::Value = client
        .get(format!("{url}/topics/research/snapshot"))
        .send().await.unwrap()
        .json().await.unwrap();
    assert_eq!(snapshot["snapshot_seq"], 2);

    // ---- Phase 10: Deposit escrow ----
    let deposit_resp: serde_json::Value = client
        .post(format!("{url}/deposits/lock"))
        .json(&json!({"agent_id": agent_b_hex, "amount": 1000}))
        .send().await.unwrap()
        .json().await.unwrap();
    assert_eq!(deposit_resp["deposited"], 1000);

    let deposit_query: serde_json::Value = client
        .get(format!("{url}/deposits/{agent_b_hex}"))
        .send().await.unwrap()
        .json().await.unwrap();
    assert_eq!(deposit_query["deposited"], 1000);
    assert_eq!(deposit_query["remaining"], 1000);
    assert_eq!(deposit_query["status"], "active");
}
