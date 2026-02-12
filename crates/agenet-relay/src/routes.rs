use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use agenet_efl::attestation::AttestationGraph;
use agenet_efl::credits::{BurnPolicy, CreditLedger};
use agenet_efl::deposit::DepositEscrow;
use agenet_efl::dynamic_pow::{AgentReputation, DifficultyConfig, TopicRateTracker};
use agenet_object::{validate_schema, Object};
use agenet_pow::{self, ChallengeStore};
use agenet_types::{AgenetError, AgentId, ObjectHash};

use crate::abuse::{BurnEscalation, RateLimiter, ReplayDetector, TtlEnforcer};
use crate::config::RelayConfig;
use crate::error::RelayError;
use crate::merkle::TopicMerkleStore;
use crate::policy::PolicyRegistry;
use crate::storage::ObjectStore;
use crate::subscription::{SubscriptionFilter, SubscriptionHub};

/// Shared relay state passed to all handlers.
#[derive(Clone)]
pub struct RelayState {
    pub store: ObjectStore,
    pub challenges: ChallengeStore,
    pub hub: SubscriptionHub,
    pub config: RelayConfig,
    pub merkle: TopicMerkleStore,
    pub rate_limiter: RateLimiter,
    pub replay_detector: ReplayDetector,
    pub credits: CreditLedger,
    pub burn_policy: BurnPolicy,
    pub attestations: AttestationGraph,
    pub rate_tracker: TopicRateTracker,
    pub difficulty_config: DifficultyConfig,
    pub policies: PolicyRegistry,
    pub deposits: Option<DepositEscrow>,
    pub burn_escalation: BurnEscalation,
}

// --- POST /objects ---

pub async fn post_object(
    State(state): State<Arc<RelayState>>,
    Json(object): Json<Object>,
) -> Result<impl IntoResponse, RelayError> {
    // 0. Rate limit by author
    if !state.rate_limiter.check_agent(&object.author) {
        return Err(AgenetError::Unauthorized("rate limited".into()).into());
    }

    // 0b. Check deposit standing (if deposits are enabled, suspended agents are blocked)
    if let Some(ref deposits) = state.deposits {
        if let Ok(Some(record)) = deposits.get_deposit(&object.author).await {
            if record.status == "suspended" {
                return Err(AgenetError::Unauthorized("deposit suspended".into()).into());
            }
        }
    }

    // 1. Validate schema
    validate_schema(&object.schema, &object.payload)?;

    // 2. Cryptographic signature verification (self-authenticating)
    object.verify_self()?;

    // 3. Check TTL
    if let Err(msg) = TtlEnforcer::check(object.ttl, object.timestamp) {
        return Err(AgenetError::Unauthorized(msg.to_string()).into());
    }

    // 4. Replay detection
    let object_hash_hex = object.hash().to_hex();
    if !state
        .replay_detector
        .check_and_record(&object_hash_hex, object.timestamp)
    {
        return Err(AgenetError::Duplicate(object_hash_hex).into());
    }

    // 5. Enforce topic policy
    if let Some(ref topic) = object.topic {
        let policy = state.policies.get(topic);

        // Check payload size limit
        if policy.max_payload_bytes > 0 {
            let payload_size = serde_json::to_string(&object.payload)
                .map(|s| s.len())
                .unwrap_or(0);
            if payload_size > policy.max_payload_bytes {
                return Err(AgenetError::Unauthorized(format!(
                    "payload exceeds topic limit of {} bytes",
                    policy.max_payload_bytes
                ))
                .into());
            }
        }

        // Check minimum reputation attestations
        if policy.min_reputation_attestations > 0 {
            let attestation_count = state.attestations.positive_attestation_count(&object.author);
            if attestation_count < policy.min_reputation_attestations {
                return Err(AgenetError::Unauthorized(format!(
                    "topic requires {} attestations, agent has {}",
                    policy.min_reputation_attestations, attestation_count
                ))
                .into());
            }
        }

        // Check minimum PoW difficulty
        if policy.min_pow > 0 {
            match &object.pow_proof {
                Some(proof) if proof.difficulty >= policy.min_pow => {
                    // PoW meets minimum — verified below
                }
                Some(_) => {
                    return Err(AgenetError::Unauthorized(format!(
                        "topic requires PoW difficulty >= {}",
                        policy.min_pow
                    ))
                    .into());
                }
                None if policy.allow_credit_substitution => {
                    // No PoW — burn credits instead (with abuse escalation)
                    let abuse_flags =
                        state.attestations.negative_attestation_count(&object.author);
                    let cost = state.burn_escalation.cost(abuse_flags);
                    state
                        .credits
                        .burn(&object.author, cost, "post (credit substitution for PoW)")
                        .await?;
                }
                None => {
                    return Err(AgenetError::Unauthorized(format!(
                        "topic requires PoW difficulty >= {}",
                        policy.min_pow
                    ))
                    .into());
                }
            }
        }
    }

    // 6. Verify PoW if present
    if let Some(ref pow_proof) = object.pow_proof {
        let mut content_obj = object.raw();
        content_obj.pow_proof = None;
        let content_hash = content_obj.hash().to_hex();
        let challenge = state.challenges.consume(&pow_proof.nonce)?;
        if pow_proof.difficulty < challenge.difficulty {
            return Err(AgenetError::InvalidPow.into());
        }
        agenet_pow::verify(pow_proof, &content_hash)?;
    }

    // 7. Store (idempotent by content hash)
    let hash = state.store.put(&object).await?;

    // 8. Update Merkle tree for the topic
    if let Some(ref topic) = object.topic {
        state.merkle.append(topic, hash.0);
        // Record for congestion tracking
        state.rate_tracker.record(topic);
    }

    // 9. If this is a Policy object, register the policy
    if object.schema.name() == "Policy" {
        state.policies.ingest_from_payload(&object.payload);
    }

    // 10. If this is an Attestation object, update the attestation graph
    if object.schema.name() == "Attestation" {
        if let (Some(attestee_hex), Some(claim_str)) = (
            object.payload.get("attestee").and_then(|v| v.as_str()),
            object.payload.get("claim").and_then(|v| v.as_str()),
        ) {
            if let Ok(attestee) = AgentId::from_hex(attestee_hex) {
                let claim = match claim_str {
                    "trustworthy" => Some(agenet_efl::attestation::AttestationClaim::Trustworthy),
                    "good_actor" => Some(agenet_efl::attestation::AttestationClaim::GoodActor),
                    "reliable_data" => {
                        Some(agenet_efl::attestation::AttestationClaim::ReliableData)
                    }
                    "malicious" => Some(agenet_efl::attestation::AttestationClaim::Malicious),
                    "spammer" => Some(agenet_efl::attestation::AttestationClaim::Spammer),
                    _ => None,
                };
                if let Some(claim) = claim {
                    state
                        .attestations
                        .record(object.author.clone(), attestee, claim);
                }
            }
        }
    }

    // 11. Broadcast to subscribers
    state.hub.broadcast(&object);

    Ok((
        StatusCode::CREATED,
        Json(json!({ "hash": hash.to_hex() })),
    ))
}

// --- GET /objects/{hash} ---

pub async fn get_object(
    State(state): State<Arc<RelayState>>,
    Path(hash_hex): Path<String>,
) -> Result<impl IntoResponse, RelayError> {
    let hash =
        ObjectHash::from_hex(&hash_hex).map_err(|_| AgenetError::NotFound(hash_hex.clone()))?;
    let object = state.store.get(&hash).await?;
    Ok(Json(object))
}

// --- GET /pow/challenge ---

#[derive(Deserialize)]
pub struct ChallengeQuery {
    pub topic: Option<String>,
    pub agent: Option<String>,
}

pub async fn get_pow_challenge(
    State(state): State<Arc<RelayState>>,
    Query(query): Query<ChallengeQuery>,
) -> impl IntoResponse {
    // Dynamic difficulty based on topic congestion and agent reputation
    let topic_rate = query
        .topic
        .as_deref()
        .map(|t| state.rate_tracker.rate_per_minute(t))
        .unwrap_or(0.0);

    let reputation = query
        .agent
        .as_deref()
        .and_then(|hex| AgentId::from_hex(hex).ok())
        .map(|agent_id| AgentReputation {
            attestation_count: state.attestations.positive_attestation_count(&agent_id),
            abuse_flags: state.attestations.negative_attestation_count(&agent_id),
        })
        .unwrap_or(AgentReputation {
            attestation_count: 0,
            abuse_flags: 0,
        });

    let mut difficulty = agenet_efl::dynamic_pow::difficulty_for(
        &state.difficulty_config,
        topic_rate,
        &reputation,
    );

    // Ensure challenge meets the topic's policy minimum
    if let Some(ref topic) = query.topic {
        let policy = state.policies.get(topic);
        if policy.min_pow > difficulty {
            difficulty = policy.min_pow;
        }
    }

    let challenge = state
        .challenges
        .issue(difficulty, state.config.pow_challenge_ttl);
    Json(challenge)
}

// --- GET /topics/{topic_id}/log ---

#[derive(Deserialize)]
pub struct TopicLogQuery {
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct TopicLogEntry {
    pub seq: i64,
    pub object_hash: String,
}

pub async fn get_topic_log(
    State(state): State<Arc<RelayState>>,
    Path(topic_id): Path<String>,
    Query(query): Query<TopicLogQuery>,
) -> Result<impl IntoResponse, RelayError> {
    let after = query.after.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).min(1000);
    let entries = state.store.topic_log(&topic_id, after, limit).await?;
    let response: Vec<TopicLogEntry> = entries
        .into_iter()
        .map(|(seq, hash)| TopicLogEntry {
            seq,
            object_hash: hash,
        })
        .collect();
    Ok(Json(response))
}

// --- GET /topics/{topic_id}/merkle-root ---

pub async fn get_merkle_root(
    State(state): State<Arc<RelayState>>,
    Path(topic_id): Path<String>,
) -> impl IntoResponse {
    match state.merkle.root(&topic_id) {
        Some(root) => Json(json!({
            "topic": topic_id,
            "root": hex::encode(root),
            "leaves": state.merkle.len(&topic_id),
        })),
        None => Json(json!({
            "topic": topic_id,
            "root": null,
            "leaves": 0,
        })),
    }
}

// --- GET /topics/{topic_id}/proof/{index} ---

pub async fn get_merkle_proof(
    State(state): State<Arc<RelayState>>,
    Path((topic_id, index)): Path<(String, usize)>,
) -> Result<impl IntoResponse, RelayError> {
    state
        .merkle
        .proof(&topic_id, index)
        .map(Json)
        .ok_or_else(|| {
            AgenetError::NotFound(format!("no proof for index {index} in {topic_id}")).into()
        })
}

// --- POST /capabilities/mint ---

#[derive(Deserialize)]
pub struct MintRequest {
    pub agent_id: String,
    pub amount: i64,
    pub reason: String,
}

pub async fn mint_credits(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<MintRequest>,
) -> Result<impl IntoResponse, RelayError> {
    let agent_id =
        AgentId::from_hex(&req.agent_id).map_err(|_| AgenetError::NotFound(req.agent_id))?;
    let balance = state
        .credits
        .mint(&agent_id, req.amount, &req.reason)
        .await?;
    Ok((
        StatusCode::OK,
        Json(json!({ "agent_id": agent_id.to_hex(), "balance": balance })),
    ))
}

// --- GET /credits/{agent_id} ---

pub async fn get_credits(
    State(state): State<Arc<RelayState>>,
    Path(agent_id_hex): Path<String>,
) -> Result<impl IntoResponse, RelayError> {
    let agent_id = AgentId::from_hex(&agent_id_hex)
        .map_err(|_| AgenetError::NotFound(agent_id_hex.clone()))?;
    let balance = state.credits.balance(&agent_id).await?;
    Ok(Json(
        json!({ "agent_id": agent_id_hex, "balance": balance }),
    ))
}

// --- GET /topics/{topic_id}/policy ---

pub async fn get_topic_policy(
    State(state): State<Arc<RelayState>>,
    Path(topic_id): Path<String>,
) -> impl IntoResponse {
    let policy = state.policies.get(&topic_id);
    Json(json!({
        "topic": topic_id,
        "min_pow": policy.min_pow,
        "min_reputation_attestations": policy.min_reputation_attestations,
        "max_payload_bytes": policy.max_payload_bytes,
        "allow_credit_substitution": policy.allow_credit_substitution,
    }))
}

// --- WS /subscribe ---

pub async fn ws_subscribe(
    State(state): State<Arc<RelayState>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_subscription(socket, state))
}

async fn handle_subscription(mut socket: WebSocket, state: Arc<RelayState>) {
    let filter = match socket.recv().await {
        Some(Ok(Message::Text(text))) => match serde_json::from_str::<SubscriptionFilter>(&text) {
            Ok(filter) => filter,
            Err(e) => {
                let _ = socket
                    .send(Message::Text(
                        json!({"error": format!("invalid filter: {e}")})
                            .to_string()
                            .into(),
                    ))
                    .await;
                return;
            }
        },
        _ => return,
    };

    let _ = socket
        .send(Message::Text(
            json!({"subscribed": true}).to_string().into(),
        ))
        .await;

    let mut receiver = state.hub.subscribe();

    loop {
        match receiver.recv().await {
            Ok(object) => {
                if filter.matches(&object) {
                    let json = match serde_json::to_string(&object) {
                        Ok(j) => j,
                        Err(_) => continue,
                    };
                    if socket.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                let _ = socket
                    .send(Message::Text(
                        json!({"warning": format!("lagged {n} messages")})
                            .to_string()
                            .into(),
                    ))
                    .await;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

// --- POST /topics/{topic_id}/compact ---

#[derive(Deserialize)]
pub struct CompactRequest {
    pub up_to_seq: i64,
}

pub async fn compact_topic(
    State(state): State<Arc<RelayState>>,
    Path(topic_id): Path<String>,
    Json(req): Json<CompactRequest>,
) -> Result<impl IntoResponse, RelayError> {
    let merkle_root = state
        .merkle
        .root(&topic_id)
        .map(hex::encode)
        .unwrap_or_default();

    let result = state
        .store
        .compact_topic(&topic_id, req.up_to_seq, &merkle_root)
        .await?;

    Ok(Json(json!({
        "topic": topic_id,
        "pruned_entries": result.pruned_entries,
        "snapshot_seq": result.snapshot_seq,
        "merkle_root": merkle_root,
    })))
}

// --- GET /topics/{topic_id}/snapshot ---

pub async fn get_topic_snapshot(
    State(state): State<Arc<RelayState>>,
    Path(topic_id): Path<String>,
) -> Result<impl IntoResponse, RelayError> {
    match state.store.latest_snapshot(&topic_id).await? {
        Some(snapshot) => Ok(Json(json!({
            "topic": topic_id,
            "snapshot_seq": snapshot.snapshot_seq,
            "merkle_root": snapshot.merkle_root,
            "object_count": snapshot.object_count,
            "created_at": snapshot.created_at,
        }))),
        None => Ok(Json(json!({
            "topic": topic_id,
            "snapshot": null,
        }))),
    }
}

// --- POST /deposits/lock ---

#[derive(Deserialize)]
pub struct DepositLockRequest {
    pub agent_id: String,
    pub amount: i64,
}

pub async fn lock_deposit(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<DepositLockRequest>,
) -> Result<impl IntoResponse, RelayError> {
    let deposits = state
        .deposits
        .as_ref()
        .ok_or(AgenetError::Unauthorized("deposits not enabled".into()))?;
    let agent_id =
        AgentId::from_hex(&req.agent_id).map_err(|_| AgenetError::NotFound(req.agent_id))?;
    deposits.lock_deposit(&agent_id, req.amount).await?;
    Ok((
        StatusCode::OK,
        Json(json!({ "agent_id": agent_id.to_hex(), "deposited": req.amount })),
    ))
}

// --- GET /deposits/{agent_id} ---

pub async fn get_deposit(
    State(state): State<Arc<RelayState>>,
    Path(agent_id_hex): Path<String>,
) -> Result<impl IntoResponse, RelayError> {
    let deposits = state
        .deposits
        .as_ref()
        .ok_or(AgenetError::Unauthorized("deposits not enabled".into()))?;
    let agent_id = AgentId::from_hex(&agent_id_hex)
        .map_err(|_| AgenetError::NotFound(agent_id_hex.clone()))?;
    match deposits.get_deposit(&agent_id).await? {
        Some(record) => Ok(Json(json!({
            "agent_id": agent_id_hex,
            "deposited": record.deposited,
            "burned": record.burned,
            "remaining": record.deposited - record.burned,
            "status": record.status,
        }))),
        None => Ok(Json(json!({
            "agent_id": agent_id_hex,
            "deposited": 0,
            "burned": 0,
            "remaining": 0,
            "status": "none",
        }))),
    }
}

// --- Health check ---

pub async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "agenet-relay",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
