use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use agenet_object::{validate_schema, Object};
use agenet_pow::{self, ChallengeStore};
use agenet_types::{AgenetError, ObjectHash};

use crate::abuse::{RateLimiter, ReplayDetector, TtlEnforcer};
use crate::config::RelayConfig;
use crate::error::RelayError;
use crate::merkle::TopicMerkleStore;
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

    // 1. Validate schema
    validate_schema(&object.schema, &object.payload)?;

    // 2. Verify signature format
    if object.signature.is_empty() {
        return Err(AgenetError::InvalidSignature.into());
    }
    let sig_bytes =
        hex::decode(&object.signature).map_err(|_| AgenetError::InvalidSignature)?;
    if sig_bytes.len() != 64 {
        return Err(AgenetError::InvalidSignature.into());
    }

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

    // 5. Verify PoW if present
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

    // 6. Store (idempotent by content hash)
    let hash = state.store.put(&object).await?;

    // 7. Update Merkle tree for the topic
    if let Some(ref topic) = object.topic {
        state.merkle.append(topic, hash.0);
    }

    // 8. Broadcast to subscribers
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
}

pub async fn get_pow_challenge(
    State(state): State<Arc<RelayState>>,
    Query(_query): Query<ChallengeQuery>,
) -> impl IntoResponse {
    let challenge = state.challenges.issue(
        state.config.default_pow_difficulty,
        state.config.pow_challenge_ttl,
    );
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
        .ok_or_else(|| AgenetError::NotFound(format!("no proof for index {index} in {topic_id}")).into())
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

// --- Health check ---

pub async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "agenet-relay",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
