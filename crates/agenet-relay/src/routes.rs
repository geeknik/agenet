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

use crate::config::RelayConfig;
use crate::error::RelayError;
use crate::storage::ObjectStore;
use crate::subscription::{SubscriptionFilter, SubscriptionHub};

/// Shared relay state passed to all handlers.
#[derive(Clone)]
pub struct RelayState {
    pub store: ObjectStore,
    pub challenges: ChallengeStore,
    pub hub: SubscriptionHub,
    pub config: RelayConfig,
}

// --- POST /objects ---

pub async fn post_object(
    State(state): State<Arc<RelayState>>,
    Json(object): Json<Object>,
) -> Result<impl IntoResponse, RelayError> {
    // 1. Validate schema
    validate_schema(&object.schema, &object.payload)?;

    // 2. Verify signature (need public key — for now, trust author field and verify structurally)
    //    Full verification requires a public key registry; stub for now verifies signature format.
    if object.signature.is_empty() {
        return Err(AgenetError::InvalidSignature.into());
    }
    let sig_bytes =
        hex::decode(&object.signature).map_err(|_| AgenetError::InvalidSignature)?;
    if sig_bytes.len() != 64 {
        return Err(AgenetError::InvalidSignature.into());
    }

    // 3. Verify PoW if present
    if let Some(ref pow_proof) = object.pow_proof {
        // Hash the object content WITHOUT the pow_proof field to avoid circularity.
        // The PoW is computed over the object's content, not over itself.
        let mut content_obj = object.raw();
        content_obj.pow_proof = None;
        let object_hash = content_obj.hash().to_hex();
        // Consume the challenge (one-use)
        let challenge = state.challenges.consume(&pow_proof.nonce)?;
        // Verify difficulty matches
        if pow_proof.difficulty < challenge.difficulty {
            return Err(AgenetError::InvalidPow.into());
        }
        // Verify the proof
        agenet_pow::verify(pow_proof, &object_hash)?;
    }

    // 4. Store (idempotent by content hash)
    let hash = state.store.put(&object).await?;

    // 5. Broadcast to subscribers
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

// --- WS /subscribe ---

pub async fn ws_subscribe(
    State(state): State<Arc<RelayState>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_subscription(socket, state))
}

async fn handle_subscription(mut socket: WebSocket, state: Arc<RelayState>) {
    // Wait for the client to send a filter
    let filter = match socket.recv().await {
        Some(Ok(Message::Text(text))) => match serde_json::from_str::<SubscriptionFilter>(&text) {
            Ok(filter) => filter,
            Err(e) => {
                let _ = socket
                    .send(Message::Text(
                        json!({"error": format!("invalid filter: {e}")}).to_string().into(),
                    ))
                    .await;
                return;
            }
        },
        _ => return,
    };

    // Acknowledge the subscription
    let _ = socket
        .send(Message::Text(json!({"subscribed": true}).to_string().into()))
        .await;

    // Subscribe to the broadcast hub
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
                        break; // Client disconnected
                    }
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                let _ = socket
                    .send(Message::Text(
                        json!({"warning": format!("lagged {n} messages")}).to_string().into(),
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
