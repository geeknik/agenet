use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;
use tracing::info;

use agenet_pow::ChallengeStore;

use crate::abuse::{RateLimitConfig, RateLimiter, ReplayDetector};
use crate::config::RelayConfig;
use crate::merkle::TopicMerkleStore;
use crate::routes::{self, RelayState};
use crate::storage::ObjectStore;
use crate::subscription::SubscriptionHub;

/// Build and run the relay server.
pub async fn run(config: RelayConfig) -> Result<(), Box<dyn std::error::Error>> {
    let store = ObjectStore::open(&config.db_path).await?;
    let challenges = ChallengeStore::new();
    let hub = SubscriptionHub::default();
    let merkle = TopicMerkleStore::new();
    let rate_limiter = RateLimiter::new(RateLimitConfig::default());
    let replay_detector = ReplayDetector::new(config.pow_challenge_ttl);

    let state = Arc::new(RelayState {
        store,
        challenges,
        hub,
        config: config.clone(),
        merkle,
        rate_limiter,
        replay_detector,
    });

    let app = router(state);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    info!("agenet-relay listening on {}", config.bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Build the router (exported for testing).
pub fn router(state: Arc<RelayState>) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route("/objects", post(routes::post_object))
        .route("/objects/{hash}", get(routes::get_object))
        .route("/pow/challenge", get(routes::get_pow_challenge))
        .route("/topics/{topic_id}/log", get(routes::get_topic_log))
        .route("/topics/{topic_id}/merkle-root", get(routes::get_merkle_root))
        .route("/topics/{topic_id}/proof/{index}", get(routes::get_merkle_proof))
        .route("/subscribe", get(routes::ws_subscribe))
        .with_state(state)
}
