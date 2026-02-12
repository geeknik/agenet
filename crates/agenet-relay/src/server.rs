use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;
use tracing::info;

use agenet_efl::attestation::AttestationGraph;
use agenet_efl::credits::{BurnPolicy, CreditLedger};
use agenet_efl::deposit::{DepositEscrow, ViolationPenalties};
use agenet_efl::dynamic_pow::{DifficultyConfig, TopicRateTracker};
use agenet_pow::ChallengeStore;

use crate::abuse::{BurnEscalation, RateLimitConfig, RateLimiter, ReplayDetector};
use crate::config::RelayConfig;
use crate::merkle::TopicMerkleStore;
use crate::policy::PolicyRegistry;
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
    let credits = CreditLedger::open(&config.credit_db_path).await?;
    let burn_policy = BurnPolicy::default();
    let attestations = AttestationGraph::new();
    let rate_tracker = TopicRateTracker::new(config.rate_window_seconds);
    let difficulty_config = DifficultyConfig {
        base_difficulty: config.default_pow_difficulty,
        ..Default::default()
    };
    let policies = PolicyRegistry::new();
    let burn_escalation = BurnEscalation::default();

    // Initialize deposit escrow if configured
    let deposits = if let Some(ref deposit_db_path) = config.deposit_db_path {
        Some(
            DepositEscrow::open(deposit_db_path, ViolationPenalties::default())
                .await?,
        )
    } else {
        None
    };

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
        deposits,
        burn_escalation,
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
        .route(
            "/topics/{topic_id}/merkle-root",
            get(routes::get_merkle_root),
        )
        .route(
            "/topics/{topic_id}/proof/{index}",
            get(routes::get_merkle_proof),
        )
        .route(
            "/topics/{topic_id}/policy",
            get(routes::get_topic_policy),
        )
        .route(
            "/topics/{topic_id}/compact",
            post(routes::compact_topic),
        )
        .route(
            "/topics/{topic_id}/snapshot",
            get(routes::get_topic_snapshot),
        )
        .route("/capabilities/mint", post(routes::mint_credits))
        .route("/credits/{agent_id}", get(routes::get_credits))
        .route("/deposits/lock", post(routes::lock_deposit))
        .route("/deposits/{agent_id}", get(routes::get_deposit))
        .route("/subscribe", get(routes::ws_subscribe))
        .with_state(state)
}
