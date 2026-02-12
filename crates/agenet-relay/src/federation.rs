use agenet_object::Object;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Configuration for a federated peer relay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    /// The peer relay's base URL.
    pub url: String,
    /// Topics to subscribe to from this peer.
    pub topics: Vec<String>,
    /// Whether to apply local policy to federated objects.
    pub apply_local_policy: bool,
    /// Whether to enforce local EFL (PoW/credits) for federated objects.
    pub enforce_local_efl: bool,
}

/// Status of a peer connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerStatus {
    Disconnected,
    Connecting,
    Connected,
    Failed(String),
}

/// Tracks federated peer state.
#[derive(Clone, Debug)]
pub struct PeerState {
    pub config: PeerConfig,
    pub status: PeerStatus,
    pub objects_received: u64,
    pub last_seen: Option<i64>,
}

/// Federation manager — coordinates relay-to-relay subscriptions.
#[derive(Clone)]
pub struct FederationManager {
    peers: Arc<RwLock<HashMap<String, PeerState>>>,
    /// Channel to send ingested federated objects to the local relay.
    ingest_tx: mpsc::Sender<FederatedObject>,
}

/// A federated object with its source peer.
#[derive(Clone, Debug)]
pub struct FederatedObject {
    pub object: Object,
    pub source_peer: String,
}

impl FederationManager {
    pub fn new(ingest_tx: mpsc::Sender<FederatedObject>) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            ingest_tx,
        }
    }

    /// Register a new peer relay.
    pub fn add_peer(&self, config: PeerConfig) {
        let url = config.url.clone();
        self.peers.write().unwrap().insert(
            url,
            PeerState {
                config,
                status: PeerStatus::Disconnected,
                objects_received: 0,
                last_seen: None,
            },
        );
    }

    /// Remove a peer relay.
    pub fn remove_peer(&self, url: &str) {
        self.peers.write().unwrap().remove(url);
    }

    /// List all peers and their status.
    pub fn list_peers(&self) -> Vec<PeerState> {
        self.peers.read().unwrap().values().cloned().collect()
    }

    /// Get a specific peer's state.
    pub fn peer_status(&self, url: &str) -> Option<PeerState> {
        self.peers.read().unwrap().get(url).cloned()
    }

    /// Update a peer's connection status.
    pub fn update_status(&self, url: &str, status: PeerStatus) {
        if let Some(peer) = self.peers.write().unwrap().get_mut(url) {
            peer.status = status;
        }
    }

    /// Record that an object was received from a peer.
    pub fn record_receive(&self, url: &str) {
        if let Some(peer) = self.peers.write().unwrap().get_mut(url) {
            peer.objects_received += 1;
            peer.last_seen = Some(chrono::Utc::now().timestamp());
        }
    }

    /// Start subscribing to a peer relay's topics.
    /// Spawns a background task that connects via HTTP polling (WS in future).
    pub fn start_peer_subscription(&self, peer_url: String) {
        let peers = self.peers.clone();
        let ingest_tx = self.ingest_tx.clone();

        tokio::spawn(async move {
            Self::update_status_static(&peers, &peer_url, PeerStatus::Connecting);

            let client = reqwest::Client::new();
            let topics = {
                let p = peers.read().unwrap();
                match p.get(&peer_url) {
                    Some(state) => state.config.topics.clone(),
                    None => return,
                }
            };

            info!(peer = %peer_url, ?topics, "starting federation subscription");

            // Poll each topic log periodically
            let mut cursors: HashMap<String, i64> = HashMap::new();
            Self::update_status_static(&peers, &peer_url, PeerStatus::Connected);

            loop {
                for topic in &topics {
                    let cursor = cursors.get(topic.as_str()).copied().unwrap_or(0);
                    let url = format!(
                        "{}/topics/{}/log?after={}&limit=100",
                        peer_url, topic, cursor
                    );

                    match client.get(&url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let entries: Vec<serde_json::Value> =
                                match resp.json().await {
                                    Ok(v) => v,
                                    Err(_) => continue,
                                };

                            for entry in &entries {
                                if let Some(hash) = entry["object_hash"].as_str() {
                                    // Fetch the full object
                                    let obj_url = format!("{}/objects/{}", peer_url, hash);
                                    if let Ok(obj_resp) = client.get(&obj_url).send().await {
                                        if let Ok(object) = obj_resp.json::<Object>().await {
                                            let federated = FederatedObject {
                                                object,
                                                source_peer: peer_url.clone(),
                                            };
                                            if ingest_tx.send(federated).await.is_err() {
                                                warn!("federation ingest channel closed");
                                                return;
                                            }
                                            Self::record_receive_static(&peers, &peer_url);
                                        }
                                    }
                                }

                                // Update cursor
                                if let Some(seq) = entry["seq"].as_i64() {
                                    cursors.insert(topic.clone(), seq);
                                }
                            }
                        }
                        Ok(resp) => {
                            warn!(peer = %peer_url, status = %resp.status(), "peer returned error");
                        }
                        Err(e) => {
                            warn!(peer = %peer_url, error = %e, "failed to connect to peer");
                            Self::update_status_static(
                                &peers,
                                &peer_url,
                                PeerStatus::Failed(e.to_string()),
                            );
                        }
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });
    }

    fn update_status_static(
        peers: &Arc<RwLock<HashMap<String, PeerState>>>,
        url: &str,
        status: PeerStatus,
    ) {
        if let Some(peer) = peers.write().unwrap().get_mut(url) {
            peer.status = status;
        }
    }

    fn record_receive_static(
        peers: &Arc<RwLock<HashMap<String, PeerState>>>,
        url: &str,
    ) {
        if let Some(peer) = peers.write().unwrap().get_mut(url) {
            peer.objects_received += 1;
            peer.last_seen = Some(chrono::Utc::now().timestamp());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> (FederationManager, mpsc::Receiver<FederatedObject>) {
        let (tx, rx) = mpsc::channel(100);
        (FederationManager::new(tx), rx)
    }

    #[test]
    fn add_and_list_peers() {
        let (mgr, _rx) = make_manager();
        mgr.add_peer(PeerConfig {
            url: "http://relay-a:9600".into(),
            topics: vec!["security".into()],
            apply_local_policy: true,
            enforce_local_efl: false,
        });
        mgr.add_peer(PeerConfig {
            url: "http://relay-b:9600".into(),
            topics: vec!["research".into()],
            apply_local_policy: false,
            enforce_local_efl: false,
        });

        let peers = mgr.list_peers();
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn remove_peer() {
        let (mgr, _rx) = make_manager();
        mgr.add_peer(PeerConfig {
            url: "http://relay-a:9600".into(),
            topics: vec![],
            apply_local_policy: true,
            enforce_local_efl: false,
        });
        assert_eq!(mgr.list_peers().len(), 1);
        mgr.remove_peer("http://relay-a:9600");
        assert_eq!(mgr.list_peers().len(), 0);
    }

    #[test]
    fn update_peer_status() {
        let (mgr, _rx) = make_manager();
        mgr.add_peer(PeerConfig {
            url: "http://relay-a:9600".into(),
            topics: vec![],
            apply_local_policy: true,
            enforce_local_efl: false,
        });

        assert_eq!(
            mgr.peer_status("http://relay-a:9600").unwrap().status,
            PeerStatus::Disconnected
        );

        mgr.update_status("http://relay-a:9600", PeerStatus::Connected);
        assert_eq!(
            mgr.peer_status("http://relay-a:9600").unwrap().status,
            PeerStatus::Connected
        );
    }

    #[test]
    fn record_receive_increments() {
        let (mgr, _rx) = make_manager();
        mgr.add_peer(PeerConfig {
            url: "http://relay-a:9600".into(),
            topics: vec![],
            apply_local_policy: true,
            enforce_local_efl: false,
        });

        mgr.record_receive("http://relay-a:9600");
        mgr.record_receive("http://relay-a:9600");
        mgr.record_receive("http://relay-a:9600");

        let state = mgr.peer_status("http://relay-a:9600").unwrap();
        assert_eq!(state.objects_received, 3);
        assert!(state.last_seen.is_some());
    }

    #[test]
    fn peer_config_serde() {
        let config = PeerConfig {
            url: "http://relay-a:9600".into(),
            topics: vec!["security".into(), "research".into()],
            apply_local_policy: true,
            enforce_local_efl: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let config2: PeerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config2.url, config.url);
        assert_eq!(config2.topics, config.topics);
    }
}
