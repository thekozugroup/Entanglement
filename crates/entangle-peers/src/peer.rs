use entangle_types::peer_id::PeerId;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// What trust level a paired peer holds. Coarse for Phase 1.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustLevel {
    /// Default after pairing. Peer can talk and exchange capabilities through biscuits.
    Trusted,
    /// Peer is on the allowlist but is read-only — can be queried, cannot push tasks.
    Observer,
    /// Peer was paired but has been revoked. Kept for audit; not allowed to connect.
    Revoked,
}

/// An authenticated, trusted peer stored in the allowlist.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedPeer {
    /// Stable identifier derived from the peer's Ed25519 public key.
    pub peer_id: PeerId,
    /// Hex of the Ed25519 verifying key (32 bytes).
    pub public_key_hex: String,
    /// Human-readable label for this peer.
    pub display_name: String,
    /// Current trust level.
    pub trust: TrustLevel,
    /// Unix seconds when this peer was paired.
    pub paired_at: u64,
    /// Unix seconds; updated when peer last successfully authenticated.
    pub last_seen_at: Option<u64>,
    /// Human-readable note.
    #[serde(default)]
    pub note: String,
}

impl TrustedPeer {
    /// Create a new trusted peer with [`TrustLevel::Trusted`] and the current timestamp.
    pub fn new(peer_id: PeerId, public_key_hex: String, display_name: String) -> Self {
        Self {
            peer_id,
            public_key_hex,
            display_name,
            trust: TrustLevel::Trusted,
            paired_at: now_secs(),
            last_seen_at: None,
            note: String::new(),
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
