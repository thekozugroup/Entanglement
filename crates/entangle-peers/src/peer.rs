use crate::errors::PeerStoreError;
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

    /// Create a trusted peer after validating the id/key relationship.
    ///
    /// `public_key_hex` must decode to exactly 32 bytes, and the [`PeerId`]
    /// derived from those bytes must equal `peer_id`. This is the constructor
    /// the CLI `mesh trust` path should use so an operator cannot record a
    /// `peer_id`/`public_key` pair that does not actually correspond.
    ///
    /// # Errors
    /// - [`PeerStoreError::Hex`] if the key is not valid hex or is not exactly
    ///   32 bytes.
    /// - [`PeerStoreError::IdKeyMismatch`] if the key does not derive to
    ///   `peer_id`.
    pub fn new_validated(
        peer_id: PeerId,
        public_key_hex: String,
        display_name: String,
    ) -> Result<Self, PeerStoreError> {
        let peer = Self::new(peer_id, public_key_hex, display_name);
        peer.validate()?;
        Ok(peer)
    }

    /// Validate that `public_key_hex` decodes to exactly 32 bytes and that the
    /// derived [`PeerId`] matches `peer_id`.
    ///
    /// Shared by [`Self::new_validated`] and by the store's load path.
    pub(crate) fn validate(&self) -> Result<(), PeerStoreError> {
        let bytes = hex::decode(&self.public_key_hex)
            .map_err(|e| PeerStoreError::Hex(format!("public_key_hex: {e}")))?;
        let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            PeerStoreError::Hex(format!("expected 32-byte key, got {} bytes", bytes.len()))
        })?;
        if PeerId::from_public_key_bytes(&key) != self.peer_id {
            return Err(PeerStoreError::IdKeyMismatch(self.peer_id.to_hex()));
        }
        Ok(())
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_peer_toml_round_trip_preserves_fields() {
        let peer = TrustedPeer {
            peer_id: PeerId::from_public_key_bytes(&[7u8; 32]),
            public_key_hex: "0".repeat(64),
            display_name: "lab-mac".into(),
            trust: TrustLevel::Observer,
            paired_at: 1_700_000_000,
            last_seen_at: Some(1_700_010_000),
            note: "co-located in the LAN".into(),
        };
        let serialised = toml::to_string(&peer).expect("toml serialise");
        let parsed: TrustedPeer = toml::from_str(&serialised).expect("toml deserialise");
        assert_eq!(parsed, peer);
    }

    #[test]
    fn trust_level_kebab_form_round_trips_via_json() {
        // toml requires a top-level table so we use JSON to verify the
        // kebab-case wire form directly.
        let s = serde_json::to_string(&TrustLevel::Revoked).expect("serialise");
        assert_eq!(s, "\"revoked\"");
        let parsed: TrustLevel = serde_json::from_str(&s).expect("deserialise");
        assert_eq!(parsed, TrustLevel::Revoked);
    }

    #[test]
    fn new_sets_trusted_level_and_no_last_seen() {
        let p = TrustedPeer::new(
            PeerId::from_public_key_bytes(&[1u8; 32]),
            "ab".repeat(32),
            "lap".into(),
        );
        assert_eq!(p.trust, TrustLevel::Trusted);
        assert!(p.last_seen_at.is_none());
        assert!(p.note.is_empty());
    }

    #[test]
    fn new_validated_accepts_matching_pair() {
        let key = [3u8; 32];
        let id = PeerId::from_public_key_bytes(&key);
        let p = TrustedPeer::new_validated(id, hex::encode(key), "ok".into())
            .expect("matching pair should validate");
        assert_eq!(p.peer_id, id);
        assert_eq!(p.trust, TrustLevel::Trusted);
    }

    #[test]
    fn new_validated_rejects_mismatched_id_and_key() {
        let key = [1u8; 32];
        // Derive an id from a *different* key so it cannot match.
        let wrong_id = PeerId::from_public_key_bytes(&[2u8; 32]);
        let res = TrustedPeer::new_validated(wrong_id, hex::encode(key), "bad".into());
        assert!(matches!(res, Err(PeerStoreError::IdKeyMismatch(_))));
    }

    #[test]
    fn new_validated_rejects_wrong_length_key() {
        let id = PeerId::from_public_key_bytes(&[4u8; 32]);
        // 16-byte key -> not 32 bytes.
        let res = TrustedPeer::new_validated(id, hex::encode([4u8; 16]), "short".into());
        assert!(matches!(res, Err(PeerStoreError::Hex(_))));
    }

    #[test]
    fn new_validated_rejects_non_hex_key() {
        let id = PeerId::from_public_key_bytes(&[5u8; 32]);
        let res = TrustedPeer::new_validated(id, "nothex!!".into(), "bad".into());
        assert!(matches!(res, Err(PeerStoreError::Hex(_))));
    }
}
