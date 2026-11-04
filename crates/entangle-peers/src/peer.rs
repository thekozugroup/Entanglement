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
    /// Hex of the `mesh.peer` capability token this node **presents** to the
    /// peer: minted by the peer during pairing, rooted at its identity key,
    /// issued to this node (spec §6.3 step 4). `None` for a peer paired
    /// before tokens existed, or added by hand with `entangle mesh trust`;
    /// such a peer refuses this node's requests while it requires tokens
    /// (re-pair with `entangle pair`).
    ///
    /// Optional with a serde default, so `peers.toml` files written before
    /// this field existed still load, and older binaries ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<String>,
    /// Hex revocation ids of the `mesh.peer` token this node **issued** to
    /// the peer while pairing. `entangle peers remove` adds them to the
    /// local revocation set (see [`crate::RevocationStore`]), so re-adding
    /// the peer to the allowlist later does not revive that token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issued_token_revocation_ids: Vec<String>,
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
            capability_token: None,
            issued_token_revocation_ids: Vec::new(),
        }
    }

    /// Record the token exchange of a pairing: `presented` is the token the
    /// peer issued to this node (raw biscuit bytes), `issued` the revocation
    /// ids of the token this node issued to the peer.
    #[must_use]
    pub fn with_tokens(mut self, presented: Option<&[u8]>, issued: &[Vec<u8>]) -> Self {
        self.capability_token = presented.map(hex::encode);
        self.issued_token_revocation_ids = issued.iter().map(hex::encode).collect();
        self
    }

    /// Whether this node holds a token to present to the peer.
    pub fn has_capability_token(&self) -> bool {
        self.capability_token.is_some()
    }

    /// The token to present, decoded. `None` when there is none or it is not
    /// valid hex (a hand-edited file); either way the peer gets no token.
    pub fn capability_token_bytes(&self) -> Option<Vec<u8>> {
        hex::decode(self.capability_token.as_deref()?).ok()
    }

    /// The token to present to this peer and the key it is rooted at (the
    /// peer's own): `None` when the peer is revoked, holds no token, or its
    /// record does not decode.
    pub fn presentable_token(&self) -> Option<(Vec<u8>, [u8; 32])> {
        if self.trust == TrustLevel::Revoked {
            return None;
        }
        Some((self.capability_token_bytes()?, self.public_key_bytes()?))
    }

    /// The revocation ids of the token this node issued, decoded. Entries
    /// that are not valid hex are skipped.
    pub fn issued_revocation_ids(&self) -> Vec<Vec<u8>> {
        self.issued_token_revocation_ids
            .iter()
            .filter_map(|h| hex::decode(h).ok())
            .collect()
    }

    /// The peer's raw Ed25519 public key (`None` if `public_key_hex` is not
    /// 32 hex-encoded bytes).
    pub fn public_key_bytes(&self) -> Option<[u8; 32]> {
        hex::decode(&self.public_key_hex).ok()?.try_into().ok()
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
            capability_token: Some("0a0b".into()),
            issued_token_revocation_ids: vec!["ff".into()],
        };
        let serialised = toml::to_string(&peer).expect("toml serialise");
        let parsed: TrustedPeer = toml::from_str(&serialised).expect("toml deserialise");
        assert_eq!(parsed, peer);
    }

    /// A record written before the token fields existed still loads, and a
    /// record without tokens serializes exactly as before (no new keys), so
    /// older binaries keep reading `peers.toml`.
    #[test]
    fn token_fields_are_optional_both_ways() {
        let old = "peer_id = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]\n\
                   public_key_hex = \"00\"\ndisplay_name = \"x\"\ntrust = \"trusted\"\n\
                   paired_at = 1\n";
        let parsed: TrustedPeer = toml::from_str(old).expect("pre-token record loads");
        assert!(parsed.capability_token.is_none());
        assert!(parsed.issued_token_revocation_ids.is_empty());
        let text = toml::to_string(&parsed).unwrap();
        assert!(!text.contains("capability_token"), "{text}");
        assert!(!text.contains("issued_token_revocation_ids"), "{text}");

        let with = parsed.with_tokens(Some(&[1, 2]), &[vec![3], vec![4]]);
        assert_eq!(with.capability_token_bytes(), Some(vec![1, 2]));
        assert_eq!(with.issued_revocation_ids(), vec![vec![3], vec![4]]);
        assert!(with.has_capability_token());
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
