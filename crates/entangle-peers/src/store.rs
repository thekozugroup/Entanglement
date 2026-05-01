use crate::{
    errors::PeerStoreError,
    peer::{TrustLevel, TrustedPeer},
};
use entangle_types::peer_id::PeerId;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

/// On-disk TOML envelope.  Uses `[[peer]]` array-of-tables for readability.
#[derive(Default, Serialize, Deserialize)]
struct DiskFormat {
    #[serde(default, rename = "peer")]
    peers: Vec<TrustedPeer>,
}

/// Thread-safe, optionally-persistent peer allowlist.
///
/// Clone is cheap — the inner map is `Arc`-wrapped.
#[derive(Clone)]
pub struct PeerStore {
    inner: Arc<RwLock<HashMap<PeerId, TrustedPeer>>>,
    /// `None` = in-memory only (useful in tests).
    path: Option<PathBuf>,
}

impl PeerStore {
    /// Create an in-memory-only store (no persistence).
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            path: None,
        }
    }

    /// Open (or create) the TOML file at `path`.
    ///
    /// If the file does not yet exist the store starts empty and will create
    /// it (including parent directories) on the first write.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PeerStoreError> {
        let path = path.as_ref().to_path_buf();
        let map = if path.exists() {
            let s = std::fs::read_to_string(&path)?;
            let parsed: DiskFormat = toml::from_str(&s)?;
            parsed.peers.into_iter().map(|p| (p.peer_id, p)).collect()
        } else {
            HashMap::new()
        };
        Ok(Self {
            inner: Arc::new(RwLock::new(map)),
            path: Some(path),
        })
    }

    /// Add or replace a peer (last-write-wins on `peer_id` collision).
    pub fn add(&self, peer: TrustedPeer) -> Result<(), PeerStoreError> {
        self.inner.write().insert(peer.peer_id, peer);
        self.save()
    }

    /// Remove a peer by id.  Returns the removed entry, if any.
    pub fn remove(&self, peer_id: &PeerId) -> Result<Option<TrustedPeer>, PeerStoreError> {
        let removed = self.inner.write().remove(peer_id);
        if removed.is_some() {
            self.save()?;
        }
        Ok(removed)
    }

    /// Retrieve a peer by id.
    pub fn get(&self, peer_id: &PeerId) -> Option<TrustedPeer> {
        self.inner.read().get(peer_id).cloned()
    }

    /// Return all peers in an unspecified order.
    pub fn list(&self) -> Vec<TrustedPeer> {
        self.inner.read().values().cloned().collect()
    }

    /// `true` when no peers are present.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Number of peers in the store.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Flip a peer's trust level to [`TrustLevel::Revoked`].
    pub fn revoke(&self, peer_id: &PeerId) -> Result<(), PeerStoreError> {
        {
            let mut map = self.inner.write();
            let entry = map
                .get_mut(peer_id)
                .ok_or_else(|| PeerStoreError::NotFound(peer_id.to_hex()))?;
            entry.trust = TrustLevel::Revoked;
        }
        self.save()
    }

    /// Update `last_seen_at` for `peer_id` to the current Unix second.
    ///
    /// No-ops (without error) if the peer is not in the store.
    pub fn touch_last_seen(&self, peer_id: &PeerId) -> Result<(), PeerStoreError> {
        {
            let mut map = self.inner.write();
            if let Some(entry) = map.get_mut(peer_id) {
                entry.last_seen_at = Some(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                );
            }
        }
        self.save()
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    fn save(&self) -> Result<(), PeerStoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let snap = self.inner.read();
        let mut peers: Vec<_> = snap.values().cloned().collect();
        // Deterministic ordering for stable diffs.
        peers.sort_by(|a, b| a.peer_id.to_hex().cmp(&b.peer_id.to_hex()));
        let disk = DiskFormat { peers };
        let s = toml::to_string(&disk)?;
        std::fs::write(path, s)?;
        Ok(())
    }
}

impl Default for PeerStore {
    fn default() -> Self {
        Self::new()
    }
}

// ======================================================================
// Tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::TrustedPeer;
    use entangle_types::peer_id::PeerId;

    fn make_peer(seed: u8, name: &str) -> TrustedPeer {
        let key = [seed; 32];
        let peer_id = PeerId::from_public_key_bytes(&key);
        TrustedPeer::new(peer_id, hex::encode(key), name.to_string())
    }

    // ------------------------------------------------------------------

    #[test]
    fn empty_store_is_empty() {
        let store = PeerStore::new();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn add_and_get() {
        let store = PeerStore::new();
        let peer = make_peer(1, "alice");
        let id = peer.peer_id;
        store.add(peer.clone()).unwrap();
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
        let got = store.get(&id).expect("peer should be present");
        assert_eq!(got, peer);
    }

    #[test]
    fn remove_peer() {
        let store = PeerStore::new();
        let peer = make_peer(2, "bob");
        let id = peer.peer_id;
        store.add(peer).unwrap();
        let removed = store.remove(&id).unwrap();
        assert!(removed.is_some());
        assert!(store.is_empty());
        // Removing again returns None (not an error).
        let none = store.remove(&id).unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn revoke_flips_trust_level() {
        let store = PeerStore::new();
        let peer = make_peer(3, "carol");
        let id = peer.peer_id;
        store.add(peer).unwrap();
        store.revoke(&id).unwrap();
        let got = store.get(&id).unwrap();
        assert_eq!(got.trust, TrustLevel::Revoked);
    }

    #[test]
    fn revoke_unknown_peer_errors() {
        let store = PeerStore::new();
        let id = PeerId::from_public_key_bytes(&[9u8; 32]);
        assert!(matches!(
            store.revoke(&id),
            Err(PeerStoreError::NotFound(_))
        ));
    }

    #[test]
    fn round_trip_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.toml");

        // Write 3 peers.
        {
            let store = PeerStore::open(&path).unwrap();
            store.add(make_peer(10, "alpha")).unwrap();
            store.add(make_peer(11, "beta")).unwrap();
            store.add(make_peer(12, "gamma")).unwrap();
            assert_eq!(store.len(), 3);
        }

        // Re-open from disk and verify all 3 are present.
        {
            let store = PeerStore::open(&path).unwrap();
            assert_eq!(store.len(), 3);
            let names: std::collections::HashSet<_> =
                store.list().into_iter().map(|p| p.display_name).collect();
            assert!(names.contains("alpha"));
            assert!(names.contains("beta"));
            assert!(names.contains("gamma"));
        }
    }

    #[test]
    fn touch_last_seen_updates_field() {
        let store = PeerStore::new();
        let peer = make_peer(20, "dave");
        let id = peer.peer_id;
        store.add(peer).unwrap();

        assert!(store.get(&id).unwrap().last_seen_at.is_none());
        store.touch_last_seen(&id).unwrap();
        assert!(store.get(&id).unwrap().last_seen_at.is_some());
    }

    #[test]
    fn add_same_peer_id_overwrites() {
        let store = PeerStore::new();
        let peer_a = make_peer(30, "original");
        let id = peer_a.peer_id;
        store.add(peer_a).unwrap();

        // Same peer_id, different display_name.
        let mut peer_b = make_peer(30, "replacement");
        peer_b.peer_id = id;
        store.add(peer_b).unwrap();

        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&id).unwrap().display_name, "replacement");
    }

    #[test]
    fn open_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dir").join("peers.toml");
        let store = PeerStore::open(&path).unwrap();
        store.add(make_peer(40, "eve")).unwrap();
        assert!(path.exists());
    }
}
