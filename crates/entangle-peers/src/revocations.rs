//! The local set of revoked capability-token ids (spec §6.5: revocation is
//! local; there is no revocation gossip).
//!
//! `entangle peers remove` (and `entangle mesh untrust` / `mesh revoke`)
//! copies the revocation ids of the `mesh.peer` token this node issued to
//! the peer into this set, so a token handed out while pairing stays dead
//! even if the peer is later re-added to the allowlist by hand. Re-pairing
//! issues a new token (and revokes the one it supersedes).
//!
//! # Persistence
//!
//! `~/.entangle/revoked-tokens.toml`, written atomically with mode `0600`
//! under the same advisory lock discipline as `peers.toml`:
//!
//! ```toml
//! [[revoked]]
//! id = "<hex revocation id>"
//! peer_id = "<hex peer id the token was issued to>"
//! revoked_at = 1735689600
//! reason = "peers remove"
//! ```
//!
//! A reader re-checks the file (path, inode, size, modification time) on
//! every query and reloads it when it changed, so a daemon sees a CLI
//! revocation at once, without a restart. A file that exists but cannot be
//! read or parsed is an **error** — callers that gate on it refuse every
//! token rather than treat it as empty.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use entangle_types::peer_id::PeerId;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::errors::PeerStoreError;
use crate::peer::{TrustLevel, TrustedPeer};
use crate::store::{write_atomic, FileLock, PeerStore};

/// File name of the revocation set inside `~/.entangle/`.
pub const REVOCATIONS_FILE: &str = "revoked-tokens.toml";

/// One revoked token id and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedToken {
    /// Hex of the revocation id (a biscuit block signature).
    pub id: String,
    /// Hex peer id the token was issued to.
    pub peer_id: String,
    /// Unix seconds.
    pub revoked_at: u64,
    /// The operation that revoked it (`peers remove`, `re-paired`, ...).
    #[serde(default)]
    pub reason: String,
}

#[derive(Default, Serialize, Deserialize)]
struct DiskFormat {
    #[serde(default, rename = "revoked")]
    entries: Vec<RevokedToken>,
}

/// What identifies one version of the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    inode: u64,
    len: u64,
    modified: Option<SystemTime>,
}

#[derive(Default)]
struct Cache {
    /// `None`: not loaded yet, or the file did not exist when last checked.
    stamp: Option<Stamp>,
    entries: Vec<RevokedToken>,
    ids: HashSet<Vec<u8>>,
}

/// The persisted revocation set. Clone is not provided: share it in an
/// `Arc`.
pub struct RevocationStore {
    path: Option<PathBuf>,
    cache: RwLock<Cache>,
}

impl std::fmt::Debug for RevocationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationStore")
            .field("path", &self.path)
            .field("revoked", &self.cache.read().ids.len())
            .finish()
    }
}

impl Default for RevocationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationStore {
    /// An in-memory set (tests).
    pub fn new() -> Self {
        Self {
            path: None,
            cache: RwLock::new(Cache::default()),
        }
    }

    /// The set persisted at `path` (created on the first revocation). Fails
    /// if the file exists but cannot be read or parsed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PeerStoreError> {
        let store = Self {
            path: Some(path.as_ref().to_path_buf()),
            cache: RwLock::new(Cache::default()),
        };
        store.refresh()?;
        Ok(store)
    }

    /// The set persisted at `path`, loaded lazily: nothing is read until the
    /// first query, and a file that cannot be read then makes that query
    /// (and every one after it, until the file is fixed) an error. For a
    /// long-running reader that must start even when the file is damaged and
    /// fail closed per query instead.
    pub fn at(path: impl AsRef<Path>) -> Self {
        Self {
            path: Some(path.as_ref().to_path_buf()),
            cache: RwLock::new(Cache::default()),
        }
    }

    /// The backing file, if persistent.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Add `ids` (raw revocation ids of a token issued to `peer`) to the
    /// set, persisting it. Returns how many were not already revoked.
    pub fn revoke(
        &self,
        ids: &[Vec<u8>],
        peer: &PeerId,
        reason: &str,
    ) -> Result<usize, PeerStoreError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let add = |entries: &mut Vec<RevokedToken>| {
            let mut known: HashSet<String> = entries.iter().map(|e| e.id.clone()).collect();
            let mut added = 0;
            for id in ids {
                let hex_id = hex::encode(id);
                if known.insert(hex_id.clone()) {
                    entries.push(RevokedToken {
                        id: hex_id,
                        peer_id: peer.to_hex(),
                        revoked_at: now,
                        reason: reason.to_owned(),
                    });
                    added += 1;
                }
            }
            added
        };
        let Some(path) = &self.path else {
            let mut cache = self.cache.write();
            let added = add(&mut cache.entries);
            cache.ids.extend(ids.iter().cloned());
            return Ok(added);
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let _lock = FileLock::acquire(path)?;
        let mut entries = read_file(path)?.unwrap_or_default();
        let added = add(&mut entries);
        if added > 0 {
            let text = toml::to_string(&DiskFormat { entries })?;
            write_atomic(path, text.as_bytes())?;
        }
        drop(_lock);
        self.refresh()?;
        Ok(added)
    }

    /// Whether any of `ids` is revoked, re-reading the file if it changed.
    pub fn any_revoked(&self, ids: &[Vec<u8>]) -> Result<bool, PeerStoreError> {
        self.refresh()?;
        let cache = self.cache.read();
        Ok(ids.iter().any(|id| cache.ids.contains(id)))
    }

    /// Every revoked id, re-reading the file if it changed.
    pub fn list(&self) -> Result<Vec<RevokedToken>, PeerStoreError> {
        self.refresh()?;
        Ok(self.cache.read().entries.clone())
    }

    /// Number of revoked ids.
    pub fn len(&self) -> Result<usize, PeerStoreError> {
        self.refresh()?;
        Ok(self.cache.read().ids.len())
    }

    /// Whether nothing is revoked.
    pub fn is_empty(&self) -> Result<bool, PeerStoreError> {
        Ok(self.len()? == 0)
    }

    /// Reload the cache when the file changed (or appeared, or vanished).
    fn refresh(&self) -> Result<(), PeerStoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let stamp = match std::fs::metadata(path) {
            Ok(meta) => {
                use std::os::unix::fs::MetadataExt as _;
                Some(Stamp {
                    inode: meta.ino(),
                    len: meta.len(),
                    modified: meta.modified().ok(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        if stamp.is_some() && self.cache.read().stamp == stamp {
            return Ok(());
        }
        let entries = read_file(path)?.unwrap_or_default();
        let mut ids = HashSet::with_capacity(entries.len());
        for e in &entries {
            let id = hex::decode(&e.id)
                .map_err(|err| PeerStoreError::Hex(format!("revoked id {:?}: {err}", e.id)))?;
            ids.insert(id);
        }
        *self.cache.write() = Cache {
            stamp,
            entries,
            ids,
        };
        Ok(())
    }
}

/// The parsed file, `None` when it does not exist.
fn read_file(path: &Path) -> Result<Option<Vec<RevokedToken>>, PeerStoreError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(toml::from_str::<DiskFormat>(&text)?.entries)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

impl PeerStore {
    /// `entangle peers remove`: revoke the token this node issued to
    /// `peer_id` (first, so a failure leaves the peer in place), then drop
    /// the peer. Returns the removed record.
    pub fn remove_revoking(
        &self,
        peer_id: &PeerId,
        revocations: &RevocationStore,
    ) -> Result<Option<TrustedPeer>, PeerStoreError> {
        let current = self.reload_one(peer_id)?;
        if let Some(peer) = &current {
            revocations.revoke(&peer.issued_revocation_ids(), peer_id, "peers remove")?;
        }
        self.remove(peer_id)
    }

    /// `entangle mesh revoke`: revoke the issued token, then mark the peer
    /// [`TrustLevel::Revoked`].
    pub fn revoke_revoking(
        &self,
        peer_id: &PeerId,
        revocations: &RevocationStore,
    ) -> Result<(), PeerStoreError> {
        let peer = self
            .reload_one(peer_id)?
            .ok_or_else(|| PeerStoreError::NotFound(peer_id.to_hex()))?;
        revocations.revoke(&peer.issued_revocation_ids(), peer_id, "peer revoked")?;
        self.revoke(peer_id)
    }

    /// Store a freshly paired peer. When a record for it already exists, the
    /// token this node issued earlier is superseded and revoked (so one
    /// peer never holds two live tokens from this node).
    pub fn add_paired(
        &self,
        peer: TrustedPeer,
        revocations: &RevocationStore,
    ) -> Result<(), PeerStoreError> {
        if let Some(old) = self.reload_one(&peer.peer_id)? {
            let fresh: HashSet<String> = peer.issued_token_revocation_ids.iter().cloned().collect();
            let stale: Vec<Vec<u8>> = old
                .issued_revocation_ids()
                .into_iter()
                .filter(|id| !fresh.contains(&hex::encode(id)))
                .collect();
            revocations.revoke(&stale, &peer.peer_id, "re-paired")?;
        }
        self.add(peer)
    }

    /// `entangle mesh trust`: add a peer by hand. An existing record keeps
    /// its token fields (the token it presents, and the issued token's
    /// revocation ids) unless `peer` carries its own, so re-trusting a
    /// paired peer never loses the ability to revoke what it was issued.
    pub fn add_keeping_tokens(&self, mut peer: TrustedPeer) -> Result<(), PeerStoreError> {
        if let Some(old) = self.reload_one(&peer.peer_id)? {
            if peer.capability_token.is_none() && old.trust != TrustLevel::Revoked {
                peer.capability_token = old.capability_token;
            }
            if peer.issued_token_revocation_ids.is_empty() {
                peer.issued_token_revocation_ids = old.issued_token_revocation_ids;
            }
        }
        self.add(peer)
    }

    /// The current on-disk record of `peer_id` (in-memory for a
    /// non-persistent store).
    fn reload_one(&self, peer_id: &PeerId) -> Result<Option<TrustedPeer>, PeerStoreError> {
        match self.path() {
            Some(path) => Ok(PeerStore::open(path)?.get(peer_id)),
            None => Ok(self.get(peer_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> TrustedPeer {
        let key = [seed; 32];
        TrustedPeer::new(
            PeerId::from_public_key_bytes(&key),
            hex::encode(key),
            "p".into(),
        )
    }

    #[test]
    fn revocations_persist_with_0600_and_are_seen_by_other_readers() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(REVOCATIONS_FILE);
        let writer = RevocationStore::open(&path).unwrap();
        let reader = RevocationStore::open(&path).unwrap();
        assert!(!reader.any_revoked(&[vec![1, 2]]).unwrap());

        let p = PeerId::from_public_key_bytes(&[1; 32]);
        assert_eq!(
            writer.revoke(&[vec![1, 2], vec![3]], &p, "test").unwrap(),
            2
        );
        assert_eq!(
            writer.revoke(&[vec![1, 2]], &p, "test").unwrap(),
            0,
            "idempotent"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // The other handle sees the change without being told.
        assert!(reader.any_revoked(&[vec![9], vec![3]]).unwrap());
        assert_eq!(reader.len().unwrap(), 2);
        assert_eq!(
            RevocationStore::open(&path).unwrap().list().unwrap()[0].peer_id,
            p.to_hex()
        );
    }

    #[test]
    fn an_unreadable_set_is_an_error_not_an_empty_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(REVOCATIONS_FILE);
        let store = RevocationStore::open(&path).unwrap();
        std::fs::write(&path, "[[revoked]\nnot toml").unwrap();
        assert!(store.any_revoked(&[vec![1]]).is_err());
        std::fs::write(
            &path,
            "[[revoked]]\nid = \"zz\"\npeer_id = \"\"\nrevoked_at = 0\n",
        )
        .unwrap();
        assert!(
            store.any_revoked(&[vec![1]]).is_err(),
            "bad hex fails closed"
        );
        assert!(RevocationStore::open(&path).is_err());
        let lazy = RevocationStore::at(&path);
        assert!(
            lazy.any_revoked(&[vec![1]]).is_err(),
            "a lazy reader fails per query"
        );
        std::fs::remove_file(&path).unwrap();
        assert!(
            !lazy.any_revoked(&[vec![1]]).unwrap(),
            "and recovers once the file is gone"
        );
    }

    #[test]
    fn removing_a_peer_revokes_its_issued_token_and_re_adding_does_not_revive_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(dir.path().join("peers.toml")).unwrap();
        let revs = RevocationStore::open(dir.path().join(REVOCATIONS_FILE)).unwrap();
        let p = peer(4).with_tokens(Some(&[0xaa]), &[vec![7, 7]]);
        let id = p.peer_id;
        store.add_paired(p, &revs).unwrap();
        assert!(!revs.any_revoked(&[vec![7, 7]]).unwrap());

        let removed = store.remove_revoking(&id, &revs).unwrap();
        assert!(removed.is_some());
        assert!(store.get(&id).is_none());
        assert!(revs.any_revoked(&[vec![7, 7]]).unwrap());

        // Manual re-add (`mesh trust`): the peer is allowlisted again, the
        // old token stays revoked.
        store.add_keeping_tokens(peer(4)).unwrap();
        assert!(store.get(&id).is_some());
        assert!(revs.any_revoked(&[vec![7, 7]]).unwrap());
    }

    #[test]
    fn revoking_a_peer_revokes_its_issued_token() {
        let store = PeerStore::new();
        let revs = RevocationStore::new();
        let p = peer(5).with_tokens(None, &[vec![1]]);
        let id = p.peer_id;
        store.add(p).unwrap();
        store.revoke_revoking(&id, &revs).unwrap();
        assert_eq!(store.get(&id).unwrap().trust, TrustLevel::Revoked);
        assert!(revs.any_revoked(&[vec![1]]).unwrap());
        assert!(matches!(
            store.revoke_revoking(&PeerId::from_public_key_bytes(&[9; 32]), &revs),
            Err(PeerStoreError::NotFound(_))
        ));
    }

    #[test]
    fn re_pairing_supersedes_and_revokes_the_old_issued_token() {
        let store = PeerStore::new();
        let revs = RevocationStore::new();
        store
            .add_paired(peer(6).with_tokens(Some(&[1]), &[vec![10]]), &revs)
            .unwrap();
        store
            .add_paired(peer(6).with_tokens(Some(&[2]), &[vec![20]]), &revs)
            .unwrap();
        assert!(revs.any_revoked(&[vec![10]]).unwrap());
        assert!(!revs.any_revoked(&[vec![20]]).unwrap());
        let id = peer(6).peer_id;
        assert_eq!(
            store.get(&id).unwrap().capability_token_bytes(),
            Some(vec![2])
        );
    }

    #[test]
    fn re_trusting_by_hand_keeps_the_token_fields() {
        let store = PeerStore::new();
        let p = peer(8).with_tokens(Some(&[5]), &[vec![6]]);
        let id = p.peer_id;
        store.add(p).unwrap();
        let mut by_hand = peer(8);
        by_hand.display_name = "renamed".into();
        store.add_keeping_tokens(by_hand).unwrap();
        let got = store.get(&id).unwrap();
        assert_eq!(got.display_name, "renamed");
        assert_eq!(got.capability_token_bytes(), Some(vec![5]));
        assert_eq!(got.issued_revocation_ids(), vec![vec![6]]);
    }
}
