use crate::{
    errors::PeerStoreError,
    peer::{TrustLevel, TrustedPeer},
};
use entangle_types::peer_id::PeerId;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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
        let map = load_map(&path)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(map)),
            path: Some(path),
        })
    }

    /// Add or replace a peer (last-write-wins on `peer_id` collision).
    pub fn add(&self, peer: TrustedPeer) -> Result<(), PeerStoreError> {
        self.locked_mutate(|map| {
            map.insert(peer.peer_id, peer);
            Ok(())
        })
    }

    /// Remove a peer by id.  Returns the removed entry, if any.
    pub fn remove(&self, peer_id: &PeerId) -> Result<Option<TrustedPeer>, PeerStoreError> {
        self.locked_mutate(|map| Ok(map.remove(peer_id)))
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
        self.locked_mutate(|map| {
            let entry = map
                .get_mut(peer_id)
                .ok_or_else(|| PeerStoreError::NotFound(peer_id.to_hex()))?;
            entry.trust = TrustLevel::Revoked;
            Ok(())
        })
    }

    /// Update `last_seen_at` for `peer_id` to the current Unix second.
    ///
    /// No-ops (without error) if the peer is not in the store.
    pub fn touch_last_seen(&self, peer_id: &PeerId) -> Result<(), PeerStoreError> {
        self.locked_mutate(|map| {
            if let Some(entry) = map.get_mut(peer_id) {
                entry.last_seen_at = Some(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                );
            }
            Ok(())
        })
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Run a read-modify-write against the in-memory map and persist it.
    ///
    /// For persistent stores this holds an advisory exclusive [`FileLock`]
    /// across the whole operation and re-loads the file from disk under that
    /// lock, so concurrent CLI invocations serialize and cannot clobber each
    /// other's changes (each `save` rewrites the whole file from the snapshot).
    /// For in-memory stores it simply mutates the map.
    fn locked_mutate<F, R>(&self, f: F) -> Result<R, PeerStoreError>
    where
        F: FnOnce(&mut HashMap<PeerId, TrustedPeer>) -> Result<R, PeerStoreError>,
    {
        let Some(path) = &self.path else {
            let mut map = self.inner.write();
            return f(&mut map);
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // Serialize concurrent writers; released when `_lock` drops.
        let _lock = FileLock::acquire(path)?;
        let mut map = self.inner.write();
        // Refresh from disk under the lock so we don't overwrite changes made
        // by another process since we last read.
        *map = load_map(path)?;
        let result = f(&mut map)?;
        save_map(path, &map)?;
        Ok(result)
    }
}

// ----------------------------------------------------------------------
// Free helpers: load, save, atomic write, advisory lock
// ----------------------------------------------------------------------

/// Load and validate the on-disk allowlist.
///
/// A missing file yields an empty map. Entries whose `public_key_hex` does not
/// decode to a 32-byte key that derives to their recorded `peer_id` are skipped
/// with a warning rather than failing the whole load, so a single corrupt entry
/// cannot block daemon startup. Malformed TOML still surfaces as
/// [`PeerStoreError::Parse`].
fn load_map(path: &Path) -> Result<HashMap<PeerId, TrustedPeer>, PeerStoreError> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let s = std::fs::read_to_string(path)?;
    let parsed: DiskFormat = toml::from_str(&s)?;
    let mut map = HashMap::with_capacity(parsed.peers.len());
    for peer in parsed.peers {
        if let Err(e) = peer.validate() {
            eprintln!(
                "entangle-peers: skipping peer {} with invalid id/key: {e}",
                peer.peer_id.to_hex()
            );
            continue;
        }
        map.insert(peer.peer_id, peer);
    }
    Ok(map)
}

/// Serialize `map` to TOML and write it durably over `path`.
fn save_map(path: &Path, map: &HashMap<PeerId, TrustedPeer>) -> Result<(), PeerStoreError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut peers: Vec<_> = map.values().cloned().collect();
    // Deterministic ordering for stable diffs.
    peers.sort_by_key(|p| p.peer_id.to_hex());
    let disk = DiskFormat { peers };
    let s = toml::to_string(&disk)?;
    write_atomic(path, s.as_bytes())?;
    Ok(())
}

/// Durably and atomically replace `path` with `contents`.
///
/// Writes to a uniquely named sibling temp file (mode `0600` at creation),
/// `fsync`s it, `rename`s it over the target, then best-effort `fsync`s the
/// parent directory. A crash before the rename leaves the previous file intact;
/// on any error the temp file is removed. The temp name incorporates the pid, a
/// nanosecond timestamp and a counter so a stale temp left by a crashed process
/// (even after PID reuse) never collides with a fresh write.
fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("peers.toml");
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{stem}.tmp.{pid}.{nanos}.{seq}"));

    let attempt = || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    };

    match attempt() {
        Ok(()) => {
            // Best-effort: fsync the directory so the rename itself is durable.
            if let Ok(dir_file) = std::fs::File::open(dir) {
                let _ = dir_file.sync_all();
            }
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Path of the advisory lock file that sits beside the allowlist.
fn lock_path_for(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}

/// An advisory exclusive `flock` on the allowlist's sibling lock file.
///
/// The lock is advisory (only cooperating `PeerStore` writers honor it) and is
/// released automatically when the handle drops or the process exits, so it does
/// not suffer the stale-lock problem of `O_EXCL` lockfiles.
struct FileLock {
    _file: std::fs::File,
}

impl FileLock {
    fn acquire(target: &Path) -> Result<Self, PeerStoreError> {
        let lock_path = lock_path_for(target);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
            .map_err(std::io::Error::from)?;
        Ok(Self { _file: file })
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

    #[test]
    fn truncated_toml_is_parse_error_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.toml");

        // Serialize one valid peer, then keep only the first half — this lands
        // mid-record and is no longer valid TOML.
        let good = make_peer(7, "good");
        let full = toml::to_string(&DiskFormat { peers: vec![good] }).unwrap();
        let truncated = &full[..full.len() / 2];
        std::fs::write(&path, truncated).unwrap();

        let res = PeerStore::open(&path);
        assert!(matches!(res, Err(PeerStoreError::Parse(_))));
    }

    #[test]
    fn saved_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.toml");
        let store = PeerStore::open(&path).unwrap();
        store.add(make_peer(5, "erin")).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }

    #[test]
    fn crash_between_temp_write_and_rename_preserves_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.toml");

        // Establish a good previous version.
        {
            let store = PeerStore::open(&path).unwrap();
            store.add(make_peer(1, "alice")).unwrap();
        }
        let before = std::fs::read_to_string(&path).unwrap();

        // Simulate a process that crashed after writing its temp file but
        // before renaming it over the target: a stray temp with garbage.
        let stray = dir.path().join(".peers.toml.tmp.99999.123456789.0");
        std::fs::write(&stray, "this is [ not valid toml").unwrap();

        // The previous file is untouched and still parses to the same content.
        assert_eq!(before, std::fs::read_to_string(&path).unwrap());
        let store = PeerStore::open(&path).unwrap();
        assert_eq!(store.len(), 1);

        // A subsequent save is NOT blocked by the leftover stale temp file
        // (unique temp names never collide with a stray one).
        store.add(make_peer(2, "bob")).unwrap();
        assert_eq!(PeerStore::open(&path).unwrap().len(), 2);
        assert!(stray.exists(), "stray temp is left untouched, just ignored");
    }

    #[test]
    fn stale_temp_file_does_not_block_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.toml");

        // Pre-seed a leftover temp file from a hypothetical crashed writer.
        let stale = dir.path().join(".peers.toml.tmp.4242.7.0");
        std::fs::write(&stale, "leftover").unwrap();

        let store = PeerStore::open(&path).unwrap();
        store.add(make_peer(3, "carol")).unwrap();
        assert!(path.exists());
        assert_eq!(PeerStore::open(&path).unwrap().len(), 1);
    }

    #[test]
    fn open_skips_peer_with_mismatched_id_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.toml");

        // `good` has a matching id/key; `bad` records a key that derives to a
        // different id. Build the file through the real serializer (PeerId is
        // stored as a byte array on disk, not hex).
        let good = make_peer(7, "good");
        let bad = TrustedPeer::new(
            PeerId::from_public_key_bytes(&[9u8; 32]),
            hex::encode([8u8; 32]),
            "bad".into(),
        );
        let good_id = good.peer_id;
        let bad_id = bad.peer_id;
        let contents = toml::to_string(&DiskFormat {
            peers: vec![good, bad],
        })
        .unwrap();
        std::fs::write(&path, contents).unwrap();

        let store = PeerStore::open(&path).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.get(&good_id).is_some());
        assert!(store.get(&bad_id).is_none());
    }

    #[test]
    fn concurrent_writers_do_not_clobber() {
        // Two stores backed by the same file, writing different peers. Because
        // each mutation re-reads under the advisory lock, both survive.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.toml");

        let a = PeerStore::open(&path).unwrap();
        let b = PeerStore::open(&path).unwrap();
        a.add(make_peer(1, "a")).unwrap();
        b.add(make_peer(2, "b")).unwrap();

        assert_eq!(PeerStore::open(&path).unwrap().len(), 2);
    }
}
