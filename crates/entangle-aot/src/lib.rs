//! On-disk AOT compilation cache for WebAssembly components (spec §2.1
//! "plugin AOT cache", §3.1 "AOT via Cranelift", §3.3 "pre-compile", §9.5
//! "AOT cache GC").
//!
//! Compiling a component with Cranelift is the expensive part of a plugin
//! load. [`AotCache::load_or_compile`] keeps the compiled artifact
//! ([`Component::serialize`]) on disk, keyed by
//!
//! - BLAKE3 of the component bytes,
//! - the Wasmtime version ([`WASMTIME_VERSION`]),
//! - [`Engine::precompile_compatibility_hash`] — the target triple, compiler
//!   flags, tunables and wasm features: everything about the engine's
//!   configuration that affects code generation,
//! - the host architecture / OS,
//!
//! so a later load of the same bytes by an equally configured engine skips
//! compilation.
//!
//! # Trust
//!
//! Loading an artifact ([`Component::deserialize`]) is `unsafe`: Wasmtime
//! only lightly validates it, so arbitrary bytes could be arbitrary native
//! code. The cache therefore only loads entries **this node wrote**:
//!
//! - the cache directory is `0700` and every file in it `0600`, owned by the
//!   daemon's user, and is refused (the cache is disabled,
//!   `ENTANGLE-E0786`) when it is not;
//! - every entry has a sidecar (`<key>.meta`) holding a keyed BLAKE3 MAC over
//!   the sidecar's header and the artifact bytes, under a per-node cache key
//!   (`cache.key`, 32 random bytes, `0600`) that never leaves the node;
//! - the artifact is read into memory, its MAC verified over exactly those
//!   bytes, and only then deserialized from memory — a file changed after the
//!   check can never reach Wasmtime.
//!
//! Anything that does not check out — wrong owner or mode, a symbolic link,
//! a malformed sidecar, another Wasmtime version, a MAC mismatch, a
//! deserialize error — deletes the entry, is counted
//! (`entangle_aot_cache_rejections_total{reason}`), logged
//! (`ENTANGLE-E0785`) and answered by compiling normally. A bad entry never
//! fails a load and never crashes the daemon.
//!
//! # Garbage collection
//!
//! [`AotCache::gc`] (run by the daemon's maintenance loop) removes entries
//! not used for [`AotCacheConfig::max_unused`], then the least recently used
//! ones until the cache is under [`AotCacheConfig::max_bytes`], and partial
//! writes left behind by a crash.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use entangle_observability::{catalog, Registry};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use wasmtime::component::Component;
use wasmtime::Engine;

/// The Wasmtime version entries are written for. Part of every entry key
/// and recorded in every sidecar; an entry from another version is a miss
/// (and Wasmtime itself refuses such artifacts deterministically). Kept in
/// step with `Cargo.lock` by this crate's tests.
pub const WASMTIME_VERSION: &str = "43.0.2";

/// First line of every sidecar: format name and version.
const META_MAGIC: &str = "entangle-aot-cache 1";
/// Name of the per-node MAC key file inside the cache directory.
const KEY_FILE: &str = "cache.key";
/// Suffix of an artifact file.
const ARTIFACT_EXT: &str = "cwasm";
/// Suffix of a sidecar file.
const META_EXT: &str = "meta";
/// Prefix of a file being written (renamed into place when complete).
const TMP_PREFIX: &str = ".tmp-";
/// A partial write older than this is garbage.
const ORPHAN_AGE: Duration = Duration::from_secs(3600);
/// Upper bound on a sidecar's size.
const MAX_META_BYTES: u64 = 4096;

/// Where the cache lives and how big it may grow.
#[derive(Clone, Debug)]
pub struct AotCacheConfig {
    /// Cache directory, created `0700` when absent.
    pub dir: PathBuf,
    /// Size cap in bytes; GC evicts least recently used entries above it,
    /// and an artifact larger than this is not cached at all.
    pub max_bytes: u64,
    /// GC removes entries not used for this long.
    pub max_unused: Duration,
}

impl AotCacheConfig {
    /// Default size cap: 512 MiB.
    pub const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;
    /// Default unused age: 30 days.
    pub const DEFAULT_MAX_UNUSED: Duration = Duration::from_secs(30 * 24 * 3600);

    /// The defaults for a cache in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            max_bytes: Self::DEFAULT_MAX_BYTES,
            max_unused: Self::DEFAULT_MAX_UNUSED,
        }
    }
}

/// The cache cannot be used at all (the daemon then compiles every
/// component, as without a cache).
#[derive(Debug, thiserror::Error)]
pub enum AotError {
    /// The directory or key file is not private to this user, or could not
    /// be created or read.
    #[error("ENTANGLE-E0786: AOT cache {path} is unusable: {reason}")]
    Unusable {
        /// The offending path.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
}

/// Why an entry was refused (the `reason` label of
/// `entangle_aot_cache_rejections_total`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Wrong owner, group/other mode bits, or not a regular file.
    Permissions,
    /// The sidecar is malformed or does not describe this entry.
    Header,
    /// Written by another Wasmtime version.
    Version,
    /// The keyed MAC does not verify.
    Mac,
    /// Wasmtime refused the artifact.
    Deserialize,
    /// It could not be read.
    Io,
}

impl Rejection {
    /// The metric label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Permissions => "permissions",
            Self::Header => "header",
            Self::Version => "version",
            Self::Mac => "mac",
            Self::Deserialize => "deserialize",
            Self::Io => "io",
        }
    }
}

/// How a [`AotCache::load_or_compile`] call was answered.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Deserialized from a verified entry.
    Hit,
    /// No entry: compiled (and stored).
    Miss,
    /// An entry existed but was refused and deleted: compiled (and stored).
    Rejected(Rejection),
}

/// What one [`AotCache::gc`] pass removed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Entries unused for longer than the configured age.
    pub expired: u64,
    /// Least recently used entries evicted to get under the size cap.
    pub over_cap: u64,
    /// Partial writes and half entries left behind.
    pub orphans: u64,
    /// Bytes the cache holds afterwards.
    pub bytes: u64,
}

/// The on-disk AOT cache (see the crate docs). Cheap to share behind an
/// `Arc`; every method takes `&self`.
pub struct AotCache {
    cfg: AotCacheConfig,
    key: [u8; 32],
    uid: u32,
    metrics: std::sync::OnceLock<Registry>,
    /// Approximate bytes on disk: exact after `open` and each `gc`, then
    /// increased by each store.
    bytes: AtomicU64,
}

impl std::fmt::Debug for AotCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AotCache")
            .field("dir", &self.cfg.dir)
            .field("max_bytes", &self.cfg.max_bytes)
            .field("max_unused", &self.cfg.max_unused)
            .finish_non_exhaustive()
    }
}

impl AotCache {
    /// Open (creating when absent) the cache in `cfg.dir`.
    ///
    /// Refuses ([`AotError::Unusable`]) a directory or key file that is not
    /// owned by this user, is a symbolic link, or is accessible to group or
    /// others: the cache's whole safety argument rests on nobody else being
    /// able to write it.
    pub fn open(cfg: AotCacheConfig) -> Result<Self, AotError> {
        let uid = current_uid();
        ensure_private_dir(&cfg.dir, uid)?;
        let (key, created) = load_or_create_key(&cfg.dir, &cfg.dir.join(KEY_FILE), uid)?;
        let cache = Self {
            cfg,
            key,
            uid,
            metrics: std::sync::OnceLock::new(),
            bytes: AtomicU64::new(0),
        };
        if created {
            // Entries already here were MAC'd under a key that is gone (an
            // unreadable key file regenerated, or one deleted by hand): none
            // can be verified any more, so they are removed now instead of
            // one refusal at a time. Partial writes (another process's, in
            // flight) are left to GC.
            for e in cache.scan() {
                if !e.temp {
                    cache.remove(&e);
                }
            }
        }
        let bytes = cache.scan().iter().map(|e| e.bytes).sum();
        cache.bytes.store(bytes, Ordering::Relaxed);
        Ok(cache)
    }

    /// Record lookups, rejections, evictions and the size in `registry`.
    #[must_use]
    pub fn with_metrics(self, registry: Registry) -> Self {
        self.attach_metrics(registry);
        self
    }

    /// As [`AotCache::with_metrics`], on a shared cache. Only the first
    /// registry attached is used.
    pub fn attach_metrics(&self, registry: Registry) {
        catalog::aot_cache_bytes(&registry, self.bytes.load(Ordering::Relaxed));
        let _ = self.metrics.set(registry);
    }

    /// The configuration in force.
    pub fn config(&self) -> &AotCacheConfig {
        &self.cfg
    }

    /// The entry key for `bytes` compiled by `engine` (hex): the file stem
    /// of its artifact and sidecar.
    pub fn entry_key(engine: &Engine, bytes: &[u8]) -> String {
        let mut engine_hash = Blake3StdHasher(blake3::Hasher::new());
        std::hash::Hash::hash(&engine.precompile_compatibility_hash(), &mut engine_hash);
        let mut h = blake3::Hasher::new_derive_key("entangle aot cache entry key v1");
        h.update(blake3::hash(bytes).as_bytes());
        h.update(WASMTIME_VERSION.as_bytes());
        h.update(&[0]);
        h.update(engine_hash.0.finalize().as_bytes());
        h.update(target().as_bytes());
        hex::encode(h.finalize().as_bytes())
    }

    /// The artifact path of entry `key`.
    pub fn artifact_path(&self, key: &str) -> PathBuf {
        self.cfg.dir.join(format!("{key}.{ARTIFACT_EXT}"))
    }

    /// The sidecar path of entry `key`.
    pub fn meta_path(&self, key: &str) -> PathBuf {
        self.cfg.dir.join(format!("{key}.{META_EXT}"))
    }

    /// The component for `bytes`: from a verified cache entry when there is
    /// one, otherwise compiled with `engine` (and the result stored, best
    /// effort). Only compilation errors are returned; every cache problem
    /// falls back to compiling.
    pub fn load_or_compile(
        &self,
        engine: &Engine,
        bytes: &[u8],
    ) -> wasmtime::Result<(Component, Lookup)> {
        let key = Self::entry_key(engine, bytes);
        let lookup = match self.load(engine, &key) {
            Ok(Some(component)) => {
                self.record_lookup(true);
                return Ok((component, Lookup::Hit));
            }
            Ok(None) => Lookup::Miss,
            Err(reason) => {
                self.reject(&key, reason);
                Lookup::Rejected(reason)
            }
        };
        self.record_lookup(false);
        let component = Component::from_binary(engine, bytes)?;
        match component.serialize() {
            Ok(artifact) => {
                if let Err(e) = self.store(&key, &artifact) {
                    tracing::warn!(error = %e, entry = %key, "AOT cache: could not store a compiled component");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "AOT cache: could not serialize a compiled component")
            }
        }
        Ok((component, lookup))
    }

    /// Remove expired entries, then least recently used ones above the size
    /// cap, then partial writes (see the crate docs). Never fails: an entry
    /// that cannot be removed is left for the next pass.
    pub fn gc(&self) -> GcReport {
        let now = SystemTime::now();
        let mut report = GcReport::default();
        let mut entries = self.scan();
        entries.sort_by_key(|e| e.last_used);
        let mut kept = Vec::new();
        for e in entries {
            if e.orphan {
                if now.duration_since(e.last_used).unwrap_or_default() >= ORPHAN_AGE
                    && self.remove(&e)
                {
                    report.orphans += 1;
                } else {
                    kept.push(e);
                }
            } else if now.duration_since(e.last_used).unwrap_or_default() > self.cfg.max_unused
                && self.remove(&e)
            {
                report.expired += 1;
            } else {
                kept.push(e);
            }
        }
        let mut total: u64 = kept.iter().map(|e| e.bytes).sum();
        // Oldest first: `kept` is still in last-used order.
        for e in &kept {
            if total <= self.cfg.max_bytes {
                break;
            }
            if !e.orphan && self.remove(e) {
                total = total.saturating_sub(e.bytes);
                report.over_cap += 1;
            }
        }
        report.bytes = total;
        self.bytes.store(total, Ordering::Relaxed);
        if let Some(reg) = self.metrics.get() {
            for (reason, n) in [
                ("age", report.expired),
                ("size", report.over_cap),
                ("orphan", report.orphans),
            ] {
                if n > 0 {
                    catalog::aot_cache_evictions(reg, reason, n);
                }
            }
            catalog::aot_cache_bytes(reg, total);
        }
        if report.expired + report.over_cap + report.orphans > 0 {
            tracing::info!(
                expired = report.expired,
                over_cap = report.over_cap,
                orphans = report.orphans,
                bytes = total,
                "AOT cache: garbage collected"
            );
        }
        report
    }

    // ── private ──────────────────────────────────────────────────────────────

    /// `Ok(None)`: no entry. `Err`: an entry that must be refused.
    fn load(&self, engine: &Engine, key: &str) -> Result<Option<Component>, Rejection> {
        let meta_path = self.meta_path(key);
        let mut meta_file = match open_private(&meta_path, self.uid, false) {
            Ok(f) => f,
            Err(OpenError::NotFound) => return Ok(None),
            Err(OpenError::Rejected(r)) => return Err(r),
        };
        let mut meta = String::new();
        (&mut meta_file)
            .take(MAX_META_BYTES)
            .read_to_string(&mut meta)
            .map_err(|_| Rejection::Header)?;
        let header = Header::parse(&meta)?;
        if header.entry != key {
            return Err(Rejection::Header);
        }
        if header.wasmtime != WASMTIME_VERSION || header.target != target() {
            return Err(Rejection::Version);
        }
        if header.length > self.cfg.max_bytes {
            return Err(Rejection::Header);
        }
        let mut artifact_file = match open_private(&self.artifact_path(key), self.uid, false) {
            Ok(f) => f,
            Err(OpenError::NotFound) => return Err(Rejection::Io),
            Err(OpenError::Rejected(r)) => return Err(r),
        };
        let mut artifact = Vec::with_capacity(usize::try_from(header.length).unwrap_or(0));
        (&mut artifact_file)
            .take(header.length.saturating_add(1))
            .read_to_end(&mut artifact)
            .map_err(|_| Rejection::Io)?;
        if artifact.len() as u64 != header.length {
            return Err(Rejection::Header);
        }
        let expected = self.mac(&header.signed_text(), &artifact);
        // `blake3::Hash` compares in constant time.
        if blake3::Hash::from_hex(&header.mac).ok() != Some(expected) {
            return Err(Rejection::Mac);
        }
        let component = deserialize_verified(engine, &artifact).map_err(|e| {
            tracing::debug!(error = %e, "AOT cache: Wasmtime refused a verified entry");
            Rejection::Deserialize
        })?;
        // Last use, for GC: the sidecar's mtime.
        if let Ok(f) = open_private(&meta_path, self.uid, true) {
            let _ = f.set_modified(SystemTime::now());
        }
        Ok(Some(component))
    }

    /// Write entry `key` (artifact first, then sidecar; each to a private
    /// temporary file renamed into place).
    fn store(&self, key: &str, artifact: &[u8]) -> std::io::Result<()> {
        if artifact.len() as u64 > self.cfg.max_bytes {
            return Ok(());
        }
        let header = Header {
            entry: key.to_owned(),
            wasmtime: WASMTIME_VERSION.to_owned(),
            target: target(),
            length: artifact.len() as u64,
            mac: String::new(),
        };
        let mac = self.mac(&header.signed_text(), artifact);
        let meta = format!("{}mac {}\n", header.signed_text(), mac.to_hex());
        write_private(&self.cfg.dir, &self.artifact_path(key), artifact)?;
        write_private(&self.cfg.dir, &self.meta_path(key), meta.as_bytes())?;
        let added = artifact.len() as u64 + meta.len() as u64;
        let total = self.bytes.fetch_add(added, Ordering::Relaxed) + added;
        if let Some(reg) = self.metrics.get() {
            catalog::aot_cache_bytes(reg, total);
        }
        Ok(())
    }

    fn mac(&self, header: &str, artifact: &[u8]) -> blake3::Hash {
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(header.as_bytes());
        h.update(artifact);
        h.finalize()
    }

    fn record_lookup(&self, hit: bool) {
        if let Some(reg) = self.metrics.get() {
            catalog::aot_cache_lookup(reg, hit);
        }
    }

    /// Delete a refused entry and say so.
    fn reject(&self, key: &str, reason: Rejection) {
        let _ = std::fs::remove_file(self.meta_path(key));
        let _ = std::fs::remove_file(self.artifact_path(key));
        tracing::warn!(
            code = "ENTANGLE-E0785",
            entry = %key,
            reason = reason.as_str(),
            "ENTANGLE-E0785: AOT cache entry refused and deleted; compiling instead"
        );
        if let Some(reg) = self.metrics.get() {
            catalog::aot_cache_rejection(reg, reason.as_str());
        }
    }

    /// Every entry, half entry and partial write in the directory.
    fn scan(&self) -> Vec<Scanned> {
        let Ok(dir) = std::fs::read_dir(&self.cfg.dir) else {
            return Vec::new();
        };
        let mut by_key: std::collections::BTreeMap<String, Scanned> = Default::default();
        let mut out = Vec::new();
        for entry in dir.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(meta) = entry.metadata() else { continue };
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            if name.starts_with(TMP_PREFIX) {
                out.push(Scanned {
                    files: vec![entry.path()],
                    bytes: meta.len(),
                    last_used: modified,
                    orphan: true,
                    temp: true,
                });
                continue;
            }
            let Some((stem, ext)) = name.rsplit_once('.') else {
                continue;
            };
            if ext != ARTIFACT_EXT && ext != META_EXT {
                continue;
            }
            let e = by_key.entry(stem.to_owned()).or_insert_with(|| Scanned {
                files: Vec::new(),
                bytes: 0,
                last_used: SystemTime::UNIX_EPOCH,
                orphan: true,
                temp: false,
            });
            e.files.push(entry.path());
            e.bytes += meta.len();
            if ext == META_EXT {
                e.last_used = modified;
            } else if e.files.len() == 1 {
                // Artifact seen first: until the sidecar shows up, its age.
                e.last_used = modified;
            }
        }
        for (_, mut e) in by_key {
            e.orphan = e.files.len() != 2;
            out.push(e);
        }
        out
    }

    fn remove(&self, e: &Scanned) -> bool {
        e.files.iter().all(|f| match std::fs::remove_file(f) {
            Ok(()) => true,
            Err(err) => err.kind() == std::io::ErrorKind::NotFound,
        })
    }
}

/// One scanned cache entry (artifact + sidecar), half entry or temp file.
struct Scanned {
    files: Vec<PathBuf>,
    bytes: u64,
    last_used: SystemTime,
    orphan: bool,
    /// A partial write (temporary file), possibly still in progress.
    temp: bool,
}

/// Deserialize `artifact`, which the caller has just verified.
///
/// The one `unsafe` call in the crate.
#[allow(unsafe_code)]
fn deserialize_verified(engine: &Engine, artifact: &[u8]) -> wasmtime::Result<Component> {
    // SAFETY: `Component::deserialize` requires bytes produced by
    // `Component::serialize` / `Engine::precompile_component`, unmodified.
    // `artifact` is in memory (no file can change under this call) and its
    // keyed BLAKE3 MAC under this node's private cache key — readable and
    // writable only by the daemon's user, in a directory only that user can
    // write — was verified over exactly these bytes by the caller, and the
    // only code that computes such MACs is `AotCache::store`, over the output
    // of `Component::serialize`. Wasmtime additionally refuses (with an
    // error, safely) artifacts from another Wasmtime version or an
    // incompatible engine configuration.
    unsafe { Component::deserialize(engine, artifact) }
}

/// A parsed sidecar.
struct Header {
    entry: String,
    wasmtime: String,
    target: String,
    length: u64,
    mac: String,
}

impl Header {
    /// The sidecar text the MAC covers (every line but `mac`).
    fn signed_text(&self) -> String {
        format!(
            "{META_MAGIC}\nentry {}\nwasmtime {}\ntarget {}\nlength {}\n",
            self.entry, self.wasmtime, self.target, self.length
        )
    }

    fn parse(text: &str) -> Result<Self, Rejection> {
        let mut lines = text.lines();
        if lines.next() != Some(META_MAGIC) {
            return Err(Rejection::Header);
        }
        let mut field = |name: &str| -> Result<String, Rejection> {
            lines
                .next()
                .and_then(|l| l.strip_prefix(name))
                .and_then(|v| v.strip_prefix(' '))
                .map(str::to_owned)
                .ok_or(Rejection::Header)
        };
        let entry = field("entry")?;
        let wasmtime = field("wasmtime")?;
        let target = field("target")?;
        let length = field("length")?.parse().map_err(|_| Rejection::Header)?;
        let mac = field("mac")?;
        Ok(Self {
            entry,
            wasmtime,
            target,
            length,
            mac,
        })
    }
}

/// `arch-os-family` of this build: part of the entry key and the sidecar.
fn target() -> String {
    format!(
        "{}-{}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        std::env::consts::FAMILY
    )
}

/// Feeds `std::hash::Hash` output into BLAKE3 (deterministic for a given
/// build, unlike `DefaultHasher`'s contract).
struct Blake3StdHasher(blake3::Hasher);

impl std::hash::Hasher for Blake3StdHasher {
    fn finish(&self) -> u64 {
        let h = self.0.finalize();
        let mut first = [0u8; 8];
        first.copy_from_slice(&h.as_bytes()[..8]);
        u64::from_le_bytes(first)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

// ── private files ────────────────────────────────────────────────────────────

#[cfg(unix)]
fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

enum OpenError {
    NotFound,
    Rejected(Rejection),
}

/// Open `path` without following a symbolic link and check, on the open
/// file, that it is a regular file owned by `uid` with no group/other bits.
fn open_private(path: &Path, uid: u32, write: bool) -> Result<File, OpenError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(OpenError::NotFound),
        // ELOOP: a symbolic link.
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(OpenError::Rejected(Rejection::Permissions))
        }
        Err(_) => return Err(OpenError::Rejected(Rejection::Io)),
    };
    let meta = file
        .metadata()
        .map_err(|_| OpenError::Rejected(Rejection::Io))?;
    if !meta.is_file() || !private_to(&meta, uid) {
        return Err(OpenError::Rejected(Rejection::Permissions));
    }
    Ok(file)
}

#[cfg(unix)]
fn private_to(meta: &std::fs::Metadata, uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.uid() == uid && meta.mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_to(_meta: &std::fs::Metadata, _uid: u32) -> bool {
    true
}

/// Create `dir` (`0700`) when absent; refuse one that is not a directory
/// private to `uid`.
fn ensure_private_dir(dir: &Path, uid: u32) -> Result<(), AotError> {
    let unusable = |reason: String| AotError::Unusable {
        path: dir.to_path_buf(),
        reason,
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| unusable(format!("cannot create it: {e}")))?;
    let meta = std::fs::symlink_metadata(dir).map_err(|e| unusable(e.to_string()))?;
    if !meta.is_dir() {
        return Err(unusable("not a directory (or a symbolic link)".into()));
    }
    if !private_to(&meta, uid) {
        return Err(unusable(
            "it must be owned by the daemon's user and have no group/other permissions \
             (chmod 700)"
                .into(),
        ));
    }
    Ok(())
}

/// What [`read_key`] found.
enum KeyFile {
    /// A valid 32-byte key.
    Valid([u8; 32]),
    /// No key file.
    Absent,
    /// A private key file shorter than a key: what a crash between creating
    /// and filling it (as earlier versions wrote it) leaves behind.
    Short,
}

/// Read the cache key at `path` (a private regular file, see
/// [`open_private`]).
fn read_key(path: &Path, uid: u32) -> Result<KeyFile, AotError> {
    let unusable = |reason: String| AotError::Unusable {
        path: path.to_path_buf(),
        reason,
    };
    let mut f = match open_private(path, uid, false) {
        Ok(f) => f,
        Err(OpenError::NotFound) => return Ok(KeyFile::Absent),
        Err(OpenError::Rejected(r)) => {
            return Err(unusable(format!(
                "the cache key is not a private regular file ({})",
                r.as_str()
            )))
        }
    };
    let mut bytes = Vec::with_capacity(33);
    (&mut f)
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(|e| unusable(format!("cannot read the cache key: {e}")))?;
    match <[u8; 32]>::try_from(bytes.as_slice()) {
        Ok(key) => Ok(KeyFile::Valid(key)),
        Err(_) if bytes.len() < 32 => Ok(KeyFile::Short),
        Err(_) => Err(unusable("the cache key is not 32 bytes".into())),
    }
}

/// Read the 32-byte cache key at `path` (in `dir`), or create it. Returns
/// the key and whether this call created it (every existing entry is then
/// unverifiable).
///
/// A new key is written whole to a private temporary file, synced, and only
/// then hard-linked into place, which never replaces an existing file: a
/// crash leaves either no key or a complete one (plus a temporary file GC
/// removes), and of several processes opening a fresh cache at once exactly
/// one key wins — the others find it and read it. A short key file (left by
/// a crash of an earlier version, which wrote the key in place) is
/// regenerated instead of disabling the cache for good. Two processes
/// regenerating the same short file at the same moment can end up with
/// different keys; each then refuses (and recompiles) the other's entries,
/// which costs compile time but never trusts an unverified entry.
fn load_or_create_key(dir: &Path, path: &Path, uid: u32) -> Result<([u8; 32], bool), AotError> {
    let unusable = |reason: String| AotError::Unusable {
        path: path.to_path_buf(),
        reason,
    };
    // Bounded: each round either returns or saw the file change under it.
    for _ in 0..4 {
        match read_key(path, uid)? {
            KeyFile::Valid(key) => return Ok((key, false)),
            KeyFile::Short => {
                tracing::warn!(
                    path = %path.display(),
                    "AOT cache key file is truncated (an interrupted first start); \
                     regenerating it and dropping the entries it signed"
                );
                match std::fs::remove_file(path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(unusable(format!(
                            "cannot replace a truncated cache key: {e}"
                        )))
                    }
                }
            }
            KeyFile::Absent => {}
        }
        let mut key = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut key);
        match publish_key(dir, path, &key) {
            Ok(()) => return Ok((key, true)),
            // Another process created it first: use theirs.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(unusable(format!("cannot create the cache key: {e}"))),
        }
    }
    Err(unusable(
        "the cache key keeps changing while it is read (another process is rewriting it)".into(),
    ))
}

/// Put `key` at `path` without ever exposing a partial file or replacing an
/// existing one (`AlreadyExists` then).
fn publish_key(dir: &Path, path: &Path, key: &[u8; 32]) -> std::io::Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = dir.join(format!(
        "{TMP_PREFIX}key-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(key)?;
        f.sync_all()?;
        // `link` fails with `EEXIST` rather than replacing `path`.
        std::fs::hard_link(&tmp, path)
    })();
    let _ = std::fs::remove_file(&tmp);
    match result {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            // A file system without hard links (some network and FAT
            // mounts): create the key in place, exclusively, as before. A
            // crash mid-write there leaves a short key, regenerated at the
            // next open.
            let mut f = opts.open(path)?;
            f.write_all(key)?;
            f.sync_all()
        }
        other => other,
    }
}

/// Write `bytes` to `dest` via a private temporary file in `dir`.
fn write_private(dir: &Path, dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = dir.join(format!(
        "{TMP_PREFIX}{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, dest)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasmtime_version_matches_the_lock_file() {
        let lock =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
                .expect("Cargo.lock");
        let version = lock
            .split("[[package]]")
            .find(|p| p.contains("\nname = \"wasmtime\"\n"))
            .and_then(|p| p.lines().find_map(|l| l.strip_prefix("version = ")))
            .map(|v| v.trim_matches('"').to_owned())
            .expect("wasmtime in Cargo.lock");
        assert_eq!(
            version, WASMTIME_VERSION,
            "update entangle_aot::WASMTIME_VERSION with the wasmtime bump"
        );
    }

    #[test]
    fn header_round_trips_and_rejects_junk() {
        let h = Header {
            entry: "ab".into(),
            wasmtime: WASMTIME_VERSION.into(),
            target: target(),
            length: 7,
            mac: String::new(),
        };
        let text = format!("{}mac cd\n", h.signed_text());
        let p = Header::parse(&text).unwrap();
        assert_eq!(
            (p.entry.as_str(), p.length, p.mac.as_str()),
            ("ab", 7, "cd")
        );
        assert!(Header::parse("garbage").is_err());
        assert!(Header::parse(&text.replace("length 7", "length x")).is_err());
    }
}
