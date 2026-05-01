//! Built-in maintenance loop: log rotation, cache GC, key-rotation reminders,
//! and identity-backup nags.
//!
//! Spec §9.5 — maintenance plugin (Phase-1 built-in tier-2 task scheduler).
//!
//! All tasks are small async fns driven from a single [`MaintenanceLoop`] that
//! runs on a tokio interval and is spawned by the daemon's main loop.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tokio::time::{interval, MissedTickBehavior};
use tracing::{error, info, warn};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Configuration for the built-in maintenance loop.
#[derive(Clone, Debug)]
pub struct MaintenanceConfig {
    /// Rotate `entangled.log` once it exceeds this size in bytes (default 100 MiB).
    pub log_rotate_threshold_bytes: u64,
    /// Path to `~/.entangle/cache/`.
    pub cache_dir: PathBuf,
    /// Path to `~/.entangle/logs/`.
    pub log_dir: PathBuf,
    /// Path to `~/.entangle/identity.key`.
    pub identity_path: PathBuf,
    /// Delete cache blobs whose mtime is older than this many seconds (default 7 days).
    pub cache_ttl_secs: u64,
    /// Emit a key-rotation warning once the identity key is this many days old (default 365).
    pub key_rotation_warn_days: u64,
    /// Emit a backup nag if the sentinel file is absent for this many days (default 7).
    /// In Phase-1 this is not a per-sentinel age check — we nag unconditionally if the
    /// `.identity_backed_up` sentinel is absent.
    pub backup_nag_days: u64,
    /// How often the loop ticks in seconds (default 3600 = 1 h).
    pub tick_interval_secs: u64,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_default();
        let base = PathBuf::from(home).join(".entangle");
        Self {
            log_rotate_threshold_bytes: 100 * 1024 * 1024,
            cache_dir: base.join("cache"),
            log_dir: base.join("logs"),
            identity_path: base.join("identity.key"),
            cache_ttl_secs: 7 * 24 * 3600,
            key_rotation_warn_days: 365,
            backup_nag_days: 7,
            tick_interval_secs: 3600,
        }
    }
}

// ── MaintenanceLoop ───────────────────────────────────────────────────────────

/// Tier-2 task scheduler that runs inside the daemon process.
pub struct MaintenanceLoop {
    config: MaintenanceConfig,
}

impl MaintenanceLoop {
    /// Create a new loop with the given configuration.
    pub fn new(config: MaintenanceConfig) -> Self {
        Self { config }
    }

    /// Run the maintenance loop until the shutdown watch fires `true`.
    ///
    /// Designed to be called from [`tokio::spawn`] in the daemon's main loop:
    /// ```ignore
    /// let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    /// tokio::spawn(MaintenanceLoop::new(Default::default()).run(shutdown_rx));
    /// // …on signal: shutdown_tx.send(true).ok();
    /// ```
    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut tick = interval(Duration::from_secs(self.config.tick_interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Run a startup pass immediately for cache GC — do this before the
        // first interval tick so stale blobs are purged on restart.
        if let Err(e) = self.gc_stale_cache().await {
            error!(error = %e, "maintenance: stale cache GC failed at startup");
        }

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if let Err(e) = self.rotate_logs().await {
                        error!(error = %e, "maintenance: log rotation failed");
                    }
                    if let Err(e) = self.warn_key_rotation().await {
                        error!(error = %e, "maintenance: key-rotation check failed");
                    }
                    if let Err(e) = self.warn_backup().await {
                        error!(error = %e, "maintenance: backup nag failed");
                    }
                    if let Err(e) = self.gc_stale_cache().await {
                        error!(error = %e, "maintenance: stale cache GC failed on tick");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
            }
        }

        info!("maintenance loop shut down cleanly");
    }

    // ── Individual tasks ──────────────────────────────────────────────────────

    /// Rotate `entangled.log` when it exceeds the configured threshold.
    ///
    /// The rotated file is renamed to `entangled.log.<unix_timestamp>` and
    /// compressed to `.gz` in a [`tokio::task::spawn_blocking`] worker.
    /// Compression is best-effort; failure is logged but does not propagate.
    pub async fn rotate_logs(&self) -> std::io::Result<()> {
        let log_file = self.config.log_dir.join("entangled.log");
        if !log_file.exists() {
            return Ok(());
        }
        let metadata = std::fs::metadata(&log_file)?;
        if metadata.len() < self.config.log_rotate_threshold_bytes {
            return Ok(());
        }

        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let rotated = self.config.log_dir.join(format!("entangled.log.{ts}"));

        std::fs::rename(&log_file, &rotated)?;
        // Re-create an empty live log so the logger can keep writing.
        std::fs::File::create(&log_file)?;

        info!(rotated = %rotated.display(), "maintenance: rotated entangled.log");

        // Gzip in a blocking worker — best-effort.
        let path_clone = rotated.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = gzip_in_place(&path_clone) {
                // Use eprintln here: the tracing subscriber may have moved to the
                // new log file at this point, making warn!/error! unreliable.
                eprintln!("maintenance: gzip of {} failed: {e}", path_clone.display());
            }
        });

        Ok(())
    }

    /// Delete cache blobs whose mtime is older than `cache_ttl_secs`.
    pub async fn gc_stale_cache(&self) -> std::io::Result<()> {
        if !self.config.cache_dir.exists() {
            return Ok(());
        }
        let cutoff = SystemTime::now() - Duration::from_secs(self.config.cache_ttl_secs);
        let mut removed = 0usize;

        for entry in std::fs::read_dir(&self.config.cache_dir)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                if let Ok(mtime) = metadata.modified() {
                    if mtime < cutoff && std::fs::remove_file(entry.path()).is_ok() {
                        removed += 1;
                    }
                }
            }
        }

        if removed > 0 {
            info!(removed, "maintenance: GC'd stale cache entries");
        }
        Ok(())
    }

    /// Emit a warning when the identity key file is older than `key_rotation_warn_days`.
    pub async fn warn_key_rotation(&self) -> std::io::Result<()> {
        if !self.config.identity_path.exists() {
            return Ok(());
        }
        let metadata = std::fs::metadata(&self.config.identity_path)?;
        if let Ok(created) = metadata.created() {
            let age = SystemTime::now()
                .duration_since(created)
                .unwrap_or(Duration::ZERO);
            let days = age.as_secs() / 86400;
            if days >= self.config.key_rotation_warn_days {
                warn!(
                    days,
                    "maintenance: identity key is {days} days old; consider rotating"
                );
            }
        }
        Ok(())
    }

    /// Emit a warning when the `.identity_backed_up` sentinel file is absent.
    pub async fn warn_backup(&self) -> std::io::Result<()> {
        let sentinel = self
            .config
            .identity_path
            .parent()
            .map(|p| p.join(".identity_backed_up"))
            .unwrap_or_default();

        if sentinel.exists() {
            return Ok(());
        }

        warn!(
            identity = %self.config.identity_path.display(),
            "maintenance: identity has no backup sentinel — after backing up, \
             run: touch ~/.entangle/.identity_backed_up"
        );
        Ok(())
    }
}

// ── Gzip helper ───────────────────────────────────────────────────────────────

/// Compress `path` to `path.gz` (in-place) using flate2.
///
/// On success the original uncompressed file is removed.
/// On any error the original file is left intact so log data is not lost.
fn gzip_in_place(path: &Path) -> std::io::Result<()> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::{Read, Write};

    let mut input = std::fs::File::open(path)?;
    let mut data = Vec::new();
    input.read_to_end(&mut data)?;
    drop(input);

    // Build the output path: `entangled.log.1234567890.gz`
    let gz_path = {
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext.is_empty() {
            path.with_extension("gz")
        } else {
            path.with_extension(format!("{ext}.gz"))
        }
    };

    let mut output = std::fs::File::create(&gz_path)?;
    let mut enc = GzEncoder::new(&mut output, Compression::default());
    enc.write_all(&data)?;
    enc.finish()?;

    // Only remove the source after a successful write.
    let _ = std::fs::remove_file(path);
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn cfg_for(tmp: &TempDir) -> MaintenanceConfig {
        MaintenanceConfig {
            log_rotate_threshold_bytes: 512 * 1024, // 512 KiB for tests
            cache_dir: tmp.path().join("cache"),
            log_dir: tmp.path().join("logs"),
            identity_path: tmp.path().join("identity.key"),
            cache_ttl_secs: 7 * 24 * 3600,
            key_rotation_warn_days: 365,
            backup_nag_days: 7,
            tick_interval_secs: 3600,
        }
    }

    // -- rotate_logs -----------------------------------------------------------

    #[tokio::test]
    async fn rotate_logs_noop_when_file_missing() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        std::fs::create_dir_all(&cfg.log_dir).unwrap();
        // No log file exists — should succeed without doing anything.
        let loop_ = MaintenanceLoop::new(cfg);
        loop_.rotate_logs().await.unwrap();
    }

    #[tokio::test]
    async fn rotate_logs_noop_below_threshold() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        std::fs::create_dir_all(&cfg.log_dir).unwrap();
        let log_path = cfg.log_dir.join("entangled.log");
        std::fs::write(&log_path, b"small").unwrap();

        let loop_ = MaintenanceLoop::new(cfg);
        loop_.rotate_logs().await.unwrap();

        // File must still be at its original path.
        assert!(log_path.exists(), "file should not have been rotated");
    }

    #[tokio::test]
    async fn rotate_logs_triggers_above_threshold() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        std::fs::create_dir_all(&cfg.log_dir).unwrap();
        let log_path = cfg.log_dir.join("entangled.log");

        // Write 1 MiB — above the 512 KiB threshold in the test config.
        let data = vec![b'x'; 1024 * 1024];
        std::fs::write(&log_path, &data).unwrap();

        let loop_ = MaintenanceLoop::new(cfg.clone());
        loop_.rotate_logs().await.unwrap();

        // The live log file must have been recreated (empty).
        assert!(log_path.exists(), "live log file should be recreated");
        assert_eq!(
            std::fs::metadata(&log_path).unwrap().len(),
            0,
            "live log should be empty after rotation"
        );

        // At least one rotated file should exist in the log dir.
        let rotated_count = std::fs::read_dir(&cfg.log_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("entangled.log.")
            })
            .count();
        assert!(rotated_count >= 1, "rotated file should exist");
    }

    // -- gc_stale_cache --------------------------------------------------------

    /// Set the mtime of `path` to a point `age` before now using
    /// `std::fs::File::set_modified` (stable since Rust 1.75).
    fn backdate(path: &Path, age: Duration) {
        let target = SystemTime::now() - age;
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_modified(target).unwrap();
    }

    #[tokio::test]
    async fn gc_removes_old_files_keeps_new() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = cfg_for(&tmp);
        // 5-second TTL — stale file is 10 s old, fresh file has current mtime.
        cfg.cache_ttl_secs = 5;
        std::fs::create_dir_all(&cfg.cache_dir).unwrap();

        let stale = cfg.cache_dir.join("old_blob");
        std::fs::write(&stale, b"old").unwrap();
        backdate(&stale, Duration::from_secs(10));

        let fresh = cfg.cache_dir.join("new_blob");
        std::fs::write(&fresh, b"new").unwrap();

        let loop_ = MaintenanceLoop::new(cfg);
        loop_.gc_stale_cache().await.unwrap();

        assert!(!stale.exists(), "stale file should have been deleted");
        assert!(fresh.exists(), "fresh file should remain");
    }

    #[tokio::test]
    async fn gc_noop_when_cache_dir_missing() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        // cache_dir does NOT exist
        let loop_ = MaintenanceLoop::new(cfg);
        loop_.gc_stale_cache().await.unwrap(); // must not error
    }

    // -- warn_backup -----------------------------------------------------------

    #[tokio::test]
    async fn warn_backup_silent_when_sentinel_present() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        // Create the sentinel file.
        std::fs::write(tmp.path().join(".identity_backed_up"), b"").unwrap();
        let loop_ = MaintenanceLoop::new(cfg);
        loop_.warn_backup().await.unwrap(); // should succeed silently
    }

    #[tokio::test]
    async fn warn_backup_succeeds_when_sentinel_absent() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        // No sentinel — warn_backup should still return Ok (just emit a warning).
        let loop_ = MaintenanceLoop::new(cfg);
        loop_.warn_backup().await.unwrap();
    }

    // -- warn_key_rotation -----------------------------------------------------

    #[tokio::test]
    async fn warn_key_rotation_noop_when_identity_missing() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let loop_ = MaintenanceLoop::new(cfg);
        loop_.warn_key_rotation().await.unwrap();
    }
}
