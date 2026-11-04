//! The plugin-state file: plugins come back after a restart (spec §2.1
//! "plugin states are reconstructed on restart from manifest +
//! last-known-good").
//!
//! `~/.entangle/plugins.state.toml` (mode `0600`, written atomically) lists
//! every plugin the daemon has loaded: where its package is, the digests of
//! the artifact and manifest that were verified, its tier, and its grants
//! (granted, denied by policy, revoked at run time). The daemon rewrites it
//! after every `plugins/load` (including hot reloads), `plugins/unload`,
//! `perms/revoke` and tier-ceiling change.
//!
//! At startup [`restore`] reloads each entry **through the normal load
//! path** — signature, keyring, tier ceiling, `[plugins] disabled`, runtime
//! kind all re-run — with two additions
//! ([`entangle_runtime::Kernel::load_plugin_expecting`]):
//!
//! - a package whose id, artifact or manifest differs from what was recorded
//!   is refused before anything of it is loaded (no registration, grant,
//!   compile, storage, `migrate` hook or hot reload of a plugin restored
//!   earlier): the operator never approved those bytes; `entangle plugins
//!   load` them explicitly;
//! - run-time revocations are withdrawn as soon as the plugin's grants exist,
//!   before it can be called (`entangle perms revoke` survives a restart;
//!   a native plugin's sandbox is derived without them).
//!
//! An entry that fails is skipped with one structured warning
//! (`ENTANGLE-E0784`, target `entangle::telemetry`) and counted in
//! `entangle_plugin_restores_total{outcome}`; it **stays in the file**,
//! marked with the reason, so the operator can see it and so it is retried
//! at the next start (after the keyring is fixed, the plugin re-enabled, …).
//! It is dropped when the operator loads that plugin again or runs
//! `entangle plugins unload <id>` for it.

use entangle_broker::GrantState;
use entangle_runtime::Kernel;
use entangle_types::plugin_id::PluginId;
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// File name of the plugin-state file inside the config directory.
pub const STATE_FILE: &str = "plugins.state.toml";

/// Current format version.
const FORMAT: u32 = 1;

/// The whole file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginStateFile {
    /// Format version (`1`).
    #[serde(default)]
    pub format: u32,
    /// One entry per plugin, in load order.
    #[serde(default, rename = "plugin")]
    pub plugins: Vec<PluginEntry>,
}

/// One recorded plugin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginEntry {
    /// `<publisher>/<name>@<version>`.
    pub id: String,
    /// The package directory it was loaded from.
    pub dir: PathBuf,
    /// BLAKE3 (hex) of the verified artifact.
    pub artifact_digest: String,
    /// BLAKE3 (hex) of the verified manifest.
    pub manifest_digest: String,
    /// Its effective tier when recorded.
    pub tier: u8,
    /// Capability keys granted when recorded.
    #[serde(default)]
    pub granted: Vec<String>,
    /// Capability keys the operator's policy denied.
    #[serde(default)]
    pub denied: Vec<String>,
    /// Capability keys revoked at run time; revoked again after a restore.
    #[serde(default)]
    pub revoked: Vec<String>,
    /// Why the last restore did not bring it back (`None`: loaded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<String>,
}

impl PluginStateFile {
    /// Read `path`; an absent file is empty.
    pub fn read(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(toml::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Write to `path` atomically (a `0600` temporary file in the same
    /// directory, synced, renamed over it).
    pub fn write(&self, path: &Path) -> anyhow::Result<()> {
        let text = toml::to_string_pretty(self)?;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join(format!(".{STATE_FILE}.{}.tmp", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let result = (|| -> std::io::Result<()> {
            let mut f = opts.open(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        Ok(result?)
    }
}

/// The current entry for a loaded plugin, from the kernel.
fn entry_for(kernel: &Kernel, id: &PluginId) -> Option<PluginEntry> {
    let source = kernel.loaded_source(id)?;
    let report = kernel.capability_report(id).unwrap_or_default();
    let keys = |want: fn(&GrantState) -> bool| -> Vec<String> {
        report
            .iter()
            .filter(|s| want(&s.state))
            .map(|s| s.capability.key().into_owned())
            .collect()
    };
    let tier = kernel
        .broker()
        .effective_tier(id)
        .map(|t| t as u8)
        .unwrap_or(0);
    Some(PluginEntry {
        id: id.to_string(),
        dir: source.dir,
        artifact_digest: source.artifact_digest,
        manifest_digest: source.manifest_digest,
        tier,
        granted: keys(|s| matches!(s, GrantState::Granted { .. })),
        denied: keys(|s| matches!(s, GrantState::Denied { .. })),
        revoked: keys(|s| matches!(s, GrantState::Revoked)),
        failed: None,
    })
}

/// The plugin-state file of one daemon. Writes are serialised, and each
/// writes a snapshot of the kernel taken under the lock, so the file always
/// ends up describing the latest state.
#[derive(Debug)]
pub struct PluginStateStore {
    path: PathBuf,
    lock: parking_lot::Mutex<()>,
}

impl PluginStateStore {
    /// The store at `path` (usually `<config_dir>/plugins.state.toml`).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: parking_lot::Mutex::new(()),
        }
    }

    /// Where the file is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rewrite the file from `kernel`'s loaded plugins, keeping entries that
    /// failed to restore unless `forget` names them or another version of
    /// the same plugin is loaded now. Failures are logged, never returned:
    /// a state file that cannot be written must not fail the operation that
    /// changed the state.
    pub fn record(&self, kernel: &Kernel, forget: Option<&PluginId>) {
        let _serial = self.lock.lock();
        let previous = match PluginStateFile::read(&self.path) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(path = %self.path.display(), error = %e, "plugin-state file unreadable; rewriting it");
                PluginStateFile::default()
            }
        };
        let loaded = kernel.list_plugins();
        let same_plugin = |id: &str| -> bool {
            id.parse::<PluginId>().is_ok_and(|p| {
                loaded
                    .iter()
                    .any(|l| l.publisher == p.publisher && l.name == p.name)
            })
        };
        let mut plugins: Vec<PluginEntry> = Vec::new();
        // Recorded order first (restore order), then plugins loaded since.
        for old in &previous.plugins {
            if let Ok(id) = old.id.parse::<PluginId>() {
                if let Some(now) = entry_for(kernel, &id) {
                    plugins.push(now);
                    continue;
                }
            }
            let forgotten = forget.is_some_and(|f| f.to_string() == old.id);
            if old.failed.is_some() && !forgotten && !same_plugin(&old.id) {
                plugins.push(old.clone());
            }
        }
        for id in &loaded {
            if !plugins.iter().any(|e| e.id == id.to_string()) {
                if let Some(now) = entry_for(kernel, id) {
                    plugins.push(now);
                }
            }
        }
        let file = PluginStateFile {
            format: FORMAT,
            plugins,
        };
        if let Err(e) = file.write(&self.path) {
            tracing::error!(path = %self.path.display(), error = %e, "cannot write the plugin-state file; plugins loaded now will not come back after a restart");
        }
    }

    /// Whether the file holds an entry for `id` that failed to restore.
    pub fn has_failed_entry(&self, id: &PluginId) -> bool {
        let _serial = self.lock.lock();
        PluginStateFile::read(&self.path).is_ok_and(|f| {
            f.plugins
                .iter()
                .any(|e| e.id == id.to_string() && e.failed.is_some())
        })
    }
}

/// What [`restore`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Plugins loaded again.
    pub restored: Vec<String>,
    /// Entries skipped because `[plugins] disabled` names them.
    pub disabled: Vec<String>,
    /// Entries that failed, with the reason.
    pub failed: Vec<(String, String)>,
}

/// Reload every plugin recorded in `store`'s file into `kernel` (see the
/// module docs), then rewrite the file. `metrics` receives
/// `entangle_plugin_restores_total{outcome}`.
pub async fn restore(
    kernel: &Kernel,
    store: &PluginStateStore,
    metrics: Option<&entangle_observability::Registry>,
) -> RestoreReport {
    let mut report = RestoreReport::default();
    let file = match PluginStateFile::read(store.path()) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(
                target: "entangle::telemetry",
                code = "ENTANGLE-E0784",
                path = %store.path().display(),
                error = %e,
                "ENTANGLE-E0784: plugin-state file unreadable; no plugin restored"
            );
            return report;
        }
    };
    let mut failures: Vec<(String, String)> = Vec::new();
    for entry in &file.plugins {
        let outcome = restore_one(kernel, entry).await;
        let label = match &outcome {
            Ok(()) => {
                report.restored.push(entry.id.clone());
                "restored"
            }
            Err(Skip::Disabled(reason)) => {
                warn_skipped(entry, reason);
                report.disabled.push(entry.id.clone());
                failures.push((entry.id.clone(), reason.clone()));
                "disabled"
            }
            Err(Skip::Failed(reason)) => {
                warn_skipped(entry, reason);
                report.failed.push((entry.id.clone(), reason.clone()));
                failures.push((entry.id.clone(), reason.clone()));
                "failed"
            }
        };
        if let Some(reg) = metrics {
            entangle_observability::catalog::plugin_restore(reg, label);
        }
    }
    // Rewrite: loaded entries from the kernel, failed ones with their reason.
    let mut out = PluginStateFile {
        format: FORMAT,
        plugins: Vec::new(),
    };
    for entry in &file.plugins {
        if let Ok(id) = entry.id.parse::<PluginId>() {
            if let Some(now) = entry_for(kernel, &id) {
                out.plugins.push(now);
                continue;
            }
        }
        if let Some((_, reason)) = failures.iter().find(|(id, _)| *id == entry.id) {
            out.plugins.push(PluginEntry {
                failed: Some(reason.clone()),
                ..entry.clone()
            });
        }
    }
    {
        let _serial = store.lock.lock();
        if let Err(e) = out.write(store.path()) {
            tracing::error!(path = %store.path().display(), error = %e, "cannot write the plugin-state file");
        }
    }
    if !file.plugins.is_empty() {
        tracing::info!(
            restored = report.restored.len(),
            disabled = report.disabled.len(),
            failed = report.failed.len(),
            "plugin state restored"
        );
    }
    report
}

enum Skip {
    Disabled(String),
    Failed(String),
}

fn warn_skipped(entry: &PluginEntry, reason: &str) {
    tracing::warn!(
        target: "entangle::telemetry",
        code = "ENTANGLE-E0784",
        plugin = %entry.id,
        dir = %entry.dir.display(),
        reason = %reason,
        "ENTANGLE-E0784: plugin not restored at startup; it stays in the plugin-state file, \
         marked failed, and is retried at the next start"
    );
}

async fn restore_one(kernel: &Kernel, entry: &PluginEntry) -> Result<(), Skip> {
    let expected: PluginId = entry
        .id
        .parse()
        .map_err(|e| Skip::Failed(format!("invalid plugin id in the state file: {e}")))?;
    if kernel.is_plugin_disabled(&expected) {
        return Err(Skip::Disabled(format!(
            "ENTANGLE-E0759: {expected} is in [plugins] disabled"
        )));
    }
    // The kernel compares the package with the entry on the bytes it then
    // verifies, before anything of it is registered, granted, compiled or
    // swapped in, and withdraws the recorded revocations before the plugin
    // can be called.
    let want = entangle_runtime::ExpectedPackage {
        plugin_id: expected.clone(),
        artifact_digest: entry.artifact_digest.clone(),
        manifest_digest: entry.manifest_digest.clone(),
        revoked: entry.revoked.clone(),
    };
    kernel
        .load_plugin_expecting(&entry.dir, entangle_runtime::LoadOptions::default(), &want)
        .await
        .map_err(|e| match e {
            entangle_runtime::RuntimeError::PluginDisabled(_) => Skip::Disabled(e.to_string()),
            entangle_runtime::RuntimeError::PackageChanged { found, .. } => Skip::Failed(format!(
                "the package in {} changed since it was recorded (now {found}); it was not \
                     reloaded automatically — load it again with `entangle plugins load`",
                entry.dir.display()
            )),
            e => Skip::Failed(e.to_string()),
        })?;
    Ok(())
}
