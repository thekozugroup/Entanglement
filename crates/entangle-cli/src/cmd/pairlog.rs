//! A record of recent `entangle pair` attempts, so `entangle diag pair` can
//! show what was tried and how it ended (spec §6.3 "No reachability").
//!
//! JSON, next to `peers.toml` (`pairing-attempts.json`, mode 0600), keeping
//! the last [`KEEP`] attempts. Recording is best-effort: a pairing never
//! fails because its log could not be written. Nothing secret is stored —
//! no codes and no tokens, only what was dialled and the outcome.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File name, next to `peers.toml`.
pub const FILE: &str = "pairing-attempts.json";

/// Attempts kept.
pub const KEEP: usize = 20;

/// One transport (or discovery step) a pairing attempt used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tried {
    /// What was used, e.g. `mesh.local (mDNS)` or `mesh.iroh (QUIC)`.
    pub transport: String,
    /// What it was pointed at (an address, a service name).
    pub target: String,
    /// How it went (`ok`, or why it failed).
    pub result: String,
}

impl Tried {
    /// A step.
    pub fn new(
        transport: impl Into<String>,
        target: impl Into<String>,
        result: impl Into<String>,
    ) -> Self {
        Self {
            transport: transport.into(),
            target: target.into(),
            result: result.into(),
        }
    }
}

/// One `entangle pair` run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    /// Unix seconds when it ended.
    pub at_unix: u64,
    /// `show-code` (this device showed the code) or `enter-code`.
    pub role: String,
    /// `paired`, `failed` or `not-confirmed`.
    pub outcome: String,
    /// The other device, when known (name and peer id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// The error, for a failed attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// What was tried, in order.
    #[serde(default)]
    pub tried: Vec<Tried>,
}

/// The log next to `peers`.
pub fn path_next_to(peers: &Path) -> PathBuf {
    peers.with_file_name(FILE)
}

/// Every recorded attempt, oldest first (empty when there is no log or it
/// cannot be read).
pub fn load(path: &Path) -> Vec<Attempt> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Append `attempt`, keeping the last [`KEEP`]. Errors are reported on
/// stderr, never returned.
pub fn record(path: &Path, attempt: Attempt) {
    let mut all = load(path);
    all.push(attempt);
    let excess = all.len().saturating_sub(KEEP);
    all.drain(..excess);
    let result = serde_json::to_vec_pretty(&all)
        .map_err(std::io::Error::other)
        .and_then(|bytes| crate::fsutil::atomic_write(path, &bytes, 0o600));
    if let Err(e) = result {
        eprintln!(
            "note: could not record this attempt in {} ({e}); `entangle diag pair` will not show it",
            path.display()
        );
    }
}

/// Unix seconds now.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_last_attempts_privately() {
        let d = tempfile::tempdir().unwrap();
        let p = path_next_to(&d.path().join("peers.toml"));
        for i in 0..(KEEP + 3) {
            record(
                &p,
                Attempt {
                    at_unix: i as u64,
                    role: "enter-code".into(),
                    outcome: "failed".into(),
                    peer: None,
                    error: Some("x".into()),
                    tried: vec![Tried::new("mesh.iroh (QUIC)", "a", "timeout")],
                },
            );
        }
        let all = load(&p);
        assert_eq!(all.len(), KEEP);
        assert_eq!(all[0].at_unix, 3);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
