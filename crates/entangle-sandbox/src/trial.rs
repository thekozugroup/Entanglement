//! Trial engagement: prove the sandbox works on this host by running real
//! children under it. Used by `entangle doctor`.
//!
//! Two spawns, both with a deny-everything profile:
//! 1. `true` must run and exit 0 — the sandbox engages and a dynamically
//!    linked system binary can still start under it;
//! 2. `cat <file>` on a file this process just created *outside* the profile
//!    must fail — the sandbox actually denies.

use std::path::{Path, PathBuf};

use crate::plan::{plan, Plan, Policy};
use crate::probe::probe;
use crate::profile::{ResourceLimits, SandboxProfile};

/// Result of [`run_trial`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrialOutcome {
    /// Both spawns behaved: the child ran, and reading outside its scope was
    /// refused.
    Enforced {
        /// The plan that was engaged.
        plan: Plan,
    },
    /// The child ran under the sandbox, but denial could not be checked
    /// (no `cat` found).
    Engaged {
        /// The plan that was engaged.
        plan: Plan,
        /// Why the denial check was skipped.
        note: String,
    },
    /// The child read a file outside its scope: the sandbox is NOT enforcing.
    NotEnforcing {
        /// The plan that was supposedly engaged.
        plan: Plan,
    },
    /// Planning or spawning failed.
    Failed {
        /// The plan, if planning got that far.
        plan: Option<Plan>,
        /// What went wrong.
        error: String,
    },
    /// No trivial program to run was found.
    Skipped {
        /// Why.
        reason: String,
    },
}

fn find(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()))
}

fn trial_profile(program: PathBuf) -> SandboxProfile {
    SandboxProfile::new(program).limits(ResourceLimits {
        address_space_bytes: Some(512 * 1024 * 1024),
        cpu_time_secs: Some(5),
        open_files: Some(64),
    })
}

#[cfg(unix)]
fn run_quiet(profile: &SandboxProfile, plan: &Plan) -> Result<bool, String> {
    use std::process::Stdio;
    let mut cmd = crate::sandboxed_command(profile, plan).map_err(|e| e.to_string())?;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = cmd.status().map_err(|e| format!("spawn failed: {e}"))?;
    Ok(status.success())
}

/// Run the trial (blocking; spawns two short-lived children).
pub fn run_trial(policy: Policy) -> TrialOutcome {
    #[cfg(not(unix))]
    {
        let _ = policy;
        TrialOutcome::Skipped {
            reason: "native plugins are not supported on this platform".into(),
        }
    }
    #[cfg(unix)]
    {
        let Some(truth) = find(&["/usr/bin/true", "/bin/true"]) else {
            return TrialOutcome::Skipped {
                reason: "no `true` binary found to run under the sandbox".into(),
            };
        };
        let profile = trial_profile(truth);
        let plan = match plan(&profile, probe(), policy) {
            Ok(p) => p,
            Err(e) => {
                return TrialOutcome::Failed {
                    plan: None,
                    error: e.to_string(),
                }
            }
        };
        match run_quiet(&profile, &plan) {
            Ok(true) => {}
            Ok(false) => {
                return TrialOutcome::Failed {
                    plan: Some(plan),
                    error: "`true` exited non-zero under the sandbox".into(),
                }
            }
            Err(error) => {
                return TrialOutcome::Failed {
                    plan: Some(plan),
                    error,
                }
            }
        }

        let Some(cat) = find(&["/usr/bin/cat", "/bin/cat"]) else {
            return TrialOutcome::Engaged {
                plan,
                note: "no `cat` binary found; denial not verified".into(),
            };
        };
        let secret = std::env::temp_dir().join(format!(
            "entangle-sandbox-trial-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        if let Err(e) = std::fs::write(&secret, b"outside the sandbox") {
            return TrialOutcome::Engaged {
                plan,
                note: format!("could not create a probe file ({e}); denial not verified"),
            };
        }
        let probe_profile = trial_profile(cat).arg(&secret);
        let read = run_quiet(&probe_profile, &plan);
        let _ = std::fs::remove_file(&secret);
        match read {
            Ok(false) => TrialOutcome::Enforced { plan },
            Ok(true) => TrialOutcome::NotEnforcing { plan },
            Err(error) => TrialOutcome::Failed {
                plan: Some(plan),
                error,
            },
        }
    }
}
