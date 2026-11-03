//! Trial engagement: prove the sandbox works on this host by running real
//! children under it. Used by `entangle doctor`.
//!
//! Three spawns under the same plan:
//! 1. `true` with a deny-everything profile must run and exit 0 — the sandbox
//!    engages and a dynamically linked system binary can still start;
//! 2. `cat <file>` on a file this process just created, *granted* read-only,
//!    must succeed — the control: `cat` itself works under the sandbox;
//! 3. the same `cat <file>` without the grant must fail — the sandbox, and
//!    nothing else, denies.

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
    /// The child ran under the sandbox, but denial could not be checked (no
    /// `cat` found, or `cat` could not read even a granted file).
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

/// The first candidate that exists, *as named*: not canonicalised, because a
/// multi-call binary (BusyBox: `/bin/cat` → `/bin/busybox`) picks its applet
/// from `argv[0]`. (Seatbelt needs resolved paths; `sandboxed_command`
/// resolves them itself.)
fn find(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .map(Path::to_path_buf)
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
    run_trial_with(
        policy,
        &["/usr/bin/true", "/bin/true"],
        &["/usr/bin/cat", "/bin/cat"],
    )
}

/// [`run_trial`] with the candidate locations of `true` and `cat`.
fn run_trial_with(policy: Policy, trues: &[&str], cats: &[&str]) -> TrialOutcome {
    #[cfg(not(unix))]
    {
        let _ = (policy, trues, cats);
        TrialOutcome::Skipped {
            reason: "native plugins are not supported on this platform".into(),
        }
    }
    #[cfg(unix)]
    {
        let Some(truth) = find(trues) else {
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

        let Some(cat) = find(cats) else {
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
        // Grants are resolved without following links: name the file by its
        // canonical path (the temp dir may sit under one, e.g. on macOS).
        let secret = std::fs::canonicalize(&secret).unwrap_or(secret);
        // Control: the same program, under the same plan, must read the file
        // when it *is* granted — otherwise a failure below could be `cat`'s
        // own (a missing library, a multi-call binary, a limit) and would
        // prove nothing about the sandbox.
        let control = run_quiet(
            &trial_profile(cat.clone()).arg(&secret).read_only(&secret),
            &plan,
        );
        let read = match control {
            Ok(true) => run_quiet(&trial_profile(cat).arg(&secret), &plan),
            Ok(false) => {
                let _ = std::fs::remove_file(&secret);
                return TrialOutcome::Engaged {
                    plan,
                    note: format!(
                        "`{}` could not read a file it was granted under the sandbox; \
                         denial not verified",
                        cat.display()
                    ),
                };
            }
            Err(error) => Err(error),
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe program keeps the name it was found under: on a multi-call
    /// system (BusyBox) `/bin/cat` is a link to `/bin/busybox`, which picks
    /// the applet from `argv[0]` — canonicalised, it would not run `cat`.
    #[cfg(unix)]
    #[test]
    fn probe_programs_keep_the_name_they_were_found_under() {
        let Some(cat) = find(&["/usr/bin/cat", "/bin/cat"]) else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("cat");
        std::os::unix::fs::symlink(&cat, &link).unwrap();
        assert_eq!(find(&[link.to_str().unwrap()]), Some(link));
    }

    /// A `cat` that fails for a reason of its own proves nothing about the
    /// sandbox: denial is only reported once the same program, under the same
    /// plan, has been shown to read a file it *was* granted.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_reader_that_always_fails_proves_nothing() {
        let outcome = run_trial_with(
            Policy::default(),
            &["/usr/bin/true", "/bin/true"],
            &["/usr/bin/false", "/bin/false"],
        );
        assert!(
            !matches!(outcome, TrialOutcome::Enforced { .. }),
            "{outcome:?}"
        );
        if crate::probe().has_primitive() {
            assert!(
                matches!(&outcome, TrialOutcome::Engaged { note, .. } if note.contains("granted")),
                "{outcome:?}"
            );
        }
    }
}
