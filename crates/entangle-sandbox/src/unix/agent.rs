//! Child-side engagement of the agent-session sandbox (see [`crate::agent`]).
//!
//! Same discipline as the native-plugin path in the parent module: every
//! allocation happens in [`confine`] (the parent); the `pre_exec` hook runs
//! [`AgentChildSetup::run`], which only issues raw syscalls on data prepared
//! there.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use super::{cloexec_inherited_fds, set_rlimit};
use crate::agent::{
    temp_dirs, AgentFilesystem, AgentPlan, AgentProfile, AgentSandboxError, AGENT_SYSTEM_DEVICES,
    AGENT_SYSTEM_READ_EXEC, AGENT_SYSTEM_READ_WRITE,
};
use crate::linux::{caps, landlock, seccomp};
use crate::profile::{ResourceLimits, SandboxProfile};

/// Pre-built state the forked child consumes.
struct AgentChildSetup {
    limits: ResourceLimits,
    no_new_privs: bool,
    landlock: Option<OwnedFd>,
    seccomp: Option<seccomp::Filter>,
}

impl AgentChildSetup {
    /// Engage the sandbox on the calling process.
    ///
    /// Runs in the forked child between `fork` and `exec`. Async-signal-safe:
    /// only raw syscalls on fields built by the parent; no allocation, no
    /// locks. The first failure aborts the spawn.
    fn run(&self) -> io::Result<()> {
        set_rlimit(libc::RLIMIT_CORE, 0, 0)?;
        if let Some(bytes) = self.limits.address_space_bytes {
            set_rlimit(libc::RLIMIT_AS, bytes, bytes)?;
        }
        if let Some(secs) = self.limits.cpu_time_secs {
            set_rlimit(libc::RLIMIT_CPU, secs, secs.saturating_add(1))?;
        }
        cloexec_inherited_fds()?;
        if let Some(n) = self.limits.open_files {
            set_rlimit(libc::RLIMIT_NOFILE, n, n)?;
        }
        if self.no_new_privs {
            // SAFETY: forked child, before exec.
            unsafe { caps::drop_all()? };
            // SAFETY: integer-only prctl.
            let r = unsafe {
                libc::prctl(
                    libc::PR_SET_NO_NEW_PRIVS,
                    1 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            if r != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if let Some(ruleset) = &self.landlock {
            // SAFETY: forked child, after NO_NEW_PRIVS, Landlock ruleset fd.
            unsafe { landlock::restrict_self(ruleset.as_raw_fd())? };
        }
        if let Some(filter) = &self.seccomp {
            // SAFETY: forked child, after NO_NEW_PRIVS; the program lives in
            // `self`, which outlives the call.
            unsafe { filter.install()? };
        }
        Ok(())
    }
}

fn existing(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p).ok()
}

fn required(p: &Path, what: &str) -> Result<PathBuf, AgentSandboxError> {
    if !p.is_absolute() {
        return Err(AgentSandboxError::Path {
            path: p.to_path_buf(),
            reason: format!("the {what} must be an absolute path"),
        });
    }
    std::fs::canonicalize(p).map_err(|e| AgentSandboxError::Path {
        path: p.to_path_buf(),
        reason: format!("the {what} cannot be resolved: {e}"),
    })
}

/// The Landlock allowlist for `profile`, expressed as a [`SandboxProfile`]
/// so the ruleset builder of the native path is reused unchanged. Every path
/// is canonical and exists (the builder treats profile paths as required).
pub(crate) fn landlock_profile(
    profile: &AgentProfile,
) -> Result<SandboxProfile, AgentSandboxError> {
    let program = required(&profile.program, "agent executable")?;
    let project = required(&profile.project_dir, "project directory")?;
    let mut p = SandboxProfile::new(program).allow_network(true);
    let mut rx: Vec<PathBuf> = Vec::new();
    let mut rw: Vec<PathBuf> = vec![project];
    rx.extend(
        AGENT_SYSTEM_READ_EXEC
            .iter()
            .filter_map(|s| existing(Path::new(s))),
    );
    rw.extend(
        AGENT_SYSTEM_READ_WRITE
            .iter()
            .filter_map(|s| existing(Path::new(s))),
    );
    rw.extend(temp_dirs().iter().filter_map(|t| existing(t)));
    for path in &profile.read_only {
        if !path.is_absolute() {
            return Err(AgentSandboxError::Path {
                path: path.clone(),
                reason: "sandbox paths must be absolute".into(),
            });
        }
        rx.extend(existing(path));
    }
    for path in &profile.read_write {
        if !path.is_absolute() {
            return Err(AgentSandboxError::Path {
                path: path.clone(),
                reason: "sandbox paths must be absolute".into(),
            });
        }
        rw.extend(existing(path));
    }
    // A writable tree is also readable and executable: the agent builds and
    // runs code in the project and in temporary directories. Rules on the
    // same path are unioned by the kernel.
    for path in &rw {
        p.read_exec.push(path.clone());
        p.read_write.push(path.clone());
    }
    p.read_exec.extend(rx);
    p.devices.extend(
        AGENT_SYSTEM_DEVICES
            .iter()
            .filter_map(|s| existing(Path::new(s))),
    );
    Ok(p)
}

/// See [`crate::agent::confine_agent_command`].
pub(crate) fn confine(
    cmd: &mut Command,
    profile: &AgentProfile,
    plan: &AgentPlan,
) -> Result<(), AgentSandboxError> {
    if !plan.engages_anything() {
        return Ok(());
    }
    let landlock = match &plan.filesystem {
        AgentFilesystem::Landlock { abi } => {
            let lp = landlock_profile(profile)?;
            Some(
                // TCP is not handled (the agent keeps the network); scopes
                // apply from ABI 6.
                landlock::build_ruleset(&lp, *abi, false, plan.scopes)
                    .map_err(|e| AgentSandboxError::Setup(e.to_string()))?,
            )
        }
        AgentFilesystem::NotConfined { .. } => None,
    };
    let seccomp = if plan.seccomp {
        Some(seccomp::agent::filter().ok_or_else(|| {
            AgentSandboxError::Setup("no syscall table for this architecture".into())
        })?)
    } else {
        None
    };
    let setup = Arc::new(AgentChildSetup {
        limits: profile.limits.clone(),
        no_new_privs: plan.no_new_privs,
        landlock,
        seccomp,
    });
    // SAFETY: `AgentChildSetup::run` is async-signal-safe (raw syscalls on
    // data prepared above; no allocation, no locks), which is the contract
    // `pre_exec` requires in a possibly multi-threaded parent.
    unsafe {
        cmd.pre_exec(move || setup.run());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allowlist_makes_the_project_and_temp_dirs_writable_and_nothing_in_home() {
        let project = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let ap = AgentProfile::new("/bin/sh", project.path())
            .read_write(state.path())
            .read_write("/definitely/not/here/entangle")
            .read_only("/also/not/here");
        let lp = landlock_profile(&ap).unwrap();
        let project = std::fs::canonicalize(project.path()).unwrap();
        let state = std::fs::canonicalize(state.path()).unwrap();
        assert!(lp.read_write.contains(&project));
        assert!(lp.read_write.contains(&state));
        assert!(lp.read_write.contains(&PathBuf::from("/tmp")));
        // Writable trees are executable too.
        assert!(lp.read_exec.contains(&project));
        // Missing optional paths are skipped, not errors.
        assert!(lp
            .read_write
            .iter()
            .chain(&lp.read_exec)
            .all(|p| p.exists()));
        // The home directory is never granted as a whole.
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            if home != Path::new("/") {
                assert!(!lp.read_write.contains(&home) && !lp.read_exec.contains(&home));
            }
        }
        assert!(lp.allow_network, "name resolution files must be readable");
    }

    #[test]
    fn relative_and_missing_required_paths_are_e0682() {
        let err = landlock_profile(&AgentProfile::new("sh", "/tmp")).unwrap_err();
        assert!(err.to_string().starts_with("ENTANGLE-E0682"), "{err}");
        let err = landlock_profile(&AgentProfile::new("/bin/sh", "/no/such/project")).unwrap_err();
        assert!(err.to_string().contains("project directory"), "{err}");
        let err =
            landlock_profile(&AgentProfile::new("/bin/sh", "/tmp").read_only("rel")).unwrap_err();
        assert!(err.to_string().contains("absolute"), "{err}");
    }
}
