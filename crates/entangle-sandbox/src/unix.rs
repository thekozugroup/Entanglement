//! Turning a [`Plan`] into a `std::process::Command` whose child engages the
//! sandbox between `fork` and `exec`.
//!
//! Everything allocating happens in [`sandboxed_command`] (the parent). The
//! `pre_exec` hook runs [`ChildSetup::run`], which only issues raw syscalls on
//! data prepared here — see the crate docs for why.

use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use crate::error::SandboxError;
use crate::plan::{Mechanism, Plan};
use crate::profile::{ResourceLimits, SandboxProfile};

/// Pre-built state the forked child consumes.
struct ChildSetup {
    limits: ResourceLimits,
    #[cfg(target_os = "linux")]
    no_new_privs: bool,
    /// Drop every capability (not for bubblewrap, which may be setuid root
    /// and drops them itself with `--cap-drop ALL`).
    #[cfg(target_os = "linux")]
    drop_caps: bool,
    /// The spawning process: the child checks it is still its parent after
    /// arming `PR_SET_PDEATHSIG`.
    #[cfg(target_os = "linux")]
    parent: libc::pid_t,
    #[cfg(target_os = "linux")]
    userns: Option<crate::linux::userns::IdMaps>,
    #[cfg(target_os = "linux")]
    landlock: Option<std::os::fd::OwnedFd>,
    #[cfg(target_os = "linux")]
    seccomp: Option<crate::linux::seccomp::Filter>,
}

/// The integer type `setrlimit` takes for its resource argument.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
type Resource = libc::c_int;

/// `setrlimit(resource, min(soft, hard'), hard')` where `hard'` never exceeds
/// the current hard limit (raising it needs privilege). Async-signal-safe.
fn set_rlimit(resource: Resource, soft: u64, hard: u64) -> io::Result<()> {
    let mut cur = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `cur` is a valid out-pointer for the duration of the call.
    if unsafe { libc::getrlimit(resource, &mut cur) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let hard = (hard as libc::rlim_t).min(cur.rlim_max);
    let soft = (soft as libc::rlim_t).min(hard);
    let new = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: `new` is a valid in-pointer for the duration of the call.
    if unsafe { libc::setrlimit(resource, &new) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Highest descriptor the fallback loop will mark close-on-exec.
const FD_SCAN_CAP: libc::c_int = 1 << 16;

/// Mark every descriptor ≥ 3 close-on-exec. Async-signal-safe.
///
/// Close-on-exec rather than close: std's spawn uses a CLOEXEC pipe to report
/// a failed `exec` back to the parent, and closing it would turn every
/// sandbox failure into a silent success.
fn cloexec_inherited_fds() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: raw syscall with integer arguments only.
        let r = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        };
        if r == 0 {
            return Ok(());
        }
        // ENOSYS (< 5.9) / EINVAL (< 5.11, flag unknown): fall back.
    }
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid out-pointer.
    let max = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
        libc::c_int::try_from(lim.rlim_cur).unwrap_or(FD_SCAN_CAP)
    } else {
        FD_SCAN_CAP
    }
    .min(FD_SCAN_CAP);
    for fd in 3..max {
        // SAFETY: fcntl on an arbitrary integer is safe; EBADF for closed fds.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
            // SAFETY: as above.
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        }
    }
    Ok(())
}

impl ChildSetup {
    /// Engage the sandbox on the calling process.
    ///
    /// Runs in the forked child between `fork` and `exec`. Async-signal-safe:
    /// only raw syscalls on fields built by the parent; no allocation, no
    /// locks. The first failure aborts the spawn (std reports it as the
    /// spawn error), so no child ever execs half-sandboxed.
    fn run(&self) -> io::Result<()> {
        set_rlimit(libc::RLIMIT_CORE, 0, 0)?;
        // Address-space limits are Linux-only: macOS accepts RLIMIT_AS
        // inconsistently and does not enforce it.
        #[cfg(target_os = "linux")]
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

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            // Before anything changes credentials or installs the filter
            // (which refuses keyctl): drop possession of the parent's session
            // keyring. Where the seccomp filter will refuse the key syscalls
            // anyway, a failure here (e.g. EDQUOT) does not fail the spawn.
            // SAFETY: forked child, before exec.
            match unsafe { crate::linux::keyring::join_fresh_session() } {
                Ok(()) => {}
                Err(_) if self.seccomp.is_some() => {}
                Err(e) => return Err(e),
            }
            if let Some(maps) = &self.userns {
                // SAFETY: we are the single-threaded forked child.
                unsafe { crate::linux::userns::enter(maps)? };
            }
            if self.drop_caps {
                // SAFETY: forked child, before exec; after the namespace
                // entry, whose map writes need no capability.
                unsafe { crate::linux::caps::drop_all()? };
            }
            // Die with the spawning thread. Armed after every credential
            // change above (a change of uid/gid or a capability gain would
            // clear it). If the parent died before this point, getppid()
            // already names a reaper: fail rather than run unsupervised.
            // SAFETY: integer-only prctl.
            let r = unsafe {
                libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            if r != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: getppid cannot fail.
            if unsafe { libc::getppid() } != self.parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            if self.no_new_privs {
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
                unsafe { crate::linux::landlock::restrict_self(ruleset.as_raw_fd())? };
            }
            if let Some(filter) = &self.seccomp {
                // SAFETY: forked child, after NO_NEW_PRIVS; the program lives
                // in `self`, which outlives the call.
                unsafe { filter.install()? };
            }
        }
        Ok(())
    }
}

/// Canonicalize existing paths (Seatbelt matches resolved paths); keep
/// missing ones as given so the failure surfaces at spawn.
fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Build a `Command` that runs `profile.program` under `plan`.
///
/// The returned command has an empty environment plus the profile's entries,
/// its own process group (so a supervisor can kill everything it forks), and
/// a `pre_exec` hook that engages the sandbox. Stdio is left to the caller.
///
/// On Linux the child is killed (`PR_SET_PDEATHSIG`) when the *thread* that
/// spawns it exits, so a supervisor killed outright does not leave plugins
/// running. Spawn from a thread that outlives the child — the thread that
/// waits for it, or a runtime worker thread — not from a short-lived
/// helper thread.
///
/// Errors are raised here for anything that can be checked in the parent
/// (invalid profile, ruleset construction, a required path missing);
/// failures inside the child surface as the spawn error.
pub fn sandboxed_command(profile: &SandboxProfile, plan: &Plan) -> Result<Command, SandboxError> {
    profile.validate()?;

    let mut cmd = match &plan.mechanism {
        Mechanism::Landlock { .. } | Mechanism::Unsandboxed => {
            let mut c = Command::new(&profile.program);
            c.args(&profile.args);
            c.current_dir(profile.cwd.as_deref().unwrap_or(Path::new("/")));
            c
        }
        Mechanism::Bubblewrap { path } => {
            let mut c = Command::new(path);
            c.args(crate::bwrap::bwrap_args(profile, &|p: &Path| p.exists()));
            c.current_dir("/");
            c
        }
        Mechanism::Seatbelt { path } => {
            let mut resolved = profile.clone();
            resolved.program = canonical(&profile.program);
            for list in [
                &mut resolved.read_exec,
                &mut resolved.read_only,
                &mut resolved.read_write,
                &mut resolved.devices,
            ] {
                for p in list.iter_mut() {
                    *p = canonical(p);
                }
            }
            let sbpl = crate::seatbelt::seatbelt_profile(&resolved)?;
            let mut c = Command::new(path);
            c.arg("-p")
                .arg(sbpl)
                .arg(&resolved.program)
                .args(&profile.args);
            c.current_dir(profile.cwd.as_deref().unwrap_or(Path::new("/")));
            c
        }
    };
    cmd.env_clear();
    cmd.envs(profile.env.iter().map(|(k, v)| (k, v)));
    cmd.process_group(0);

    let setup = build_setup(profile, plan)?;
    let setup = Arc::new(setup);
    // SAFETY: `ChildSetup::run` is async-signal-safe (raw syscalls on data
    // prepared above; no allocation, no locks), which is the contract
    // `pre_exec` requires in a possibly multi-threaded parent.
    unsafe {
        cmd.pre_exec(move || setup.run());
    }
    Ok(cmd)
}

#[cfg(target_os = "linux")]
fn build_setup(profile: &SandboxProfile, plan: &Plan) -> Result<ChildSetup, SandboxError> {
    use crate::linux::{landlock, seccomp, userns};

    let landlock = match &plan.mechanism {
        Mechanism::Landlock { abi } => Some(landlock::build_ruleset(
            profile,
            *abi,
            plan.landlock_net,
            plan.landlock_scopes,
        )?),
        _ => None,
    };
    let seccomp = if plan.seccomp {
        Some(
            seccomp::Filter::for_native(seccomp::SocketPolicy {
                inet: profile.allow_network,
                unix: profile.allow_unix_sockets,
            })
            .ok_or_else(|| {
                SandboxError::Seccomp("no syscall table for this architecture".into())
            })?,
        )
    } else {
        None
    };
    Ok(ChildSetup {
        limits: profile.limits.clone(),
        no_new_privs: plan.no_new_privs,
        drop_caps: matches!(
            plan.mechanism,
            Mechanism::Landlock { .. } | Mechanism::Unsandboxed
        ),
        // SAFETY: getpid cannot fail.
        parent: unsafe { libc::getpid() },
        userns: plan.net_namespace.then(userns::IdMaps::identity),
        landlock,
        seccomp,
    })
}

#[cfg(not(target_os = "linux"))]
fn build_setup(profile: &SandboxProfile, _plan: &Plan) -> Result<ChildSetup, SandboxError> {
    Ok(ChildSetup {
        limits: profile.limits.clone(),
    })
}
