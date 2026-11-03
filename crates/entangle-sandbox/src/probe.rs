//! Host capability probes: what sandbox primitives this machine offers.
//!
//! [`probe`] performs the checks once per process and caches the result. It
//! never engages a sandbox on the calling process. On Linux the user-namespace
//! check forks a short-lived child that attempts `unshare` and writes its own
//! uid/gid maps, because a host can allow `unshare(CLONE_NEWUSER)` and still
//! deny the map writes (AppArmor's `apparmor_restrict_unprivileged_userns`):
//! only the full sequence tells the truth.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The operating-system family, as far as native plugins are concerned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Platform {
    /// Linux: Landlock + seccomp + namespaces, bubblewrap fallback.
    Linux,
    /// macOS: Seatbelt via `sandbox-exec`.
    MacOs,
    /// Anything else: native plugins are not supported.
    Unsupported {
        /// Operator-facing reason.
        reason: &'static str,
    },
}

/// What the host offers. Produced by [`probe`]; also constructible by hand so
/// [`crate::plan()`] can be tested against every host shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostSupport {
    /// OS family.
    pub platform: Platform,
    /// Landlock ABI version (Linux), from the version query syscall. `None`
    /// when the kernel lacks Landlock or it is disabled at boot.
    pub landlock_abi: Option<u32>,
    /// Whether an unprivileged process can create a user + network namespace
    /// *and* map its own uid/gid in it (Linux).
    pub user_namespaces: bool,
    /// Whether seccomp-bpf filters can be installed and this crate knows the
    /// syscall numbers for the running architecture (Linux).
    pub seccomp: bool,
    /// Path of the `bwrap` executable, if one is on `PATH` (Linux).
    pub bubblewrap: Option<PathBuf>,
    /// Path of `sandbox-exec` (macOS).
    pub sandbox_exec: Option<PathBuf>,
}

impl HostSupport {
    /// Whether any primitive that can confine the filesystem is present.
    pub fn has_primitive(&self) -> bool {
        match self.platform {
            Platform::Linux => self.landlock_abi.is_some() || self.bubblewrap.is_some(),
            Platform::MacOs => self.sandbox_exec.is_some(),
            Platform::Unsupported { .. } => false,
        }
    }

    /// One-line operator-facing summary, e.g. for `entangle doctor` and
    /// `entangle print-platform`.
    pub fn describe(&self) -> String {
        match &self.platform {
            Platform::Linux => {
                let mut parts = Vec::new();
                match self.landlock_abi {
                    Some(abi) => parts.push(format!("Landlock ABI {abi}")),
                    None => parts.push("no Landlock".to_owned()),
                }
                parts.push(if self.seccomp {
                    "seccomp-bpf".to_owned()
                } else {
                    "no seccomp".to_owned()
                });
                parts.push(if self.user_namespaces {
                    "user+net namespaces".to_owned()
                } else {
                    "no unprivileged user namespaces".to_owned()
                });
                if let Some(b) = &self.bubblewrap {
                    parts.push(format!("bubblewrap at {}", b.display()));
                }
                parts.join(", ")
            }
            Platform::MacOs => match &self.sandbox_exec {
                Some(p) => format!("macOS Seatbelt ({})", p.display()),
                None => "macOS without sandbox-exec".to_owned(),
            },
            Platform::Unsupported { reason } => (*reason).to_owned(),
        }
    }
}

/// Probe the host once and cache the answer for the life of the process.
pub fn probe() -> &'static HostSupport {
    static CACHE: OnceLock<HostSupport> = OnceLock::new();
    CACHE.get_or_init(probe_uncached)
}

/// Probe the host without the cache (for diagnostics that want fresh data).
pub fn probe_uncached() -> HostSupport {
    #[cfg(target_os = "linux")]
    {
        HostSupport {
            platform: Platform::Linux,
            landlock_abi: crate::linux::landlock::abi_version(),
            user_namespaces: crate::linux::userns::probe(),
            seccomp: crate::linux::seccomp::supported(),
            bubblewrap: find_in_path("bwrap"),
            sandbox_exec: None,
        }
    }
    #[cfg(target_os = "macos")]
    {
        let fixed = PathBuf::from("/usr/bin/sandbox-exec");
        let sandbox_exec = if fixed.is_file() {
            Some(fixed)
        } else {
            find_in_path("sandbox-exec")
        };
        HostSupport {
            platform: Platform::MacOs,
            landlock_abi: None,
            user_namespaces: false,
            seccomp: false,
            bubblewrap: None,
            sandbox_exec,
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        HostSupport {
            platform: Platform::Unsupported {
                reason: if cfg!(windows) {
                    "native Windows (AppContainer) support is Phase 5+; use WSL2"
                } else {
                    "no sandbox primitive is supported on this platform"
                },
            },
            landlock_abi: None,
            user_namespaces: false,
            seccomp: false,
            bubblewrap: None,
            sandbox_exec: None,
        }
    }
}

/// Look `name` up on `PATH` without spawning anything.
pub fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_is_cached_and_platform_consistent() {
        let a = probe();
        let b = probe();
        assert!(std::ptr::eq(a, b), "probe must be computed once");
        #[cfg(target_os = "linux")]
        assert_eq!(a.platform, Platform::Linux);
        #[cfg(target_os = "macos")]
        assert_eq!(a.platform, Platform::MacOs);
        assert!(!a.describe().is_empty());
    }

    /// The fix this module exists for: Landlock is detected through the ABI
    /// version syscall. If the kernel answers, the ABI is at least 1.
    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_abi_comes_from_the_syscall() {
        if let Some(abi) = crate::linux::landlock::abi_version() {
            assert!(abi >= 1);
            assert!(probe().describe().contains(&format!("Landlock ABI {abi}")));
        }
    }

    #[test]
    fn describe_names_every_linux_layer() {
        let h = HostSupport {
            platform: Platform::Linux,
            landlock_abi: Some(4),
            user_namespaces: false,
            seccomp: true,
            bubblewrap: Some(PathBuf::from("/usr/bin/bwrap")),
            sandbox_exec: None,
        };
        let d = h.describe();
        assert!(d.contains("Landlock ABI 4"), "{d}");
        assert!(d.contains("seccomp-bpf"), "{d}");
        assert!(d.contains("no unprivileged user namespaces"), "{d}");
        assert!(d.contains("bubblewrap"), "{d}");
        assert!(h.has_primitive());
    }

    #[test]
    fn find_in_path_misses_nonsense() {
        assert!(find_in_path("entangle-definitely-not-a-binary-xyz").is_none());
    }
}
