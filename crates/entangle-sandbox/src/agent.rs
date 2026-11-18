//! The OS sandbox for an *agent session* (spec §8.2, §8.5): the profile
//! `entangle agent run` engages on the agent subprocess.
//!
//! An agent is not a tier-5 plugin. It is an interactive program the user
//! started in a project directory: it inherits the terminal, the user's
//! environment and the foreground process group, it runs shells, compilers
//! and test suites, and it talks to its model provider over the network. The
//! native-plugin profile (empty environment, own process group, no network,
//! `setsid` refused, write-only-data scopes) would break all of that, so the
//! agent profile is a separate, deliberately different one built from the
//! same primitives:
//!
//! - **Landlock filesystem allowlist.** Readable and executable: the system
//!   trees (`/usr`, `/bin`, `/lib*`, `/etc`, `/opt`, …), `/proc` and `/sys`,
//!   the directories on `PATH`, the agent's install tree, and whatever the
//!   caller lists in [`AgentProfile::read_only`]. Writable as well: the
//!   project directory, the temporary directories, and whatever the caller
//!   lists in [`AgentProfile::read_write`] (the agent's own state
//!   directories, the session directory when the agent writes there).
//!   Everything else — the rest of the home directory with its keys and
//!   tokens, other projects — can be neither read nor written. On ABI ≥ 6
//!   signals and abstract Unix sockets are scoped to the sandbox.
//! - **`no_new_privs`** (setuid programs such as `sudo` gain nothing) and
//!   **no capabilities** (an agent started by root holds none).
//! - **A seccomp socket filter**: `socket()`/`socketpair()` succeed only for
//!   `AF_UNIX`, `AF_INET`, `AF_INET6` and `AF_NETLINK`, and never with
//!   `SOCK_RAW`/`SOCK_PACKET` on an IP family; packet sockets, Bluetooth,
//!   CAN, `AF_ALG` and every other family are refused. `io_uring_setup` is
//!   refused (io_uring creates sockets without the `socket` syscall), as is
//!   creating or joining namespaces (a user namespace would hand the agent
//!   capabilities of its own).
//! - **rlimits**: core dumps off; address-space, CPU-time and open-file
//!   limits when the caller sets them.
//!
//! # What this profile does NOT do
//! **Network egress is not restricted.** IP sockets are allowed to any
//! address: restricting the agent to the gateway plus an allowlist of hosts
//! (spec §8.3) needs a network namespace and a filtering proxy, which is not
//! implemented. The plan's [`describe`](AgentPlan::describe) says so every
//! time.
//!
//! # Degraded mode
//! Without Landlock (kernel < 5.13, or disabled at boot) there is no
//! filesystem allowlist. [`agent_plan`] then reports
//! [`AgentFilesystem::NotConfined`] with the reason; the remaining layers
//! (`no_new_privs`, capability drop, the socket filter, rlimits) still
//! apply, and the caller decides whether to start the agent (`entangle agent
//! run` does, with a warning, unless `--require-sandbox` was given).

use std::path::{Path, PathBuf};

use crate::probe::{HostSupport, Platform};
use crate::profile::ResourceLimits;

/// Errors raised while preparing the agent sandbox.
#[derive(Debug, thiserror::Error)]
pub enum AgentSandboxError {
    /// ENTANGLE-E0681: the sandbox could not be prepared (Landlock ruleset,
    /// seccomp program). The agent is not started.
    #[error("ENTANGLE-E0681: cannot prepare the agent sandbox: {0}")]
    Setup(String),

    /// ENTANGLE-E0682: a path given to the sandbox is unusable (relative,
    /// missing, or not resolvable).
    #[error("ENTANGLE-E0682: agent sandbox path {path}: {reason}")]
    Path {
        /// The offending path.
        path: PathBuf,
        /// Why it cannot be used.
        reason: String,
    },
}

/// System trees an agent may read and execute from. Missing ones are skipped.
pub const AGENT_SYSTEM_READ_EXEC: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/opt",
    "/etc",
    "/nix",
    "/gnu",
    "/snap",
    "/run/current-system",
    "/home/linuxbrew/.linuxbrew",
    "/proc",
    "/sys",
    // Targets of the `/etc/resolv.conf` symbolic link on common distributions.
    "/run/systemd/resolve",
    "/run/resolvconf",
    "/run/NetworkManager/resolv.conf",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
];

/// System locations an agent may also write. Missing ones are skipped.
pub const AGENT_SYSTEM_READ_WRITE: &[&str] = &["/dev/null", "/dev/shm"];

/// Terminal devices an agent may open and issue ioctls on (pty allocation,
/// window size, raw mode). Missing ones are skipped.
pub const AGENT_SYSTEM_DEVICES: &[&str] = &["/dev/tty", "/dev/ptmx", "/dev/pts"];

/// Temporary directories that are always writable (plus `$TMPDIR`).
pub const AGENT_TEMP_DIRS: &[&str] = &["/tmp", "/var/tmp"];

/// What the agent subprocess may touch. Paths are absolute; a listed path
/// that does not exist is skipped (an agent that was never run has no state
/// directory yet), except the program and the project directory.
#[derive(Clone, Debug)]
pub struct AgentProfile {
    /// The agent executable (absolute). Readable and executable.
    pub program: PathBuf,
    /// The project directory: readable, writable, executable.
    pub project_dir: PathBuf,
    /// Extra trees or files that are readable and executable (tool install
    /// paths, read-only configuration).
    pub read_only: Vec<PathBuf>,
    /// Extra trees or files that are readable, writable and executable (the
    /// agent's own config and cache directories).
    pub read_write: Vec<PathBuf>,
    /// Resource limits. Core dumps are always disabled; the other limits
    /// apply when set.
    pub limits: ResourceLimits,
}

impl AgentProfile {
    /// A profile for `program` working in `project_dir`, with no extra
    /// paths and no resource limits beyond disabled core dumps.
    pub fn new(program: impl Into<PathBuf>, project_dir: impl Into<PathBuf>) -> Self {
        // The three coarse limits are off for agents (V8 reserves a large
        // address space, sessions run for hours, and language servers hold
        // many descriptors). The struct update keeps the default of any
        // limit added to `ResourceLimits` later; today it sets nothing.
        #[allow(clippy::needless_update)]
        let limits = ResourceLimits {
            address_space_bytes: None,
            cpu_time_secs: None,
            open_files: None,
            ..ResourceLimits::default()
        };
        Self {
            program: program.into(),
            project_dir: project_dir.into(),
            read_only: Vec::new(),
            read_write: Vec::new(),
            limits,
        }
    }

    /// Grant read+execute on a tree or file.
    pub fn read_only(mut self, p: impl Into<PathBuf>) -> Self {
        self.read_only.push(p.into());
        self
    }

    /// Grant read+write+execute on a tree or file.
    pub fn read_write(mut self, p: impl Into<PathBuf>) -> Self {
        self.read_write.push(p.into());
        self
    }

    /// Replace the resource limits.
    pub fn limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The writable roots this profile resolves to on this host, for
    /// display: the project directory, the temporary directories and the
    /// existing entries of [`read_write`](Self::read_write).
    pub fn writable_roots(&self) -> Vec<PathBuf> {
        let mut out = vec![self.project_dir.clone()];
        out.extend(temp_dirs());
        out.extend(self.read_write.iter().filter(|p| p.exists()).cloned());
        dedup(out)
    }
}

/// How the agent's filesystem access is confined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentFilesystem {
    /// A Landlock allowlist at this ABI version.
    Landlock {
        /// ABI version reported by the kernel.
        abi: u32,
    },
    /// No filesystem confinement on this host.
    NotConfined {
        /// Operator-facing reason.
        reason: String,
    },
}

/// Which layers an agent session engages on this host. Produced by
/// [`agent_plan`] (pure, so every host shape is unit-tested).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentPlan {
    /// Filesystem confinement.
    pub filesystem: AgentFilesystem,
    /// Install the seccomp socket-family filter.
    pub seccomp: bool,
    /// Set `PR_SET_NO_NEW_PRIVS` and drop every capability.
    pub no_new_privs: bool,
    /// Landlock scopes signals and abstract Unix sockets (ABI ≥ 6).
    pub scopes: bool,
}

impl AgentPlan {
    /// Whether the filesystem allowlist is enforced.
    pub fn filesystem_confined(&self) -> bool {
        matches!(self.filesystem, AgentFilesystem::Landlock { .. })
    }

    /// Whether any layer at all is engaged.
    pub fn engages_anything(&self) -> bool {
        self.filesystem_confined() || self.seccomp || self.no_new_privs
    }

    /// The Landlock ABI in force, if any.
    pub fn landlock_abi(&self) -> Option<u32> {
        match self.filesystem {
            AgentFilesystem::Landlock { abi } => Some(abi),
            AgentFilesystem::NotConfined { .. } => None,
        }
    }

    /// `true` when every layer `--require-sandbox` asks for is engaged: a
    /// Landlock allowlist at ABI ≥ 3 (below 3 truncation is not restricted,
    /// so a read-only file can still be emptied), the seccomp filter, and
    /// `no_new_privs`.
    pub fn enforces_every_layer(&self) -> bool {
        self.landlock_abi()
            .is_some_and(|abi| abi >= MIN_FULL_LANDLOCK_ABI)
            && self.seccomp
            && self.no_new_privs
    }

    /// `true` when a layer of the full profile is missing on this host: no
    /// filesystem allowlist, Landlock below ABI 3, no socket filter, or no
    /// signal scoping.
    pub fn is_degraded(&self) -> bool {
        !self.enforces_every_layer() || !self.scopes
    }

    /// What Landlock at `abi` does not restrict, for the operator. Empty
    /// when there is no Landlock. The last entries hold at every ABI.
    pub fn landlock_gaps(&self) -> Vec<&'static str> {
        let Some(abi) = self.landlock_abi() else {
            return Vec::new();
        };
        let mut gaps = Vec::new();
        if abi < 2 {
            gaps.push("files cannot be renamed or linked across directories (Landlock ABI 1)");
        }
        if abi < 3 {
            gaps.push("truncation NOT restricted (Landlock ABI < 3)");
        }
        if abi < 5 {
            gaps.push("device ioctls NOT restricted (Landlock ABI < 5)");
        }
        if abi < 6 {
            gaps.push(
                "signals and abstract Unix sockets NOT scoped (Landlock ABI < 6: the agent can \
                 signal your other processes)",
            );
        }
        gaps.push("chmod, chown, timestamps and extended attributes NOT restricted by Landlock");
        gaps.push(
            "local Unix sockets (D-Bus, ssh-agent, tmux, X11, Docker, the Entanglement daemon) \
             stay reachable",
        );
        gaps
    }

    /// Operator-facing summary. Always ends by stating that network egress
    /// is not restricted, because it is not.
    pub fn describe(&self) -> String {
        let mut layers: Vec<String> = Vec::new();
        match &self.filesystem {
            AgentFilesystem::Landlock { abi } => {
                layers.push(format!("Landlock ABI {abi} filesystem allowlist"));
            }
            AgentFilesystem::NotConfined { reason } => {
                layers.push(format!("NO filesystem allowlist ({reason})"));
            }
        }
        if self.seccomp {
            layers.push("seccomp socket filter".to_owned());
        }
        if self.no_new_privs {
            layers.push("no_new_privs".to_owned());
        }
        let mut out = layers.join(" + ");
        for gap in self.landlock_gaps() {
            out.push_str("; ");
            out.push_str(gap);
        }
        if self.engages_anything() && !self.seccomp {
            out.push_str("; NO seccomp: socket families are NOT filtered");
        }
        out.push_str("; network egress NOT restricted");
        out
    }
}

/// The lowest Landlock ABI `--require-sandbox` accepts: ABI 3 adds
/// `LANDLOCK_ACCESS_FS_TRUNCATE`.
pub const MIN_FULL_LANDLOCK_ABI: u32 = 3;

/// Choose the layers for an agent session on `host`.
///
/// Linux: Landlock when the kernel has it (any ABI), the seccomp filter when
/// available, `no_new_privs` always. Other platforms: nothing is engaged
/// (the macOS Seatbelt profile of spec §8.2 is not implemented for agents).
pub fn agent_plan(host: &HostSupport) -> AgentPlan {
    match &host.platform {
        Platform::Linux => match host.landlock_abi.filter(|a| *a >= 1) {
            Some(abi) => AgentPlan {
                filesystem: AgentFilesystem::Landlock { abi },
                seccomp: host.seccomp,
                no_new_privs: true,
                scopes: abi >= 6,
            },
            None => AgentPlan {
                filesystem: AgentFilesystem::NotConfined {
                    reason: "Landlock is not available: kernel older than 5.13, or Landlock \
                             not enabled at boot"
                        .to_owned(),
                },
                seccomp: host.seccomp,
                no_new_privs: true,
                scopes: false,
            },
        },
        Platform::MacOs => unconfined(
            "the agent sandbox is implemented for Linux only; on macOS \
             the agent runs without one",
        ),
        Platform::Unsupported { reason } => unconfined(reason),
    }
}

fn unconfined(reason: &str) -> AgentPlan {
    AgentPlan {
        filesystem: AgentFilesystem::NotConfined {
            reason: reason.to_owned(),
        },
        seccomp: false,
        no_new_privs: false,
        scopes: false,
    }
}

/// The temporary directories that exist here: [`AGENT_TEMP_DIRS`] plus an
/// absolute `$TMPDIR`.
pub fn temp_dirs() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = AGENT_TEMP_DIRS.iter().map(PathBuf::from).collect();
    if let Some(t) = std::env::var_os("TMPDIR").map(PathBuf::from) {
        if t.is_absolute() {
            out.push(t);
        }
    }
    dedup(out.into_iter().filter(|p| p.is_dir()).collect())
}

fn dedup(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::with_capacity(paths.len());
    for p in paths {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// The trees that make up the install of `program`, for the read+execute
/// allowlist: an agent installed under the home directory (npm prefix,
/// `nvm`, `pipx`, a native installer) is usually a symbolic link in a `bin`
/// directory pointing into a package tree, and both must be readable.
///
/// Returned (existing paths only, canonical):
/// - the directory holding `program`, and the directory holding the file it
///   resolves to;
/// - when the resolved file lies in a `node_modules` tree, the package
///   directory directly under the outermost `node_modules`, and the `bin`
///   directory next to `lib` in that prefix (where `node` itself lives);
/// - when the resolved file lies in `<root>/bin/`, `<root>/lib` and
///   `<root>/libexec` (a self-contained virtualenv or tool prefix).
///
/// Nothing above the program's own trees is granted: never the home
/// directory, never `~/.local` as a whole.
pub fn install_roots(program: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut add = |p: &Path| {
        if let Ok(c) = std::fs::canonicalize(p) {
            if c.parent().is_some() {
                out.push(c);
            }
        }
    };
    if let Some(dir) = program.parent() {
        add(dir);
    }
    let Ok(real) = std::fs::canonicalize(program) else {
        return dedup(out);
    };
    if let Some(dir) = real.parent() {
        add(dir);
        if dir.file_name().is_some_and(|n| n == "bin") {
            if let Some(root) = dir.parent() {
                add(&root.join("lib"));
                add(&root.join("libexec"));
            }
        }
    }
    // Outermost `node_modules` component of the resolved path.
    let comps: Vec<_> = real.components().collect();
    if let Some(i) = comps.iter().position(|c| c.as_os_str() == "node_modules") {
        let node_modules: PathBuf = comps[..=i].iter().collect();
        let mut pkg = node_modules.clone();
        if let Some(first) = comps.get(i + 1) {
            pkg.push(first);
            // Scoped package: `@scope/name`.
            if first.as_os_str().to_string_lossy().starts_with('@') {
                if let Some(second) = comps.get(i + 2) {
                    pkg.push(second);
                }
            }
            add(&pkg);
        }
        // `<prefix>/lib/node_modules` → `<prefix>/bin`.
        if let Some(prefix) = node_modules.parent().and_then(Path::parent) {
            add(&prefix.join("bin"));
        }
    }
    dedup(out)
}

/// Engage the agent sandbox on `cmd`'s child: adds a `pre_exec` hook that
/// applies the rlimits, drops capabilities, sets `no_new_privs`, restricts
/// the process with the Landlock ruleset built here from `profile`, and
/// installs the seccomp filter — whichever of those `plan` names.
///
/// Unlike [`crate::sandboxed_command`] the command's environment, working
/// directory, stdio and process group are left exactly as the caller set
/// them: the agent stays the terminal's foreground job with the user's
/// environment.
///
/// Fails closed: an error here (a ruleset that cannot be built) means the
/// caller must not spawn, and a step that fails in the child fails the
/// spawn. A plan that engages nothing (non-Linux) leaves `cmd` untouched.
#[cfg(target_os = "linux")]
pub fn confine_agent_command(
    cmd: &mut std::process::Command,
    profile: &AgentProfile,
    plan: &AgentPlan,
) -> Result<(), AgentSandboxError> {
    crate::unix::agent::confine(cmd, profile, plan)
}

/// Engage the agent sandbox on `cmd`'s child. On this platform no layer is
/// implemented: the command is left untouched (see [`agent_plan`]).
#[cfg(not(target_os = "linux"))]
pub fn confine_agent_command(
    _cmd: &mut std::process::Command,
    _profile: &AgentProfile,
    _plan: &AgentPlan,
) -> Result<(), AgentSandboxError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux(landlock: Option<u32>, seccomp: bool) -> HostSupport {
        HostSupport {
            platform: Platform::Linux,
            landlock_abi: landlock,
            user_namespaces: false,
            seccomp,
            bubblewrap: None,
            sandbox_exec: None,
        }
    }

    #[test]
    fn full_profile_on_a_current_kernel() {
        let p = agent_plan(&linux(Some(7), true));
        assert_eq!(p.filesystem, AgentFilesystem::Landlock { abi: 7 });
        assert!(p.seccomp && p.no_new_privs && p.scopes);
        assert!(!p.is_degraded());
        let d = p.describe();
        assert!(d.contains("Landlock ABI 7 filesystem allowlist"), "{d}");
        assert!(d.contains("seccomp socket filter"), "{d}");
        // Never claims a network restriction.
        assert!(d.ends_with("network egress NOT restricted"), "{d}");
    }

    #[test]
    fn landlock_unavailable_is_degraded_and_says_why() {
        let p = agent_plan(&linux(None, true));
        assert!(!p.filesystem_confined());
        assert!(p.is_degraded());
        // The remaining layers still apply.
        assert!(p.seccomp && p.no_new_privs && p.engages_anything());
        let d = p.describe();
        assert!(d.contains("NO filesystem allowlist"), "{d}");
        assert!(d.contains("Landlock is not available"), "{d}");
        assert!(d.contains("kernel older than 5.13"), "{d}");
    }

    #[test]
    fn old_landlock_abi_reports_unscoped_signals() {
        let p = agent_plan(&linux(Some(3), true));
        assert!(p.filesystem_confined() && !p.scopes && p.is_degraded());
        assert!(p
            .describe()
            .contains("signals and abstract Unix sockets NOT scoped"));
    }

    #[test]
    fn landlock_below_abi_3_is_degraded_and_names_the_gaps() {
        for abi in [1, 2] {
            let p = agent_plan(&linux(Some(abi), true));
            assert!(p.filesystem_confined() && p.is_degraded());
            assert!(!p.enforces_every_layer(), "ABI {abi}");
            let d = p.describe();
            assert!(d.contains("truncation NOT restricted"), "{d}");
            assert!(d.contains("chmod, chown"), "{d}");
        }
        assert!(agent_plan(&linux(Some(1), true))
            .describe()
            .contains("renamed or linked across directories"));
        let p = agent_plan(&linux(Some(3), true));
        assert!(p.enforces_every_layer());
        assert!(!p.describe().contains("truncation"));
        // No ABI closes the Unix-socket gap.
        let p = agent_plan(&linux(Some(7), true));
        assert!(
            p.describe().contains("local Unix sockets"),
            "{}",
            p.describe()
        );
        assert!(!p.describe().contains("NOT scoped"));
    }

    #[test]
    fn every_layer_needs_seccomp_too() {
        assert!(!agent_plan(&linux(Some(7), false)).enforces_every_layer());
        assert!(!agent_plan(&linux(None, true)).enforces_every_layer());
    }

    #[test]
    fn missing_seccomp_is_reported() {
        let p = agent_plan(&linux(Some(7), false));
        assert!(p.is_degraded());
        assert!(p.describe().contains("NO seccomp"));
    }

    #[test]
    fn other_platforms_engage_nothing_and_say_so() {
        let mac = HostSupport {
            platform: Platform::MacOs,
            landlock_abi: None,
            user_namespaces: false,
            seccomp: false,
            bubblewrap: None,
            sandbox_exec: Some(PathBuf::from("/usr/bin/sandbox-exec")),
        };
        let p = agent_plan(&mac);
        assert!(!p.engages_anything() && p.is_degraded());
        assert!(p.describe().contains("Linux only"), "{}", p.describe());
    }

    #[test]
    fn profile_defaults_set_no_coarse_limits() {
        let p = AgentProfile::new("/usr/bin/agent", "/work/project");
        assert_eq!(p.limits.address_space_bytes, None);
        assert_eq!(p.limits.cpu_time_secs, None);
        assert_eq!(p.limits.open_files, None);
        assert_eq!(p.writable_roots()[0], PathBuf::from("/work/project"));
    }

    #[test]
    fn install_roots_follow_a_bin_link_into_a_node_package() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let pkg = root.join("prefix/lib/node_modules/@scope/agent");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::create_dir_all(root.join("prefix/bin")).unwrap();
        std::fs::write(pkg.join("cli.js"), "#!/usr/bin/env node\n").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(pkg.join("cli.js"), root.join("prefix/bin/agent")).unwrap();
            let roots = install_roots(&root.join("prefix/bin/agent"));
            assert!(roots.contains(&root.join("prefix/bin")), "{roots:?}");
            assert!(roots.contains(&pkg), "{roots:?}");
            // Never the prefix's parent, never a sibling package.
            assert!(!roots.contains(&root), "{roots:?}");
            assert!(roots.iter().all(|r| r.starts_with(root.join("prefix"))));
        }
    }

    #[test]
    fn install_roots_of_a_prefix_binary_include_its_lib() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("venv/bin")).unwrap();
        std::fs::create_dir_all(root.join("venv/lib")).unwrap();
        std::fs::write(root.join("venv/bin/agent"), "").unwrap();
        let roots = install_roots(&root.join("venv/bin/agent"));
        assert_eq!(roots, vec![root.join("venv/bin"), root.join("venv/lib")]);
    }
}
