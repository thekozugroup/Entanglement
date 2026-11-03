//! [`SandboxProfile`] — the platform-neutral description of what a sandboxed
//! child may touch.
//!
//! A profile is *derived from granted capabilities* by the caller (the
//! runtime maps `storage.local`, `net.*`, … onto it); this crate turns it into
//! Landlock rules, a bubblewrap argv, or a Seatbelt SBPL program. Everything a
//! profile does not name is denied.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::SandboxError;

/// Resource limits applied to the child with `setrlimit` before `exec`.
///
/// `None` leaves the inherited limit untouched. Core dumps are always
/// disabled (`RLIMIT_CORE = 0`): a core file of a plugin could contain
/// secrets handed to it and would land outside its storage scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    /// `RLIMIT_AS`: maximum virtual address space, in bytes (Linux only;
    /// macOS does not enforce it).
    ///
    /// Address-space limits are coarse (they count reservations, not resident
    /// memory); runtimes that reserve large virtual regions up front (V8's
    /// pointer cage) need a generous value or `None`.
    pub address_space_bytes: Option<u64>,
    /// `RLIMIT_CPU`: CPU seconds. The soft limit delivers `SIGXCPU`, the hard
    /// limit (one second later) `SIGKILL`.
    pub cpu_time_secs: Option<u64>,
    /// `RLIMIT_NOFILE`: maximum number of open file descriptors.
    pub open_files: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            address_space_bytes: Some(2 * 1024 * 1024 * 1024),
            cpu_time_secs: Some(60),
            open_files: Some(256),
        }
    }
}

/// What a sandboxed child may do. Build with [`SandboxProfile::new`] and the
/// chained setters; everything not granted is denied.
#[derive(Clone, Debug)]
pub struct SandboxProfile {
    /// Absolute path of the executable to run. It is granted read+execute.
    pub program: PathBuf,
    /// Arguments passed to the program (not including `argv[0]`).
    pub args: Vec<OsString>,
    /// The child's *entire* environment: nothing is inherited from the parent.
    pub env: Vec<(OsString, OsString)>,
    /// Working directory. Defaults to `/` (always resolvable, never listable).
    pub cwd: Option<PathBuf>,
    /// Trees the child may read and execute from (e.g. the plugin directory).
    pub read_exec: Vec<PathBuf>,
    /// Trees or files the child may read.
    pub read_only: Vec<PathBuf>,
    /// Trees or files the child may read and write (its storage scopes).
    pub read_write: Vec<PathBuf>,
    /// Device nodes (or directories of them, e.g. `/dev/dri`) the child may
    /// open read-write *and issue ioctls on* — GPU drivers work almost
    /// entirely through ioctls. Ordinary scopes never get device ioctls.
    pub devices: Vec<PathBuf>,
    /// Whether outbound/inbound IP networking is allowed.
    pub allow_network: bool,
    /// Whether the child may create `AF_UNIX` sockets (e.g. to reach a
    /// granted Docker socket). Off by default: a path-addressed Unix socket is
    /// not covered by filesystem rules, so this is how the daemon's own RPC
    /// socket stays out of reach.
    pub allow_unix_sockets: bool,
    /// Whether to add the minimal system paths a dynamically linked program
    /// needs (`/lib`, `/usr/lib`, the loader cache, `/dev/null`, …). Default
    /// `true`; turn off only for statically linked programs.
    pub system_paths: bool,
    /// Resource limits applied before `exec`.
    pub limits: ResourceLimits,
}

impl SandboxProfile {
    /// A deny-everything profile that may only run `program`.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            read_exec: Vec::new(),
            read_only: Vec::new(),
            read_write: Vec::new(),
            devices: Vec::new(),
            allow_network: false,
            allow_unix_sockets: false,
            system_paths: true,
            limits: ResourceLimits::default(),
        }
    }

    /// Append a program argument.
    pub fn arg(mut self, a: impl Into<OsString>) -> Self {
        self.args.push(a.into());
        self
    }

    /// Set an environment variable for the child.
    pub fn env(mut self, k: impl Into<OsString>, v: impl Into<OsString>) -> Self {
        self.env.push((k.into(), v.into()));
        self
    }

    /// Set the working directory.
    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// Grant read+execute on a tree.
    pub fn read_exec(mut self, p: impl Into<PathBuf>) -> Self {
        self.read_exec.push(p.into());
        self
    }

    /// Grant read on a tree or file.
    pub fn read_only(mut self, p: impl Into<PathBuf>) -> Self {
        self.read_only.push(p.into());
        self
    }

    /// Grant read+write on a tree or file.
    pub fn read_write(mut self, p: impl Into<PathBuf>) -> Self {
        self.read_write.push(p.into());
        self
    }

    /// Grant read+write+ioctl on a device node or a directory of them.
    pub fn device(mut self, p: impl Into<PathBuf>) -> Self {
        self.devices.push(p.into());
        self
    }

    /// Allow or deny IP networking.
    pub fn allow_network(mut self, yes: bool) -> Self {
        self.allow_network = yes;
        self
    }

    /// Allow or deny creating `AF_UNIX` sockets.
    pub fn allow_unix_sockets(mut self, yes: bool) -> Self {
        self.allow_unix_sockets = yes;
        self
    }

    /// Replace the resource limits.
    pub fn limits(mut self, l: ResourceLimits) -> Self {
        self.limits = l;
        self
    }

    /// Check the profile is usable: every path absolute and NUL-free.
    pub fn validate(&self) -> Result<(), SandboxError> {
        let all = std::iter::once(&self.program)
            .chain(self.cwd.iter())
            .chain(self.read_exec.iter())
            .chain(self.read_only.iter())
            .chain(self.read_write.iter())
            .chain(self.devices.iter());
        for p in all {
            check_path(p)?;
        }
        for a in &self.args {
            if a.as_encoded_bytes().contains(&0) {
                return Err(SandboxError::InvalidProfile(
                    "argument contains a NUL byte".into(),
                ));
            }
        }
        for (k, v) in &self.env {
            if k.as_encoded_bytes().contains(&0)
                || v.as_encoded_bytes().contains(&0)
                || k.as_encoded_bytes().contains(&b'=')
            {
                return Err(SandboxError::InvalidProfile(format!(
                    "invalid environment entry {k:?}"
                )));
            }
        }
        Ok(())
    }
}

fn check_path(p: &Path) -> Result<(), SandboxError> {
    if !p.is_absolute() {
        return Err(SandboxError::InvalidProfile(format!(
            "path {} is not absolute",
            p.display()
        )));
    }
    if p.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(SandboxError::InvalidProfile(format!(
            "path {} contains a NUL byte",
            p.display()
        )));
    }
    Ok(())
}

/// System paths a dynamically linked Linux program needs, read+execute:
/// the dynamic loader and shared libraries.
///
/// The ELF interpreter is opened by the kernel with exec intent, so Landlock
/// requires `EXECUTE` on it, not just `READ_FILE`. Missing entries are skipped.
pub const LINUX_SYSTEM_READ_EXEC: &[&str] = &[
    "/lib",
    "/lib32",
    "/lib64",
    "/usr/lib",
    "/usr/lib32",
    "/usr/lib64",
    "/usr/local/lib",
];

/// System files a Linux program may read: loader configuration, time zones,
/// and the harmless character devices.
pub const LINUX_SYSTEM_READ_ONLY: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/localtime",
    "/usr/share/zoneinfo",
    "/dev/urandom",
    "/dev/random",
    "/dev/zero",
];

/// System files a Linux program may write.
pub const LINUX_SYSTEM_READ_WRITE: &[&str] = &["/dev/null"];

/// Extra read-only files needed only when networking is granted: name
/// resolution and the trust store for TLS.
pub const LINUX_NETWORK_READ_ONLY: &[&str] = &[
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/gai.conf",
    "/etc/host.conf",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/pki",
    "/usr/share/ca-certificates",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_profile_denies_everything_but_the_program() {
        let p = SandboxProfile::new("/opt/plugin/bin");
        assert!(!p.allow_network);
        assert!(!p.allow_unix_sockets);
        assert!(p.read_write.is_empty() && p.read_only.is_empty() && p.read_exec.is_empty());
        assert!(p.env.is_empty());
        p.validate().unwrap();
    }

    #[test]
    fn relative_and_nul_paths_are_rejected() {
        let err = SandboxProfile::new("bin/plugin").validate().unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0704"), "{err}");
        let err = SandboxProfile::new("/bin/x")
            .read_write("data")
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("not absolute"), "{err}");
        let err = SandboxProfile::new("/bin/x")
            .env("A=B", "c")
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("environment"), "{err}");
    }

    #[test]
    fn default_limits_disable_nothing_silently() {
        let l = ResourceLimits::default();
        assert!(l.address_space_bytes.is_some());
        assert!(l.cpu_time_secs.is_some());
        assert!(l.open_files.is_some());
    }
}
