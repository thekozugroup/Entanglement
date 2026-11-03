//! Landlock: ABI probe, ruleset construction (parent) and self-restriction
//! (child, async-signal-safe).
//!
//! The kernel UAPI (`linux/landlock.h`) is not in the `libc` crate beyond the
//! syscall numbers, so the structs and access bits are declared here.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::error::SandboxError;
use crate::profile::{
    SandboxProfile, LINUX_NETWORK_READ_ONLY, LINUX_SYSTEM_READ_EXEC, LINUX_SYSTEM_READ_ONLY,
    LINUX_SYSTEM_READ_WRITE,
};

// ── UAPI ─────────────────────────────────────────────────────────────────────

const CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;
const RULE_PATH_BENEATH: libc::c_int = 1;

/// `LANDLOCK_ACCESS_FS_*` (ABI 1 unless noted).
pub(crate) mod fs {
    pub const EXECUTE: u64 = 1 << 0;
    pub const WRITE_FILE: u64 = 1 << 1;
    pub const READ_FILE: u64 = 1 << 2;
    pub const READ_DIR: u64 = 1 << 3;
    pub const REMOVE_DIR: u64 = 1 << 4;
    pub const REMOVE_FILE: u64 = 1 << 5;
    /// Listed for UAPI completeness; deliberately never granted.
    #[allow(dead_code)]
    pub const MAKE_CHAR: u64 = 1 << 6;
    pub const MAKE_DIR: u64 = 1 << 7;
    pub const MAKE_REG: u64 = 1 << 8;
    pub const MAKE_SOCK: u64 = 1 << 9;
    pub const MAKE_FIFO: u64 = 1 << 10;
    /// Listed for UAPI completeness; deliberately never granted.
    #[allow(dead_code)]
    pub const MAKE_BLOCK: u64 = 1 << 11;
    pub const MAKE_SYM: u64 = 1 << 12;
    /// ABI 2.
    pub const REFER: u64 = 1 << 13;
    /// ABI 3.
    pub const TRUNCATE: u64 = 1 << 14;
    /// ABI 5.
    pub const IOCTL_DEV: u64 = 1 << 15;

    /// Rights that may appear in a rule on a non-directory.
    pub const FILE_ONLY: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;
}

/// `LANDLOCK_ACCESS_NET_*` (ABI 4).
const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;

/// `LANDLOCK_SCOPE_*` (ABI 6).
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

// ── probe ────────────────────────────────────────────────────────────────────

/// The Landlock ABI version, or `None` when Landlock is not built in or is
/// disabled at boot (`ENOSYS` / `EOPNOTSUPP`).
pub(crate) fn abi_version() -> Option<u32> {
    // SAFETY: with a NULL attribute pointer, size 0 and the VERSION flag the
    // kernel only returns the ABI number; no memory is read or written and no
    // file descriptor is created.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if r >= 1 {
        u32::try_from(r).ok()
    } else {
        None
    }
}

/// Every filesystem right the kernel at `abi` understands.
pub(crate) fn fs_handled(abi: u32) -> u64 {
    let mut all = (1u64 << 13) - 1; // ABI 1: EXECUTE..=MAKE_SYM
    if abi >= 2 {
        all |= fs::REFER;
    }
    if abi >= 3 {
        all |= fs::TRUNCATE;
    }
    if abi >= 5 {
        all |= fs::IOCTL_DEV;
    }
    all
}

/// Access classes a profile path can be granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Access {
    /// Read and execute.
    Rx,
    /// Read only.
    Ro,
    /// Read and write (no execute, no device nodes, no device ioctls).
    Rw,
    /// Device nodes: read, write and ioctl (`IOCTL_DEV`, ABI ≥ 5) — nothing
    /// that creates, removes or renames entries.
    Dev,
}

impl Access {
    /// Rights for a directory rule under `handled`.
    pub(crate) fn dir_rights(self, handled: u64) -> u64 {
        let r = match self {
            Access::Rx => fs::EXECUTE | fs::READ_FILE | fs::READ_DIR,
            Access::Ro => fs::READ_FILE | fs::READ_DIR,
            // Everything except executing and creating device nodes: a
            // plugin may not write code into its data directory and run it.
            Access::Rw => {
                fs::WRITE_FILE
                    | fs::READ_FILE
                    | fs::READ_DIR
                    | fs::REMOVE_DIR
                    | fs::REMOVE_FILE
                    | fs::MAKE_DIR
                    | fs::MAKE_REG
                    | fs::MAKE_SOCK
                    | fs::MAKE_FIFO
                    | fs::MAKE_SYM
                    | fs::REFER
                    | fs::TRUNCATE
            }
            Access::Dev => fs::READ_FILE | fs::WRITE_FILE | fs::READ_DIR | fs::IOCTL_DEV,
        };
        r & handled
    }

    /// Rights for a rule on a single file under `handled`.
    pub(crate) fn file_rights(self, handled: u64) -> u64 {
        let r = match self {
            Access::Rx => fs::EXECUTE | fs::READ_FILE,
            Access::Ro => fs::READ_FILE,
            Access::Rw => fs::READ_FILE | fs::WRITE_FILE | fs::TRUNCATE,
            Access::Dev => fs::READ_FILE | fs::WRITE_FILE | fs::IOCTL_DEV,
        };
        r & handled & fs::FILE_ONLY
    }
}

/// One allowlist entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rule {
    pub(crate) path: PathBuf,
    pub(crate) access: Access,
    /// Profile-named paths are required (a missing one fails the build);
    /// system paths that do not exist on this host are skipped.
    pub(crate) required: bool,
    /// Whether symbolic links in the path are followed. Scopes (read-only,
    /// read-write, devices) are resolved without following any link: a
    /// plugin with write access to a share could otherwise swap another
    /// plugin's scope directory (or one above it) for a link and have that
    /// plugin's next invocation granted the link's target. The program, the
    /// read-exec trees and the system paths (`/lib` → `usr/lib`) follow.
    pub(crate) follow_links: bool,
}

fn rule(path: &Path, access: Access, required: bool, follow_links: bool) -> Rule {
    Rule {
        path: path.to_path_buf(),
        access,
        required,
        follow_links,
    }
}

/// The rule list for `profile`. Optional entries (system paths) that do not
/// exist on this host are skipped; required ones (everything the profile
/// names) fail the build.
pub(crate) fn rules_for(profile: &SandboxProfile) -> Vec<Rule> {
    let mut rules = vec![rule(&profile.program, Access::Rx, true, true)];
    rules.extend(
        profile
            .read_exec
            .iter()
            .map(|p| rule(p, Access::Rx, true, true)),
    );
    rules.extend(
        profile
            .read_only
            .iter()
            .map(|p| rule(p, Access::Ro, true, false)),
    );
    rules.extend(
        profile
            .read_write
            .iter()
            .map(|p| rule(p, Access::Rw, true, false)),
    );
    rules.extend(
        profile
            .devices
            .iter()
            .map(|p| rule(p, Access::Dev, true, false)),
    );
    if profile.system_paths {
        let sys = |list: &[&str], a: Access| {
            list.iter()
                .map(move |p| rule(Path::new(p), a, false, true))
                .collect::<Vec<_>>()
        };
        rules.extend(sys(LINUX_SYSTEM_READ_EXEC, Access::Rx));
        rules.extend(sys(LINUX_SYSTEM_READ_ONLY, Access::Ro));
        rules.extend(sys(LINUX_SYSTEM_READ_WRITE, Access::Rw));
        if profile.allow_network {
            rules.extend(sys(LINUX_NETWORK_READ_ONLY, Access::Ro));
        }
    }
    rules
}

/// Open the absolute `path` as an `O_PATH` handle without following a
/// symbolic link in *any* component: each component is opened with
/// `O_NOFOLLOW` relative to the previous one, and a component that is a link
/// is refused. The rule is then added on this very handle, so nothing can be
/// swapped between the check and the grant.
pub(crate) fn open_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let mut cur: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/")?;
    let mut walked = PathBuf::from("/");
    for comp in path.components() {
        let name = match comp {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a grant path may not contain '..'",
                ))
            }
        };
        walked.push(name);
        let c = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
        // SAFETY: `cur` is an open directory handle and `c` a NUL-terminated
        // name; the returned descriptor is owned below.
        let fd = unsafe {
            libc::openat(
                cur.as_raw_fd(),
                c.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned to us and is owned by nobody else.
        let next = unsafe { File::from_raw_fd(fd) };
        if next.metadata()?.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is a symbolic link; storage and device grants are resolved \
                     without following links",
                    walked.display()
                ),
            ));
        }
        cur = next;
    }
    Ok(cur)
}

/// Refuse `path` if any component is a symbolic link (for mechanisms that
/// resolve the path themselves, such as bubblewrap's bind mounts).
pub(crate) fn check_no_symlinks(path: &Path) -> io::Result<()> {
    open_no_follow(path).map(|_| ())
}

// ── parent side ──────────────────────────────────────────────────────────────

/// Create and populate a ruleset for `profile`. The returned descriptor is
/// close-on-exec (Landlock always sets `O_CLOEXEC`) and is consumed by
/// [`restrict_self`] in the forked child.
pub(crate) fn build_ruleset(
    profile: &SandboxProfile,
    abi: u32,
    handle_tcp: bool,
    scopes: bool,
) -> Result<OwnedFd, SandboxError> {
    let handled = fs_handled(abi);
    let attr = RulesetAttr {
        handled_access_fs: handled,
        handled_access_net: if handle_tcp && abi >= 4 {
            NET_BIND_TCP | NET_CONNECT_TCP
        } else {
            0
        },
        scoped: if scopes && abi >= 6 {
            SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL
        } else {
            0
        },
    };
    // SAFETY: `attr` is a live, properly aligned `landlock_ruleset_attr`; the
    // size passed is its exact size. Fields this kernel does not know are
    // zero, which `copy_struct_from_user` accepts on older ABIs.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if fd < 0 {
        return Err(SandboxError::Ruleset(io::Error::last_os_error()));
    }
    let raw = RawFd::try_from(fd)
        .map_err(|_| SandboxError::Ruleset(io::Error::other("ruleset fd out of range")))?;
    // SAFETY: the syscall just returned this descriptor to us; nothing else
    // owns it.
    let ruleset = unsafe { OwnedFd::from_raw_fd(raw) };

    for r in rules_for(profile) {
        match add_path_rule(&ruleset, &r, handled) {
            Ok(()) => {}
            Err(e) if !r.required => {
                tracing::trace!(path = %r.path.display(), error = %e, "optional system path skipped");
            }
            Err(source) => {
                return Err(SandboxError::PathRule {
                    path: r.path,
                    source,
                })
            }
        }
    }
    Ok(ruleset)
}

fn add_path_rule(ruleset: &OwnedFd, r: &Rule, handled: u64) -> io::Result<()> {
    let access = r.access;
    // O_PATH: we only need a handle to the inode, not permission to read it.
    let file: File = if r.follow_links {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(&r.path)?
    } else {
        open_no_follow(&r.path)?
    };
    let is_dir = file.metadata()?.is_dir();
    let allowed = if is_dir {
        access.dir_rights(handled)
    } else {
        access.file_rights(handled)
    };
    if allowed == 0 {
        return Ok(());
    }
    let attr = PathBeneathAttr {
        allowed_access: allowed,
        parent_fd: file.as_raw_fd(),
    };
    // SAFETY: `ruleset` and `file` are open descriptors owned by this frame;
    // `attr` is a live packed `landlock_path_beneath_attr`.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            &attr as *const PathBeneathAttr,
            0u32,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ── child side ───────────────────────────────────────────────────────────────

/// Enforce the ruleset on the calling (single-threaded, forked) process.
///
/// Async-signal-safe: one raw syscall, no allocation.
///
/// # Safety
/// Must be called in a child between `fork` and `exec`, after
/// `PR_SET_NO_NEW_PRIVS`; `ruleset` must be a Landlock ruleset descriptor.
pub(crate) unsafe fn restrict_self(ruleset: RawFd) -> io::Result<()> {
    // SAFETY: plain syscall on an integer descriptor; no memory is passed.
    let r = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handled_rights_grow_with_the_abi() {
        assert_eq!(fs_handled(1), (1 << 13) - 1);
        assert!(fs_handled(2) & fs::REFER != 0);
        assert!(fs_handled(2) & fs::TRUNCATE == 0);
        assert!(fs_handled(3) & fs::TRUNCATE != 0);
        assert!(fs_handled(4) & fs::IOCTL_DEV == 0);
        assert!(fs_handled(7) & fs::IOCTL_DEV != 0);
    }

    #[test]
    fn data_scopes_never_get_execute() {
        for abi in 1..=7 {
            let h = fs_handled(abi);
            assert_eq!(Access::Rw.dir_rights(h) & fs::EXECUTE, 0);
            assert_eq!(Access::Rw.dir_rights(h) & fs::MAKE_BLOCK, 0);
            assert_eq!(Access::Rw.dir_rights(h) & fs::MAKE_CHAR, 0);
            assert_eq!(Access::Rw.file_rights(h) & fs::EXECUTE, 0);
            assert_eq!(Access::Ro.dir_rights(h) & fs::WRITE_FILE, 0);
            // Every granted right is one the kernel handles.
            for a in [Access::Rx, Access::Ro, Access::Rw, Access::Dev] {
                assert_eq!(a.dir_rights(h) & !h, 0);
                assert_eq!(a.file_rights(h) & !fs::FILE_ONLY, 0);
            }
        }
    }

    /// Device ioctls (ABI ≥ 5) only on device grants: without `IOCTL_DEV` a
    /// granted GPU node opens but every driver ioctl fails with EACCES.
    #[test]
    fn only_device_grants_carry_ioctl_rights() {
        for abi in 1..=7 {
            let h = fs_handled(abi);
            let has_ioctl = abi >= 5;
            assert_eq!(Access::Dev.file_rights(h) & fs::IOCTL_DEV != 0, has_ioctl);
            assert_eq!(Access::Dev.dir_rights(h) & fs::IOCTL_DEV != 0, has_ioctl);
            for a in [Access::Rx, Access::Ro, Access::Rw] {
                assert_eq!(a.file_rights(h) & fs::IOCTL_DEV, 0, "{a:?}");
                assert_eq!(a.dir_rights(h) & fs::IOCTL_DEV, 0, "{a:?}");
            }
            // A device grant creates, removes and executes nothing.
            let d = Access::Dev.dir_rights(h);
            for r in [
                fs::EXECUTE,
                fs::MAKE_REG,
                fs::MAKE_CHAR,
                fs::REMOVE_FILE,
                fs::REFER,
            ] {
                assert_eq!(d & r, 0);
            }
        }
        let rules = rules_for(&SandboxProfile::new("/p").device("/dev/dri"));
        assert!(rules.contains(&rule(Path::new("/dev/dri"), Access::Dev, true, false)));
    }

    #[test]
    fn rules_cover_program_scopes_and_system_paths() {
        let p = SandboxProfile::new("/opt/p/bin")
            .read_write("/data/p")
            .read_only("/assets");
        let rules = rules_for(&p);
        // Scopes never follow links; the program and system paths do.
        assert!(rules.contains(&rule(Path::new("/opt/p/bin"), Access::Rx, true, true)));
        assert!(rules.contains(&rule(Path::new("/data/p"), Access::Rw, true, false)));
        assert!(rules.contains(&rule(Path::new("/assets"), Access::Ro, true, false)));
        assert!(rules.contains(&rule(Path::new("/usr/lib"), Access::Rx, false, true)));
        assert!(rules.contains(&rule(Path::new("/dev/null"), Access::Rw, false, true)));
        // Name resolution files only with the network.
        assert!(!rules
            .iter()
            .any(|r| r.path == Path::new("/etc/resolv.conf")));
        let rules = rules_for(&p.clone().allow_network(true));
        assert!(rules
            .iter()
            .any(|r| r.path == Path::new("/etc/resolv.conf")));
    }

    #[test]
    fn scope_paths_are_opened_without_following_links() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();
        assert!(open_no_follow(&real).unwrap().metadata().unwrap().is_dir());
        let err = open_no_follow(&dir.path().join("link")).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        // A link in a middle component is refused too.
        let err = open_no_follow(&dir.path().join("link/x")).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(open_no_follow(Path::new("/a/../b")).is_err());
    }

    #[test]
    fn a_missing_required_path_fails_the_build() {
        let Some(abi) = abi_version() else {
            return; // no Landlock on this kernel: nothing to build
        };
        let p = SandboxProfile::new("/bin/sh").read_write("/definitely/not/here/entangle");
        let err = build_ruleset(&p, abi, true, true).unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0703"), "{err}");
    }
}
