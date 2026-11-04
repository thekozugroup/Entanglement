//! Unprivileged user + network namespaces: probe (parent) and entry (child).

use std::ffi::CStr;
use std::io;

/// uid/gid map lines, formatted in the parent so the child does no
/// formatting (formatting may allocate).
pub(crate) struct IdMaps {
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
}

impl IdMaps {
    /// Map the caller's uid/gid to themselves inside the new namespace, so
    /// files the plugin creates keep the daemon's ownership and the plugin
    /// sees its real ids. Without a mapping file creation fails (`EOVERFLOW`).
    pub(crate) fn identity() -> Self {
        // SAFETY: getuid/getgid cannot fail and take no arguments.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Self {
            uid_map: format!("{uid} {uid} 1\n").into_bytes(),
            gid_map: format!("{gid} {gid} 1\n").into_bytes(),
        }
    }
}

const SETGROUPS: &CStr = c"/proc/self/setgroups";
const UID_MAP: &CStr = c"/proc/self/uid_map";
const GID_MAP: &CStr = c"/proc/self/gid_map";

/// Write `data` to a `/proc/self` control file. Async-signal-safe.
fn write_proc(path: &CStr, data: &[u8]) -> io::Result<()> {
    // SAFETY: `path` is a NUL-terminated constant.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `data` is a live slice; `fd` was just opened by us.
    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    let result = if n < 0 {
        Err(io::Error::last_os_error())
    } else if n as usize != data.len() {
        Err(io::Error::from_raw_os_error(libc::EIO))
    } else {
        Ok(())
    };
    // SAFETY: closing the descriptor opened above.
    unsafe { libc::close(fd) };
    result
}

/// Move the calling process into a fresh user + network namespace with an
/// identity uid/gid mapping.
///
/// Async-signal-safe: `unshare`, then `open`/`write`/`close` of pre-built
/// buffers.
///
/// # Safety
/// Must be called in a single-threaded process (a forked child): `unshare`
/// of a user namespace fails in multi-threaded processes anyway, and the
/// caller must not rely on network state from before the call.
pub(crate) unsafe fn enter(maps: &IdMaps) -> io::Result<()> {
    // SAFETY: plain syscall with integer flags.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // Required before an unprivileged gid_map write (kernel ≥ 3.19); absent
    // on older kernels, where the gid_map write works without it.
    match write_proc(SETGROUPS, b"deny") {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
        Err(e) => return Err(e),
    }
    write_proc(UID_MAP, &maps.uid_map)?;
    write_proc(GID_MAP, &maps.gid_map)?;
    Ok(())
}

/// Whether the full namespace entry sequence works for this user here.
///
/// Forks a throw-away child that runs [`enter`] and exits; only that child's
/// namespaces change. The child performs only async-signal-safe calls.
pub(crate) fn probe() -> bool {
    let maps = IdMaps::identity();
    // SAFETY: the child branch only calls async-signal-safe functions
    // (`unshare`, `open`, `write`, `close`, `_exit`) on memory prepared before
    // the fork, so forking from a multi-threaded process is sound.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // SAFETY: we are the single-threaded forked child.
        let code = match unsafe { enter(&maps) } {
            Ok(()) => 0,
            Err(_) => 1,
        };
        // SAFETY: `_exit` never returns and runs no atexit handlers.
        unsafe { libc::_exit(code) };
    }
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: waiting for the specific child we just forked.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            break;
        }
        if r < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return false;
    }
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_maps_name_the_callers_ids() {
        let m = IdMaps::identity();
        let uid = unsafe { libc::getuid() };
        assert_eq!(m.uid_map, format!("{uid} {uid} 1\n").into_bytes());
        assert!(m.gid_map.ends_with(b" 1\n"));
    }

    #[test]
    fn probe_does_not_change_the_caller() {
        let before = std::fs::read_link("/proc/self/ns/user").ok();
        let _ = probe();
        let after = std::fs::read_link("/proc/self/ns/user").ok();
        assert_eq!(before, after, "probe must only affect its forked child");
    }
}
