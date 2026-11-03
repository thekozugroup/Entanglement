//! Detach the child from the parent's session keyring.
//!
//! The session keyring is inherited across `fork` and `exec`, and the child
//! *possesses* it, so it could search and read every key the daemon — or,
//! under the CLI's local kernel, the user's login session (Kerberos
//! `KEYRING:` caches, fscrypt/ecryptfs keys) — keeps there. Landlock,
//! namespaces and the socket filter do not cover keyrings. Joining a fresh
//! anonymous session keyring drops that possession; the seccomp filter
//! additionally refuses the key syscalls, which also closes the user and
//! user-session keyrings that remain reachable by special id.

use std::io;

/// `KEYCTL_JOIN_SESSION_KEYRING` (`linux/keyctl.h`).
const KEYCTL_JOIN_SESSION_KEYRING: libc::c_long = 1;

/// Replace the calling process's session keyring with a new, empty,
/// anonymous one.
///
/// Async-signal-safe: one raw syscall with a NULL name. A kernel built
/// without key support (`ENOSYS`) has nothing to leak and is accepted.
///
/// # Safety
/// Must be called in the forked child before `exec` (it changes the
/// caller's credentials).
pub(crate) unsafe fn join_fresh_session() -> io::Result<()> {
    // SAFETY: integer arguments and a NULL name pointer.
    let r = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_JOIN_SESSION_KEYRING,
            std::ptr::null::<libc::c_char>(),
        )
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOSYS) {
            return Ok(());
        }
        return Err(e);
    }
    Ok(())
}
