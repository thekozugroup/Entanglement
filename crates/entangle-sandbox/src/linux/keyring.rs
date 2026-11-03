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
/// without key support (`ENOSYS`) has nothing to leak, and a `keyctl`
/// refused by an outer seccomp policy (`EPERM`: Docker's default profile,
/// systemd's `SystemCallFilter=~@keyring`) is refused to the child as well —
/// seccomp filters are inherited — so both are accepted.
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
        if matches!(e.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EPERM)) {
            return Ok(());
        }
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Under an outer seccomp policy that refuses `keyctl` with EPERM
    /// (Docker's default profile, systemd's `SystemCallFilter=~@keyring`) the
    /// child inherits that refusal, so there is nothing to detach from: the
    /// spawn must not fail, whatever plan is engaged.
    #[test]
    fn a_keyctl_refused_by_an_outer_filter_is_not_an_error() {
        let ld_nr = libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        };
        let is_keyctl = libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_keyctl as u32,
        };
        let eperm = libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        };
        let allow = libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        };
        let prog = [ld_nr, is_keyctl, eperm, allow];
        let fprog = libc::sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_ptr().cast_mut(),
        };
        // SAFETY: the child only issues raw syscalls on memory prepared
        // before the fork, then _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                let code = if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER,
                        &fprog as *const libc::sock_fprog,
                    ) != 0
                {
                    2
                } else if join_fresh_session().is_ok() {
                    0
                } else {
                    1
                };
                libc::_exit(code);
            }
        }
        let mut status = 0;
        // SAFETY: waiting for the child forked above.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "1 = refused, 2 = setup failed"
        );
    }
}
