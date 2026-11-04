//! Drop every capability in the forked child.
//!
//! `PR_SET_NO_NEW_PRIVS` stops a plugin from *gaining* privileges at `exec`,
//! but it does not remove capabilities already held. A daemon (or CLI) run as
//! root — unsupported, but nothing refuses it — would otherwise hand its
//! plugins the full root capability set: raw sockets, netlink administration,
//! `init_module`, `kexec_load`, `prlimit` on PID 1. Inside the plugin's own
//! user namespace an identity-mapped root keeps uid 0 there too.
//!
//! A uid-0 process regains `bounding | inheritable` at every `exec`, so
//! emptying the effective/permitted sets is not enough: the bounding set is
//! emptied as well (needs `CAP_SETPCAP`, which a root process — or any
//! process in a user namespace it just created — has). A non-root process
//! without `CAP_SETPCAP` cannot shrink its bounding set, and does not need
//! to: with `no_new_privs` an `exec` can only keep or lose capabilities.

use std::io;

/// `_LINUX_CAPABILITY_VERSION_3`: 64-bit sets as two 32-bit words.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn prctl(op: libc::c_int, arg2: libc::c_ulong) -> libc::c_int {
    // SAFETY: integer-only prctl.
    unsafe {
        libc::prctl(
            op,
            arg2,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    }
}

fn errno() -> Option<i32> {
    io::Error::last_os_error().raw_os_error()
}

/// Clear the ambient, bounding, effective, permitted and inheritable sets.
///
/// Async-signal-safe: `prctl`/`capset` on stack data only. Fails closed:
/// a process with uid 0 whose bounding set cannot be emptied would regain
/// capabilities at `exec`, so that is an error.
///
/// # Safety
/// Must be called in the forked child before `exec` (it changes the
/// caller's credentials).
pub(crate) unsafe fn drop_all() -> io::Result<()> {
    // Ambient capabilities survive exec for non-root processes too (e.g. a
    // daemon started with AmbientCapabilities=). Unprivileged; EINVAL only
    // on kernels before 4.3, which have no ambient set.
    if prctl(
        libc::PR_CAP_AMBIENT,
        libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
    ) != 0
        && errno() != Some(libc::EINVAL)
    {
        return Err(io::Error::last_os_error());
    }

    let mut bounding_kept = false;
    for cap in 0..64 {
        if prctl(libc::PR_CAPBSET_DROP, cap) != 0 {
            match errno() {
                // Past CAP_LAST_CAP: done.
                Some(libc::EINVAL) => break,
                // No CAP_SETPCAP: fine for a non-root process (see module
                // docs), checked below.
                Some(libc::EPERM) => {
                    bounding_kept = true;
                    break;
                }
                _ => return Err(io::Error::last_os_error()),
            }
        }
    }

    let mut hdr = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let empty = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: valid header and a two-element data array, as version 3 needs;
    // both live on this stack frame for the duration of the call.
    if unsafe { libc::syscall(libc::SYS_capset, &mut hdr, empty.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    if bounding_kept {
        let (mut r, mut e, mut s) = (0, 0, 0);
        // SAFETY: valid out-pointers.
        if unsafe { libc::getresuid(&mut r, &mut e, &mut s) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if r == 0 || e == 0 || s == 0 {
            // uid 0 regains `bounding | inheritable` at exec.
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
    }
    Ok(())
}
