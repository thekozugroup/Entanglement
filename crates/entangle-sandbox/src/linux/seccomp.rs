//! A small seccomp-bpf program that filters `socket()` and `socketpair()` by
//! address family.
//!
//! Built in the parent (allocation is fine there), installed in the forked
//! child with one `prctl` (async-signal-safe).
//!
//! Program shape:
//! ```text
//!   arch != native            -> KILL_PROCESS   (no i386/x32 bypass)
//!   nr has the x32 bit        -> ERRNO(EPERM)   (x86_64 only)
//!   nr == io_uring_setup      -> ERRNO(EPERM)   (io_uring can create sockets)
//!   nr == clone3              -> ERRNO(ENOSYS)  (libc falls back to clone)
//!   nr == setns               -> ERRNO(EPERM)
//!   nr == keyctl|add_key|request_key -> ERRNO(EPERM)
//!   nr == unshare|clone with a CLONE_NEW* flag -> ERRNO(EPERM)
//!   nr == prlimit64|sched_set{param,scheduler,affinity,attr} on pid != 0
//!                             -> ERRNO(EPERM)   (not on the daemon)
//!   nr == setpriority|ioprio_set unless (PROCESS, 0) -> ERRNO(EPERM)
//!   nr == socket|socketpair:
//!     domain in allowed set   -> ALLOW
//!     otherwise               -> ERRNO(EACCES)
//!   otherwise                 -> ALLOW
//! ```

use std::io;

/// Syscall numbers the filter refers to, for one architecture.
///
/// Values are from the kernel's syscall tables (x86_64:
/// `arch/x86/entry/syscalls/syscall_64.tbl`; aarch64 and riscv64 share the
/// generic table `include/uapi/asm-generic/unistd.h`). A unit test checks the
/// running architecture's entry against `libc::SYS_*`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Nr {
    pub(crate) socket: u32,
    pub(crate) socketpair: u32,
    pub(crate) io_uring_setup: u32,
    pub(crate) unshare: u32,
    pub(crate) clone: u32,
    pub(crate) clone3: u32,
    pub(crate) setns: u32,
    pub(crate) prlimit64: u32,
    pub(crate) setpriority: u32,
    pub(crate) sched_setparam: u32,
    pub(crate) sched_setscheduler: u32,
    pub(crate) sched_setaffinity: u32,
    pub(crate) sched_setattr: u32,
    pub(crate) ioprio_set: u32,
    pub(crate) keyctl: u32,
    pub(crate) add_key: u32,
    pub(crate) request_key: u32,
}

/// Per-architecture constants. Only architectures listed here get a filter;
/// elsewhere [`supported`] is `false` and the plan does not count on seccomp.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Arch {
    pub(crate) audit_arch: u32,
    pub(crate) has_x32: bool,
    pub(crate) nr: Nr,
}

/// x86_64.
// Only the running architecture's table feeds NATIVE; the others are
// kept (and unit-tested) so every supported table is exercised everywhere.
#[allow(dead_code)]
pub(crate) const X86_64: Arch = Arch {
    audit_arch: 0xC000_003E, // AUDIT_ARCH_X86_64
    has_x32: true,
    nr: Nr {
        socket: 41,
        socketpair: 53,
        io_uring_setup: 425,
        unshare: 272,
        clone: 56,
        clone3: 435,
        setns: 308,
        prlimit64: 302,
        setpriority: 141,
        sched_setparam: 142,
        sched_setscheduler: 144,
        sched_setaffinity: 203,
        sched_setattr: 314,
        ioprio_set: 251,
        keyctl: 250,
        add_key: 248,
        request_key: 249,
    },
};

/// The asm-generic syscall table shared by aarch64 and riscv64.
// Only the running architecture's table feeds NATIVE; the others are
// kept (and unit-tested) so every supported table is exercised everywhere.
#[allow(dead_code)]
const GENERIC_NR: Nr = Nr {
    socket: 198,
    socketpair: 199,
    io_uring_setup: 425,
    unshare: 97,
    clone: 220,
    clone3: 435,
    setns: 268,
    prlimit64: 261,
    setpriority: 140,
    sched_setparam: 118,
    sched_setscheduler: 119,
    sched_setaffinity: 122,
    sched_setattr: 274,
    ioprio_set: 30,
    keyctl: 219,
    add_key: 217,
    request_key: 218,
};

/// aarch64.
// Only the running architecture's table feeds NATIVE; the others are
// kept (and unit-tested) so every supported table is exercised everywhere.
#[allow(dead_code)]
pub(crate) const AARCH64: Arch = Arch {
    audit_arch: 0xC000_00B7, // AUDIT_ARCH_AARCH64
    has_x32: false,
    nr: GENERIC_NR,
};

/// riscv64.
// Only the running architecture's table feeds NATIVE; the others are
// kept (and unit-tested) so every supported table is exercised everywhere.
#[allow(dead_code)]
pub(crate) const RISCV64: Arch = Arch {
    audit_arch: 0xC000_00F3, // AUDIT_ARCH_RISCV64
    has_x32: false,
    nr: GENERIC_NR,
};

#[cfg(all(target_arch = "x86_64", target_endian = "little"))]
pub(crate) const NATIVE: Option<Arch> = Some(X86_64);
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
pub(crate) const NATIVE: Option<Arch> = Some(AARCH64);
#[cfg(all(target_arch = "riscv64", target_endian = "little"))]
pub(crate) const NATIVE: Option<Arch> = Some(RISCV64);
// Big-endian variants would need the high-word argument offsets; they are
// not supported rather than filtered wrongly.
#[cfg(not(all(
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ),
    target_endian = "little"
)))]
pub(crate) const NATIVE: Option<Arch> = None;

const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// struct seccomp_data offsets (little-endian: low word of args[0] at 16).
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0_LO: u32 = 16;
const OFF_ARG1_LO: u32 = 24;

const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const JGE_K: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
const JSET_K: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

pub(crate) const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
pub(crate) const RET_KILL_PROCESS: u32 = libc::SECCOMP_RET_KILL_PROCESS;
pub(crate) const RET_EPERM: u32 = libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32);
pub(crate) const RET_EACCES: u32 = libc::SECCOMP_RET_ERRNO | (libc::EACCES as u32);
pub(crate) const RET_ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32);

/// Which address families `socket()` may create.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SocketPolicy {
    /// `AF_INET`, `AF_INET6` and `AF_NETLINK` (getaddrinfo needs the latter).
    pub(crate) inet: bool,
    /// `AF_UNIX`.
    pub(crate) unix: bool,
}

impl SocketPolicy {
    fn families(self) -> Vec<u32> {
        let mut f = Vec::new();
        if self.unix {
            f.push(libc::AF_UNIX as u32);
        }
        if self.inet {
            f.push(libc::AF_INET as u32);
            f.push(libc::AF_INET6 as u32);
            f.push(libc::AF_NETLINK as u32);
        }
        f
    }
}

/// An assembled filter program.
pub(crate) struct Filter {
    prog: Vec<libc::sock_filter>,
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// `if nr == syscall { <block> }`: the block runs (and must end in a
/// return) when the syscall matches; otherwise it is skipped with the
/// syscall number still in the accumulator.
fn guarded(p: &mut Vec<libc::sock_filter>, syscall: u32, block: &[libc::sock_filter]) {
    let skip = u8::try_from(block.len()).unwrap_or(u8::MAX);
    debug_assert!(block.len() <= usize::from(u8::MAX), "BPF block too long");
    p.push(jump(JEQ_K, syscall, 0, skip));
    p.extend_from_slice(block);
}

/// `if nr == syscall { return ret }`.
fn deny(p: &mut Vec<libc::sock_filter>, syscall: u32, ret: u32) {
    guarded(p, syscall, &[stmt(RET_K, ret)]);
}

/// Block: allow when the low word of `args[0]` is one of `families`, else
/// `EACCES`.
fn family_block(families: &[u32]) -> Vec<libc::sock_filter> {
    let mut b = vec![stmt(LD_W_ABS, OFF_ARG0_LO)];
    let k = families.len();
    for (i, fam) in families.iter().enumerate() {
        // Jump over the remaining comparisons and the deny to the final ALLOW.
        let to_allow = u8::try_from(k - i).unwrap_or(u8::MAX);
        b.push(jump(JEQ_K, *fam, to_allow, 0));
    }
    b.push(stmt(RET_K, RET_EACCES));
    b.push(stmt(RET_K, RET_ALLOW));
    b
}

/// Every `CLONE_NEW*` flag (`unshare` and `clone` share the bit values).
const NAMESPACE_FLAGS: u32 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWTIME) as u32;

/// `clone()` keeps the exit signal in its low byte (`CSIGNAL`), where
/// `CLONE_NEWTIME` would sit; `clone()` cannot create a time namespace.
const CSIGNAL: u32 = 0xff;

/// Block: `EPERM` when the low word of `args[0]` has any of `flags` set.
/// Namespace flags all live in the low word (the kernel takes `clone`'s
/// flags from the lower 32 bits and rejects unknown `unshare` flags).
fn flags_block(flags: u32) -> [libc::sock_filter; 4] {
    [
        stmt(LD_W_ABS, OFF_ARG0_LO),
        jump(JSET_K, flags, 0, 1),
        stmt(RET_K, RET_EPERM),
        stmt(RET_K, RET_ALLOW),
    ]
}

/// Block: allow only when the low word of `args[0]` (a `pid_t`) is 0, i.e.
/// the calling process itself; `EPERM` otherwise.
fn self_only_block() -> [libc::sock_filter; 4] {
    [
        stmt(LD_W_ABS, OFF_ARG0_LO),
        jump(JEQ_K, 0, 0, 1),
        stmt(RET_K, RET_ALLOW),
        stmt(RET_K, RET_EPERM),
    ]
}

/// Block for `(which, who, ...)` calls: allow only `which == which_process`
/// with `who == 0` (the calling process); `EPERM` for any other process,
/// process group or user.
fn which_who_block(which_process: u32) -> [libc::sock_filter; 6] {
    [
        stmt(LD_W_ABS, OFF_ARG0_LO),
        jump(JEQ_K, which_process, 0, 3),
        stmt(LD_W_ABS, OFF_ARG1_LO),
        jump(JEQ_K, 0, 0, 1),
        stmt(RET_K, RET_ALLOW),
        stmt(RET_K, RET_EPERM),
    ]
}

/// `PRIO_PROCESS` (`setpriority`'s `which`).
const PRIO_PROCESS: u32 = 0;
/// `IOPRIO_WHO_PROCESS` (`ioprio_set`'s `which`).
const IOPRIO_WHO_PROCESS: u32 = 1;

/// Assemble the program for `arch` (exposed separately for unit tests).
pub(crate) fn assemble(arch: Arch, policy: SocketPolicy) -> Vec<libc::sock_filter> {
    let nr = arch.nr;
    let mut p = vec![
        stmt(LD_W_ABS, OFF_ARCH),
        jump(JEQ_K, arch.audit_arch, 1, 0),
        stmt(RET_K, RET_KILL_PROCESS),
        stmt(LD_W_ABS, OFF_NR),
    ];
    if arch.has_x32 {
        p.push(jump(JGE_K, X32_SYSCALL_BIT, 0, 1));
        p.push(stmt(RET_K, RET_EPERM));
    }
    deny(&mut p, nr.io_uring_setup, RET_EPERM);
    // No namespaces of the plugin's own: a fresh user namespace grants every
    // capability inside it (CAP_NET_ADMIN reaches nf_tables and friends).
    // clone3 passes its flags behind a pointer the filter cannot read, so it
    // reports ENOSYS and libc falls back to clone, whose flags are checked.
    deny(&mut p, nr.clone3, RET_ENOSYS);
    deny(&mut p, nr.setns, RET_EPERM);
    // Keyrings: the user and user-session keyrings are reachable by special
    // id from any process of the uid, and nothing else mediates them.
    deny(&mut p, nr.keyctl, RET_EPERM);
    deny(&mut p, nr.add_key, RET_EPERM);
    deny(&mut p, nr.request_key, RET_EPERM);
    guarded(&mut p, nr.unshare, &flags_block(NAMESPACE_FLAGS));
    guarded(&mut p, nr.clone, &flags_block(NAMESPACE_FLAGS & !CSIGNAL));
    // Resource and scheduling calls on *other* processes. There is no PID
    // namespace and the uid is the daemon's, so the kernel would let the
    // plugin set the daemon's RLIMIT_CPU to 1 (a kill) or renice it; Landlock
    // hooks none of these. The plugin may still adjust itself.
    for call in [
        nr.prlimit64,
        nr.sched_setparam,
        nr.sched_setscheduler,
        nr.sched_setaffinity,
        nr.sched_setattr,
    ] {
        guarded(&mut p, call, &self_only_block());
    }
    guarded(&mut p, nr.setpriority, &which_who_block(PRIO_PROCESS));
    guarded(&mut p, nr.ioprio_set, &which_who_block(IOPRIO_WHO_PROCESS));
    // `socketpair` creates sockets just like `socket`: an `AF_UNIX`
    // `SOCK_DGRAM` pair can `sendto` any path-named socket.
    let families = family_block(&policy.families());
    guarded(&mut p, nr.socket, &families);
    guarded(&mut p, nr.socketpair, &families);
    p.push(stmt(RET_K, RET_ALLOW));
    p
}

impl Filter {
    /// Build the filter for the running architecture, or `None` if this crate
    /// has no syscall table for it.
    pub(crate) fn for_native(policy: SocketPolicy) -> Option<Self> {
        NATIVE.map(|arch| Self {
            prog: assemble(arch, policy),
        })
    }

    /// Install the filter on the calling process.
    ///
    /// Async-signal-safe: builds a `sock_fprog` on the stack pointing at the
    /// program assembled in the parent, then one `prctl`.
    ///
    /// # Safety
    /// Must be called in a forked child before `exec`, after
    /// `PR_SET_NO_NEW_PRIVS`.
    pub(crate) unsafe fn install(&self) -> io::Result<()> {
        let len = u16::try_from(self.prog.len())
            .map_err(|_| io::Error::from_raw_os_error(libc::E2BIG))?;
        let fprog = libc::sock_fprog {
            len,
            filter: self.prog.as_ptr().cast_mut(),
        };
        // SAFETY: `fprog` points at `self.prog`, which outlives this call; the
        // kernel copies the program before returning.
        let r = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &fprog as *const libc::sock_fprog,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Whether seccomp filters can be installed here.
///
/// Passing a NULL program makes the kernel fail with `EFAULT` when filter
/// mode exists (it copies the program before any other check) and `EINVAL`
/// when it does not; nothing is installed either way.
pub(crate) fn supported() -> bool {
    if NATIVE.is_none() {
        return false;
    }
    // SAFETY: NULL program pointer; the kernel rejects it without installing
    // anything or touching our memory.
    let r = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    r == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EFAULT)
}

#[cfg(test)]
mod tests {
    use super::*;

    const X86: Arch = X86_64;
    const ARM: Arch = AARCH64;

    /// A classic-BPF interpreter for the instructions the assembler emits,
    /// so the program's *behaviour* is tested, not its bytes.
    fn run(prog: &[libc::sock_filter], arch: u32, nr: u32, arg0: u32) -> u32 {
        run2(prog, arch, nr, arg0, 0)
    }

    fn run2(prog: &[libc::sock_filter], arch: u32, nr: u32, arg0: u32, arg1: u32) -> u32 {
        let mut a = 0u32;
        let mut pc = 0usize;
        loop {
            let ins = prog[pc];
            match ins.code {
                LD_W_ABS => {
                    a = match ins.k {
                        OFF_NR => nr,
                        OFF_ARCH => arch,
                        OFF_ARG0_LO => arg0,
                        OFF_ARG1_LO => arg1,
                        other => panic!("unexpected load offset {other}"),
                    };
                    pc += 1;
                }
                JEQ_K | JGE_K | JSET_K => {
                    let taken = match ins.code {
                        JEQ_K => a == ins.k,
                        JGE_K => a >= ins.k,
                        _ => a & ins.k != 0,
                    };
                    pc += 1 + usize::from(if taken { ins.jt } else { ins.jf });
                }
                RET_K => return ins.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
        }
    }

    const AF_UNIX: u32 = libc::AF_UNIX as u32;
    const AF_INET: u32 = libc::AF_INET as u32;
    const AF_INET6: u32 = libc::AF_INET6 as u32;
    const AF_PACKET: u32 = libc::AF_PACKET as u32;

    #[test]
    fn no_network_policy_denies_every_family() {
        for arch in [X86, ARM] {
            let p = assemble(
                arch,
                SocketPolicy {
                    inet: false,
                    unix: false,
                },
            );
            for fam in [AF_UNIX, AF_INET, AF_INET6, AF_PACKET] {
                assert_eq!(run(&p, arch.audit_arch, arch.nr.socket, fam), RET_EACCES);
            }
            // Unrelated syscalls pass through untouched.
            assert_eq!(run(&p, arch.audit_arch, 0, AF_INET), RET_ALLOW);
            assert_eq!(run(&p, arch.audit_arch, 63, 0), RET_ALLOW);
        }
    }

    #[test]
    fn granted_families_are_allowed_and_raw_packet_never() {
        let p = assemble(
            X86,
            SocketPolicy {
                inet: true,
                unix: false,
            },
        );
        assert_eq!(run(&p, X86.audit_arch, 41, AF_INET), RET_ALLOW);
        assert_eq!(run(&p, X86.audit_arch, 41, AF_INET6), RET_ALLOW);
        assert_eq!(run(&p, X86.audit_arch, 41, AF_UNIX), RET_EACCES);
        assert_eq!(run(&p, X86.audit_arch, 41, AF_PACKET), RET_EACCES);

        let p = assemble(
            X86,
            SocketPolicy {
                inet: false,
                unix: true,
            },
        );
        assert_eq!(run(&p, X86.audit_arch, 41, AF_UNIX), RET_ALLOW);
        assert_eq!(run(&p, X86.audit_arch, 41, AF_INET), RET_EACCES);
    }

    /// `socketpair` creates sockets too: a `SOCK_DGRAM` pair can `sendto`
    /// any path-named socket, so it is filtered by family exactly like
    /// `socket`.
    #[test]
    fn socketpair_is_filtered_like_socket() {
        for arch in [X86, ARM, RISCV64] {
            let p = assemble(
                arch,
                SocketPolicy {
                    inet: false,
                    unix: false,
                },
            );
            assert_eq!(
                run(&p, arch.audit_arch, arch.nr.socketpair, AF_UNIX),
                RET_EACCES
            );
            let p = assemble(
                arch,
                SocketPolicy {
                    inet: false,
                    unix: true,
                },
            );
            assert_eq!(
                run(&p, arch.audit_arch, arch.nr.socketpair, AF_UNIX),
                RET_ALLOW
            );
        }
    }

    /// A plugin must not create (or join) namespaces of its own: a fresh
    /// user namespace hands it every capability inside it, which makes
    /// `CAP_NET_ADMIN`-gated kernel code (nf_tables, ...) reachable.
    /// `clone3` hides its flags behind a pointer, so it answers `ENOSYS` and
    /// libc falls back to `clone`, whose flags are checked.
    #[test]
    fn namespace_creation_is_refused_but_threads_and_fork_are_not() {
        const SIGCHLD: u32 = libc::SIGCHLD as u32;
        let thread_flags = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as u32;
        for arch in [X86, ARM, RISCV64] {
            for pol in [
                SocketPolicy {
                    inet: false,
                    unix: false,
                },
                SocketPolicy {
                    inet: true,
                    unix: true,
                },
            ] {
                let p = assemble(arch, pol);
                let nr = arch.nr;
                let aa = arch.audit_arch;
                for ns in [
                    libc::CLONE_NEWUSER,
                    libc::CLONE_NEWNET,
                    libc::CLONE_NEWNS,
                    libc::CLONE_NEWPID,
                    libc::CLONE_NEWIPC,
                    libc::CLONE_NEWUTS,
                    libc::CLONE_NEWCGROUP,
                    libc::CLONE_NEWTIME,
                ] {
                    let ns = ns as u32;
                    assert_eq!(run(&p, aa, nr.unshare, ns), RET_EPERM, "unshare {ns:#x}");
                    if ns != libc::CLONE_NEWTIME as u32 {
                        assert_eq!(run(&p, aa, nr.clone, ns | SIGCHLD), RET_EPERM, "{ns:#x}");
                    }
                }
                assert_eq!(run(&p, aa, nr.setns, 3), RET_EPERM);
                assert_eq!(run(&p, aa, nr.clone3, 0), RET_ENOSYS);
                // fork() and pthread_create() stay possible.
                assert_eq!(run(&p, aa, nr.clone, SIGCHLD), RET_ALLOW);
                assert_eq!(run(&p, aa, nr.clone, thread_flags), RET_ALLOW);
                assert_eq!(run(&p, aa, nr.unshare, libc::CLONE_FS as u32), RET_ALLOW);
            }
        }
    }

    /// Without a PID namespace the plugin shares the daemon's kuid, so the
    /// kernel lets it change the daemon's rlimits (RLIMIT_CPU = 1 kills it)
    /// and priorities. Only calls on the plugin itself (`pid` / `who` 0)
    /// pass; Landlock hooks none of these.
    #[test]
    fn resource_calls_on_other_processes_are_refused() {
        const PRIO_PROCESS: u32 = 0;
        const PRIO_PGRP: u32 = 1;
        const PRIO_USER: u32 = 2;
        const IOPRIO_WHO_PROCESS: u32 = 1;
        const IOPRIO_WHO_USER: u32 = 3;
        for arch in [X86, ARM, RISCV64] {
            let p = assemble(
                arch,
                SocketPolicy {
                    inet: true,
                    unix: true,
                },
            );
            let nr = arch.nr;
            let aa = arch.audit_arch;
            for call in [
                nr.prlimit64,
                nr.sched_setparam,
                nr.sched_setscheduler,
                nr.sched_setaffinity,
                nr.sched_setattr,
            ] {
                assert_eq!(run(&p, aa, call, 0), RET_ALLOW, "nr {call} on self");
                assert_eq!(
                    run(&p, aa, call, 4242),
                    RET_EPERM,
                    "nr {call} on another pid"
                );
            }
            assert_eq!(run2(&p, aa, nr.setpriority, PRIO_PROCESS, 0), RET_ALLOW);
            assert_eq!(run2(&p, aa, nr.setpriority, PRIO_PROCESS, 4242), RET_EPERM);
            assert_eq!(run2(&p, aa, nr.setpriority, PRIO_PGRP, 0), RET_EPERM);
            assert_eq!(run2(&p, aa, nr.setpriority, PRIO_USER, 0), RET_EPERM);
            assert_eq!(
                run2(&p, aa, nr.ioprio_set, IOPRIO_WHO_PROCESS, 0),
                RET_ALLOW
            );
            assert_eq!(
                run2(&p, aa, nr.ioprio_set, IOPRIO_WHO_PROCESS, 4242),
                RET_EPERM
            );
            assert_eq!(run2(&p, aa, nr.ioprio_set, IOPRIO_WHO_USER, 0), RET_EPERM);
        }
    }

    /// Keyrings are not covered by Landlock or namespaces; the user and
    /// user-session keyrings stay reachable by special id even after the
    /// child joins a fresh session keyring, so the key syscalls are refused.
    #[test]
    fn keyring_syscalls_are_refused() {
        for arch in [X86, ARM, RISCV64] {
            let p = assemble(
                arch,
                SocketPolicy {
                    inet: true,
                    unix: true,
                },
            );
            for call in [arch.nr.keyctl, arch.nr.add_key, arch.nr.request_key] {
                assert_eq!(run(&p, arch.audit_arch, call, 0), RET_EPERM, "nr {call}");
            }
        }
    }

    #[test]
    fn io_uring_foreign_arch_and_x32_are_closed() {
        let pol = SocketPolicy {
            inet: true,
            unix: true,
        };
        let p = assemble(X86, pol);
        assert_eq!(run(&p, X86.audit_arch, 425, 0), RET_EPERM);
        assert_eq!(
            run(&p, X86.audit_arch, X32_SYSCALL_BIT | 41, AF_INET),
            RET_EPERM
        );
        // i386 (AUDIT_ARCH_I386) syscalls on an x86_64 kernel: kill.
        assert_eq!(run(&p, 0x4000_0003, 41, AF_INET), RET_KILL_PROCESS);

        let p = assemble(ARM, pol);
        assert_eq!(run(&p, ARM.audit_arch, 425, 0), RET_EPERM);
        assert_eq!(run(&p, X86.audit_arch, 198, AF_INET), RET_KILL_PROCESS);
    }

    /// The hand-written tables match the `libc` crate's numbers for the
    /// architecture this test runs on.
    #[test]
    fn native_table_matches_libc() {
        let Some(arch) = NATIVE else { return };
        let n = arch.nr;
        let pairs: &[(u32, libc::c_long)] = &[
            (n.socket, libc::SYS_socket),
            (n.socketpair, libc::SYS_socketpair),
            (n.io_uring_setup, libc::SYS_io_uring_setup),
            (n.unshare, libc::SYS_unshare),
            (n.clone, libc::SYS_clone),
            (n.clone3, libc::SYS_clone3),
            (n.setns, libc::SYS_setns),
            (n.prlimit64, libc::SYS_prlimit64),
            (n.setpriority, libc::SYS_setpriority),
            (n.sched_setparam, libc::SYS_sched_setparam),
            (n.sched_setscheduler, libc::SYS_sched_setscheduler),
            (n.sched_setaffinity, libc::SYS_sched_setaffinity),
            (n.sched_setattr, libc::SYS_sched_setattr),
            (n.ioprio_set, libc::SYS_ioprio_set),
            (n.keyctl, libc::SYS_keyctl),
            (n.add_key, libc::SYS_add_key),
            (n.request_key, libc::SYS_request_key),
        ];
        for (ours, theirs) in pairs {
            assert_eq!(*ours as libc::c_long, *theirs);
        }
        assert_eq!(RISCV64.nr.socketpair, AARCH64.nr.socketpair);
    }

    #[test]
    fn native_filter_exists_on_supported_arches() {
        let f = Filter::for_native(SocketPolicy {
            inet: false,
            unix: false,
        });
        assert_eq!(f.is_some(), NATIVE.is_some());
    }
}
