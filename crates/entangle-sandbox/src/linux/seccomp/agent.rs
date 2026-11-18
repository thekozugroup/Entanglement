//! The seccomp program of an agent session (see [`crate::agent`]).
//!
//! Narrower than the native-plugin program in the parent module: an agent
//! is an interactive tool that runs shells, so process groups, sessions,
//! keyrings and resource calls are left alone. What it refuses:
//!
//! ```text
//!   arch != native            -> KILL_PROCESS   (no i386/x32 bypass)
//!   nr has the x32 bit        -> ERRNO(EPERM)   (x86_64 only)
//!   nr == io_uring_setup      -> ERRNO(EPERM)   (io_uring can create sockets)
//!   nr == clone3              -> ERRNO(ENOSYS)  (libc falls back to clone)
//!   nr == setns               -> ERRNO(EPERM)
//!   nr == unshare|clone with a CLONE_NEW* flag -> ERRNO(EPERM)
//!   nr == ioctl:
//!     request is TIOCSTI | TIOCLINUX  -> ERRNO(EPERM)   (terminal input injection)
//!     otherwise                       -> ALLOW
//!   nr == socket|socketpair:
//!     AF_UNIX                         -> ALLOW
//!     AF_NETLINK:
//!       protocol == NETLINK_ROUTE     -> ALLOW          (getaddrinfo, `ip`)
//!       otherwise                     -> ERRNO(EACCES)
//!     AF_INET | AF_INET6:
//!       type is SOCK_RAW | SOCK_PACKET -> ERRNO(EACCES)
//!       otherwise                      -> ALLOW
//!     any other family                -> ERRNO(EACCES)
//!   otherwise                 -> ALLOW
//! ```

use super::{
    deny, flags_block, guarded, jump, stmt, Arch, Filter, CSIGNAL, JEQ_K, LD_W_ABS,
    NAMESPACE_FLAGS, NATIVE, OFF_ARCH, OFF_ARG0_LO, OFF_ARG1_LO, OFF_NR, RET_ALLOW, RET_EACCES,
    RET_ENOSYS, RET_EPERM, RET_K, RET_KILL_PROCESS, X32_SYSCALL_BIT,
};

const AND_K: u16 = (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16;
const JGE_K: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;

/// `SOCK_TYPE_MASK`: the low bits of `socket()`'s type argument (the rest
/// are `SOCK_NONBLOCK` / `SOCK_CLOEXEC`).
const SOCK_TYPE_MASK: u32 = 0xf;
/// `SOCK_PACKET` (obsolete packet interface on `AF_INET`).
const SOCK_PACKET: u32 = 10;

/// Offset of the low word of `args[2]` in `struct seccomp_data`
/// (little-endian; the parent module's offsets assume the same).
const OFF_ARG2_LO: u32 = 32;

/// `TIOCSTI`: push a byte into the terminal's input queue.
const TIOCSTI: u32 = 0x5412;
/// `TIOCLINUX`: virtual-console subcommands, including paste-selection.
const TIOCLINUX: u32 = 0x541C;

/// `ioctl` is not in the shared [`super::Nr`] table (the native-plugin
/// program does not filter it): 16 on x86_64, 29 in the generic table that
/// aarch64 and riscv64 use.
fn ioctl_nr(arch: Arch) -> u32 {
    if arch.audit_arch == super::X86_64.audit_arch {
        16
    } else {
        29
    }
}

/// Block for `ioctl`: the kernel takes the request as `unsigned int`, so the
/// low word of `args[1]` is the whole request.
fn ioctl_block() -> [libc::sock_filter; 5] {
    [
        stmt(LD_W_ABS, OFF_ARG1_LO),
        jump(JEQ_K, TIOCSTI, 2, 0),
        jump(JEQ_K, TIOCLINUX, 1, 0),
        stmt(RET_K, RET_ALLOW),
        stmt(RET_K, RET_EPERM),
    ]
}

/// Block for `socket`/`socketpair`: see the module docs.
fn socket_block() -> [libc::sock_filter; 15] {
    [
        /*  0 */ stmt(LD_W_ABS, OFF_ARG0_LO),
        /*  1 */ jump(JEQ_K, libc::AF_UNIX as u32, 11, 0),
        /*  2 */ jump(JEQ_K, libc::AF_NETLINK as u32, 3, 0),
        /*  3 */ jump(JEQ_K, libc::AF_INET as u32, 5, 0),
        /*  4 */ jump(JEQ_K, libc::AF_INET6 as u32, 4, 0),
        /*  5 */ stmt(RET_K, RET_EACCES),
        /*  6 */ stmt(LD_W_ABS, OFF_ARG2_LO),
        /*  7 */ jump(JEQ_K, libc::NETLINK_ROUTE as u32, 5, 0),
        /*  8 */ stmt(RET_K, RET_EACCES),
        /*  9 */ stmt(LD_W_ABS, OFF_ARG1_LO),
        /* 10 */ stmt(AND_K, SOCK_TYPE_MASK),
        /* 11 */ jump(JEQ_K, libc::SOCK_RAW as u32, 2, 0),
        /* 12 */ jump(JEQ_K, SOCK_PACKET, 1, 0),
        /* 13 */ stmt(RET_K, RET_ALLOW),
        /* 14 */ stmt(RET_K, RET_EACCES),
    ]
}

/// Assemble the agent program for `arch`.
pub(crate) fn assemble(arch: Arch) -> Vec<libc::sock_filter> {
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
    deny(&mut p, nr.clone3, RET_ENOSYS);
    deny(&mut p, nr.setns, RET_EPERM);
    guarded(&mut p, nr.unshare, &flags_block(NAMESPACE_FLAGS));
    guarded(&mut p, nr.clone, &flags_block(NAMESPACE_FLAGS & !CSIGNAL));
    guarded(&mut p, ioctl_nr(arch), &ioctl_block());
    let sockets = socket_block();
    guarded(&mut p, nr.socket, &sockets);
    guarded(&mut p, nr.socketpair, &sockets);
    p.push(stmt(RET_K, RET_ALLOW));
    p
}

/// The agent filter for the running architecture, or `None` if this crate
/// has no syscall table for it.
pub(crate) fn filter() -> Option<Filter> {
    NATIVE.map(|arch| Filter {
        prog: assemble(arch),
    })
}

#[cfg(test)]
mod tests {
    use super::super::{AARCH64, X86_64};
    use super::*;

    /// A classic-BPF interpreter for the instructions the assembler emits.
    fn run(prog: &[libc::sock_filter], arch: u32, nr: u32, arg0: u32, arg1: u32) -> u32 {
        run3(prog, arch, nr, arg0, arg1, 0)
    }

    fn run3(
        prog: &[libc::sock_filter],
        arch: u32,
        nr: u32,
        arg0: u32,
        arg1: u32,
        arg2: u32,
    ) -> u32 {
        const JSET_K: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
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
                        32 => arg2,
                        other => panic!("unexpected load offset {other}"),
                    };
                    pc += 1;
                }
                AND_K => {
                    a &= ins.k;
                    pc += 1;
                }
                c if c == JEQ_K || c == JGE_K || c == JSET_K => {
                    let taken = if c == JEQ_K {
                        a == ins.k
                    } else if c == JGE_K {
                        a >= ins.k
                    } else {
                        a & ins.k != 0
                    };
                    pc += 1 + usize::from(if taken { ins.jt } else { ins.jf });
                }
                RET_K => return ins.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
        }
    }

    #[test]
    fn socket_families_and_types() {
        for arch in [X86_64, AARCH64] {
            let p = assemble(arch);
            let sock =
                |fam: i32, ty: i32| run(&p, arch.audit_arch, arch.nr.socket, fam as u32, ty as u32);
            let pair = |fam: i32, ty: i32| {
                run(
                    &p,
                    arch.audit_arch,
                    arch.nr.socketpair,
                    fam as u32,
                    ty as u32,
                )
            };
            // What an agent needs.
            assert_eq!(sock(libc::AF_UNIX, libc::SOCK_STREAM), RET_ALLOW);
            assert_eq!(
                pair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC),
                RET_ALLOW
            );
            assert_eq!(
                sock(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK),
                RET_ALLOW
            );
            assert_eq!(
                sock(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC),
                RET_ALLOW
            );
            // getaddrinfo opens a raw NETLINK_ROUTE socket.
            assert_eq!(
                sock(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC),
                RET_ALLOW
            );
            // Raw and packet sockets.
            assert_eq!(sock(libc::AF_INET, libc::SOCK_RAW), RET_EACCES);
            assert_eq!(
                sock(libc::AF_INET6, libc::SOCK_RAW | libc::SOCK_CLOEXEC),
                RET_EACCES
            );
            assert_eq!(sock(libc::AF_INET, SOCK_PACKET as i32), RET_EACCES);
            assert_eq!(sock(libc::AF_PACKET, libc::SOCK_RAW), RET_EACCES);
            assert_eq!(sock(libc::AF_PACKET, libc::SOCK_DGRAM), RET_EACCES);
            // Families an agent does not need.
            for fam in [
                libc::AF_BLUETOOTH,
                libc::AF_CAN,
                libc::AF_ALG,
                libc::AF_VSOCK,
                libc::AF_XDP,
            ] {
                assert_eq!(sock(fam, libc::SOCK_STREAM), RET_EACCES, "family {fam}");
                assert_eq!(pair(fam, libc::SOCK_STREAM), RET_EACCES, "family {fam}");
            }
        }
    }

    #[test]
    fn namespaces_io_uring_and_foreign_architectures_are_refused() {
        let a = X86_64;
        let p = assemble(a);
        let call = |nr: u32, arg0: u32| run(&p, a.audit_arch, nr, arg0, 0);
        assert_eq!(call(a.nr.io_uring_setup, 0), RET_EPERM);
        assert_eq!(call(a.nr.clone3, 0), RET_ENOSYS);
        assert_eq!(call(a.nr.setns, 0), RET_EPERM);
        assert_eq!(call(a.nr.unshare, libc::CLONE_NEWUSER as u32), RET_EPERM);
        assert_eq!(call(a.nr.unshare, libc::CLONE_FILES as u32), RET_ALLOW);
        assert_eq!(call(a.nr.clone, libc::CLONE_NEWNET as u32), RET_EPERM);
        // An ordinary fork (exit signal SIGCHLD in the low byte).
        assert_eq!(call(a.nr.clone, libc::SIGCHLD as u32), RET_ALLOW);
        assert_eq!(
            run(&p, AARCH64.audit_arch, a.nr.socket, 2, 1),
            RET_KILL_PROCESS
        );
        assert_eq!(call(a.nr.socket | X32_SYSCALL_BIT, 2), RET_EPERM);
    }

    /// TIOCSTI / TIOCLINUX push input into the controlling terminal; the
    /// agent shares the user's terminal, so both are refused. Other ioctls
    /// (window size, raw mode) still work.
    #[test]
    fn terminal_injection_ioctls_are_refused() {
        // ioctl is 16 on x86_64, 29 in the generic table (aarch64, riscv64).
        for (arch, ioctl) in [(X86_64, 16u32), (AARCH64, 29u32)] {
            let p = assemble(arch);
            let io = |req: u32| run(&p, arch.audit_arch, ioctl, 0, req);
            assert_eq!(io(libc::TIOCSTI as u32), RET_EPERM);
            assert_eq!(io(0x541C), RET_EPERM); // TIOCLINUX
            assert_eq!(io(libc::TIOCGWINSZ as u32), RET_ALLOW);
            assert_eq!(io(libc::TCGETS as u32), RET_ALLOW);
        }
    }

    #[test]
    fn ioctl_number_matches_libc() {
        if let Some(arch) = super::super::NATIVE {
            assert_eq!(libc::c_long::from(ioctl_nr(arch)), libc::SYS_ioctl);
        }
    }

    /// Only NETLINK_ROUTE (what getaddrinfo and `ip` use) is allowed among
    /// netlink protocols.
    #[test]
    fn only_netlink_route_is_allowed() {
        for arch in [X86_64, AARCH64] {
            let p = assemble(arch);
            let nl = |proto: i32| {
                run3(
                    &p,
                    arch.audit_arch,
                    arch.nr.socket,
                    libc::AF_NETLINK as u32,
                    (libc::SOCK_RAW | libc::SOCK_CLOEXEC) as u32,
                    proto as u32,
                )
            };
            assert_eq!(nl(libc::NETLINK_ROUTE), RET_ALLOW);
            for proto in [
                libc::NETLINK_AUDIT,
                libc::NETLINK_KOBJECT_UEVENT,
                libc::NETLINK_NETFILTER,
                libc::NETLINK_SOCK_DIAG,
                libc::NETLINK_GENERIC,
            ] {
                assert_eq!(nl(proto), RET_EACCES, "protocol {proto}");
            }
        }
    }

    /// Unlike the native-plugin program: job control and sessions work.
    #[test]
    fn process_groups_sessions_and_everything_else_are_allowed() {
        let a = X86_64;
        let p = assemble(a);
        for nr in [
            a.nr.setsid,
            a.nr.setpgid,
            a.nr.keyctl,
            a.nr.prlimit64,
            a.nr.setpriority,
        ] {
            assert_eq!(run(&p, a.audit_arch, nr, 1234, 0), RET_ALLOW, "nr {nr}");
        }
        assert_eq!(run(&p, a.audit_arch, 0, 0, 0), RET_ALLOW); // read
    }
}
