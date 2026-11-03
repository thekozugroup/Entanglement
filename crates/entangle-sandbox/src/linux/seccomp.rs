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
pub(crate) const X86_64: Arch = Arch {
    audit_arch: 0xC000_003E, // AUDIT_ARCH_X86_64
    has_x32: true,
    nr: Nr {
        socket: 41,
        socketpair: 53,
        io_uring_setup: 425,
    },
};

/// The asm-generic syscall table shared by aarch64 and riscv64.
const GENERIC_NR: Nr = Nr {
    socket: 198,
    socketpair: 199,
    io_uring_setup: 425,
};

/// aarch64.
pub(crate) const AARCH64: Arch = Arch {
    audit_arch: 0xC000_00B7, // AUDIT_ARCH_AARCH64
    has_x32: false,
    nr: GENERIC_NR,
};

/// riscv64.
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

const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const JGE_K: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

pub(crate) const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
pub(crate) const RET_KILL_PROCESS: u32 = libc::SECCOMP_RET_KILL_PROCESS;
pub(crate) const RET_EPERM: u32 = libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32);
pub(crate) const RET_EACCES: u32 = libc::SECCOMP_RET_ERRNO | (libc::EACCES as u32);

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
                        other => panic!("unexpected load offset {other}"),
                    };
                    pc += 1;
                }
                JEQ_K | JGE_K => {
                    let taken = if ins.code == JEQ_K {
                        a == ins.k
                    } else {
                        a >= ins.k
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
        ];
        for (ours, theirs) in pairs {
            assert_eq!(i64::from(*ours), i64::from(*theirs));
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
