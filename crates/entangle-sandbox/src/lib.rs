//! OS-sandbox engagement and the subprocess supervisor for tier-5 native
//! plugins (spec §0.2, §3.4, §3.5, §8.2).
//!
//! # What this crate does
//! 1. [`probe()`] reports what the host offers: the Landlock ABI version
//!    (from `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`
//!    — not a `/proc` file), whether unprivileged user+network namespaces
//!    work, whether seccomp filters are available, `bwrap`, `sandbox-exec`.
//! 2. [`plan()`] chooses, purely from a [`SandboxProfile`] and a
//!    [`HostSupport`], which mechanisms to engage — or refuses. It performs no
//!    I/O, so the selection logic is unit-tested for every host shape.
//! 3. `sandboxed_command` (Unix) turns a plan into a `std::process::Command`
//!    whose child engages the sandbox between `fork` and `exec`.
//! 4. [`supervisor`] runs one request/response exchange with a sandboxed
//!    child over length-prefixed frames on stdin/stdout, enforcing a
//!    deadline (killing the process group), an output cap, and logging the
//!    child's stderr through `tracing`.
//!
//! # Linux enforcement layers
//! A child that is not granted the network and runs under Landlock gets:
//! - **Landlock** filesystem allowlist: its program (read+exec), the minimal
//!   system paths to exec a dynamically linked binary, its storage scopes,
//!   nothing else. On ABI ≥ 4 TCP `bind`/`connect` are handled (denied); on
//!   ABI ≥ 6 signals and abstract Unix sockets are scoped to the sandbox, so
//!   the plugin cannot signal the daemon.
//! - **A fresh user + network namespace** (when unprivileged user namespaces
//!   work): the child sees only a downed loopback interface. Its uid/gid are
//!   mapped to themselves so files it creates in its storage scope keep the
//!   daemon's ownership.
//! - **A seccomp-bpf filter**: `socket()` and `socketpair()` are refused for
//!   every address family the profile does not grant (`AF_INET`/`AF_INET6`/
//!   `AF_NETLINK` without the network, `AF_UNIX` unless explicitly granted,
//!   `AF_PACKET` never);
//!   `io_uring_setup` is refused because io_uring can create sockets without
//!   passing through the `socket` syscall; foreign-architecture and x32
//!   syscalls are refused.
//! - `PR_SET_NO_NEW_PRIVS`, `RLIMIT_CORE = 0`, address-space / CPU / fd
//!   rlimits, every inherited descriptor above stderr marked close-on-exec,
//!   an empty environment plus what the profile sets, and its own process
//!   group so a timeout can kill everything it forked.
//!
//! Network denial therefore does not depend on user namespaces alone: on
//! hosts that restrict them (Ubuntu ≥ 23.10 with
//! `kernel.apparmor_restrict_unprivileged_userns=1`) the seccomp filter and
//! Landlock's TCP rules still apply. If only Landlock TCP rules remain the
//! plan reports [`NetworkIsolation::TcpOnly`] instead of pretending.
//!
//! # Why `pre_exec` with raw syscalls, not a re-exec trampoline
//! The daemon and CLI are multi-threaded tokio processes. Between `fork` and
//! `exec` only async-signal-safe operations are allowed: another thread may
//! have held the allocator lock at the moment of the fork, so allocating (or
//! taking any lock) in the child can deadlock forever.
//!
//! The alternative — re-executing a single-threaded trampoline binary that
//! then sandboxes itself — needs a second executable that must be found,
//! trusted and kept in lockstep with the daemon on every install path, and
//! the trampoline would itself have to be allowed through the sandbox.
//! Everything the sandbox needs can instead be *prepared in the parent*:
//! the Landlock ruleset is created and populated there (its fd is inherited
//! across `fork`), the seccomp program is assembled there, the uid/gid map
//! lines are formatted there. What is left for the child is a fixed sequence
//! of raw syscalls on pre-built data — `setrlimit`, `close_range`/`fcntl`,
//! `unshare`, `open`/`write`/`close` on `/proc/self/*_map`, `prctl`,
//! `landlock_restrict_self` — none of which allocates or locks. That is the
//! approach implemented here; [`std::io::Error::from_raw_os_error`] and
//! [`std::io::Error::last_os_error`] are allocation-free, so even the error
//! path is safe. A failing step fails the spawn (fail closed): the child never
//! reaches `exec` with a partially engaged sandbox.
//!
//! # Fallbacks
//! - **bubblewrap** when Landlock is absent: the argv is built by
//!   [`bwrap::bwrap_args`] (bind-mount allowlist, `--unshare-all`,
//!   `--share-net` only when granted, `--die-with-parent`).
//! - **macOS Seatbelt**: [`seatbelt::seatbelt_profile`] renders an SBPL
//!   program from the profile, run via `sandbox-exec -p`.
//! - **None available**: refused with `ENTANGLE-E0700` unless the operator
//!   set the explicit opt-out ([`Policy::allow_unsandboxed`]).
//!
//! # Known limits (stated, not hidden)
//! - Path-based Unix sockets are not covered by Landlock (through ABI 7); the
//!   seccomp `AF_UNIX` rule is what keeps the daemon's RPC socket out of
//!   reach. Without seccomp support that protection is absent.
//! - A plugin's descendants that call `setsid()` leave its process group and
//!   survive the timeout kill (they stay sandboxed). PID namespaces or
//!   cgroups would close this; neither is used yet.
//! - No cgroup memory/CPU accounting: limits are per-process rlimits.

#![warn(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod bwrap;
pub mod error;
pub mod frame;
pub mod plan;
pub mod probe;
pub mod profile;
pub mod seatbelt;
pub mod supervisor;
pub mod trial;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub use unix::sandboxed_command;

pub use error::{SandboxError, SupervisorError};
pub use plan::{plan, Mechanism, NetworkIsolation, Plan, Policy};
pub use probe::{probe, HostSupport, Platform};
pub use profile::{ResourceLimits, SandboxProfile};
pub use supervisor::{InvokeLimits, Supervisor};
