//! Linux primitives: Landlock, seccomp-bpf, user/network namespaces.
//!
//! Every function here that runs in the forked child is `unsafe`, documented
//! as async-signal-safe, and operates only on data prepared in the parent.

pub(crate) mod landlock;
pub(crate) mod seccomp;
pub(crate) mod userns;
