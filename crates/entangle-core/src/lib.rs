//! Shared kernel utilities and foundational abstractions for the Entanglement workspace.
//!
//! See spec §2 (core runtime responsibilities) and §10 (crate layout) in
//! `docs/architecture.md`.
//!
//! **Phase**: 1 (utility functions used across all Phase-1 crates).
//!
//! # Key items
//! - [`version`] — returns the crate version string (build-time constant).
//! - [`fault`] — process fault isolation (spec §2.1): the daemon's panic
//!   hook and exit code, contained plugin calls, critical sections, the core
//!   task supervisor, and debug-only fault injection.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod fault;

/// Returns the crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
