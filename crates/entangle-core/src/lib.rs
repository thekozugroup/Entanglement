//! Shared kernel utilities and foundational abstractions for the Entanglement workspace.
//!
//! See spec §10 (crate layout) in
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! **Phase**: 1 (utility functions used across all Phase-1 crates).
//!
//! # Key items
//! - [`version`] — returns the crate version string (build-time constant).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Returns the crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
