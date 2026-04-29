//! OCI registry distribution — fetch and verify plugins from OCI registries.
//!
//! See spec §3.6 (OCI/tarball distribution) in
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! **Phase**: 2 scaffold (stub only in Phase 1; no public API beyond `version`).
//!
//! # Key items
//! - [`version`] — returns the crate version string.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Returns the crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
