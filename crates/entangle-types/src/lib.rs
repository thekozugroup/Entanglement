//! `entangle-types` — foundational domain types for the Entanglement architecture.
//!
//! This crate is intentionally pure: no I/O, no async, no runtime dependencies.
//! All other crates in the workspace may depend on this crate.
//!
//! See spec §4 (capability tiers), §7 (task model), §4.1 (plugin identifiers) in
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! **Phase**: 1 (foundational; extended in Phase 2 for mesh task scheduling).
//!
//! # Key types
//! - [`plugin_id::PluginId`] — `"<publisher-hex>/<name>@<version>"` identifier.
//! - [`tier::Tier`] — capability tier 1–5 (Pure … Native).
//! - [`capability::CapabilityKind`] — enumeration of all declarable capabilities.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod capability;
pub mod errors;
pub mod peer_id;
pub mod plugin_id;
pub mod resource;
pub mod task;
pub mod tier;
