//! TOML manifest schema, parsing, and semantic validation for Entanglement plugins.
//!
//! See spec §4.4 (manifest format) and §4.4.1 (implied vs declared capabilities) in
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! **Phase**: 1 (all plugin loads require a valid manifest).
//!
//! # Quick start
//!
//! ```no_run
//! use entangle_manifest::load_manifest;
//! let vm = load_manifest(std::path::Path::new("entangle.toml")).unwrap();
//! println!("effective tier: {:?}", vm.effective_tier);
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod loader;
pub mod schema;
pub mod validate;

pub use loader::load_manifest;
pub use schema::{BuildSection, Manifest, PluginSection, Runtime, SignatureSection};
pub use validate::{ValidatedManifest, ValidationError};

// Re-export CapabilitiesSection alias for callers that import it by name.
// The capabilities map is typed as BTreeMap<String, toml::Value> in Manifest;
// we expose a type alias so the public API surface matches the spec.

/// Type alias for the raw capabilities map stored in [`Manifest`].
pub type CapabilitiesSection = std::collections::BTreeMap<String, toml::Value>;
