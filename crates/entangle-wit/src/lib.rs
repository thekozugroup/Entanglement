//! WIT contract definitions for the `entangle:plugin@0.1.0` component-model package.
//!
//! See spec §4.4 (`wit_world` field), §9.3 (hello-world uses these interfaces) in
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! **Phase**: 1 (all wasm plugins target these interfaces).
//!
//! Plugins import this package; WIT source files live in `wit/` and are exposed
//! at compile time via `include_str!`. Both `entangle-host` (linker setup) and
//! `entangle-sdk` (wit-bindgen consumer) depend on this crate.
//!
//! # Key items
//! - [`WIT_PACKAGE`] — canonical package identifier string.
//! - [`wit_files`] — returns all WIT file bytes in deterministic order.
//! - [`world`] — maps a world name to its canonical form.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Canonical package identifier per spec §4.4 `wit_world`.
pub const WIT_PACKAGE: &str = "entangle:plugin@0.1.0";

/// Available world names plugins can target.
pub const WORLDS: &[&str] = &["plugin", "stream-plugin"];

/// Default world for the §9.3 hello-world walkthrough.
pub const DEFAULT_WORLD: &str = "plugin";

/// Returns the bytes of every WIT file in deterministic order.
/// Used by the host to build the Wasmtime component-model `Linker`.
pub fn wit_files() -> &'static [(&'static str, &'static str)] {
    &[
        ("world.wit", include_str!("../wit/world.wit")),
        ("logging.wit", include_str!("../wit/logging.wit")),
        ("capability.wit", include_str!("../wit/capability.wit")),
        ("host-info.wit", include_str!("../wit/host-info.wit")),
        ("stream.wit", include_str!("../wit/stream.wit")),
    ]
}

/// Returns the canonical world name for a given world keyword.
pub fn world(name: &str) -> Option<&'static str> {
    match name {
        "plugin" => Some("plugin"),
        "stream-plugin" | "stream_plugin" => Some("stream-plugin"),
        _ => None,
    }
}
