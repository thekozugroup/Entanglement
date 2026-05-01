//! Wasmtime + WASI 0.2 host for tier 1–3 WebAssembly plugins.
//!
//! See spec §10 (entangle-host crate responsibilities) in
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! **Phase**: 1 (compile + instantiate); Phase 2 adds sandboxed filesystem/network.
//!
//! # Key types
//! - [`HostEngine`] — shared Wasmtime engine (cheaply cloneable; one per daemon).
//! - [`LoadedPlugin`] — compiled wasm component ready for one-shot invocation.
//! - [`HostState`] — per-invocation WASI context and log buffer.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bindings;
pub mod engine;
pub mod errors;
pub mod plugin;
pub mod state;

pub use engine::HostEngine;
pub use errors::HostError;
pub use plugin::{LoadedPlugin, PluginRunResult};
pub use state::HostState;
