//! Wasmtime + WASI 0.2 host for tier 1–3 WebAssembly plugins.
//!
//! See spec §10 (entangle-host crate responsibilities) in
//! `docs/architecture.md`.
//!
//! **Phase**: 1 (compile + instantiate); Phase 2 adds sandboxed filesystem/network.
//!
//! # Key types
//! - [`HostEngine`] — shared Wasmtime engine (cheaply cloneable; one per daemon).
//! - [`LoadedPlugin`] — compiled wasm component ready for one-shot invocation.
//! - [`HostState`] — per-invocation WASI context and log buffer.
//! - [`LoadedMetric`] — a compiled `entangle:integrity/metric` component
//!   (spec §7.5), run at tier 2 with an observable instantiation counter.
//! - [`LoadedStreamPlugin`] — a compiled `stream-plugin` component (spec
//!   §7.1) and the [`StreamPort`] its chunks flow through.
//! - [`CompiledPlugin`] — either kind, classified by the world it exports.
//! - [`check_runtime_kind`] — magic-byte check that an artifact is the runtime
//!   kind its manifest declares (ATC-MAN-3).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bindings;
pub mod engine;
pub mod errors;
pub mod metric;
pub mod plugin;
pub mod runtime_kind;
pub mod state;
pub mod stream;

pub use engine::HostEngine;
pub use errors::HostError;
pub use metric::LoadedMetric;
pub use plugin::{CompiledPlugin, LoadedPlugin, PluginRunResult};
pub use runtime_kind::{check_runtime_kind, ArtifactKind, DeclaredRuntime};
pub use state::HostState;
pub use stream::{
    stream_port, ChunkAck, ChunkResult, LoadedStreamPlugin, PluginChunk, StreamInput, StreamPort,
    StreamPortDriver, StreamRunResult, INPUT_HANDLE, OUTPUT_HANDLE,
};
