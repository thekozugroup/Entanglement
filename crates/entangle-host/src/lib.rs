//! Wasmtime + WASI 0.2 host for tier 1–3 WebAssembly plugins.
//!
//! See spec §10 (entangle-host crate responsibilities) in
//! `docs/architecture.md`.
//!
//! **Phase**: 1 (compile + instantiate) and capability grants: storage and
//! network grants from the broker are realised in each instance's WASI
//! context (see [`capability`]).
//!
//! # Key types
//! - [`HostEngine`] — shared Wasmtime engine (cheaply cloneable; one per daemon).
//! - [`LoadedPlugin`] — compiled wasm component ready for one-shot invocation.
//! - [`HostState`] — per-invocation WASI context and log buffer.
//! - [`CapabilityContext`] — the broker and storage root a plugin's
//!   `capability.fetch` and WASI grants are decided and realised against.
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
pub mod capability;
pub mod engine;
pub mod errors;
mod lookup;
pub mod metric;
pub mod net;
pub mod plugin;
pub mod runtime_kind;
pub mod state;
pub mod storage;
pub mod stream;
mod udp_inbound;

pub use capability::{CapabilityContext, WasiGrants};
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
