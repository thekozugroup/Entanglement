//! Top-level runtime orchestration — wires all subsystems into the plugin lifecycle.
//!
//! See spec §3 (plugin load pipeline), §9 (runtime crate layout) in
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! **Phase**: 1 (kernel + lifecycle); Phase 2 adds mesh-aware scheduling.
//!
//! # Lifecycle (spec §3)
//! 1. Manifest is loaded and validated (`entangle-manifest`).
//! 2. Plugin artifact + signature bundle are verified (`entangle-signing`).
//! 3. Plugin is registered with the capability broker (`entangle-broker`).
//! 4. The plugin is instantiated by the host (`entangle-host`).
//! 5. Lifecycle events are emitted on the IPC bus (`entangle-ipc`).
//!
//! # Key types
//! - [`Kernel`] — top-level orchestrator; call `load_plugin_from_dir` to run the pipeline.
//! - [`KernelConfig`] — daemon-wide tuning (max tier, bus capacity).
//! - [`LifecycleEvent`] — bus payload emitted at each pipeline phase.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod errors;
pub mod integrity;
pub mod kernel;
pub mod lifecycle;
pub mod loader;

#[cfg(test)]
mod tests;

pub use errors::RuntimeError;
pub use integrity::{check_trusted_executor, verify_deterministic, IntegrityError, ReplicaOutput};
pub use kernel::{Kernel, KernelConfig};
pub use lifecycle::{LifecycleEvent, LifecyclePhase};
pub use loader::PluginPackage;
