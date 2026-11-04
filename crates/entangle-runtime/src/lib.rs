//! Top-level runtime orchestration — wires all subsystems into the plugin lifecycle.
//!
//! See spec §3 (plugin load pipeline), §9 (runtime crate layout) in
//! `docs/architecture.md`.
//!
//! **Phase**: 1 (kernel + lifecycle); Phase 2 adds mesh-aware scheduling.
//!
//! # Lifecycle (spec §3)
//! 1. Manifest is loaded and validated (`entangle-manifest`).
//! 2. Plugin artifact + signature bundle are verified (`entangle-signing`).
//! 3. Plugin is registered with the capability broker (`entangle-broker`).
//! 4. The plugin is instantiated by the host (`entangle-host`), or — for a
//!    native tier 4–5 plugin — staged and run in an OS sandbox
//!    (`entangle-sandbox`, see [`native`]).
//! 5. Lifecycle events are emitted on the IPC bus (`entangle-ipc`).
//!
//! # Key types
//! - [`Kernel`] — top-level orchestrator; call `load_plugin_from_dir` to run the pipeline.
//! - [`KernelConfig`] — daemon-wide tuning (max tier, bus capacity).
//! - [`LifecycleEvent`] — bus payload emitted at each pipeline phase.
//! - [`MetricRegistry`] — verified `SemanticEquivalent` metric components
//!   (spec §7.5), used by the scheduler's submitter-side verifier.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod errors;
pub mod integrity;
pub mod kernel;
pub mod lifecycle;
pub mod loader;
pub mod metric;
pub mod native;
pub mod os_sandbox;
mod slot;

#[cfg(test)]
mod tests;

/// The on-disk AOT compilation cache ([`KernelConfig::aot_cache`]).
pub use entangle_aot::{AotCache, AotCacheConfig, GcReport as AotGcReport};
/// The `[security] deny_capabilities` pattern type ([`KernelConfig::denied_capabilities`]).
pub use entangle_broker::CapabilityPattern;
pub use entangle_manifest::lifecycle::{Activation, Lifecycle};
pub use errors::RuntimeError;
pub use integrity::{check_trusted_executor, verify_deterministic, IntegrityError, ReplicaOutput};
pub use kernel::{
    DisabledPlugins, Kernel, KernelConfig, LoadedPluginInfo, MaxTierOutcome, MaxTierRefusal,
    PluginSource,
};
pub use lifecycle::{LifecycleEvent, LifecyclePhase};
pub use loader::PluginPackage;
pub use metric::{MetricEntry, MetricRegistry};
pub use native::{NativeConfig, NativeError};
pub use os_sandbox::{probe as probe_os_sandbox, SandboxProbe};
