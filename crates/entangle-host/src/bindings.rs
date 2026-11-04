//! Generated host bindings for the `entangle:plugin@0.1.0` package.
//!
//! Uses `wasmtime::component::bindgen!` to generate typed host-side bindings
//! for the `plugin` world.  The macro reads the WIT files at compile time and
//! emits:
//!   - A `Plugin` struct with `add_to_linker_async` / `instantiate_async` helpers.
//!   - `Host` traits for each imported interface the host must implement.
//!
//! In async bindgen mode, WIT host functions become `async fn` on the `Host`
//! traits.  The wasmtime store is configured for async (required by
//! wasmtime-wasi p2), so `instantiate_async` and `call_run(...).await` are
//! the correct call sites.

#![allow(missing_docs)] // generated code

wasmtime::component::bindgen!({
    // Path is relative to the crate's Cargo.toml (crates/entangle-host/).
    path: "../entangle-wit/wit",
    world: "plugin",
    // async: true is the wasmtime ≥44 syntax; wasmtime 43 uses per-section flags.
    imports: { default: async },
    exports: { default: async },
});

// ---------------------------------------------------------------------------
// Host trait implementations on HostState
// ---------------------------------------------------------------------------

use crate::HostState;
use entangle::plugin::capability::FetchError;

// -- logging ----------------------------------------------------------------

impl entangle::plugin::logging::Host for HostState {
    async fn log(&mut self, level: entangle::plugin::logging::Level, message: String) {
        let level_str = match level {
            entangle::plugin::logging::Level::Trace => "trace",
            entangle::plugin::logging::Level::Debug => "debug",
            entangle::plugin::logging::Level::Info => "info",
            entangle::plugin::logging::Level::Warn => "warn",
            entangle::plugin::logging::Level::Error => "error",
        };
        // Enforced cap: see HostState::push_log (MAX_LOG_LINES / MAX_LOG_BYTES).
        self.push_log(level_str, message);
    }
}

// -- capability -------------------------------------------------------------

/// The WIT name of a `capability.kind` case (see
/// [`crate::capability::capability_key`]).
pub fn kind_name(kind: entangle::plugin::capability::Kind) -> &'static str {
    use entangle::plugin::capability::Kind;
    match kind {
        Kind::ComputeCpu => "compute-cpu",
        Kind::ComputeGpu => "compute-gpu",
        Kind::ComputeNpu => "compute-npu",
        Kind::StorageLocal => "storage-local",
        Kind::StorageShare => "storage-share",
        Kind::NetLan => "net-lan",
        Kind::NetWan => "net-wan",
        Kind::MeshPeer => "mesh-peer",
        Kind::AgentInvoke => "agent-invoke",
        Kind::HostDockerSocket => "host-docker-socket",
        Kind::Custom => "custom",
    }
}

/// Brokered: see [`crate::capability`]. Every decision is made, audited and
/// counted by the broker; a malformed `(kind, name)` pair is `invalid-kind`
/// before it reaches it.
impl entangle::plugin::capability::Host for HostState {
    async fn fetch(
        &mut self,
        kind: entangle::plugin::capability::Kind,
        name: Option<String>,
    ) -> Result<u32, FetchError> {
        let Some(key) = crate::capability::capability_key(kind_name(kind), name.as_deref()) else {
            return Err(FetchError::InvalidKind);
        };
        self.fetch_capability(&key).map_err(|r| match r {
            crate::capability::FetchRefusal::NotGranted(why) => FetchError::NotGranted(why),
            crate::capability::FetchRefusal::InvalidKind => FetchError::InvalidKind,
            crate::capability::FetchRefusal::Revoked => FetchError::Revoked,
        })
    }

    async fn release(&mut self, h: u32) {
        self.release_capability(h);
    }
}

// -- host-info --------------------------------------------------------------

impl entangle::plugin::host_info::Host for HostState {
    async fn get(&mut self) -> entangle::plugin::host_info::Info {
        // Debug-build fault point: a panic in a host call the kernel
        // contains (spec §2.1; see `entangle_core::fault`).
        entangle_core::fault::inject("host-call");
        entangle::plugin::host_info::Info {
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            plugin_id: format!(
                "{}/{}@{}",
                self.plugin_id.publisher, self.plugin_id.name, self.plugin_id.version
            ),
            declared_tier: self.effective_tier as u8,
            effective_tier: self.effective_tier as u8,
        }
    }
}

// -- types --------------------------------------------------------------------
// The `types` interface defines `plugin-error` and `stream-handle`; both are
// used on the guest side only. bindgen! may still generate an empty Host trait
// that HostState must implement.

impl entangle::plugin::types::Host for HostState {}
