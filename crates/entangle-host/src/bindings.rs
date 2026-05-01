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
        self.log_buffer.push((level_str.to_string(), message));
    }
}

// -- capability -------------------------------------------------------------

impl entangle::plugin::capability::Host for HostState {
    async fn fetch(
        &mut self,
        _kind: entangle::plugin::capability::Kind,
        _name: Option<String>,
    ) -> Result<u32, FetchError> {
        // Iter-1 stub: deny everything.
        // Future iter wires through the broker.
        Err(FetchError::NotGranted("not yet wired to broker".into()))
    }

    async fn release(&mut self, _h: u32) {
        // no-op
    }
}

// -- host-info --------------------------------------------------------------

impl entangle::plugin::host_info::Host for HostState {
    async fn get(&mut self) -> entangle::plugin::host_info::Info {
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
