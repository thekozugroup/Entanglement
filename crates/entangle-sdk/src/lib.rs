//! Guest-side plugin SDK — the only crate a plugin author needs to depend on.
//!
//! See spec §9.3 (hello-world walkthrough), §4.4 (plugin manifest) in
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! **Phase**: 1 (ships with the initial SDK; wasm32-wasip2 target only for WIT bindings).
//!
//! Rust plugins compiled to `wasm32-wasip2` use this crate to:
//! 1. Declare an entrypoint with [`entangle_plugin!`].
//! 2. Log to the host via [`log`] wrappers.
//! 3. Fetch capability handles via `cap::Cap` (wasm32 only).
//! 4. Read host info (plugin id, effective tier) via the `host_info` import.
//!
//! # Quick start
//! ```ignore
//! use entangle_sdk::{entangle_plugin, log};
//!
//! entangle_plugin!(run);
//!
//! fn run(input: Vec<u8>) -> Result<Vec<u8>, entangle_sdk::PluginError> {
//!     log::info("hello from plugin");
//!     Ok(b"hello, host!".to_vec())
//! }
//! ```

// wit-bindgen generates code that requires the wasm component-model ABI, so
// the generated bindings only compile for the wasm32-wasip2 target.
// Native builds (cargo check / cargo test on host) compile only the
// cfg-gated stub and the version sanity test.
#![allow(unsafe_code)] // wit-bindgen requires unsafe internally; we re-export safe wrappers
#![warn(missing_docs)]

#[cfg(target_arch = "wasm32")]
#[allow(missing_docs)] // generated code: doc comments come from the WIT source, not here
mod wasm {
    // Generate bindings from the entangle:plugin@0.1.0 WIT package.
    //
    // `path` is relative to this crate's Cargo.toml (workspace-relative
    // `../entangle-wit/wit` from `crates/entangle-sdk/`).
    //
    // `pub_export_macro = true` causes wit-bindgen to emit a public `export!`
    // macro (named `export!`) that the `entangle_plugin!` macro below calls to
    // register the component-model export bindings.
    //
    // What wit-bindgen 0.57 generates for the `plugin` world
    // (which has only top-level export `run`):
    //   - import modules:  `entangle::plugin::logging`, `::capability`, `::host_info`, `::types`
    //   - a top-level `Guest` trait with `fn run(input: Vec<u8>) -> Result<Vec<u8>, PluginError>`
    //   - a top-level `PluginError` type (from the `use types.{plugin-error}`)
    //   - a public `export!` macro (because pub_export_macro = true)
    // NOTE: `exports::` module is only generated when the world exports
    // named *interfaces*, not for top-level function exports.
    wit_bindgen::generate!({
        world: "plugin",
        path: "../entangle-wit/wit",
        pub_export_macro: true,
    });

    // Re-export the generated interface modules at the `wasm` module level so
    // they bubble up to crate root.

    /// Capability interface imported from the host.
    pub use entangle::plugin::capability;
    /// Host-info interface imported from the host.
    pub use entangle::plugin::host_info;
    /// Logging interface imported from the host.
    pub use entangle::plugin::logging;
    // PluginError and Guest are emitted at module root by generate! (top-level export)
    // and are already visible in `wasm::`. No re-export needed — they surface via
    // `pub use wasm::*` below.
}

#[cfg(target_arch = "wasm32")]
pub use wasm::*;

// ------------------------------------------------------------------
// Convenience sub-modules (only meaningful on wasm target)
// ------------------------------------------------------------------

/// Ergonomic logging wrappers over the host `entangle:plugin/logging` interface.
pub mod log;

/// Capability handle helpers — RAII wrapper over `entangle:plugin/capability`.
pub mod cap;

// ------------------------------------------------------------------
// The `entangle_plugin!` macro
// ------------------------------------------------------------------

/// Wire up a user-defined `run` function as the wasm-component `run` export.
///
/// The function must have the signature:
/// ```ignore
/// fn run(input: Vec<u8>) -> Result<Vec<u8>, entangle_sdk::PluginError>
/// ```
///
/// # Example
/// ```ignore
/// use entangle_sdk::{entangle_plugin, PluginError};
///
/// entangle_plugin!(my_run);
///
/// fn my_run(input: Vec<u8>) -> Result<Vec<u8>, PluginError> {
///     Ok(input) // echo back
/// }
/// ```
#[macro_export]
macro_rules! entangle_plugin {
    ($run_fn:ident) => {
        struct __EntanglePluginImpl;
        impl $crate::Guest for __EntanglePluginImpl {
            fn run(
                input: ::std::vec::Vec<u8>,
            ) -> ::std::result::Result<::std::vec::Vec<u8>, $crate::PluginError>
            {
                $run_fn(input)
            }
        }
        // `export!` is emitted by wit-bindgen when `pub_export_macro = true`.
        // It registers the component-model export ABI for the `plugin` world.
        $crate::export!(__EntanglePluginImpl with_types_in $crate);
    };
}

// ------------------------------------------------------------------
// Native-target sanity test (compiles and runs on any platform)
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    /// Verifies the crate version string is non-empty (basic build smoke test).
    #[test]
    fn sdk_version_is_set() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }
}
