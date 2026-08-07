//! `compress` — round-trippable DEFLATE compression / decompression.
//!
//! Tier 1, no declared capabilities: bytes in, bytes out, no host access beyond
//! logging. See `README.md` for the wire format.
//!
//! Layout: all real work lives in [`codec`], which is free of wasm-only types so
//! it can be exercised with `cargo test` on the host target.
#![warn(missing_docs)]

pub mod codec;
pub mod error;

pub use codec::process;
pub use error::Error;

/// wasm entrypoint. Maps [`Error`] onto the WIT `plugin-error` variant and never
/// panics: a trap would reach the host as a bare "invocation failed".
#[cfg(target_arch = "wasm32")]
fn run(input: Vec<u8>) -> Result<Vec<u8>, entangle_sdk::PluginError> {
    entangle_sdk::log::info(&format!("compress: {} bytes in", input.len()));
    match codec::process(&input) {
        Ok(out) => {
            entangle_sdk::log::info(&format!("compress: {} bytes out", out.len()));
            Ok(out)
        }
        Err(e) => {
            entangle_sdk::log::warn(&format!("compress: {e}"));
            Err(match e {
                Error::InvalidInput(m) => entangle_sdk::PluginError::InvalidInput(m),
                Error::ResourceExhausted(m) => entangle_sdk::PluginError::ResourceExhausted(m),
                Error::Internal(m) => entangle_sdk::PluginError::Internal(m),
            })
        }
    }
}

#[cfg(target_arch = "wasm32")]
entangle_sdk::entangle_plugin!(run);
