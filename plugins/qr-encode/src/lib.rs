//! `qr-encode` — UTF-8 text in, QR code out (SVG, block art or JSON).
//!
//! Tier 1, no declared capabilities: bytes in, bytes out, no host access beyond
//! logging. See `README.md` for the wire format.
//!
//! Layout: all real work lives in [`qr`], which is free of wasm-only types so it
//! can be exercised with `cargo test` on the host target.
#![warn(missing_docs)]

pub mod error;
pub mod qr;

pub use error::Error;
pub use qr::process;

/// wasm entrypoint. Maps [`Error`] onto the WIT `plugin-error` variant and never
/// panics: a trap would reach the host as a bare "invocation failed".
#[cfg(target_arch = "wasm32")]
fn run(input: Vec<u8>) -> Result<Vec<u8>, entangle_sdk::PluginError> {
    entangle_sdk::log::info(&format!("qr-encode: {} bytes in", input.len()));
    match qr::process(&input) {
        Ok(out) => {
            entangle_sdk::log::info(&format!("qr-encode: {} bytes out", out.len()));
            Ok(out)
        }
        Err(e) => {
            entangle_sdk::log::warn(&format!("qr-encode: {e}"));
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
