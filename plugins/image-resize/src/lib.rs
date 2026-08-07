//! `image-resize` — decode a PNG/JPEG, resample it, re-encode it.
//!
//! Tier 1, no declared capabilities: bytes in, bytes out, no host access beyond
//! logging. See `README.md` for the wire format.
//!
//! Layout: all real work lives in [`resize`], which is free of wasm-only types so
//! it can be exercised with `cargo test` on the host target.
#![warn(missing_docs)]

pub mod error;
pub mod resize;

pub use error::Error;
pub use resize::process;

/// wasm entrypoint. Maps [`Error`] onto the WIT `plugin-error` variant and never
/// panics: a trap would reach the host as a bare "invocation failed".
///
/// Reimplements [`resize::process`] step by step so the log line can name the
/// source and target geometry — useful when this runs on a remote device.
#[cfg(target_arch = "wasm32")]
fn run(input: Vec<u8>) -> Result<Vec<u8>, entangle_sdk::PluginError> {
    entangle_sdk::log::info(&format!("image-resize: {} bytes in", input.len()));
    match invoke(&input) {
        Ok(out) => {
            entangle_sdk::log::info(&format!("image-resize: {} bytes out", out.len()));
            Ok(out)
        }
        Err(e) => {
            entangle_sdk::log::warn(&format!("image-resize: {e}"));
            Err(match e {
                Error::InvalidInput(m) => entangle_sdk::PluginError::InvalidInput(m),
                Error::ResourceExhausted(m) => entangle_sdk::PluginError::ResourceExhausted(m),
                Error::Internal(m) => entangle_sdk::PluginError::Internal(m),
            })
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn invoke(input: &[u8]) -> Result<Vec<u8>, Error> {
    let (header, body) = resize::split_envelope(input)?;
    let (src_format, src_w, src_h) = resize::probe(body)?;
    let plan = resize::plan(&header, src_format, src_w, src_h)?;
    entangle_sdk::log::info(&format!(
        "image-resize: {}",
        resize::describe(&plan, src_w, src_h)
    ));
    resize::transform(body, &plan)
}

#[cfg(target_arch = "wasm32")]
entangle_sdk::entangle_plugin!(run);
