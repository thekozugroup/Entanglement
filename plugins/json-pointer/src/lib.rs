//! Stand-alone RFC 6901 JSON Pointer resolver.

#![forbid(unsafe_code)]

mod pointer;

use serde::Deserialize;
use serde_json::value::RawValue;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input<'a> {
    pointer: String,
    #[serde(borrow)]
    data: &'a RawValue,
}

/// Resolve the input envelope and return the selected value as JSON bytes.
pub fn transform(input: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(input).map_err(|_| "input must be UTF-8 JSON")?;
    if !text
        .trim_start_matches([' ', '\t', '\n', '\r'])
        .starts_with('{')
    {
        return Err("invalid input envelope: expected a JSON object".into());
    }
    let input: Input =
        serde_json::from_str(text).map_err(|error| format!("invalid input envelope: {error}"))?;
    let tokens =
        pointer::parse(&input.pointer).map_err(|error| format!("invalid pointer: {error}"))?;
    let selected = pointer::resolve(input.data, &tokens)?;
    Ok(selected.get().as_bytes().to_vec())
}

#[cfg(target_arch = "wasm32")]
mod wasm_entry {
    use entangle_sdk::{entangle_plugin, PluginError};

    fn run(input: Vec<u8>) -> Result<Vec<u8>, PluginError> {
        super::transform(&input).map_err(PluginError::InvalidInput)
    }

    entangle_plugin!(run);
}
