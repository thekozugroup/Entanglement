//! Hash plugin — BLAKE3 hex of input bytes. Pure tier-2 compute, no capabilities.

use entangle_sdk::{entangle_plugin, log};

fn run(input: Vec<u8>) -> Result<Vec<u8>, entangle_sdk::PluginError> {
    log::info(&format!("hash-it: hashing {} bytes", input.len()));
    let h = blake3::hash(&input);
    let hex = h.to_hex().to_string();
    Ok(hex.into_bytes())
}

entangle_plugin!(run);
