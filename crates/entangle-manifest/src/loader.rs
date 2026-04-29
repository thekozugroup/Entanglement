//! Load a [`ValidatedManifest`] from disk.

use std::path::Path;

use thiserror::Error;

use crate::schema::Manifest;
use crate::validate::{validate, ValidatedManifest, ValidationError};

/// Errors that can occur while loading a manifest from disk.
#[derive(Debug, Error)]
pub enum LoadError {
    /// An I/O error occurred while reading the file.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// The file contents could not be parsed as TOML.
    #[error("toml parse: {0}")]
    Parse(#[from] toml::de::Error),

    /// The manifest parsed as TOML but failed semantic validation.
    #[error("validation: {0}")]
    Validation(#[from] ValidationError),
}

/// Read, parse, and validate the `entangle.toml` at `path`.
///
/// This is the primary entry point for consuming a manifest file.
///
/// # Errors
/// Returns [`LoadError::Io`] if the file cannot be read,
/// [`LoadError::Parse`] if the TOML is malformed, or
/// [`LoadError::Validation`] if it fails semantic validation.
pub fn load_manifest(path: &Path) -> Result<ValidatedManifest, LoadError> {
    let text = std::fs::read_to_string(path)?;
    let raw: Manifest = toml::from_str(&text)?;
    let validated = validate(raw)?;
    Ok(validated)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Test 9 — load_manifest round-trip via tempfile.
    #[test]
    fn load_manifest_valid_roundtrip() {
        use std::io::Write;

        // publisher must be exactly 32 lowercase hex chars (BLAKE3-16).
        // tier=3 (Networked), compute.cpu min_tier=Sandboxed(2) → valid.
        let toml_content = r#"
[plugin]
id = "aabbccddeeff00112233445566778899/hello-world@0.1.0"
version = "0.1.0"
tier = 3
runtime = "wasm"
description = "A basic test plugin"

[capabilities]
"compute.cpu" = {}

[build]
wit_world = "entangle:plugin/hello@0.1.0"
target = "wasm32-wasip2"
"#;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("entangle.toml");
        let mut f = std::fs::File::create(&path).expect("create file");
        f.write_all(toml_content.as_bytes()).expect("write");
        drop(f);

        let vm = load_manifest(&path).expect("should load and validate");
        // effective_tier = max(declared=Networked(3), implied=Sandboxed(2)) = Networked.
        use entangle_types::tier::Tier;
        assert_eq!(vm.effective_tier, Tier::Networked);
    }
}
