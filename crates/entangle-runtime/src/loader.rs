//! On-disk plugin package loader.

use entangle_signing::package_io::{
    read_regular_file, COMPONENT_LIMIT, MANIFEST_LIMIT, SIGNATURE_LIMIT,
};
use std::path::{Path, PathBuf};

/// An on-disk plugin "package": the bytes + manifest + signature bundle.
///
/// Expected layout:
/// ```text
/// <dir>/entangle.toml      — manifest
/// <dir>/plugin.wasm        — compiled artifact (or .bin for tier 4/5 native — Phase 2+)
/// <dir>/plugin.wasm.sig    — TOML signature bundle
/// ```
pub struct PluginPackage {
    /// Path to the `entangle.toml` manifest.
    pub manifest_path: PathBuf,
    /// Path to the compiled artifact.
    pub artifact_path: PathBuf,
    /// Path to the signature bundle file.
    pub signature_path: PathBuf,
    /// Raw bytes of the artifact.
    pub bytes: Vec<u8>,
    /// Raw bytes of the manifest (`entangle.toml`).
    ///
    /// Read once so that the exact bytes covered by the signature bundle's
    /// manifest hash are the same bytes the kernel parses — no window for the
    /// file to change between hashing and parsing.
    pub manifest_bytes: Vec<u8>,
}

impl PluginPackage {
    /// Load a package from a directory using the conventional file layout.
    ///
    /// Reads `plugin.wasm` and `entangle.toml` into memory. The signature
    /// path is stored for later loading by the kernel.
    pub fn from_directory(dir: &Path) -> Result<Self, std::io::Error> {
        let manifest_path = dir.join("entangle.toml");
        let artifact_path = dir.join("plugin.wasm");
        let signature_path = dir.join("plugin.wasm.sig");
        let manifest_bytes = read_regular_file(&manifest_path, MANIFEST_LIMIT)?;
        let bytes = read_regular_file(&artifact_path, COMPONENT_LIMIT)?;
        Ok(Self {
            manifest_path,
            artifact_path,
            signature_path,
            bytes,
            manifest_bytes,
        })
    }

    /// Read the signature bundle after the kernel has admitted the manifest identity.
    pub(crate) fn read_signature(&self) -> std::io::Result<Vec<u8>> {
        read_regular_file(&self.signature_path, SIGNATURE_LIMIT)
    }
}
