//! On-disk plugin package loader.

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
}

impl PluginPackage {
    /// Load a package from a directory using the conventional file layout.
    ///
    /// Reads `plugin.wasm` into memory. The manifest and signature paths are
    /// stored for later loading by the kernel.
    pub fn from_directory(dir: &Path) -> Result<Self, std::io::Error> {
        let manifest_path = dir.join("entangle.toml");
        let artifact_path = dir.join("plugin.wasm");
        let signature_path = dir.join("plugin.wasm.sig");
        let bytes = std::fs::read(&artifact_path)?;
        Ok(Self {
            manifest_path,
            artifact_path,
            signature_path,
            bytes,
        })
    }
}
