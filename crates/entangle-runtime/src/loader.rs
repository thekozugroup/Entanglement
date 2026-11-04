//! On-disk plugin package loader.

use std::path::{Path, PathBuf};

/// Artifact file name of a WebAssembly plugin.
pub const WASM_ARTIFACT: &str = "plugin.wasm";
/// Artifact file name of a native (tier 4–5) plugin.
pub const NATIVE_ARTIFACT: &str = "plugin.bin";

/// An on-disk plugin "package": the bytes + manifest + signature bundle.
///
/// Expected layout:
/// ```text
/// <dir>/entangle.toml                        — manifest
/// <dir>/plugin.wasm     | <dir>/plugin.bin   — wasm component | native executable
/// <dir>/plugin.wasm.sig | <dir>/plugin.bin.sig — TOML signature bundle
/// ```
/// `plugin.wasm` wins when both artifacts exist. The file name is only a
/// convention: the kernel checks the artifact's *bytes* against the
/// manifest's declared runtime (ATC-MAN-3), so renaming a native executable
/// to `plugin.wasm` does not get it run as wasm, or the reverse.
pub struct PluginPackage {
    /// The package directory.
    pub dir: PathBuf,
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
    /// Reads the artifact and `entangle.toml` into memory. The signature
    /// path is stored for later loading by the kernel.
    pub fn from_directory(dir: &Path) -> Result<Self, std::io::Error> {
        let manifest_path = dir.join("entangle.toml");
        let artifact_name = if dir.join(WASM_ARTIFACT).exists() {
            WASM_ARTIFACT
        } else if dir.join(NATIVE_ARTIFACT).exists() {
            NATIVE_ARTIFACT
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "no plugin artifact in {}: expected {WASM_ARTIFACT} (wasm) or \
                     {NATIVE_ARTIFACT} (native)",
                    dir.display()
                ),
            ));
        };
        let artifact_path = dir.join(artifact_name);
        let signature_path = dir.join(format!("{artifact_name}.sig"));
        let bytes = std::fs::read(&artifact_path)?;
        let manifest_bytes = std::fs::read(&manifest_path)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            manifest_path,
            artifact_path,
            signature_path,
            bytes,
            manifest_bytes,
        })
    }
}
