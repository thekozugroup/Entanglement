//! The plugin package layer, and the publisher-trust verifier.
//!
//! A package is the signed directory `entangle plugins build` produces
//! (`entangle.toml`, `plugin.wasm`, `plugin.wasm.sig`) as a zstd-compressed
//! ustar archive (media type [`crate::LAYER_TYPE_PLUGIN`]).
//!
//! # Trust (ATC-MIR-1)
//! [`verify_package`] is the only place a pulled package is judged, and its
//! signature is the whole argument list: `(&[u8], &Keyring)`. There is no
//! parameter through which a registry name, TLS identity, descriptor or
//! manifest annotation could reach the decision, and `Keyring` is the
//! publisher keyring, a different type from the mirror keyring used for
//! listings.

use std::io::Read as _;
use std::path::Path;
use std::str::FromStr as _;

use entangle_signing::{verify_artifact, Keyring, SignatureBundle, VerificationError};
use entangle_types::plugin_id::PluginId;

use crate::error::{OciError, Result};

/// Manifest file name inside a package.
pub const FILE_MANIFEST: &str = "entangle.toml";
/// Artifact file name inside a package.
pub const FILE_WASM: &str = "plugin.wasm";
/// Signature bundle file name inside a package.
pub const FILE_SIGNATURE: &str = "plugin.wasm.sig";

/// Cap on the decompressed size of a package (zip-bomb guard).
pub const MAX_UNPACKED_BYTES: u64 = 256 * 1024 * 1024;

/// The three files of a signed package, unverified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageFiles {
    /// `entangle.toml` bytes (the exact bytes the signature covers).
    pub manifest: Vec<u8>,
    /// `plugin.wasm` bytes.
    pub wasm: Vec<u8>,
    /// `plugin.wasm.sig` bytes (TOML signature bundle).
    pub signature: Vec<u8>,
}

impl PackageFiles {
    /// Read the three files from a build output directory.
    pub fn read_dir(dir: &Path) -> Result<Self> {
        let rd = |name: &str| {
            std::fs::read(dir.join(name)).map_err(|e| {
                OciError::InvalidPackage(format!("reading {}: {e}", dir.join(name).display()))
            })
        };
        Ok(Self {
            manifest: rd(FILE_MANIFEST)?,
            wasm: rd(FILE_WASM)?,
            signature: rd(FILE_SIGNATURE)?,
        })
    }

    /// Write the files into `dir` (created if needed) in the loader's layout.
    pub fn write_dir(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join(FILE_MANIFEST), &self.manifest)?;
        std::fs::write(dir.join(FILE_WASM), &self.wasm)?;
        std::fs::write(dir.join(FILE_SIGNATURE), &self.signature)?;
        Ok(())
    }
}

/// Pack files into the layer format. Deterministic for the same input
/// (fixed order, zero mtimes, zero owners).
pub fn pack(files: &PackageFiles) -> Result<Vec<u8>> {
    let mut tar = Vec::new();
    for (name, data) in [
        (FILE_MANIFEST, &files.manifest),
        (FILE_WASM, &files.wasm),
        (FILE_SIGNATURE, &files.signature),
    ] {
        tar_entry(&mut tar, name, data);
    }
    tar.extend_from_slice(&[0u8; 1024]);
    zstd::stream::encode_all(&tar[..], 9)
        .map_err(|e| OciError::InvalidPackage(format!("zstd compression failed: {e}")))
}

/// Read a build directory and pack it.
pub fn pack_dir(dir: &Path) -> Result<Vec<u8>> {
    pack(&PackageFiles::read_dir(dir)?)
}

fn tar_entry(out: &mut Vec<u8>, name: &str, data: &[u8]) {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[148..156].copy_from_slice(b"        ");
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(data);
    out.resize(out.len() + (512 - data.len() % 512) % 512, 0);
}

/// Unpack a package, rejecting anything but the three expected regular files.
pub fn unpack(bytes: &[u8]) -> Result<PackageFiles> {
    let bad = |m: String| OciError::InvalidPackage(m);
    let mut tar = Vec::new();
    zstd::stream::read::Decoder::new(bytes)
        .map_err(|e| bad(format!("not zstd data: {e}")))?
        .take(MAX_UNPACKED_BYTES + 1)
        .read_to_end(&mut tar)
        .map_err(|e| bad(format!("zstd decompression failed: {e}")))?;
    if tar.len() as u64 > MAX_UNPACKED_BYTES {
        return Err(bad(format!(
            "decompressed package exceeds {MAX_UNPACKED_BYTES} bytes"
        )));
    }

    let (mut manifest, mut wasm, mut signature) = (None, None, None);
    let mut pos = 0usize;
    loop {
        let Some(h) = tar.get(pos..pos + 512) else {
            return Err(bad(
                "truncated archive (missing end-of-archive blocks)".into()
            ));
        };
        if h.iter().all(|b| *b == 0) {
            break;
        }
        // Header checksum: sum with the chksum field as spaces.
        let stored =
            parse_octal(&h[148..156]).ok_or_else(|| bad("bad header checksum field".into()))?;
        let sum: u64 = h
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(*b)
                }
            })
            .sum();
        if sum != stored {
            return Err(bad("tar header checksum mismatch".into()));
        }
        if !matches!(h[156], b'0' | 0) {
            return Err(bad(format!(
                "entry type {:?} is not a regular file (links, directories and extended headers are refused)",
                h[156] as char
            )));
        }
        let name_end = h[..100].iter().position(|b| *b == 0).unwrap_or(100);
        let name =
            std::str::from_utf8(&h[..name_end]).map_err(|_| bad("non-UTF-8 entry name".into()))?;
        if h[345..500].iter().any(|b| *b != 0) {
            return Err(bad("tar prefix field is not supported".into()));
        }
        let size = parse_octal(&h[124..136]).ok_or_else(|| bad("bad entry size".into()))?;
        let start = pos + 512;
        let end = start
            .checked_add(usize::try_from(size).map_err(|_| bad("entry too large".into()))?)
            .filter(|e| *e <= tar.len())
            .ok_or_else(|| bad(format!("entry {name:?} runs past the end of the archive")))?;
        let slot = match name {
            FILE_MANIFEST => &mut manifest,
            FILE_WASM => &mut wasm,
            FILE_SIGNATURE => &mut signature,
            other => return Err(bad(format!("unexpected entry {other:?}"))),
        };
        if slot.is_some() {
            return Err(bad(format!("duplicate entry {name:?}")));
        }
        *slot = Some(tar[start..end].to_vec());
        pos = start + (end - start).div_ceil(512) * 512;
    }
    let need =
        |v: Option<Vec<u8>>, n: &str| v.ok_or_else(|| bad(format!("package is missing {n}")));
    Ok(PackageFiles {
        manifest: need(manifest, FILE_MANIFEST)?,
        wasm: need(wasm, FILE_WASM)?,
        signature: need(signature, FILE_SIGNATURE)?,
    })
}

fn parse_octal(field: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(field).ok()?;
    let s = s.trim_matches(|c| c == '\0' || c == ' ');
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s, 8).ok()
}

/// A package whose publisher signature verified against a keyring.
#[derive(Clone, Debug)]
pub struct VerifiedPackage {
    /// The verified files.
    pub files: PackageFiles,
    /// `<publisher>/<name>@<version>` from the signed manifest.
    pub plugin_id: String,
    /// Fingerprint (hex) of the trusted key that signed.
    pub signer_fingerprint: String,
}

/// Verify package bytes against the **publisher** keyring.
///
/// This is the same Ed25519 check a local `plugin.wasm.sig` gets
/// ([`entangle_signing::verify_artifact`]), followed by the loader's
/// publisher-binding rules (the signer must be the publisher named in the
/// manifest's plugin id and in the optional `[signature]` section).
///
/// Deliberately takes only bytes and a keyring: see the module docs.
pub fn verify_package(bytes: &[u8], keyring: &Keyring) -> Result<VerifiedPackage> {
    let files = unpack(bytes)?;
    let sig_text = std::str::from_utf8(&files.signature)
        .map_err(|_| OciError::InvalidPackage("signature bundle is not UTF-8".into()))?;
    let bundle: SignatureBundle = toml::from_str(sig_text)
        .map_err(|e| OciError::InvalidPackage(format!("signature bundle TOML: {e}")))?;

    let entry = verify_artifact(&files.wasm, &files.manifest, &bundle, keyring)?;
    let signer = hex::encode(entry.fingerprint);

    let manifest_text = std::str::from_utf8(&files.manifest)
        .map_err(|_| OciError::InvalidPackage("entangle.toml is not UTF-8".into()))?;
    let doc: toml::Value = toml::from_str(manifest_text)
        .map_err(|e| OciError::InvalidPackage(format!("entangle.toml: {e}")))?;
    let id_text = doc
        .get("plugin")
        .and_then(|p| p.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| OciError::InvalidPackage("entangle.toml has no plugin.id".into()))?;
    let id = PluginId::from_str(id_text)
        .map_err(|e| OciError::InvalidPackage(format!("plugin.id {id_text:?}: {e}")))?;
    if !signer.eq_ignore_ascii_case(&id.publisher) {
        return Err(VerificationError::PublisherMismatch {
            manifest_publisher: id.publisher,
            signer_fingerprint: signer,
        }
        .into());
    }
    if let Some(section) = doc.get("signature") {
        let declared = section.get("publisher").and_then(|v| v.as_str());
        if let Some(p) = declared {
            if !p.eq_ignore_ascii_case(&signer) {
                return Err(VerificationError::PublisherMismatch {
                    manifest_publisher: p.to_owned(),
                    signer_fingerprint: signer,
                }
                .into());
            }
        }
        if let Some(a) = section.get("algorithm").and_then(|v| v.as_str()) {
            if a != bundle.algorithm {
                return Err(VerificationError::UnsupportedAlgorithm(a.to_owned()).into());
            }
        }
    }
    Ok(VerifiedPackage {
        files,
        plugin_id: id.to_string(),
        signer_fingerprint: signer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PackageFiles {
        PackageFiles {
            manifest: b"[plugin]\nid = \"x\"\n".to_vec(),
            wasm: [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9].repeat(200),
            signature: b"sig".to_vec(),
        }
    }

    #[test]
    fn pack_unpack_round_trip_and_determinism() {
        let f = sample();
        let a = pack(&f).unwrap();
        assert_eq!(unpack(&a).unwrap(), f);
        assert_eq!(a, pack(&f).unwrap());
    }

    #[test]
    fn unpack_rejects_garbage_extras_and_bombs() {
        assert!(unpack(b"not zstd").is_err());

        // An extra entry.
        let mut tar = Vec::new();
        tar_entry(&mut tar, FILE_MANIFEST, b"m");
        tar_entry(&mut tar, "../evil", b"x");
        tar.extend_from_slice(&[0u8; 1024]);
        let z = zstd::stream::encode_all(&tar[..], 3).unwrap();
        assert!(unpack(&z)
            .unwrap_err()
            .to_string()
            .contains("unexpected entry"));

        // Missing file.
        let mut tar = Vec::new();
        tar_entry(&mut tar, FILE_MANIFEST, b"m");
        tar.extend_from_slice(&[0u8; 1024]);
        let z = zstd::stream::encode_all(&tar[..], 3).unwrap();
        assert!(unpack(&z).unwrap_err().to_string().contains("missing"));

        // A symlink entry.
        let mut tar = Vec::new();
        tar_entry(&mut tar, FILE_MANIFEST, b"");
        tar[156] = b'2';
        // recompute checksum
        tar[148..156].copy_from_slice(b"        ");
        let sum: u32 = tar[..512].iter().map(|b| u32::from(*b)).sum();
        tar[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        tar.extend_from_slice(&[0u8; 1024]);
        let z = zstd::stream::encode_all(&tar[..], 3).unwrap();
        assert!(unpack(&z)
            .unwrap_err()
            .to_string()
            .contains("not a regular file"));
    }
}
