//! The plugin package layer, and the publisher-trust verifier.
//!
//! A package is the signed directory `entangle plugins build` produces
//! (`entangle.toml`, `plugin.wasm`, `plugin.wasm.sig`; for a native plugin
//! `plugin.bin`, `plugin.bin.sig`) as a zstd-compressed ustar archive (media
//! type [`crate::LAYER_TYPE_PLUGIN`]).
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
/// Artifact file name inside a package (wasm plugins).
pub const FILE_WASM: &str = "plugin.wasm";
/// Signature bundle file name inside a package (wasm plugins).
pub const FILE_SIGNATURE: &str = "plugin.wasm.sig";
/// Artifact file name inside a package of a native (tier 4-5) plugin.
pub const FILE_NATIVE: &str = "plugin.bin";
/// Signature bundle file name inside a package of a native plugin.
pub const FILE_NATIVE_SIGNATURE: &str = "plugin.bin.sig";

/// Optional build-provenance record inside a package (`entangle plugins build`
/// writes it; see `entangle-cli`'s `cmd::package::Provenance`). It is **not**
/// covered by the publisher signature, which binds only the artifact and
/// manifest; `entangle plugins verify --rebuild` is what checks it, by
/// rebuilding from source and comparing.
pub const FILE_PROVENANCE: &str = "provenance.json";

/// Zstd compression level used by [`pack`]. Part of the reproducible-package
/// contract (ATC-PKG-1): changing it changes every package digest.
pub const ZSTD_LEVEL: i32 = 19;

/// Cap on the decompressed size of a package (zip-bomb guard).
pub const MAX_UNPACKED_BYTES: u64 = 256 * 1024 * 1024;

/// The files of a signed package, unverified.
///
/// A package holds one artifact: a wasm component (`plugin.wasm`, the common
/// case) or, when [`PackageFiles::native`] is set, a native executable
/// (`plugin.bin`, tier 4-5 plugins). The two never mix in one package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageFiles {
    /// `entangle.toml` bytes (the exact bytes the signature covers).
    pub manifest: Vec<u8>,
    /// The artifact bytes: `plugin.wasm`, or `plugin.bin` when `native`.
    pub wasm: Vec<u8>,
    /// The signature bundle (TOML): `plugin.wasm.sig`, or `plugin.bin.sig`.
    pub signature: Vec<u8>,
    /// `provenance.json` bytes, when the builder recorded provenance.
    pub provenance: Option<Vec<u8>>,
    /// The artifact is a native executable, stored as `plugin.bin` /
    /// `plugin.bin.sig`. A native package only runs on the kind of host it
    /// was built for; the loader checks that (`ENTANGLE-E0507`).
    pub native: bool,
}

impl PackageFiles {
    /// The artifact's file name: [`FILE_WASM`] or [`FILE_NATIVE`].
    pub fn artifact_name(&self) -> &'static str {
        if self.native {
            FILE_NATIVE
        } else {
            FILE_WASM
        }
    }

    /// The signature bundle's file name.
    pub fn signature_name(&self) -> &'static str {
        if self.native {
            FILE_NATIVE_SIGNATURE
        } else {
            FILE_SIGNATURE
        }
    }

    /// Read the files from a build output directory. Like the loader, a
    /// `plugin.wasm` is preferred when both artifacts are present.
    pub fn read_dir(dir: &Path) -> Result<Self> {
        let rd = |name: &str| {
            std::fs::read(dir.join(name)).map_err(|e| {
                OciError::InvalidPackage(format!("reading {}: {e}", dir.join(name).display()))
            })
        };
        let native = !dir.join(FILE_WASM).exists() && dir.join(FILE_NATIVE).exists();
        let (artifact, signature) = if native {
            (FILE_NATIVE, FILE_NATIVE_SIGNATURE)
        } else {
            (FILE_WASM, FILE_SIGNATURE)
        };
        Ok(Self {
            manifest: rd(FILE_MANIFEST)?,
            wasm: rd(artifact)?,
            signature: rd(signature)?,
            provenance: std::fs::read(dir.join(FILE_PROVENANCE)).ok(),
            native,
        })
    }

    /// Write the files into `dir` (created if needed) in the loader's layout.
    pub fn write_dir(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join(FILE_MANIFEST), &self.manifest)?;
        let artifact = dir.join(self.artifact_name());
        std::fs::write(&artifact, &self.wasm)?;
        #[cfg(unix)]
        if self.native {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::write(dir.join(self.signature_name()), &self.signature)?;
        if let Some(p) = &self.provenance {
            std::fs::write(dir.join(FILE_PROVENANCE), p)?;
        }
        Ok(())
    }
}

/// Pack files into the layer format. Byte-for-byte deterministic for the same
/// input (ATC-PKG-1): fixed entry order, mtime 0, uid/gid 0, empty
/// uname/gname, mode 0644, and an explicitly parameterised single-threaded
/// zstd stream (level [`ZSTD_LEVEL`], content size pledged, checksum on, no
/// long-distance matching, no dictionary).
pub fn pack(files: &PackageFiles) -> Result<Vec<u8>> {
    zstd_deterministic(&package_tar(files))
        .map_err(|e| OciError::InvalidPackage(format!("zstd compression failed: {e}")))
}

/// Smallest slice of the tar stream given to one compression thread by
/// [`pack_with_threads`].
const MIN_THREAD_CHUNK: usize = 64 * 1024;

/// Like [`pack`], but compress with up to `threads` threads.
///
/// `threads <= 1` is exactly [`pack`]. Otherwise the tar stream is cut into
/// `threads` equal slices (none smaller than 64 KiB), each slice is
/// compressed on its own thread with the same parameters as [`pack`], and
/// the resulting zstd frames are concatenated; a zstd decoder reads
/// concatenated frames as one stream, so [`unpack`] accepts the result
/// unchanged.
///
/// **Not bit-stable across thread counts.** The bytes depend on where the
/// slices fall, i.e. on `threads`: an archive packed with `--threads 4`
/// differs from the default single-threaded one and from `--threads 8`, and
/// so does its SHA-256 and its detached signature. (For one given `threads`
/// value the output is still a pure function of the input.) The reproducible
/// archive a third party can re-derive is the single-threaded one.
pub fn pack_with_threads(files: &PackageFiles, threads: u32) -> Result<Vec<u8>> {
    if threads <= 1 {
        return pack(files);
    }
    let tar = package_tar(files);
    let chunk = tar.len().div_ceil(threads as usize).max(MIN_THREAD_CHUNK);
    let frames: Vec<std::io::Result<Vec<u8>>> = std::thread::scope(|scope| {
        let workers: Vec<_> = tar
            .chunks(chunk)
            .map(|slice| scope.spawn(move || zstd_deterministic(slice)))
            .collect();
        workers
            .into_iter()
            .map(|w| {
                w.join()
                    .unwrap_or_else(|_| Err(std::io::Error::other("a compression thread panicked")))
            })
            .collect()
    });
    let mut out = Vec::new();
    for frame in frames {
        out.extend(
            frame.map_err(|e| OciError::InvalidPackage(format!("zstd compression failed: {e}")))?,
        );
    }
    Ok(out)
}

/// How many zstd frames [`pack_with_threads`] writes for `files` with
/// `threads`: 1 for `threads <= 1` and for packages too small to split
/// (the archive is then byte-identical to [`pack`]'s), else one per slice.
pub fn pack_frame_count(files: &PackageFiles, threads: u32) -> usize {
    if threads <= 1 {
        return 1;
    }
    let len = package_tar(files).len();
    let chunk = len.div_ceil(threads as usize).max(MIN_THREAD_CHUNK);
    len.div_ceil(chunk).max(1)
}

/// The normalised ustar stream [`pack`] compresses.
fn package_tar(files: &PackageFiles) -> Vec<u8> {
    let mut tar = Vec::new();
    for (name, data) in [
        (FILE_MANIFEST, &files.manifest),
        (files.artifact_name(), &files.wasm),
        (files.signature_name(), &files.signature),
    ] {
        tar_entry(&mut tar, name, data);
    }
    if let Some(p) = &files.provenance {
        tar_entry(&mut tar, FILE_PROVENANCE, p);
    }
    tar.extend_from_slice(&[0u8; 1024]);
    tar
}

fn zstd_deterministic(tar: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Write as _;
    let mut enc = zstd::stream::write::Encoder::new(Vec::new(), ZSTD_LEVEL)?;
    enc.set_pledged_src_size(Some(tar.len() as u64))?;
    enc.include_contentsize(true)?;
    enc.include_checksum(true)?;
    enc.long_distance_matching(false)?;
    enc.write_all(tar)?;
    enc.finish()
}

/// Read a build directory and pack it.
pub fn pack_dir(dir: &Path) -> Result<Vec<u8>> {
    pack(&PackageFiles::read_dir(dir)?)
}

pub(crate) fn tar_entry(out: &mut Vec<u8>, name: &str, data: &[u8]) {
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

/// Unpack a package, rejecting anything but the expected regular files (one
/// artifact with its signature, the manifest, optional provenance).
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

    let (mut manifest, mut wasm, mut signature, mut provenance) = (None, None, None, None);
    let (mut native_bin, mut native_sig) = (None, None);
    for (name, data) in tar_entries(&tar).map_err(bad)? {
        let slot = match name {
            FILE_MANIFEST => &mut manifest,
            FILE_WASM => &mut wasm,
            FILE_SIGNATURE => &mut signature,
            FILE_NATIVE => &mut native_bin,
            FILE_NATIVE_SIGNATURE => &mut native_sig,
            FILE_PROVENANCE => &mut provenance,
            other => return Err(bad(format!("unexpected entry {other:?}"))),
        };
        if slot.is_some() {
            return Err(bad(format!("duplicate entry {name:?}")));
        }
        *slot = Some(data.to_vec());
    }
    let native = native_bin.is_some() || native_sig.is_some();
    if native {
        if wasm.is_some() || signature.is_some() {
            return Err(bad(format!(
                "a package holds one artifact: {FILE_WASM} and {FILE_NATIVE} entries are mixed"
            )));
        }
        let need =
            |v: Option<Vec<u8>>, n: &str| v.ok_or_else(|| bad(format!("package is missing {n}")));
        return Ok(PackageFiles {
            manifest: need(manifest, FILE_MANIFEST)?,
            wasm: need(native_bin, FILE_NATIVE)?,
            signature: need(native_sig, FILE_NATIVE_SIGNATURE)?,
            provenance,
            native: true,
        });
    }
    let need =
        |v: Option<Vec<u8>>, n: &str| v.ok_or_else(|| bad(format!("package is missing {n}")));
    Ok(PackageFiles {
        manifest: need(manifest, FILE_MANIFEST)?,
        wasm: need(wasm, FILE_WASM)?,
        signature: need(signature, FILE_SIGNATURE)?,
        provenance,
        native: false,
    })
}

/// The regular-file entries of an uncompressed ustar archive, in order, as
/// `(name, contents)`. Anything but a plain regular file with a short name
/// (links, directories, extended headers, a `prefix` field) is refused, as is
/// a truncated archive or a bad header checksum.
pub(crate) fn tar_entries(tar: &[u8]) -> std::result::Result<Vec<(&str, &[u8])>, String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let Some(h) = pos.checked_add(512).and_then(|end| tar.get(pos..end)) else {
            return Err("truncated archive (missing end-of-archive blocks)".into());
        };
        if h.iter().all(|b| *b == 0) {
            return Ok(out);
        }
        // Header checksum: sum with the chksum field as spaces.
        let stored = parse_octal(&h[148..156]).ok_or("bad header checksum field")?;
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
            return Err("tar header checksum mismatch".into());
        }
        if !matches!(h[156], b'0' | 0) {
            return Err(format!(
                "entry type {:?} is not a regular file (links, directories and extended headers are refused)",
                h[156] as char
            ));
        }
        let name_end = h[..100].iter().position(|b| *b == 0).unwrap_or(100);
        let name = std::str::from_utf8(&h[..name_end]).map_err(|_| "non-UTF-8 entry name")?;
        if h[345..500].iter().any(|b| *b != 0) {
            return Err("tar prefix field is not supported".into());
        }
        let size = parse_octal(&h[124..136]).ok_or("bad entry size")?;
        let start = pos + 512;
        let end = start
            .checked_add(usize::try_from(size).map_err(|_| "entry too large")?)
            .filter(|e| *e <= tar.len())
            .ok_or_else(|| format!("entry {name:?} runs past the end of the archive"))?;
        out.push((name, &tar[start..end]));
        pos = start + (end - start).div_ceil(512) * 512;
    }
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
            provenance: None,
            native: false,
        }
    }

    /// A native package round-trips under its own entry names, stays in
    /// alphabetical order, and cannot be mixed with a wasm artifact.
    #[test]
    fn native_packages_use_plugin_bin_and_do_not_mix_with_wasm() {
        let mut f = sample();
        f.native = true;
        f.provenance = Some(b"{}".to_vec());
        let packed = pack(&f).unwrap();
        assert_eq!(unpack(&packed).unwrap(), f);
        assert_eq!(packed, pack(&f).unwrap());
        assert_ne!(
            packed,
            pack(&PackageFiles {
                native: false,
                ..f.clone()
            })
            .unwrap()
        );
        let mut tar = Vec::new();
        zstd::stream::read::Decoder::new(&packed[..])
            .unwrap()
            .read_to_end(&mut tar)
            .unwrap();
        let names: Vec<&str> = tar_entries(&tar).unwrap().iter().map(|e| e.0).collect();
        assert_eq!(
            names,
            [
                FILE_MANIFEST,
                FILE_NATIVE,
                FILE_NATIVE_SIGNATURE,
                FILE_PROVENANCE
            ]
        );

        // Both artifacts in one archive.
        let mut tar = Vec::new();
        tar_entry(&mut tar, FILE_MANIFEST, b"m");
        tar_entry(&mut tar, FILE_NATIVE, b"b");
        tar_entry(&mut tar, FILE_NATIVE_SIGNATURE, b"s");
        tar_entry(&mut tar, FILE_WASM, b"w");
        tar.extend_from_slice(&[0u8; 1024]);
        let z = zstd::stream::encode_all(&tar[..], 3).unwrap();
        assert!(unpack(&z).unwrap_err().to_string().contains("mixed"));
        // A native artifact without its signature.
        let mut tar = Vec::new();
        tar_entry(&mut tar, FILE_MANIFEST, b"m");
        tar_entry(&mut tar, FILE_NATIVE, b"b");
        tar.extend_from_slice(&[0u8; 1024]);
        let z = zstd::stream::encode_all(&tar[..], 3).unwrap();
        assert!(unpack(&z)
            .unwrap_err()
            .to_string()
            .contains("missing plugin.bin.sig"));

        // Directory round trip: the artifact is written executable.
        let d = tempfile::tempdir().unwrap();
        f.write_dir(d.path()).unwrap();
        assert!(d.path().join(FILE_NATIVE).is_file());
        assert!(!d.path().join(FILE_WASM).exists());
        assert_eq!(PackageFiles::read_dir(d.path()).unwrap(), f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(d.path().join(FILE_NATIVE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0o111, "{mode:o}");
        }
    }

    #[test]
    fn pack_unpack_round_trip_and_determinism() {
        let f = sample();
        let a = pack(&f).unwrap();
        assert_eq!(unpack(&a).unwrap(), f);
        assert_eq!(a, pack(&f).unwrap());
    }

    /// The tar stream inside the archive carries no machine- or time-specific
    /// metadata: ATC-PKG-1's archive half.
    #[test]
    fn packed_tar_is_normalised() {
        let mut f = sample();
        f.provenance = Some(b"{}".to_vec());
        let packed = pack(&f).unwrap();
        let mut tar = Vec::new();
        zstd::stream::read::Decoder::new(&packed[..])
            .unwrap()
            .read_to_end(&mut tar)
            .unwrap();
        let mut names = Vec::new();
        let mut pos = 0;
        while tar[pos..pos + 512].iter().any(|b| *b != 0) {
            let h = &tar[pos..pos + 512];
            let end = h[..100].iter().position(|b| *b == 0).unwrap();
            names.push(String::from_utf8(h[..end].to_vec()).unwrap());
            assert_eq!(&h[100..108], b"0000644\0", "mode");
            assert_eq!(&h[108..116], b"0000000\0", "uid");
            assert_eq!(&h[116..124], b"0000000\0", "gid");
            assert_eq!(&h[136..148], b"00000000000\0", "mtime");
            assert!(h[265..345].iter().all(|b| *b == 0), "uname/gname");
            let size = parse_octal(&h[124..136]).unwrap() as usize;
            pos += 512 + size.div_ceil(512) * 512;
        }
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "entries are in alphabetical order");
        assert_eq!(names.len(), 4);
    }

    /// `--threads N`: several frames, still one valid package; the bytes
    /// depend on N (which is why the CLI warns), not on scheduling.
    #[test]
    fn multi_threaded_pack_unpacks_identically_but_is_not_the_single_threaded_bytes() {
        let mut f = sample();
        // Incompressible, so every slice is a frame of real size.
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        f.wasm = (0..600_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        let single = pack(&f).unwrap();
        assert_eq!(pack_with_threads(&f, 0).unwrap(), single);
        assert_eq!(pack_with_threads(&f, 1).unwrap(), single);
        let four = pack_with_threads(&f, 4).unwrap();
        let three = pack_with_threads(&f, 3).unwrap();
        assert_eq!(unpack(&four).unwrap(), f);
        assert_eq!(unpack(&three).unwrap(), f);
        assert_ne!(four, single, "4 threads: different bytes from the default");
        assert_ne!(four, three, "the bytes depend on the thread count");
        assert_eq!(four, pack_with_threads(&f, 4).unwrap(), "stable for one N");
        // A tiny package is one slice whatever N is.
        assert_eq!(
            pack_with_threads(&sample(), 8).unwrap(),
            pack(&sample()).unwrap()
        );
        // The frame count the CLI's warning reports.
        assert_eq!(pack_frame_count(&sample(), 8), 1);
        assert_eq!(pack_frame_count(&f, 1), 1);
        assert_eq!(pack_frame_count(&f, 4), 4);
        assert_eq!(pack_frame_count(&f, 3), 3);
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
