//! Distribution of publisher-signed WebAssembly components via OCI and signed tarballs.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod registry;
pub use registry::list_tags;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use entangle_manifest::validate;
use entangle_signing::package_io::{
    read_bounded, read_regular_file, COMPONENT_LIMIT, MANIFEST_LIMIT, SIGNATURE_LIMIT,
};
use entangle_signing::{verify_artifact, IdentityPublicKey, Keyring, Signature, SignatureBundle};
use entangle_types::{plugin_id::PluginId, tier::Tier};
use sha2::{Digest, Sha256};

/// Maximum accepted compressed package size, including frame headers.
pub const ARCHIVE_LIMIT: usize = 68 * 1024 * 1024;
const PROVENANCE_LIMIT: usize = 1024 * 1024;

const FILES: [(&str, usize); 4] = [
    ("entangle.toml", MANIFEST_LIMIT),
    ("plugin.wasm", COMPONENT_LIMIT),
    ("plugin.wasm.sig", SIGNATURE_LIMIT),
    ("rebuild.json", PROVENANCE_LIMIT),
];

/// Distribution crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Raw files authenticated by the publisher and their validated manifest identity.
#[derive(Debug)]
pub struct PackageFiles {
    /// Exact manifest bytes covered by the component signature.
    pub manifest: Vec<u8>,
    /// Signed component bytes.
    pub component: Vec<u8>,
    /// Serialized publisher signature bundle.
    pub signature: Vec<u8>,
    /// Rebuild metadata covered by the archive signature, when available.
    pub provenance: Option<Vec<u8>>,
    /// Validated identifier including publisher and version.
    pub plugin_id: PluginId,
    /// Maximum of the declared tier and the tier implied by the capabilities.
    pub effective_tier: Tier,
}

impl PackageFiles {
    fn verify(
        manifest: Vec<u8>,
        component: Vec<u8>,
        signature: Vec<u8>,
        provenance: Option<Vec<u8>>,
        keyring: &Keyring,
    ) -> Result<Self> {
        let bundle: SignatureBundle = toml::from_str(std::str::from_utf8(&signature)?)?;
        let signer = verify_artifact(&component, &manifest, &bundle, keyring)?;
        let validated = validate(toml::from_str(std::str::from_utf8(&manifest)?)?)?;
        entangle_signing::artifact::verify_publisher_binding(
            &validated.plugin_id.publisher,
            validated
                .raw
                .signature
                .as_ref()
                .map(|s| (s.publisher.as_str(), s.algorithm.as_str())),
            &hex::encode(signer.fingerprint),
            &bundle.algorithm,
        )?;
        Ok(Self {
            manifest,
            component,
            signature,
            provenance,
            plugin_id: validated.plugin_id,
            effective_tier: validated.effective_tier,
        })
    }

    /// Authenticate a bounded tar.zst and its detached Ed25519 signature before decoding.
    pub fn from_signed_archive(bytes: &[u8], sig_bytes: &[u8], keyring: &Keyring) -> Result<Self> {
        ensure!(bytes.len() <= ARCHIVE_LIMIT, "package exceeds size limit");
        let detached = Signature::from_bytes(sig_bytes)?;
        let digest = Sha256::digest(bytes);
        let outer = keyring
            .entries()
            .find_map(|entry| {
                let key = IdentityPublicKey::from_bytes(&entry.public_key).ok()?;
                key.verify(&digest, &detached).ok()?;
                Some(key.fingerprint_hex())
            })
            .context("archive signature did not verify with any trusted publisher")?;
        let mut decoder = zstd::stream::Decoder::new(bytes)?;
        decoder.window_log_max(26)?;
        let mut tar = tar::Archive::new(decoder.take((ARCHIVE_LIMIT + 1) as u64));
        let mut files: [Option<Vec<u8>>; 4] = Default::default();
        for entry in tar.entries()?.raw(true) {
            let mut entry = entry?;
            ensure!(
                entry.header().entry_type().is_file(),
                "expected regular package file"
            );
            let name = entry.path_bytes();
            let index = FILES
                .iter()
                .position(|(n, _)| n.as_bytes() == name.as_ref())
                .context("unexpected package entry")?;
            let (name, limit) = FILES[index];
            ensure!(files[index].is_none(), "duplicate {name}");
            ensure!(entry.size() <= limit as u64, "{name} exceeds size limit");
            files[index] = Some(read_bounded(&mut entry, limit)?);
        }
        // Consume the end of the zstd frame so checksum and size errors reach the caller.
        let mut remainder = tar.into_inner();
        let mut block = [0; 8192];
        loop {
            let n = remainder.read(&mut block)?;
            if n == 0 {
                break;
            }
            ensure!(
                block[..n].iter().all(|b| *b == 0),
                "unexpected data after tar entries"
            );
        }
        ensure!(remainder.limit() != 0, "decoded package exceeds size limit");
        let [manifest, component, signature, provenance] = files;
        let package = Self::verify(
            manifest.context("missing entangle.toml")?,
            component.context("missing plugin.wasm")?,
            signature.context("missing plugin.wasm.sig")?,
            Some(provenance.context("missing rebuild.json")?),
            keyring,
        )?;
        ensure!(
            outer == package.plugin_id.publisher,
            "archive and component publishers differ"
        );
        Ok(package)
    }

    /// Read and authenticate a local package directory.
    pub fn from_directory(dir: &Path, keyring: &Keyring) -> Result<Self> {
        Self::from_directory_with_tier_check(dir, keyring, |_| Ok(()))
    }

    /// Read the bounded manifest once and check the operator policy before opening artifacts.
    pub fn from_directory_with_tier_check(
        dir: &Path,
        keyring: &Keyring,
        check: impl FnOnce(Tier) -> Result<()>,
    ) -> Result<Self> {
        let read = |(name, limit)| read_file(&dir.join(name), limit);
        let manifest = read(FILES[0])?;
        let validated = validate(toml::from_str(std::str::from_utf8(&manifest)?)?)?;
        check(validated.effective_tier)?;
        Self::verify(manifest, read(FILES[1])?, read(FILES[2])?, None, keyring)
    }

    /// Atomically cache the signed package under its content digest. Concurrent
    /// installations of the same bytes converge on the same directory.
    pub fn cache(&self, root: &Path) -> Result<PathBuf> {
        let files = [&self.manifest[..], &self.component, &self.signature];
        let parts = files.into_iter().chain(self.provenance.as_deref());
        let mut digest = Sha256::new();
        for part in parts.clone() {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        std::fs::create_dir_all(root)?;
        let dest = root.join(hex::encode(digest.finalize()));
        let tmp = tempfile::tempdir_in(root)?;
        for ((name, _), bytes) in FILES.iter().zip(parts.clone()) {
            let mut file = std::fs::File::create(tmp.path().join(name))?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        #[cfg(unix)]
        std::fs::File::open(tmp.path())?.sync_all()?;
        if let Err(e) = std::fs::rename(tmp.path(), &dest) {
            if !std::fs::symlink_metadata(&dest).is_ok_and(|meta| meta.is_dir()) {
                return Err(e.into());
            }
            ensure!(
                std::fs::read_dir(&dest)?.count() == parts.clone().count(),
                "unexpected files in existing cache entry"
            );
            for ((name, limit), expected) in FILES.iter().zip(parts) {
                ensure!(
                    read_file(&dest.join(name), *limit)? == expected,
                    "existing cache entry differs"
                );
            }
        }
        #[cfg(unix)]
        std::fs::File::open(root)?.sync_all()?;
        Ok(dest)
    }
}

/// Read a local regular file up to a hard byte ceiling.
pub fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    read_regular_file(path, limit).with_context(|| format!("reading {}", path.display()))
}
