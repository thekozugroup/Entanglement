//! `.entanglepack`: several signed plugin packages in one file, for machines
//! with no route to a registry (spec §3.6 "offline / air-gapped", §6.1).
//!
//! # Format (version 1)
//! An **uncompressed** ustar archive (the packages inside are already zstd
//! streams) holding, in this order:
//!
//! 1. `entanglepack.json`, the index ([`PackIndex`]);
//! 2. `packages/<sha256>.tar.zst`, one per package, in ascending name order.
//!    Each is a package archive exactly as `entangle plugins build` or a
//!    registry produced it ([`crate::pack`]), named after the SHA-256 of its
//!    own bytes.
//!
//! Tar headers are normalised the way package archives are (mode 0644,
//! uid/gid 0, mtime 0, no user or group names), the index is serialised with
//! a fixed field order and sorted lists, and nothing in the file records a
//! time, a host name or a path: [`write_pack`] is a pure function of the set
//! of package bytes and the publisher keys that signed them.
//!
//! # Trust
//! A pack is a container, not an authority.
//!
//! * [`write_pack`] only packs packages that verify against the packer's own
//!   publisher keyring, and copies the public keys of exactly those signers
//!   into the index, so the recipient can see whose signatures to expect.
//! * [`read_pack`] checks the container (every entry named in the index,
//!   sizes and digests, package ids and signers as the index says) and
//!   judges nothing else.
//! * The recipient verifies every package with [`crate::verify_package`]
//!   against **their own** keyring. A public key found in a pack is data
//!   supplied by whoever wrote the pack: it is never trusted because it is
//!   there. The CLI refuses a package whose publisher is unknown, printing
//!   the fingerprint and the `entangle keyring add` command, unless the
//!   operator passes `--trust-pack-keys` after seeing the fingerprints.
//!
//! The index digests detect damage and mix-ups; they are not a signature
//! (anyone can rebuild an index), which is why no trust decision reads them.
//!
//! # Dependency closure
//! Plugin manifests have no plugin-to-plugin dependencies, so the closure of
//! a set of plugins is that set: a pack holds exactly the packages named.

use std::collections::BTreeMap;
use std::str::FromStr as _;

use entangle_signing::{IdentityPublicKey, Keyring, SignatureBundle};
use entangle_types::plugin_id::PluginId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{OciError, Result};
use crate::package::{tar_entries, tar_entry, unpack, verify_package};

/// File-name extension of an offline pack (without the dot).
pub const PACK_EXTENSION: &str = "entanglepack";
/// Name of the index entry, always the first in the archive.
pub const PACK_INDEX_NAME: &str = "entanglepack.json";
/// `format` value of the index.
pub const PACK_FORMAT: &str = "entanglepack";
/// Current `version` of the index.
pub const PACK_VERSION: u32 = 1;
/// Largest pack accepted by [`read_pack`].
pub const MAX_PACK_BYTES: u64 = 1024 * 1024 * 1024;
/// Most packages a pack may hold.
pub const MAX_PACK_PACKAGES: usize = 256;
/// Largest index accepted.
const MAX_INDEX_BYTES: usize = 1024 * 1024;

/// One package listed in the index.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackIndexEntry {
    /// `<publisher>/<name>@<version>` from the package's manifest.
    pub plugin_id: String,
    /// Fingerprint (32 hex) of the key that signed the package.
    pub publisher: String,
    /// Entry name inside the pack, `packages/<sha256>.tar.zst`.
    pub file: String,
    /// SHA-256 (64 hex) of the package archive bytes.
    pub sha256: String,
    /// Size of the package archive in bytes.
    pub size: u64,
}

/// A publisher public key carried in a pack. Informational: see the module
/// docs on trust.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackKey {
    /// Fingerprint (32 hex) of `public_key`.
    pub fingerprint: String,
    /// Ed25519 public key (64 hex).
    pub public_key: String,
}

/// `entanglepack.json`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackIndex {
    /// Always [`PACK_FORMAT`].
    pub format: String,
    /// Format version, currently [`PACK_VERSION`].
    pub version: u32,
    /// The packages, sorted by `plugin_id`.
    pub packages: Vec<PackIndexEntry>,
    /// Public keys of the packages' signers, sorted by fingerprint.
    pub keys: Vec<PackKey>,
}

/// A package read out of a pack: its index entry and its archive bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedPackage {
    /// What the index says about it (checked against the bytes).
    pub entry: PackIndexEntry,
    /// The package archive, unverified.
    pub bytes: Vec<u8>,
}

/// A parsed pack. Nothing in it has been judged for trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfflinePack {
    /// The index.
    pub index: PackIndex,
    /// The packages, in index order.
    pub packages: Vec<PackedPackage>,
}

impl OfflinePack {
    /// The pack's key for `fingerprint` (hex), if it carries one.
    pub fn key(&self, fingerprint: &str) -> Option<&PackKey> {
        self.index
            .keys
            .iter()
            .find(|k| k.fingerprint.eq_ignore_ascii_case(fingerprint))
    }
}

fn bad(m: impl Into<String>) -> OciError {
    OciError::InvalidPack(m.into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The plugin id and signer fingerprint a package archive *claims*, read
/// from its manifest and signature bundle without verifying either.
fn claimed_identity(package: &[u8]) -> Result<(String, String)> {
    let files = unpack(package)?;
    let manifest: toml::Value = std::str::from_utf8(&files.manifest)
        .ok()
        .and_then(|t| toml::from_str(t).ok())
        .ok_or_else(|| OciError::InvalidPackage("entangle.toml is not valid TOML".into()))?;
    let id = manifest
        .get("plugin")
        .and_then(|p| p.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| OciError::InvalidPackage("entangle.toml has no plugin.id".into()))?;
    let id = PluginId::from_str(id)
        .map_err(|e| OciError::InvalidPackage(format!("plugin.id {id:?}: {e}")))?;
    let bundle: SignatureBundle = std::str::from_utf8(&files.signature)
        .ok()
        .and_then(|t| toml::from_str(t).ok())
        .ok_or_else(|| OciError::InvalidPackage("signature bundle is not valid TOML".into()))?;
    Ok((id.to_string(), hex::encode(bundle.publisher_fingerprint)))
}

/// Build a pack from package archives.
///
/// Every package must verify against `keyring` (the packer's publisher
/// keyring): an unverifiable package is refused rather than shipped. The
/// same archive given twice is packed once; two different archives of the
/// same plugin id are refused. Deterministic: the output depends only on the
/// set of archives and the signers' public keys.
pub fn write_pack(packages: &[Vec<u8>], keyring: &Keyring) -> Result<Vec<u8>> {
    if packages.is_empty() {
        return Err(bad("nothing to pack: no packages were given"));
    }
    // plugin id -> (entry, bytes)
    let mut by_id: BTreeMap<String, (PackIndexEntry, &[u8])> = BTreeMap::new();
    let mut keys: BTreeMap<String, PackKey> = BTreeMap::new();
    for bytes in packages {
        let verified = verify_package(bytes, keyring)?;
        let sha = sha256_hex(bytes);
        let entry = PackIndexEntry {
            plugin_id: verified.plugin_id.clone(),
            publisher: verified.signer_fingerprint.clone(),
            file: format!("packages/{sha}.tar.zst"),
            sha256: sha,
            size: bytes.len() as u64,
        };
        match by_id.get(&verified.plugin_id) {
            Some((old, _)) if old.sha256 == entry.sha256 => continue,
            Some((old, _)) => {
                return Err(bad(format!(
                    "two different packages of {} were given (sha256 {} and {})",
                    verified.plugin_id, old.sha256, entry.sha256
                )))
            }
            None => {}
        }
        let fp = hex::decode(&verified.signer_fingerprint)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .and_then(|fp| keyring.lookup(&fp))
            .ok_or_else(|| bad("the signer of a verified package is not in the keyring"))?;
        keys.insert(
            verified.signer_fingerprint.clone(),
            PackKey {
                fingerprint: verified.signer_fingerprint.clone(),
                public_key: hex::encode(fp.public_key),
            },
        );
        by_id.insert(verified.plugin_id, (entry, bytes.as_slice()));
    }
    if by_id.len() > MAX_PACK_PACKAGES {
        return Err(bad(format!(
            "{} packages, over the limit of {MAX_PACK_PACKAGES} per pack",
            by_id.len()
        )));
    }
    let index = PackIndex {
        format: PACK_FORMAT.to_owned(),
        version: PACK_VERSION,
        packages: by_id.values().map(|(e, _)| e.clone()).collect(),
        keys: keys.into_values().collect(),
    };
    let mut index_json =
        serde_json::to_vec_pretty(&index).map_err(|e| bad(format!("serialising index: {e}")))?;
    index_json.push(b'\n');

    let mut tar = Vec::new();
    tar_entry(&mut tar, PACK_INDEX_NAME, &index_json);
    let mut files: Vec<(&str, &[u8])> =
        by_id.values().map(|(e, b)| (e.file.as_str(), *b)).collect();
    files.sort_by(|a, b| a.0.cmp(b.0));
    for (name, bytes) in files {
        tar_entry(&mut tar, name, bytes);
    }
    tar.extend_from_slice(&[0u8; 1024]);
    Ok(tar)
}

/// Parse a pack and check that it is internally consistent.
///
/// Checked: size cap; strict tar structure; the index comes first, has the
/// expected format and version, and lists every other entry exactly once;
/// each package's size and SHA-256; each package is a well-formed package
/// archive whose manifest id and signature-bundle signer are what the index
/// says; each key's fingerprint matches its public key; every package's
/// signer has a key entry.
///
/// **Not** checked: any signature. Verify each [`PackedPackage::bytes`] with
/// [`crate::verify_package`] against the recipient's keyring.
pub fn read_pack(bytes: &[u8]) -> Result<OfflinePack> {
    if bytes.len() as u64 > MAX_PACK_BYTES {
        return Err(OciError::TooLarge {
            what: ".entanglepack".into(),
            size: bytes.len() as u64,
            limit: MAX_PACK_BYTES,
        });
    }
    let entries = tar_entries(bytes).map_err(|m| bad(format!("not a pack archive: {m}")))?;
    let Some(((first_name, index_bytes), rest)) = entries.split_first() else {
        return Err(bad("the archive is empty"));
    };
    if *first_name != PACK_INDEX_NAME {
        return Err(bad(format!(
            "the first entry is {first_name:?}, expected {PACK_INDEX_NAME:?}"
        )));
    }
    if index_bytes.len() > MAX_INDEX_BYTES {
        return Err(bad("the index is too large"));
    }
    let index: PackIndex =
        serde_json::from_slice(index_bytes).map_err(|e| bad(format!("malformed index: {e}")))?;
    if index.format != PACK_FORMAT {
        return Err(bad(format!("index format is {:?}", index.format)));
    }
    if index.version != PACK_VERSION {
        return Err(bad(format!(
            "pack format version {} is not supported by this entangle (it reads version \
             {PACK_VERSION}); upgrade entangle or re-create the pack",
            index.version
        )));
    }
    if index.packages.is_empty() {
        return Err(bad("the index lists no packages"));
    }
    if index.packages.len() > MAX_PACK_PACKAGES {
        return Err(bad(format!(
            "the index lists {} packages, over the limit of {MAX_PACK_PACKAGES}",
            index.packages.len()
        )));
    }

    // Keys: each fingerprint must be the fingerprint of its public key.
    let mut key_fps = std::collections::BTreeSet::new();
    for k in &index.keys {
        let pk = hex::decode(&k.public_key)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| IdentityPublicKey::from_bytes(&b).ok())
            .ok_or_else(|| bad(format!("key {} is not a valid public key", k.fingerprint)))?;
        if pk.fingerprint_hex() != k.fingerprint {
            return Err(bad(format!(
                "key listed as {} actually has fingerprint {}",
                k.fingerprint,
                pk.fingerprint_hex()
            )));
        }
        if !key_fps.insert(k.fingerprint.clone()) {
            return Err(bad(format!("key {} is listed twice", k.fingerprint)));
        }
    }

    let mut content: BTreeMap<&str, &[u8]> = BTreeMap::new();
    for (name, data) in rest {
        if content.insert(name, data).is_some() {
            return Err(bad(format!("duplicate entry {name:?}")));
        }
    }
    let mut seen_ids = std::collections::BTreeSet::new();
    let mut packages = Vec::with_capacity(index.packages.len());
    for entry in &index.packages {
        if entry.file != format!("packages/{}.tar.zst", entry.sha256) {
            return Err(bad(format!(
                "index entry for {} names file {:?}, which is not packages/<sha256>.tar.zst",
                entry.plugin_id, entry.file
            )));
        }
        let data = content.remove(entry.file.as_str()).ok_or_else(|| {
            bad(format!(
                "{} is listed in the index but {:?} is not in the pack (or is listed twice)",
                entry.plugin_id, entry.file
            ))
        })?;
        if data.len() as u64 != entry.size {
            return Err(OciError::SizeMismatch {
                what: format!("{} in the pack", entry.plugin_id),
                expected: entry.size,
                actual: data.len() as u64,
            });
        }
        let actual = sha256_hex(data);
        if actual != entry.sha256 {
            return Err(OciError::DigestMismatch {
                what: format!("{} in the pack", entry.plugin_id),
                expected: format!("sha256:{}", entry.sha256),
                actual: format!("sha256:{actual}"),
            });
        }
        let (id, signer) = claimed_identity(data).map_err(|e| {
            bad(format!(
                "{} is not a plugin package: {e}",
                entry.file.as_str()
            ))
        })?;
        if id != entry.plugin_id {
            return Err(bad(format!(
                "the index says {:?} holds {}, but the package inside is {id}",
                entry.file, entry.plugin_id
            )));
        }
        if signer != entry.publisher {
            return Err(bad(format!(
                "the index says {} is signed by {}, but its signature names {signer}",
                entry.plugin_id, entry.publisher
            )));
        }
        if !key_fps.contains(&signer) {
            return Err(bad(format!(
                "{} is signed by {signer}, whose public key is not in the pack",
                entry.plugin_id
            )));
        }
        if !seen_ids.insert(entry.plugin_id.clone()) {
            return Err(bad(format!("{} is listed twice", entry.plugin_id)));
        }
        packages.push(PackedPackage {
            entry: entry.clone(),
            bytes: data.to_vec(),
        });
    }
    if let Some(extra) = content.keys().next() {
        return Err(bad(format!(
            "unexpected entry {extra:?} (not listed in the index)"
        )));
    }
    Ok(OfflinePack { index, packages })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::{pack, PackageFiles};
    use entangle_signing::{sign_artifact_at, IdentityKeyPair, TrustEntry};

    fn kp(seed: u8) -> IdentityKeyPair {
        IdentityKeyPair::from_seed(&[seed; 32])
    }

    fn ring(keys: &[&IdentityKeyPair]) -> Keyring {
        let mut r = Keyring::new();
        for k in keys {
            r.add(TrustEntry {
                fingerprint: k.fingerprint(),
                public_key: *k.public().as_bytes(),
                publisher_name: "local label that must not leak".into(),
                added_at: 12345,
                note: String::new(),
            });
        }
        r
    }

    fn package(k: &IdentityKeyPair, name: &str, version: &str, body: &[u8]) -> Vec<u8> {
        let manifest = format!(
            "[plugin]\nid = \"{}/{name}@{version}\"\nversion = \"{version}\"\ntier = 1\n\
             runtime = \"wasm\"\n",
            k.fingerprint_hex()
        );
        let mut wasm = b"\0asm\x01\0\0\0".to_vec();
        wasm.extend_from_slice(body);
        let bundle = sign_artifact_at(&wasm, manifest.as_bytes(), k, 7);
        pack(&PackageFiles {
            manifest: manifest.into_bytes(),
            wasm,
            signature: toml::to_string(&bundle).unwrap().into_bytes(),
            provenance: None,
            native: false,
        })
        .unwrap()
    }

    #[test]
    fn round_trip_keeps_every_package_and_lists_only_the_signers_keys() {
        let (a, b, unused) = (kp(1), kp(2), kp(3));
        let pa = package(&a, "alpha", "1.0.0", b"a");
        let pb = package(&b, "beta", "0.2.0", b"b");
        let bytes = write_pack(&[pb.clone(), pa.clone()], &ring(&[&a, &b, &unused])).unwrap();
        let pack = read_pack(&bytes).unwrap();
        assert_eq!(pack.index.format, PACK_FORMAT);
        assert_eq!(pack.index.version, 1);
        let ids: Vec<_> = pack.packages.iter().map(|p| &p.entry.plugin_id).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids[0] < ids[1], "sorted by plugin id: {ids:?}");
        let alpha = pack
            .packages
            .iter()
            .find(|p| p.entry.plugin_id.contains("/alpha@"))
            .unwrap();
        assert_eq!(alpha.bytes, pa);
        assert_eq!(alpha.entry.publisher, a.fingerprint_hex());
        assert_eq!(pack.index.keys.len(), 2, "only the two signers");
        assert_eq!(
            pack.key(&a.fingerprint_hex()).unwrap().public_key,
            hex::encode(a.public().as_bytes())
        );
        assert!(pack.key(&unused.fingerprint_hex()).is_none());
        // Every package still verifies against the recipient's own keyring.
        for p in &pack.packages {
            verify_package(&p.bytes, &ring(&[&a, &b])).unwrap();
        }
        // Local keyring labels and timestamps are not in the file.
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("must not leak") && !text.contains("12345"));
    }

    #[test]
    fn two_packs_of_the_same_inputs_are_byte_identical() {
        let (a, b) = (kp(1), kp(2));
        let pa = package(&a, "alpha", "1.0.0", b"a");
        let pb = package(&b, "beta", "0.2.0", b"b");
        let one = write_pack(&[pa.clone(), pb.clone()], &ring(&[&a, &b])).unwrap();
        // Different argument order, a duplicate, and a keyring in another order.
        let two = write_pack(&[pb.clone(), pa.clone(), pb], &ring(&[&b, &a, &kp(9)])).unwrap();
        assert_eq!(one, two);
        // Normalised tar headers: no mtime, owner or names anywhere.
        let mut pos = 0;
        while one[pos..pos + 512].iter().any(|b| *b != 0) {
            let h = &one[pos..pos + 512];
            assert_eq!(&h[100..108], b"0000644\0");
            assert_eq!(&h[108..124], b"0000000\x000000000\0");
            assert_eq!(&h[136..148], b"00000000000\0");
            assert!(h[265..345].iter().all(|b| *b == 0));
            let size = usize::from_str_radix(
                std::str::from_utf8(&h[124..135])
                    .unwrap()
                    .trim_matches('\0'),
                8,
            )
            .unwrap();
            pos += 512 + size.div_ceil(512) * 512;
        }
    }

    #[test]
    fn packing_refuses_an_unverifiable_package_and_conflicting_versions_of_one_id() {
        let (a, stranger) = (kp(1), kp(2));
        let e = write_pack(&[package(&stranger, "x", "1.0.0", b"x")], &ring(&[&a])).unwrap_err();
        assert!(e.to_string().contains("ENTANGLE-E0101"), "{e}");
        let e = write_pack(
            &[
                package(&a, "x", "1.0.0", b"one"),
                package(&a, "x", "1.0.0", b"two"),
            ],
            &ring(&[&a]),
        )
        .unwrap_err();
        assert!(e.to_string().starts_with("ENTANGLE-E0824"), "{e}");
        assert!(write_pack(&[], &ring(&[&a])).is_err());
    }

    /// Rebuild a pack from an edited index and entries (for the tamper cases).
    fn assemble(index: &PackIndex, entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        tar_entry(
            &mut tar,
            PACK_INDEX_NAME,
            &serde_json::to_vec(index).unwrap(),
        );
        for (n, b) in entries {
            tar_entry(&mut tar, n, b);
        }
        tar.extend_from_slice(&[0u8; 1024]);
        tar
    }

    #[test]
    fn a_tampered_or_inconsistent_pack_is_refused() {
        let (a, evil) = (kp(1), kp(2));
        let good = package(&a, "alpha", "1.0.0", b"a");
        let bytes = write_pack(std::slice::from_ref(&good), &ring(&[&a])).unwrap();
        let pack = read_pack(&bytes).unwrap();
        let index = pack.index.clone();
        let file = index.packages[0].file.clone();

        // A flipped byte in the package: digest mismatch.
        let mut flipped = bytes.clone();
        let at = bytes
            .windows(good.len())
            .position(|w| w == good.as_slice())
            .expect("the package bytes are stored verbatim");
        flipped[at + good.len() / 2] ^= 0xff;
        let e = read_pack(&flipped).unwrap_err().to_string();
        assert!(e.starts_with("ENTANGLE-E0807"), "{e}");

        // Another package swapped in under the listed name.
        let other = package(&evil, "alpha", "1.0.0", b"evil");
        let e = read_pack(&assemble(&index, &[(&file, &other)]))
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("ENTANGLE-E0809") || e.starts_with("ENTANGLE-E0807"),
            "{e}"
        );

        // The index rewritten to match the swapped package, but still claiming
        // the original publisher.
        let mut lying = index.clone();
        lying.packages[0].sha256 = sha256_hex(&other);
        lying.packages[0].size = other.len() as u64;
        lying.packages[0].file = format!("packages/{}.tar.zst", sha256_hex(&other));
        let name = lying.packages[0].file.clone();
        let e = read_pack(&assemble(&lying, &[(&name, &other)]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("but the package inside is"), "{e}");
        // ...and with the id corrected too: the signer still gives it away.
        lying.packages[0].plugin_id = format!("{}/alpha@1.0.0", evil.fingerprint_hex());
        let e = read_pack(&assemble(&lying, &[(&name, &other)]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("its signature names"), "{e}");

        // An extra, unlisted entry; a missing one; a key with a wrong fingerprint.
        let e = read_pack(&assemble(
            &index,
            &[(&file, &good), ("packages/extra", b"x")],
        ))
        .unwrap_err()
        .to_string();
        assert!(e.contains("unexpected entry"), "{e}");
        let e = read_pack(&assemble(&index, &[])).unwrap_err().to_string();
        assert!(e.contains("is not in the pack"), "{e}");
        let mut wrong_key = index.clone();
        wrong_key.keys[0].public_key = hex::encode(evil.public().as_bytes());
        let e = read_pack(&assemble(&wrong_key, &[(&file, &good)]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("actually has fingerprint"), "{e}");

        // A future format version is refused with the fix.
        let mut future = index.clone();
        future.version = 2;
        let e = read_pack(&assemble(&future, &[(&file, &good)]))
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("ENTANGLE-E0824") && e.contains("version 2"),
            "{e}"
        );

        // Not a tar at all, and a path-traversal name.
        assert!(read_pack(b"definitely not a pack").is_err());
        let mut traversal = index;
        traversal.packages[0].file = "../../etc/passwd".into();
        assert!(read_pack(&assemble(&traversal, &[("../../etc/passwd", &good)])).is_err());
    }
}
