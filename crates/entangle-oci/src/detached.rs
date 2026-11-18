//! Detached signatures over a whole package archive (`<name>.tar.zst.sig`).
//!
//! The plain-HTTPS install path (spec §3.6 path B) fetches an archive and,
//! from the same URL with `.sig` appended, this document. It lets the
//! installer decide whether a trusted publisher vouches for the download
//! **before** a single byte of the archive is decompressed or parsed: the
//! check needs only the raw archive bytes, this small TOML file and the
//! publisher keyring.
//!
//! ```toml
//! version = 1
//! algorithm = "ed25519"
//! publisher_fingerprint = "<32 hex>"
//! archive_sha256 = "<64 hex>"
//! signature = "<128 hex>"
//! ```
//!
//! The signature is Ed25519 over `"entangle package archive v1\0" ||
//! SHA-256(archive)`. The domain prefix keeps it from being replayed as an
//! artifact signature (BLAKE3-derived digest) or a mirror-listing signature
//! (a different prefix). Signing is deterministic, so the file is a pure
//! function of (archive, key) and does not disturb reproducible packaging.
//!
//! A detached signature never replaces the signature **inside** the package
//! (`plugin.wasm.sig`, which binds artifact and manifest): after it passes,
//! [`crate::verify_package`] still runs, and the two must name the same
//! publisher.

use entangle_signing::{IdentityKeyPair, IdentityPublicKey, Keyring, Signature, VerificationError};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{OciError, Result};

/// Domain prefix of the signed message.
const ARCHIVE_DOMAIN: &[u8] = b"entangle package archive v1\0";

/// Largest detached-signature document accepted (it is about 350 bytes).
pub const MAX_ARCHIVE_SIGNATURE_BYTES: u64 = 16 * 1024;

/// The detached signature document.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveSignature {
    /// Format version, currently 1.
    pub version: u32,
    /// Always `ed25519`.
    pub algorithm: String,
    /// Fingerprint (32 hex) of the signing publisher key.
    pub publisher_fingerprint: String,
    /// SHA-256 (64 hex) of the archive bytes the signature covers.
    pub archive_sha256: String,
    /// Signature (128 hex) over the domain prefix and the SHA-256.
    pub signature: String,
}

fn signed_message(sha256: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(ARCHIVE_DOMAIN.len() + 32);
    m.extend_from_slice(ARCHIVE_DOMAIN);
    m.extend_from_slice(sha256);
    m
}

/// Sign `archive` with `key`; returns the TOML text of the `.sig` file.
pub fn sign_archive(archive: &[u8], key: &IdentityKeyPair) -> Result<Vec<u8>> {
    let sha: [u8; 32] = Sha256::digest(archive).into();
    let doc = ArchiveSignature {
        version: 1,
        algorithm: "ed25519".into(),
        publisher_fingerprint: key.fingerprint_hex(),
        archive_sha256: hex::encode(sha),
        signature: key.sign(&signed_message(&sha)).to_hex(),
    };
    toml::to_string(&doc)
        .map(String::into_bytes)
        .map_err(|e| OciError::DetachedSignature(format!("serialising: {e}")))
}

/// Check a detached signature over `archive` against the **publisher**
/// keyring. Returns the fingerprint (hex) of the trusted key that signed.
///
/// Reads nothing from `archive` but its hash: the archive is not
/// decompressed or parsed here. Like [`crate::verify_package`], the whole
/// input is bytes and a keyring; where the bytes came from is not an input.
pub fn verify_archive_signature(
    archive: &[u8],
    signature: &[u8],
    keyring: &Keyring,
) -> Result<String> {
    let bad = |m: String| OciError::DetachedSignature(m);
    if signature.len() as u64 > MAX_ARCHIVE_SIGNATURE_BYTES {
        return Err(bad(format!(
            "the signature document is {} bytes, over the {MAX_ARCHIVE_SIGNATURE_BYTES}-byte limit",
            signature.len()
        )));
    }
    let text = std::str::from_utf8(signature).map_err(|_| bad("not UTF-8 text".into()))?;
    let doc: ArchiveSignature =
        toml::from_str(text).map_err(|e| bad(format!("not a signature document: {e}")))?;
    if doc.version != 1 {
        return Err(bad(format!("unsupported version {}", doc.version)));
    }
    if doc.algorithm != "ed25519" {
        return Err(VerificationError::UnsupportedAlgorithm(doc.algorithm).into());
    }
    let fp = hex::decode(&doc.publisher_fingerprint)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .ok_or_else(|| bad("malformed publisher fingerprint".into()))?;
    let sha: [u8; 32] = Sha256::digest(archive).into();
    if !doc.archive_sha256.eq_ignore_ascii_case(&hex::encode(sha)) {
        return Err(bad(format!(
            "it covers an archive with sha256 {}, but the archive fetched has sha256 {}",
            doc.archive_sha256,
            hex::encode(sha)
        )));
    }
    let entry = keyring
        .lookup(&fp)
        .ok_or(VerificationError::UnknownPublisher)?;
    let pk = IdentityPublicKey::from_bytes(&entry.public_key)
        .map_err(|_| bad("the keyring holds an invalid public key for this publisher".into()))?;
    let sig = Signature::from_hex(&doc.signature).map_err(|_| bad("malformed signature".into()))?;
    pk.verify(&signed_message(&sha), &sig)
        .map_err(|_| VerificationError::BadSignature)?;
    Ok(hex::encode(fp))
}

/// The publisher fingerprint (hex) a signature document names, without
/// verifying anything. For error messages only ("add this key to trust it").
pub fn archive_signature_signer(signature: &[u8]) -> Option<String> {
    let doc: ArchiveSignature = toml::from_str(std::str::from_utf8(signature).ok()?).ok()?;
    (doc.publisher_fingerprint.len() == 32
        && doc
            .publisher_fingerprint
            .bytes()
            .all(|b| b.is_ascii_hexdigit()))
    .then_some(doc.publisher_fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_signing::TrustEntry;

    fn kp(seed: u8) -> IdentityKeyPair {
        IdentityKeyPair::from_seed(&[seed; 32])
    }

    fn ring(keys: &[&IdentityKeyPair]) -> Keyring {
        let mut r = Keyring::new();
        for k in keys {
            r.add(TrustEntry {
                fingerprint: k.fingerprint(),
                public_key: *k.public().as_bytes(),
                publisher_name: "t".into(),
                added_at: 0,
                note: String::new(),
            });
        }
        r
    }

    #[test]
    fn a_signature_verifies_and_is_deterministic() {
        let k = kp(1);
        let sig = sign_archive(b"archive bytes", &k).unwrap();
        assert_eq!(sig, sign_archive(b"archive bytes", &k).unwrap());
        assert_eq!(
            verify_archive_signature(b"archive bytes", &sig, &ring(&[&k])).unwrap(),
            k.fingerprint_hex()
        );
        assert_eq!(archive_signature_signer(&sig), Some(k.fingerprint_hex()));
    }

    #[test]
    fn a_changed_archive_an_unknown_signer_and_a_forged_signature_are_refused() {
        let (k, other) = (kp(1), kp(2));
        let sig = sign_archive(b"archive bytes", &k).unwrap();

        let e = verify_archive_signature(b"archive bytez", &sig, &ring(&[&k])).unwrap_err();
        assert!(e.to_string().starts_with("ENTANGLE-E0823"), "{e}");

        let e = verify_archive_signature(b"archive bytes", &sig, &ring(&[&other])).unwrap_err();
        assert!(e.to_string().contains("ENTANGLE-E0101"), "{e}");

        // The attacker's signature under the trusted publisher's fingerprint.
        let mut doc: ArchiveSignature = toml::from_str(std::str::from_utf8(&sig).unwrap()).unwrap();
        let theirs: ArchiveSignature = toml::from_str(
            std::str::from_utf8(&sign_archive(b"archive bytes", &other).unwrap()).unwrap(),
        )
        .unwrap();
        doc.signature = theirs.signature;
        let forged = toml::to_string(&doc).unwrap();
        let e = verify_archive_signature(b"archive bytes", forged.as_bytes(), &ring(&[&k, &other]))
            .unwrap_err();
        assert!(e.to_string().contains("ENTANGLE-E0100"), "{e}");
    }

    #[test]
    fn malformed_documents_are_refused() {
        let r = ring(&[&kp(1)]);
        for bad in [
            &b"\xff\xfe"[..],
            b"not toml at all [",
            b"version = 1\n",
            b"version = 2\nalgorithm = \"ed25519\"\npublisher_fingerprint = \"00\"\n\
              archive_sha256 = \"00\"\nsignature = \"00\"\n",
        ] {
            let e = verify_archive_signature(b"x", bad, &r).unwrap_err();
            assert!(e.to_string().starts_with("ENTANGLE-E0823"), "{e}");
        }
        let huge = vec![b'#'; MAX_ARCHIVE_SIGNATURE_BYTES as usize + 1];
        assert!(verify_archive_signature(b"x", &huge, &r).is_err());
    }

    /// A package's own signature bundle is not accepted as an archive
    /// signature, and an archive signature's bytes do not verify as anything
    /// but an archive signature (different domain, different document).
    #[test]
    fn an_artifact_signature_bundle_is_not_an_archive_signature() {
        let k = kp(1);
        let bundle = entangle_signing::sign_artifact(b"wasm", b"manifest", &k);
        let text = toml::to_string(&bundle).unwrap();
        let e = verify_archive_signature(b"wasm", text.as_bytes(), &ring(&[&k])).unwrap_err();
        assert!(e.to_string().starts_with("ENTANGLE-E0823"), "{e}");
    }
}
