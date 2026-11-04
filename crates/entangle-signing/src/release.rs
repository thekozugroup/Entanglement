//! Release-artifact signatures (ATC-REL-1, Ed25519 half).
//!
//! A release tarball is signed with a **release key**, a different trust class
//! from plugin publisher keys: release keys live in their own keyring
//! (`~/.entangle/release-keyring.toml`), so a publisher key that is trusted to
//! sign plugins can never vouch for an `entangle` release, and vice versa.
//! The cosign / Rekor half is verified by `entangle release verify` shelling
//! out to `cosign`; see `entangle-cli`'s `cmd::release`.
//!
//! The signature is over a domain-separated BLAKE3 digest of the artifact, so
//! a release signature can never be replayed as a plugin signature.

use crate::{IdentityKeyPair, Keyring, Signature, TrustEntry};

/// Domain separator for the release-signature digest.
const RELEASE_DOMAIN: &str = "entangle.release.signature.v1";

/// Current [`ReleaseSignature::version`].
pub const RELEASE_SIGNATURE_VERSION: u32 = 1;

/// Errors from [`verify_release`].
#[derive(Debug, thiserror::Error)]
pub enum ReleaseSigError {
    /// Unsupported signature file version.
    #[error("ENTANGLE-E0840: unsupported release signature version {0}")]
    UnsupportedVersion(u32),
    /// The signature file is malformed (bad hex, wrong lengths, wrong algorithm).
    #[error("ENTANGLE-E0841: malformed release signature: {0}")]
    Malformed(String),
    /// The artifact does not hash to the digest recorded in the signature file.
    #[error("ENTANGLE-E0842: release artifact digest mismatch (computed {actual}, signature says {expected})")]
    DigestMismatch {
        /// BLAKE3 hex computed from the artifact.
        actual: String,
        /// BLAKE3 hex recorded in the signature file.
        expected: String,
    },
    /// The signing key is not in the release keyring.
    #[error("ENTANGLE-E0843: release key {0} is not in the release keyring")]
    UnknownKey(String),
    /// The Ed25519 signature does not verify.
    #[error("ENTANGLE-E0844: release signature does not verify: {0}")]
    BadSignature(String),
}

/// The `<artifact>.ed25519` companion file, serialised as TOML.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseSignature {
    /// Format version; see [`RELEASE_SIGNATURE_VERSION`].
    pub version: u32,
    /// Always `"ed25519"`.
    pub algorithm: String,
    /// 16-byte key fingerprint, hex.
    pub key_fingerprint: String,
    /// BLAKE3 of the artifact, hex.
    pub artifact_blake3: String,
    /// 64-byte Ed25519 signature, hex.
    pub signature: String,
}

fn digest(artifact_blake3: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(RELEASE_DOMAIN);
    h.update(artifact_blake3);
    *h.finalize().as_bytes()
}

/// Sign release `artifact` bytes with `key`.
pub fn sign_release(artifact: &[u8], key: &IdentityKeyPair) -> ReleaseSignature {
    let b3 = *blake3::hash(artifact).as_bytes();
    ReleaseSignature {
        version: RELEASE_SIGNATURE_VERSION,
        algorithm: "ed25519".to_owned(),
        key_fingerprint: key.fingerprint_hex(),
        artifact_blake3: hex::encode(b3),
        signature: key.sign(&digest(&b3)).to_hex(),
    }
}

/// Verify `artifact` against `sig`, requiring the signer to be in
/// `release_keyring`. Returns the matching trust entry.
pub fn verify_release<'k>(
    artifact: &[u8],
    sig: &ReleaseSignature,
    release_keyring: &'k Keyring,
) -> Result<&'k TrustEntry, ReleaseSigError> {
    if sig.version != RELEASE_SIGNATURE_VERSION {
        return Err(ReleaseSigError::UnsupportedVersion(sig.version));
    }
    if sig.algorithm != "ed25519" {
        return Err(ReleaseSigError::Malformed(format!(
            "algorithm {:?}",
            sig.algorithm
        )));
    }
    let b3 = *blake3::hash(artifact).as_bytes();
    if hex::encode(b3) != sig.artifact_blake3 {
        return Err(ReleaseSigError::DigestMismatch {
            actual: hex::encode(b3),
            expected: sig.artifact_blake3.clone(),
        });
    }
    let fp_bytes = hex::decode(&sig.key_fingerprint)
        .map_err(|e| ReleaseSigError::Malformed(format!("key_fingerprint: {e}")))?;
    let fp: [u8; 16] = fp_bytes
        .try_into()
        .map_err(|_| ReleaseSigError::Malformed("key_fingerprint is not 16 bytes".into()))?;
    let entry = release_keyring
        .lookup(&fp)
        .ok_or_else(|| ReleaseSigError::UnknownKey(sig.key_fingerprint.clone()))?;
    let pk = crate::IdentityPublicKey::from_bytes(&entry.public_key)
        .map_err(|e| ReleaseSigError::Malformed(format!("keyring public key: {e}")))?;
    let raw = Signature::from_hex(&sig.signature)
        .map_err(|e| ReleaseSigError::Malformed(format!("signature: {e}")))?;
    pk.verify(&digest(&b3), &raw)
        .map_err(|e| ReleaseSigError::BadSignature(e.to_string()))?;
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring_for(k: &IdentityKeyPair) -> Keyring {
        let mut r = Keyring::new();
        r.add(TrustEntry {
            fingerprint: k.fingerprint(),
            public_key: *k.public().as_bytes(),
            publisher_name: "release".into(),
            added_at: 0,
            note: String::new(),
        });
        r
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let k = IdentityKeyPair::generate();
        let ring = ring_for(&k);
        let sig = sign_release(b"tarball", &k);
        assert!(verify_release(b"tarball", &sig, &ring).is_ok());
        assert!(matches!(
            verify_release(b"tarbal1", &sig, &ring),
            Err(ReleaseSigError::DigestMismatch { .. })
        ));
        let other = IdentityKeyPair::generate();
        assert!(matches!(
            verify_release(b"tarball", &sig, &ring_for(&other)),
            Err(ReleaseSigError::UnknownKey(_))
        ));
        let mut forged = sig.clone();
        forged.signature = sign_release(b"x", &other).signature;
        assert!(matches!(
            verify_release(b"tarball", &forged, &ring),
            Err(ReleaseSigError::BadSignature(_))
        ));
    }
}
