//! Sign and verify file artifacts per §3.6 / §3.6.1.
//!
//! **Signing target**: BLAKE3(artifact bytes), not the raw bytes.
//! This keeps signatures compact and enables streaming verification on Iroh blobs.

use thiserror::Error;

use crate::{
    keypair::{IdentityKeyPair, IdentityPublicKey},
    keyring::{Keyring, TrustEntry},
    signature::{Signature, SignatureBundle},
};

/// Errors that can occur during artifact verification.
#[derive(Debug, Error)]
pub enum VerificationError {
    /// The signature does not verify against the stored public key.
    #[error("ENTANGLE-E0100: signature does not verify")]
    BadSignature,
    /// The publisher fingerprint is not in the trusted keyring.
    #[error("ENTANGLE-E0101: publisher fingerprint not in keyring")]
    UnknownPublisher,
    /// The artifact bytes do not hash to the value recorded in the bundle.
    #[error(
        "ENTANGLE-E0102: artifact hash mismatch (recomputed {actual_hex}, bundle says {expected_hex})"
    )]
    ArtifactHashMismatch {
        /// Hex of the hash we computed.
        actual_hex: String,
        /// Hex of the hash stored in the bundle.
        expected_hex: String,
    },
    /// The bundle declares an algorithm other than `"ed25519"`.
    #[error("ENTANGLE-E0103: unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Sign `bytes`, producing a `SignatureBundle` that can be written alongside the artifact.
///
/// The signed payload is `BLAKE3(bytes)` (the hash, not the raw bytes).
pub fn sign_artifact(bytes: &[u8], keypair: &IdentityKeyPair) -> SignatureBundle {
    let hash: [u8; 32] = *blake3::hash(bytes).as_bytes();
    let sig: Signature = keypair.sign(&hash);
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    SignatureBundle {
        publisher_fingerprint: keypair.fingerprint(),
        algorithm: "ed25519".to_owned(),
        signature: sig.0,
        artifact_blake3: hash,
        created_at,
    }
}

/// Verify `bytes` against `bundle`, looking up the publisher in `keyring`.
///
/// Verification order (per §3.6):
/// 1. Recompute `BLAKE3(bytes)`. Mismatch → `ArtifactHashMismatch`.
/// 2. Reject unknown algorithms.
/// 3. Look up publisher by fingerprint. Not found → `UnknownPublisher`.
/// 4. Verify the Ed25519 signature over `bundle.artifact_blake3`.
/// 5. Return a reference to the matched `TrustEntry`.
pub fn verify_artifact<'k>(
    bytes: &[u8],
    bundle: &SignatureBundle,
    keyring: &'k Keyring,
) -> Result<&'k TrustEntry, VerificationError> {
    // Step 1: hash check
    let actual_hash: [u8; 32] = *blake3::hash(bytes).as_bytes();
    if actual_hash != bundle.artifact_blake3 {
        return Err(VerificationError::ArtifactHashMismatch {
            actual_hex: hex::encode(actual_hash),
            expected_hex: hex::encode(bundle.artifact_blake3),
        });
    }

    // Step 2: algorithm check
    if bundle.algorithm != "ed25519" {
        return Err(VerificationError::UnsupportedAlgorithm(
            bundle.algorithm.clone(),
        ));
    }

    // Step 3: publisher lookup
    let entry = keyring
        .lookup(&bundle.publisher_fingerprint)
        .ok_or(VerificationError::UnknownPublisher)?;

    // Step 4: signature verification — signed payload is the hash
    let pub_key = IdentityPublicKey::from_bytes(&entry.public_key)
        .map_err(|_| VerificationError::BadSignature)?;
    let sig = Signature(bundle.signature);
    pub_key
        .verify(&bundle.artifact_blake3, &sig)
        .map_err(|_| VerificationError::BadSignature)?;

    Ok(entry)
}
