//! Sign and verify file artifacts per §3.6 / §3.6.1.
//!
//! **Signing target**: a domain-separated BLAKE3 digest over
//! `BLAKE3(artifact bytes) || BLAKE3(manifest bytes)`, not the raw bytes.
//! Hashing first keeps signatures compact and enables streaming verification
//! on Iroh blobs; including the manifest hash binds the plugin's declared
//! tier and capabilities to the signature, so editing `entangle.toml` after
//! signing invalidates the bundle.

use thiserror::Error;

use crate::{
    keypair::{IdentityKeyPair, IdentityPublicKey},
    keyring::{Keyring, TrustEntry},
    signature::{Signature, SignatureBundle, SIGNATURE_BUNDLE_VERSION},
};

/// BLAKE3 `derive_key` context string for the signed digest.
///
/// Domain separation ensures a signature over an artifact+manifest pair can
/// never be confused with a signature over any other Entanglement payload
/// (or a bare BLAKE3 hash, as in bundle version 1).
const SIGNING_DOMAIN: &str = "entangle-signing 2026 artifact+manifest bundle v2";

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
    /// The manifest bytes do not hash to the value recorded in the bundle.
    #[error(
        "ENTANGLE-E0104: manifest hash mismatch (recomputed {actual_hex}, bundle says {expected_hex})"
    )]
    ManifestHashMismatch {
        /// Hex of the hash we computed.
        actual_hex: String,
        /// Hex of the hash stored in the bundle.
        expected_hex: String,
    },
    /// The verified signer is not the publisher named in the manifest.
    #[error(
        "ENTANGLE-E0105: publisher mismatch: manifest names publisher \
         '{manifest_publisher}' but the artifact was signed by '{signer_fingerprint}'"
    )]
    PublisherMismatch {
        /// The publisher fingerprint hex declared in the manifest's plugin id.
        manifest_publisher: String,
        /// The fingerprint hex of the trusted key that actually signed.
        signer_fingerprint: String,
    },
    /// The bundle's format version is not supported by this verifier.
    #[error("ENTANGLE-E0106: unsupported signature bundle version {0} (expected {SIGNATURE_BUNDLE_VERSION})")]
    UnsupportedBundleVersion(u32),
}

/// Compute the domain-separated digest that is actually signed.
fn signed_digest(artifact_blake3: &[u8; 32], manifest_blake3: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SIGNING_DOMAIN);
    hasher.update(artifact_blake3);
    hasher.update(manifest_blake3);
    *hasher.finalize().as_bytes()
}

/// Sign `artifact` and `manifest` bytes, producing a [`SignatureBundle`] that
/// can be written alongside the artifact.
///
/// The signed payload is the domain-separated BLAKE3 digest over
/// `BLAKE3(artifact) || BLAKE3(manifest)` — see [`SIGNATURE_BUNDLE_VERSION`].
pub fn sign_artifact(
    artifact: &[u8],
    manifest: &[u8],
    keypair: &IdentityKeyPair,
) -> SignatureBundle {
    let artifact_hash: [u8; 32] = *blake3::hash(artifact).as_bytes();
    let manifest_hash: [u8; 32] = *blake3::hash(manifest).as_bytes();
    let sig: Signature = keypair.sign(&signed_digest(&artifact_hash, &manifest_hash));
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    SignatureBundle {
        version: SIGNATURE_BUNDLE_VERSION,
        publisher_fingerprint: keypair.fingerprint(),
        algorithm: "ed25519".to_owned(),
        signature: sig.0,
        artifact_blake3: artifact_hash,
        manifest_blake3: manifest_hash,
        created_at,
    }
}

/// Verify `artifact` and `manifest` bytes against `bundle`, looking up the
/// publisher in `keyring`.
///
/// Verification order (per §3.6):
/// 1. Reject unsupported bundle versions.
/// 2. Recompute `BLAKE3(artifact)`. Mismatch → `ArtifactHashMismatch`.
/// 3. Recompute `BLAKE3(manifest)`. Mismatch → `ManifestHashMismatch`.
/// 4. Reject unknown algorithms.
/// 5. Look up publisher by fingerprint. Not found → `UnknownPublisher`.
/// 6. Verify the Ed25519 signature over the domain-separated digest of
///    `artifact_blake3 || manifest_blake3`.
/// 7. Return a reference to the matched `TrustEntry`.
pub fn verify_artifact<'k>(
    artifact: &[u8],
    manifest: &[u8],
    bundle: &SignatureBundle,
    keyring: &'k Keyring,
) -> Result<&'k TrustEntry, VerificationError> {
    // Step 1: version check
    if bundle.version != SIGNATURE_BUNDLE_VERSION {
        return Err(VerificationError::UnsupportedBundleVersion(bundle.version));
    }

    // Step 2: artifact hash check
    let actual_artifact_hash: [u8; 32] = *blake3::hash(artifact).as_bytes();
    if actual_artifact_hash != bundle.artifact_blake3 {
        return Err(VerificationError::ArtifactHashMismatch {
            actual_hex: hex::encode(actual_artifact_hash),
            expected_hex: hex::encode(bundle.artifact_blake3),
        });
    }

    // Step 3: manifest hash check
    let actual_manifest_hash: [u8; 32] = *blake3::hash(manifest).as_bytes();
    if actual_manifest_hash != bundle.manifest_blake3 {
        return Err(VerificationError::ManifestHashMismatch {
            actual_hex: hex::encode(actual_manifest_hash),
            expected_hex: hex::encode(bundle.manifest_blake3),
        });
    }

    // Step 4: algorithm check
    if bundle.algorithm != "ed25519" {
        return Err(VerificationError::UnsupportedAlgorithm(
            bundle.algorithm.clone(),
        ));
    }

    // Step 5: publisher lookup
    let entry = keyring
        .lookup(&bundle.publisher_fingerprint)
        .ok_or(VerificationError::UnknownPublisher)?;

    // Step 6: signature verification — signed payload is the combined digest
    let pub_key = IdentityPublicKey::from_bytes(&entry.public_key)
        .map_err(|_| VerificationError::BadSignature)?;
    let sig = Signature(bundle.signature);
    pub_key
        .verify(
            &signed_digest(&bundle.artifact_blake3, &bundle.manifest_blake3),
            &sig,
        )
        .map_err(|_| VerificationError::BadSignature)?;

    Ok(entry)
}
