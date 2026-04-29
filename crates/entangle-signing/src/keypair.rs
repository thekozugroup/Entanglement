//! Ed25519 identity keypair — generation, serialization, and fingerprinting.

use ed25519_dalek::{
    pkcs8::{spki::der::pem::LineEnding, DecodePrivateKey, EncodePrivateKey},
    SigningKey, VerifyingKey,
};
use rand_core::OsRng;
use thiserror::Error;

use crate::signature::{Signature, SignatureError};

/// Errors from keypair operations.
#[derive(Debug, Error)]
pub enum KeypairError {
    /// Public key bytes were invalid.
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    /// PEM parse or encode failure.
    #[error("pem parse: {0}")]
    Pem(String),
}

/// An Ed25519 signing keypair (contains the private key — handle with care).
///
/// `Debug` shows only the fingerprint hex; the secret is never printed.
#[derive(Clone)]
pub struct IdentityKeyPair {
    signing: SigningKey,
}

impl std::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("fingerprint", &self.fingerprint_hex())
            .finish_non_exhaustive()
    }
}

impl IdentityKeyPair {
    /// Generate a new keypair using the OS random number generator.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self { signing }
    }

    /// Construct from a 32-byte seed (deterministic).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Return the corresponding public key.
    pub fn public(&self) -> IdentityPublicKey {
        IdentityPublicKey {
            verifying: self.signing.verifying_key(),
        }
    }

    /// BLAKE3-16 fingerprint over the verifying key bytes.
    pub fn fingerprint(&self) -> [u8; 16] {
        let vk = self.signing.verifying_key();
        let hash = blake3::hash(vk.as_bytes());
        let mut fp = [0u8; 16];
        fp.copy_from_slice(&hash.as_bytes()[..16]);
        fp
    }

    /// Hex-encoded fingerprint.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint())
    }

    /// Sign a message, producing a detached `Signature`.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        use ed25519_dalek::Signer as _;
        let raw: ed25519_dalek::Signature = self.signing.sign(msg);
        Signature(raw.to_bytes())
    }

    /// Serialize to PKCS#8 PEM (via ed25519_dalek's `pem` feature).
    pub fn to_pem(&self) -> String {
        self.signing
            .to_pkcs8_pem(LineEnding::LF)
            .expect("ed25519 key always serializes to PKCS#8")
            .to_string()
    }

    /// Deserialize from PKCS#8 PEM.
    pub fn from_pem(pem: &str) -> Result<Self, KeypairError> {
        let signing =
            SigningKey::from_pkcs8_pem(pem).map_err(|e| KeypairError::Pem(e.to_string()))?;
        Ok(Self { signing })
    }
}

/// An Ed25519 public key used to verify signatures.
///
/// `Debug` shows only the fingerprint hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdentityPublicKey {
    verifying: VerifyingKey,
}

impl std::fmt::Debug for IdentityPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityPublicKey")
            .field("fingerprint", &self.fingerprint_hex())
            .finish()
    }
}

impl IdentityPublicKey {
    /// Construct from raw 32-byte compressed Edwards point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeypairError> {
        let verifying =
            VerifyingKey::from_bytes(bytes).map_err(|_| KeypairError::InvalidPublicKey)?;
        Ok(Self { verifying })
    }

    /// Raw 32-byte compressed Edwards point.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.verifying.as_bytes()
    }

    /// BLAKE3-16 fingerprint over the verifying key bytes.
    pub fn fingerprint(&self) -> [u8; 16] {
        let hash = blake3::hash(self.verifying.as_bytes());
        let mut fp = [0u8; 16];
        fp.copy_from_slice(&hash.as_bytes()[..16]);
        fp
    }

    /// Hex-encoded fingerprint.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint())
    }

    /// Verify a detached signature over `msg`.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), SignatureError> {
        use ed25519_dalek::Verifier as _;
        let raw = ed25519_dalek::Signature::from_bytes(&sig.0);
        self.verifying
            .verify(msg, &raw)
            .map_err(|e| SignatureError::VerificationFailed(e.to_string()))
    }
}
