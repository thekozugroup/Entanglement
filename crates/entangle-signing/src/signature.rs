//! Detached signature types and the on-disk `SignatureBundle`.

use thiserror::Error;

/// Errors from signature operations.
#[derive(Debug, Error)]
pub enum SignatureError {
    /// The bytes provided do not constitute a valid signature.
    #[error("malformed signature")]
    Malformed,
    /// Cryptographic verification failed.
    #[error("verification failed: {0}")]
    VerificationFailed(String),
}

/// A raw 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

impl Signature {
    /// Construct from a byte slice (must be exactly 64 bytes).
    pub fn from_bytes(b: &[u8]) -> Result<Self, SignatureError> {
        if b.len() != 64 {
            return Err(SignatureError::Malformed);
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(b);
        Ok(Self(arr))
    }

    /// Raw 64-byte representation.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Lowercase hex string (128 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from lowercase hex string.
    pub fn from_hex(s: &str) -> Result<Self, SignatureError> {
        let bytes = hex::decode(s).map_err(|_| SignatureError::Malformed)?;
        Self::from_bytes(&bytes)
    }
}

/// A detached signature bundle written alongside an artifact.
///
/// The `.sig` companion file for `artifact.tar.zst` is serialized as TOML so
/// operators can inspect it in a text editor.
///
/// Per §3.6.1: we sign the BLAKE3 hash of the artifact, not the raw bytes.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureBundle {
    /// 16-byte BLAKE3 fingerprint of the publisher's verifying key (hex on wire via custom serde).
    #[serde(
        serialize_with = "serialize_bytes16_hex",
        deserialize_with = "deserialize_bytes16_hex"
    )]
    pub publisher_fingerprint: [u8; 16],
    /// Always `"ed25519"`.
    pub algorithm: String,
    /// Raw 64-byte signature over `artifact_blake3` (hex on wire).
    #[serde(
        serialize_with = "serialize_bytes64_hex",
        deserialize_with = "deserialize_bytes64_hex"
    )]
    pub signature: [u8; 64],
    /// BLAKE3 hash of the artifact bytes — what was actually signed (hex on wire).
    #[serde(
        serialize_with = "serialize_bytes32_hex",
        deserialize_with = "deserialize_bytes32_hex"
    )]
    pub artifact_blake3: [u8; 32],
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
}

impl std::fmt::Debug for SignatureBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureBundle")
            .field(
                "publisher_fingerprint",
                &hex::encode(self.publisher_fingerprint),
            )
            .field("algorithm", &self.algorithm)
            .field("artifact_blake3", &hex::encode(self.artifact_blake3))
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Serde helpers: fixed-size byte arrays as hex strings
// ---------------------------------------------------------------------------

fn serialize_bytes16_hex<S>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&hex::encode(v))
}

fn deserialize_bytes16_hex<'de, D>(d: D) -> Result<[u8; 16], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = <String as serde::Deserialize>::deserialize(d)?;
    let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom("expected 16-byte hex"))
}

fn serialize_bytes32_hex<S>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&hex::encode(v))
}

fn deserialize_bytes32_hex<'de, D>(d: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = <String as serde::Deserialize>::deserialize(d)?;
    let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom("expected 32-byte hex"))
}

fn serialize_bytes64_hex<S>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&hex::encode(v))
}

fn deserialize_bytes64_hex<'de, D>(d: D) -> Result<[u8; 64], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = <String as serde::Deserialize>::deserialize(d)?;
    let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom("expected 64-byte hex"))
}
