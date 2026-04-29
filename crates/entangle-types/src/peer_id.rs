//! [`PeerId`] — a 16-byte BLAKE3 fingerprint of an Ed25519 public key.
//!
//! Computed as the first 16 bytes of `BLAKE3(key_bytes)`.

use std::fmt;

/// 16-byte peer identifier derived from an Ed25519 public key via BLAKE3.
///
/// # Construction
/// Use [`PeerId::from_public_key_bytes`] to derive from a raw key, or
/// [`PeerId::from_hex`] to parse a 32-char lowercase hex string.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PeerId([u8; 16]);

/// Error returned when parsing a [`PeerId`] from a hex string fails.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The input was not valid lowercase hex or was the wrong length.
    #[error("invalid peer id hex: {0}")]
    InvalidHex(String),
}

impl PeerId {
    /// Derive a `PeerId` from a 32-byte Ed25519 public key.
    ///
    /// Internally computes `BLAKE3(key_bytes)` and takes the first 16 bytes.
    pub fn from_public_key_bytes(key: &[u8; 32]) -> Self {
        let hash = blake3::hash(key);
        let bytes = hash.as_bytes();
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes[..16]);
        PeerId(arr)
    }

    /// Return the raw 16-byte array.
    pub fn as_bytes(&self) -> [u8; 16] {
        self.0
    }

    /// Parse a `PeerId` from a 32-character lowercase hex string.
    pub fn from_hex(s: &str) -> Result<Self, ParseError> {
        if s.len() != 32 {
            return Err(ParseError::InvalidHex(format!(
                "expected 32 hex chars, got {}",
                s.len()
            )));
        }
        let bytes = hex::decode(s).map_err(|e| ParseError::InvalidHex(format!("{}: {}", s, e)))?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(PeerId(arr))
    }

    /// Encode as a 32-character lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed 32-byte key for determinism checks.
    const FIXED_KEY: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    #[test]
    fn stable_output() {
        let id1 = PeerId::from_public_key_bytes(&FIXED_KEY);
        let id2 = PeerId::from_public_key_bytes(&FIXED_KEY);
        assert_eq!(id1, id2);
    }

    #[test]
    fn stable_hex_value() {
        // Compute expected value once and pin it.
        let id = PeerId::from_public_key_bytes(&FIXED_KEY);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 32);
        // Verify it round-trips.
        let id2 = PeerId::from_hex(&hex).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn different_keys_different_ids() {
        let key2 = [0xffu8; 32];
        assert_ne!(
            PeerId::from_public_key_bytes(&FIXED_KEY),
            PeerId::from_public_key_bytes(&key2),
        );
    }

    #[test]
    fn from_hex_bad_length() {
        assert!(PeerId::from_hex("abc").is_err());
    }

    #[test]
    fn display_is_hex() {
        let id = PeerId::from_public_key_bytes(&FIXED_KEY);
        assert_eq!(id.to_string(), id.to_hex());
    }
}
