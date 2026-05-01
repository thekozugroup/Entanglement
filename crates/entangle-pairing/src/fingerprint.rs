use std::fmt;

/// Short fingerprint shown to humans during pairing. Computed as BLAKE3-8
/// over the verifying key's 32 raw bytes, displayed as `aaaa-bbbb-cccc-dddd`.
///
/// Per spec §6.3: this is what the user reads aloud or types to verify the
/// other side's public key. Sufficient against passive attackers in a 5-minute
/// window; a determined active MITM remains an unsolved problem (documented
/// honestly in spec §11).
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct ShortFingerprint([u8; 8]);

impl ShortFingerprint {
    /// Derive the fingerprint from an Ed25519 public key's raw 32-byte form.
    pub fn from_public_key(pubkey_bytes: &[u8; 32]) -> Self {
        let h = blake3::hash(pubkey_bytes);
        let mut out = [0u8; 8];
        out.copy_from_slice(&h.as_bytes()[..8]);
        Self(out)
    }

    /// Return the underlying 8 bytes.
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Return `aaaa-bbbb-cccc-dddd` (16 hex chars split into four groups).
    pub fn to_grouped_hex(&self) -> String {
        let s = hex::encode(self.0);
        // 16 hex chars → four 4-char groups joined with hyphens
        format!("{}-{}-{}-{}", &s[..4], &s[4..8], &s[8..12], &s[12..16])
    }

    /// Parse a grouped-hex fingerprint, tolerating hyphens and other
    /// separators between groups.
    pub fn from_grouped_hex(s: &str) -> Result<Self, crate::FingerprintError> {
        let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if cleaned.len() != 16 {
            return Err(crate::FingerprintError::Length(cleaned.len()));
        }
        let bytes =
            hex::decode(&cleaned).map_err(|e| crate::FingerprintError::Hex(e.to_string()))?;
        let mut out = [0u8; 8];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

impl fmt::Display for ShortFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_grouped_hex())
    }
}

impl fmt::Debug for ShortFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShortFingerprint({})", self.to_grouped_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn from_public_key_is_deterministic() {
        let key = sample_key();
        let fp1 = ShortFingerprint::from_public_key(&key);
        let fp2 = ShortFingerprint::from_public_key(&key);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn display_format_is_four_groups_of_four() {
        let key = sample_key();
        let fp = ShortFingerprint::from_public_key(&key);
        let s = fp.to_string();
        // ^[0-9a-f]{4}(-[0-9a-f]{4}){3}$
        let re = regex::Regex::new(r"^[0-9a-f]{4}(-[0-9a-f]{4}){3}$").unwrap();
        assert!(re.is_match(&s), "unexpected format: {s}");
    }

    #[test]
    fn from_grouped_hex_round_trip() {
        let key = sample_key();
        let fp = ShortFingerprint::from_public_key(&key);
        let s = fp.to_string();
        let fp2 = ShortFingerprint::from_grouped_hex(&s).unwrap();
        assert_eq!(fp, fp2);
    }

    #[test]
    fn from_grouped_hex_rejects_short() {
        let result = ShortFingerprint::from_grouped_hex("abcd-1234");
        assert!(result.is_err(), "expected Err for short input");
        match result.unwrap_err() {
            crate::FingerprintError::Length(_) => {}
            e => panic!("expected Length, got {e:?}"),
        }
    }
}
