use rand_core::{OsRng, RngCore};
use std::fmt;
use std::str::FromStr;

/// A 6-digit pairing code. Displayed as `123-456` for human entry; transmitted
/// as the 6-digit decimal number. Used as a transient out-of-band channel to
/// authenticate the public-key fingerprint exchange.
///
/// Per spec §6.3: codes are short-lived (≤ 5 minutes), single-use, and not
/// stored beyond the pairing session.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct PairingCode(u32); // 100_000..=999_999

impl PairingCode {
    /// Generate a cryptographically random 6-digit code using [`OsRng`].
    pub fn generate() -> Self {
        let mut buf = [0u8; 4];
        OsRng.fill_bytes(&mut buf);
        let n = u32::from_le_bytes(buf) % 900_000 + 100_000;
        Self(n)
    }

    /// Construct from an already-validated integer in `[100_000, 999_999]`.
    pub fn from_u32(n: u32) -> Result<Self, crate::CodeError> {
        if !(100_000..=999_999).contains(&n) {
            return Err(crate::CodeError::OutOfRange(n));
        }
        Ok(Self(n))
    }

    /// Return the raw integer value.
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Return the human-readable `NNN-NNN` form.
    pub fn display_grouped(&self) -> String {
        let s = self.0.to_string();
        format!("{}-{}", &s[..3], &s[3..])
    }
}

impl fmt::Display for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_grouped())
    }
}

/// Debug output intentionally redacts the value to prevent code leakage in
/// log files. Use [`PairingCode::display_grouped`] explicitly where needed.
impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode(REDACTED)")
    }
}

impl FromStr for PairingCode {
    type Err = crate::CodeError;

    /// Accept any string that yields exactly 6 ASCII decimal digits after
    /// stripping dashes, spaces, and other non-digit characters.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cleaned: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
        if cleaned.len() != 6 {
            // If too few/many digits, produce an OutOfRange so the caller sees
            // a clear message rather than a parse integer error.
            let n: u32 = cleaned.parse().unwrap_or(0);
            return Err(crate::CodeError::OutOfRange(n));
        }
        let n: u32 = cleaned
            .parse()
            .map_err(|_| crate::CodeError::Malformed(s.into()))?;
        Self::from_u32(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_yields_in_range() {
        for _ in 0..100 {
            let code = PairingCode::generate();
            let n = code.as_u32();
            assert!((100_000..=999_999).contains(&n), "out of range: {n}");
        }
    }

    #[test]
    fn display_grouped_inserts_dash() {
        let code = PairingCode::from_u32(123_456).unwrap();
        assert_eq!(code.display_grouped(), "123-456");
        assert_eq!(code.to_string(), "123-456");
    }

    #[test]
    fn from_str_strips_dashes_and_whitespace() {
        let code: PairingCode = "123 - 456".parse().unwrap();
        assert_eq!(code.as_u32(), 123_456);
    }

    #[test]
    fn from_str_rejects_5_digits() {
        let result: Result<PairingCode, _> = "12345".parse();
        assert!(result.is_err(), "expected Err for 5-digit input, got Ok");
        match result.unwrap_err() {
            crate::CodeError::OutOfRange(_) => {}
            e => panic!("expected OutOfRange, got {e:?}"),
        }
    }

    #[test]
    fn debug_redacts_value() {
        let code = PairingCode::from_u32(654_321).unwrap();
        let s = format!("{:?}", code);
        assert!(
            !s.contains("654321") && !s.contains("654") && !s.contains("321"),
            "Debug must not leak digits, got: {s}"
        );
        assert!(s.contains("REDACTED"));
    }
}
