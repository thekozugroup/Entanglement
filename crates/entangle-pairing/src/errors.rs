/// Top-level pairing error, aggregating all sub-errors.
#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    /// Wraps a code parsing or range error.
    #[error("code: {0}")]
    Code(#[from] CodeError),
    /// Wraps a fingerprint parsing error.
    #[error("fingerprint: {0}")]
    Fingerprint(#[from] FingerprintError),
    /// Malformed envelope field.
    #[error("envelope: {0}")]
    Envelope(String),
    /// Ed25519 signature check failed.
    #[error("verify: signature does not match expected key")]
    VerifyFailed,
    /// The pairing exchange timestamp is stale.
    #[error("expired: pairing exchange older than {0}s")]
    Expired(u64),
    /// Pairing codes did not match.
    #[error("code mismatch")]
    CodeMismatch,
    /// Hex decode failure.
    #[error("invalid hex: {0}")]
    Hex(String),
}

/// Errors arising from [`crate::PairingCode`] parsing or construction.
#[derive(Debug, thiserror::Error)]
pub enum CodeError {
    /// The input string could not be parsed as a 6-digit decimal number.
    #[error("malformed code: {0}")]
    Malformed(String),
    /// The parsed number is outside `[100_000, 999_999]`.
    #[error("out of range: {0}")]
    OutOfRange(u32),
}

/// Errors arising from [`crate::ShortFingerprint`] parsing.
#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    /// Wrong number of hex digits after stripping separators.
    #[error("invalid length: {0}")]
    Length(usize),
    /// `hex::decode` failure.
    #[error("invalid hex: {0}")]
    Hex(String),
}
