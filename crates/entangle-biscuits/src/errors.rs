/// Errors produced by the `entangle-biscuits` crate.
#[derive(Debug, thiserror::Error)]
pub enum BiscuitError {
    /// ENTANGLE-E0410: failed to parse a biscuit from bytes.
    #[error("ENTANGLE-E0410: parse: {0}")]
    Parse(String),
    /// ENTANGLE-E0411: failed to build/mint a biscuit.
    #[error("ENTANGLE-E0411: build: {0}")]
    Build(String),
    /// ENTANGLE-E0412: biscuit verification failed.
    #[error("ENTANGLE-E0412: verify failed: {0}")]
    Verify(String),
    /// ENTANGLE-E0413: a claim value was malformed.
    #[error("ENTANGLE-E0413: malformed claim: {0}")]
    MalformedClaim(String),
}
