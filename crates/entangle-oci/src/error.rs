//! Error type for OCI distribution. Codes `ENTANGLE-E0800`..`E0829`.

use entangle_signing::VerificationError;

/// Everything that can go wrong pulling, pushing or verifying an OCI artifact.
///
/// Messages never contain credentials: `Authorization` values and passwords
/// are not part of any variant.
#[derive(Debug, thiserror::Error)]
pub enum OciError {
    /// `ENTANGLE-E0800` — the `oci://` reference could not be parsed.
    #[error("ENTANGLE-E0800: invalid OCI reference {reference:?}: {reason}")]
    InvalidReference {
        /// The text that was rejected.
        reference: String,
        /// Why it was rejected.
        reason: String,
    },

    /// `ENTANGLE-E0801` — plain HTTP was requested for a non-loopback host
    /// without `--insecure-registry`.
    #[error(
        "ENTANGLE-E0801: refusing plain HTTP to {host}: use HTTPS, or pass --insecure-registry \
         for a registry you trust the network path to"
    )]
    InsecureTransport {
        /// Host (and port) that would have been contacted in the clear.
        host: String,
    },

    /// `ENTANGLE-E0802` — connection, TLS or HTTP-protocol failure.
    #[error("ENTANGLE-E0802: transport error talking to {host}: {detail}")]
    Transport {
        /// Host (and port) being contacted.
        host: String,
        /// Underlying failure.
        detail: String,
    },

    /// `ENTANGLE-E0803` — the registry answered with an unexpected status.
    #[error("ENTANGLE-E0803: registry {host} returned HTTP {status} for {what}{detail}")]
    Status {
        /// Host (and port) that answered.
        host: String,
        /// Numeric HTTP status.
        status: u16,
        /// What was being requested (e.g. `GET manifest`).
        what: String,
        /// Registry-supplied error text, prefixed with `: ` when present.
        detail: String,
    },

    /// `ENTANGLE-E0804` — authentication failed or could not be negotiated.
    #[error("ENTANGLE-E0804: authentication to {host} failed: {detail}")]
    Auth {
        /// Host (and port) of the registry.
        host: String,
        /// What went wrong (never includes secrets).
        detail: String,
    },

    /// `ENTANGLE-E0805` — manifest or index body is malformed.
    #[error("ENTANGLE-E0805: invalid manifest: {0}")]
    InvalidManifest(String),

    /// `ENTANGLE-E0806` — a media type or artifact type is not the expected one.
    #[error("ENTANGLE-E0806: unexpected media type for {what}: expected {expected}, got {actual}")]
    WrongMediaType {
        /// Which field was checked.
        what: String,
        /// Required value.
        expected: String,
        /// Value found.
        actual: String,
    },

    /// `ENTANGLE-E0807` — content does not hash to the digest that named it.
    #[error("ENTANGLE-E0807: digest mismatch for {what}: expected {expected}, computed {actual}")]
    DigestMismatch {
        /// Which object was hashed.
        what: String,
        /// Digest the descriptor or reference promised.
        expected: String,
        /// Digest of the bytes actually received.
        actual: String,
    },

    /// `ENTANGLE-E0808` — an object is larger than the configured cap.
    #[error("ENTANGLE-E0808: {what} is {size} bytes, over the {limit}-byte limit")]
    TooLarge {
        /// Which object.
        what: String,
        /// Size claimed or observed.
        size: u64,
        /// Configured cap.
        limit: u64,
    },

    /// `ENTANGLE-E0809` — the number of bytes received differs from the descriptor.
    #[error("ENTANGLE-E0809: size mismatch for {what}: descriptor says {expected} bytes, received {actual}")]
    SizeMismatch {
        /// Which object.
        what: String,
        /// Size from the descriptor.
        expected: u64,
        /// Size observed (or announced by `Content-Length`).
        actual: u64,
    },

    /// `ENTANGLE-E0810` — too many redirects, or a redirect that policy forbids.
    #[error("ENTANGLE-E0810: redirect refused: {0}")]
    Redirect(String),

    /// `ENTANGLE-E0811` — the registry kept answering 429/5xx.
    #[error("ENTANGLE-E0811: gave up on {host} after {attempts} attempts (last HTTP {status})")]
    RetriesExhausted {
        /// Host (and port).
        host: String,
        /// Attempts made.
        attempts: u32,
        /// Last status seen.
        status: u16,
    },

    /// `ENTANGLE-E0812` — the upload protocol was violated by the registry.
    #[error("ENTANGLE-E0812: upload failed: {0}")]
    Upload(String),

    /// `ENTANGLE-E0813` — the package layer is not a valid Entanglement package.
    #[error("ENTANGLE-E0813: invalid package: {0}")]
    InvalidPackage(String),

    /// `ENTANGLE-E0814` — publisher verification of the package failed.
    #[error("ENTANGLE-E0814: package verification failed: {0}")]
    Verification(#[from] VerificationError),

    /// `ENTANGLE-E0815` — credential configuration is unusable.
    #[error("ENTANGLE-E0815: credential configuration error: {0}")]
    Credentials(String),

    /// `ENTANGLE-E0816` — a mirror listing could not be produced or fetched.
    #[error("ENTANGLE-E0816: mirror listing error: {0}")]
    Listing(String),

    /// `ENTANGLE-E0817` — the mirror keyring is unusable.
    #[error("ENTANGLE-E0817: mirror keyring error: {0}")]
    MirrorKeys(String),

    /// `ENTANGLE-E0818` — an operation timed out.
    #[error("ENTANGLE-E0818: timed out {0}")]
    Timeout(String),

    /// `ENTANGLE-E0819` — a feature of the OCI spec this client does not implement.
    #[error("ENTANGLE-E0819: unsupported: {0}")]
    Unsupported(String),
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, OciError>;
