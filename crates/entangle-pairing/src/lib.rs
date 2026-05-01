//! Pairing-flow primitives — short codes, fingerprints, signed envelopes.
//!
//! See `docs/architecture.md` §6.3 for the protocol design and §11 for the
//! threat model. This crate provides the cryptographic primitives only;
//! transport over mesh-local and the CLI UX live in their own crates.
//!
//! # Protocol sketch
//!
//! 1. Initiator calls [`PairingCode::generate`] and displays it OOB.
//! 2. Initiator sends a [`envelope::PairingRequest`] containing a BLAKE3
//!    commitment to the code (via [`envelope::make_code_commit`]) and a random
//!    nonce. The responder cannot learn the code from this commitment alone.
//! 3. Responder displays its [`ShortFingerprint`] and the initiator verifies it
//!    OOB. Responder signs `signing_payload(code, nonce)` and sends
//!    [`envelope::PairingAccept`].
//! 4. Initiator verifies the signature, then sends
//!    [`envelope::PairingFinalize`] signed over the same payload.
//! 5. Both sides store each other's public key as TOFU; future sessions are
//!    authenticated without a code.
//!
//! Entropy source: [`rand_core::OsRng`] (system CSPRNG on all platforms).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// 6-digit short-code generation, parsing, and display.
pub mod code;
/// Signed wire envelopes and commitment/payload helpers.
pub mod envelope;
/// Error types for this crate.
pub mod errors;
/// 8-byte human-readable public-key fingerprint.
pub mod fingerprint;
/// Full Initiator/Responder pairing state machine.
pub mod session;

pub use code::PairingCode;
pub use envelope::{
    fingerprint_from_hex, make_code_commit, signing_payload, PairingAccept, PairingFinalize,
    PairingRequest,
};
pub use errors::{CodeError, FingerprintError, PairingError};
pub use fingerprint::ShortFingerprint;
pub use session::{Initiator, PairedPeer, Responder};
