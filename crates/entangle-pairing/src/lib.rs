//! Pairing-flow primitives — short codes, fingerprints, signed envelopes — and
//! the two ways to move them between devices.
//!
//! See `docs/architecture.md` §6.3 for the protocol design and §11 for the
//! threat model.
//!
//! # Two channels, one set of guarantees
//!
//! * [`session`] drives the **copy-paste** channel: a human carries three
//!   base64 blobs between the machines. It needs no network at all, which is
//!   why it survives as the air-gapped / cross-network escape hatch
//!   (`entangle pair --manual`).
//! * [`net`] + [`mesh`] drive the **over-the-network** channel: the device
//!   showing the code listens on QUIC, the other device finds it over mDNS and
//!   dials it. This is what `entangle pair` does by default.
//!
//! Both sign the same [`envelope::signing_payload`] with the same keys and end
//! at the same mutual-TOFU outcome; what differs is who speaks first and what
//! may be revealed to a caller that has not yet proved it can read the code.
//! [`net`]'s module docs explain that difference and why it matters.
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
/// Pairing over the live mesh transport (QUIC + mDNS).
pub mod mesh;
/// Transport-independent state machines for pairing over a network link.
pub mod net;
/// Full Initiator/Responder pairing state machine.
pub mod session;

pub use code::PairingCode;
pub use envelope::{
    fingerprint_from_hex, make_code_commit, signing_payload, PairingAccept, PairingFinalize,
    PairingRequest,
};
pub use errors::{CodeError, FingerprintError, PairingError};
pub use fingerprint::ShortFingerprint;
pub use mesh::{
    dial_and_pair, discover_pairing_hosts, parse_node_addr, start_pairing_transport, IrohPeer,
    PairingCandidate, PairingListener, PairingMeshError,
};
pub use net::{
    Dialer, HostConfig, HostSession, PairingNetError, PairingOffer, PairingWire, RejectReason,
    SessionEnd, DEFAULT_MAX_ATTEMPTS, DEFAULT_SESSION_TTL,
};
pub use session::{Initiator, PairedPeer, Responder};
