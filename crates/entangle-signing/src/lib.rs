//! Ed25519 publisher-key signing, verification, and per-user trust keyring.
//!
//! See spec §3.6 (artifact signing), §10.1 (trust footprint) in
//! `docs/architecture.md`.
//!
//! **Phase**: 1 (required for all plugin loads; signing is mandatory).
//!
//! # Key types
//! - [`sign_artifact`] / [`verify_artifact`] — sign or verify a raw byte slice.
//! - [`IdentityKeyPair`] — publisher signing key (Ed25519); generated via `entangle init`.
//! - [`Keyring`] — in-memory set of trusted publisher keys loaded from `~/.entangle/keyring.toml`.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod artifact;
pub mod keypair;
pub mod keyring;
pub mod signature;

pub use artifact::{sign_artifact, verify_artifact, VerificationError};
pub use keypair::{IdentityKeyPair, IdentityPublicKey, KeypairError};
pub use keyring::{Keyring, KeyringError, TrustEntry};
pub use signature::{Signature, SignatureBundle, SignatureError};

pub use entangle_biscuits::bridge::{verify_bridge, BridgeCap, RelayAuthorizationError};

pub mod relay;
pub use entangle_biscuits::bridge::{endpoint_key as relay_endpoint_key, mint_relay};
/// Public authority key type used by the signed relay-delegation API.
pub use entangle_biscuits::PublicKey as RelayPublicKey;
pub use relay::{AuthorizedRelay, BridgeReceiver, RelayError};
