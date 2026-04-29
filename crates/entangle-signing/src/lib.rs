//! Ed25519 publisher-key signing, verification, and per-user trust keyring.
//!
//! See spec §3.6 (artifact signing), §10.1 (trust footprint) in
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
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
