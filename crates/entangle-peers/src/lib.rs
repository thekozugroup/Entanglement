//! Persistent peer allowlist for the Entanglement daemon.
//!
//! The [`PeerStore`] enforces spec §11 #16: in multi-node mode, the daemon
//! refuses to start until at least one trusted peer is present.  `PeerStore`
//! is the source of truth for authenticated, trusted peers.
//!
//! # Distinction from `entangle-mesh-local::PeerSeen`
//! [`PeerStore`] holds **authenticated, trusted** peers.  The mesh-local crate
//! introduces `PeerSeen` for unauthenticated mDNS sightings; the two
//! types are intentionally separate.
//!
//! # Persistence
//! By default the store is backed by `~/.entangle/peers.toml`.  Each entry is
//! stored as a `[[peer]]` TOML array-of-tables for human readability and easy
//! manual editing.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Error types for peer store operations.
pub mod errors;
/// [`TrustedPeer`] and [`TrustLevel`] domain types.
pub mod peer;
/// [`PeerStore`] implementation with TOML persistence.
pub mod store;

pub use errors::PeerStoreError;
pub use peer::{TrustLevel, TrustedPeer};
pub use store::PeerStore;
