//! mDNS-based LAN peer discovery for the `mesh.local` transport.
//!
//! Phase 1 scope: register the daemon as a mDNS service, browse for other
//! Entanglement daemons on the same link-local network, report peer announce
//! and bye-bye events on a tokio broadcast channel. Pairing, auth, and stream
//! transport are out of scope for this crate.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod discovery;
pub mod errors;
pub mod peer;

pub use discovery::{Discovery, DiscoveryConfig, DiscoveryEvent};
pub use errors::DiscoveryError;
pub use peer::{HardwareAdvert, LocalPeer, PeerSeen};
