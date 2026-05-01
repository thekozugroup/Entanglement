//! Capability broker — deny-by-default authority resolution.
//!
//! See spec §4 (tier+capability model), §4.4.1 (implied vs declared),
//! §9.4 (max_tier_allowed), §11 (no-ambient-authority invariant) in
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! **Phase**: 1 (ships in the initial kernel release).
//!
//! # Key types
//! - [`Broker`] — grants/revokes capability handles and enforces tier ceilings.
//! - [`BrokerPolicy`] — daemon-wide policy (max tier, multi-node flag).
//! - [`AuditLog`] / [`AuditEvent`] — append-only record of every broker decision.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod broker;
pub mod errors;
pub mod policy;

pub use audit::{AuditEvent, AuditLog};
pub use broker::{Broker, GrantId, GrantedCapability};
pub use errors::BrokerError;
pub use policy::{BrokerPolicy, CrossNodePolicy, PolicyError};
