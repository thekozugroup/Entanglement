//! Internal asynchronous message bus for in-process lifecycle events.
//!
//! See spec §2 (core runtime owns IPC bus), §10 (crate layout) in
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! This is the *in-process* bus — `tokio::broadcast` backed, not networked.
//! Cross-device messaging is the mesh layer's concern (Phase 2+).
//!
//! **Phase**: 1 (lifecycle events); Phase 2 extends topics for mesh coordination.
//!
//! # Key types
//! - [`Bus`] — typed broadcast pub/sub channel; create one per event payload type.
//! - [`Envelope`] — message wrapper carrying id, topic, priority, and payload.
//! - [`Topic`] — dot-separated lowercase topic string with glob-match support.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bus;
pub mod envelope;
pub mod errors;
pub mod topic;

pub use bus::{Bus, BusHandle};
pub use envelope::{Envelope, EnvelopeId, Priority};
pub use errors::IpcError;
pub use topic::Topic;
