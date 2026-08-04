//! Library surface of the `entangled` daemon binary.
//!
//! See spec §9.1 (daemon install path) in
//! `docs/architecture.md`.
//!
//! **Phase**: 1 (Unix-domain-socket JSON-RPC 2.0 server; foreground-only).
//!
//! Exposes internal modules for integration tests and potential future embedding.
//!
//! # Key modules
//! - [`config`] — daemon config schema and `~/.entangle/config.toml` loader.
//! - [`maintenance`] — built-in tier-2 maintenance loop (log rotation, GC, nags).
//! - [`methods`] — JSON-RPC 2.0 method dispatch (`version`, `plugins/*`).
//! - [`remote`] — cross-node scheduler transport: serving work to trusted
//!   peers and dispatching work to them. Off unless configured.
//! - [`server`] — Unix-domain-socket listener that drives `methods::dispatch`.
//! - [`state`] — shared `DaemonState` constructed once at startup.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod maintenance;
pub mod methods;
pub mod remote;
pub mod server;
pub mod state;
