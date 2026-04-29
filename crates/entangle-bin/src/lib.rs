//! Library surface of the `entangled` daemon binary.
//!
//! See spec §9.1 (daemon install path) in
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! **Phase**: 1 (Unix-domain-socket JSON-RPC 2.0 server; foreground-only).
//!
//! Exposes internal modules for integration tests and potential future embedding.
//!
//! # Key modules
//! - [`config`] — daemon config schema and `~/.entangle/config.toml` loader.
//! - [`methods`] — JSON-RPC 2.0 method dispatch (`version`, `plugins/*`).
//! - [`server`] — Unix-domain-socket listener that drives `methods::dispatch`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod methods;
pub mod server;
