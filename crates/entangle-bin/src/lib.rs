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
//! - [`diag`] — the `diag/mesh` triage report.
//! - [`metrics_server`] — the Prometheus `/metrics` scrape endpoint.
//! - [`perms`] — `perms/list` and `perms/revoke`: plugins' capability grants.
//! - [`maintenance`] — built-in tier-2 maintenance loop (log rotation, GC, nags).
//! - [`methods`] — JSON-RPC 2.0 method dispatch (`version`, `plugins/*`).
//! - [`remote`] — cross-node scheduler transport: serving work to trusted
//!   peers and dispatching work to them. Off unless configured.
//! - [`server`] — Unix-domain-socket listener that drives `methods::dispatch`.
//! - [`state`] — shared `DaemonState` constructed once at startup.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod diag;
pub mod maintenance;
pub mod methods;
pub mod metrics_server;
pub mod perms;
pub mod remote;
pub mod server;
pub mod state;
pub mod tailscale;
