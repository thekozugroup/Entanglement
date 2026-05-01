//! Typed JSON-RPC 2.0 client for the `entangled` daemon.
//!
//! Connects to the Unix-domain socket the daemon listens on (default
//! `~/.entangle/sock`) and provides typed methods mirroring the server
//! surface in `entangle-bin::methods`.
//!
//! # Quick start
//!
//! ```no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), entangle_rpc::RpcError> {
//! let client = entangle_rpc::Client::new(entangle_rpc::Client::default_socket());
//! let v = client.version().await?;
//! println!("daemon {}", v.entangled);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Typed async client for the `entangled` Unix-domain socket.
pub mod client;
/// Error types for RPC operations.
pub mod errors;
/// Shared request/response types that mirror the wire format.
pub mod methods;

pub use client::Client;
pub use errors::RpcError;
pub use methods::*;
