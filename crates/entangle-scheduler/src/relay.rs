//! Opt-in handler for independently authorized relay data, separate from compute jobs.
use entangle_types::peer_id::PeerId;
use std::net::SocketAddr;

/// Scheduler ALPN extension prefix for explicit relay frames.
pub const PREFIX: &[u8] = b"\0entangle/relay/1!";
/// A configured daemon implements its transport-pair and receiver policy here.
#[async_trait::async_trait]
pub trait RelayHandler: Send + Sync {
    /// Process one relay request from the authenticated peer and observed path.
    async fn handle(&self, peer: PeerId, path: Option<SocketAddr>, bytes: Vec<u8>) -> Vec<u8>;
}
