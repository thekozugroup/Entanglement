//! Serving the scheduler protocols over the tailnet transport.

use std::sync::Arc;

use entangle_mesh_iroh::{ALPN_SCHEDULER, ALPN_STREAM};
use entangle_mesh_tailscale::{
    MeshConn, MeshTailscale, ProtocolHandler, RequestHandler, RequestProtocol,
};
use entangle_types::peer_id::PeerId;

use super::{StreamIo, TransportKind};
use crate::remote::RemoteTaskServer;
use crate::stream::{StreamServer, STREAM_TRACE_TARGET};

/// One-shot tasks: every request on the connection is a scheduler frame.
struct Tasks(Arc<RemoteTaskServer>);

#[async_trait::async_trait]
impl RequestHandler for Tasks {
    async fn handle(&self, peer: PeerId, payload: Vec<u8>) -> Vec<u8> {
        self.0
            .handle_via(peer, payload, TransportKind::Tailscale)
            .await
    }
}

/// Streams: the connection becomes one stream.
struct Streams(Arc<StreamServer>);

#[async_trait::async_trait]
impl ProtocolHandler for Streams {
    async fn serve(&self, conn: MeshConn) {
        let io = match conn.into_stream() {
            Ok(io) => StreamIo::from(io),
            Err(e) => {
                tracing::debug!(target: STREAM_TRACE_TARGET, error = %e, "tailnet stream refused");
                return;
            }
        };
        if let Err(e) = self.0.handle(io).await {
            tracing::debug!(target: STREAM_TRACE_TARGET, error = %e, "stream refused");
        }
    }
}

/// Serve `entangle/scheduler/1` (with `tasks`) and `entangle/stream/1`
/// (with `streams`) on a tailnet transport until it is shut down.
///
/// The selected sub-protocol plays the part of the ALPN (spec §6.7); a
/// connection selecting anything else is closed unread. The gates are the
/// transport's own (the handshake authenticates the peer, `entangle-on-top`
/// drops a peer that is not allowlisted before it can select a protocol)
/// and then the servers' (the transport-authenticated peer must be in
/// their [`PeerAllowlist`](crate::PeerAllowlist) before a frame is
/// decoded), so `trust-tailnet` relaxes who may *connect*, never who may
/// run work. Pass the same server instances the iroh endpoint serves, so
/// in-flight tables and stream limits are shared.
///
/// `streams` must sign with the transport's identity, or no submitter could
/// verify a chunk; a mismatched one is refused (logged) and only `tasks`
/// is served.
pub async fn serve_tailscale(
    transport: MeshTailscale,
    tasks: Option<Arc<RemoteTaskServer>>,
    streams: Option<Arc<StreamServer>>,
) {
    let mut handlers: Vec<(Vec<u8>, Arc<dyn ProtocolHandler>)> = Vec::new();
    if let Some(tasks) = tasks {
        handlers.push((
            ALPN_SCHEDULER.to_vec(),
            Arc::new(RequestProtocol(Arc::new(Tasks(tasks)))),
        ));
    }
    if let Some(streams) = streams {
        if streams.local_public_key() == transport.local_public_key() {
            handlers.push((ALPN_STREAM.to_vec(), Arc::new(Streams(streams))));
        } else {
            tracing::error!(
                target: STREAM_TRACE_TARGET,
                "refusing to serve streams over mesh.tailscale: the transport identity is not \
                 the chunk-signing identity, so no submitter could verify a chunk"
            );
        }
    }
    transport.serve_protocols(handlers).await;
}
