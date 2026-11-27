//! Deliver incoming bridge traffic to an operator-selected local sink.
//!
//! The application only installs this handler for an explicitly enabled
//! transport pair. Both endpoints' signed caps and the expected origin key
//! come from the caller's relay policy/handshake.

use std::{io::Write, sync::Arc};

use entangle_signing::{BridgeReceiver, RelayError, RelayPublicKey};

use crate::MeshRequest;

/// Deliver the authenticated request body under both independently verified
/// delegations. The original request remains available for a protocol reply.
/// Charge the actual accepted bytes on a blocking thread before touching the sink.
/// A mismatched relay identity, expired grant or exhausted budget leaves the sink empty.
pub async fn deliver_bridge_frame<W: Write + Send + 'static>(
    request: &mut MeshRequest,
    receiver: Arc<BridgeReceiver>,
    trusted_origin: RelayPublicKey,
    origin_grant: Vec<u8>,
    destination_grant: Vec<u8>,
    mut sink: W,
) -> Result<W, RelayError> {
    let bridge = request.peer_id();
    let frame = request.take_payload();
    tokio::task::spawn_blocking(move || {
        let session =
            receiver.authorize(&trusted_origin, bridge, &origin_grant, &destination_grant)?;
        receiver.receive(&session, &frame, &mut sink)?;
        Ok(sink)
    })
    .await
    .map_err(std::io::Error::other)?
}
