//! Sub-protocol selection: the tailnet transport's equivalent of an ALPN
//! (spec §6.7).
//!
//! `mesh.iroh` chooses between `entangle/scheduler/1` and `entangle/stream/1`
//! in the QUIC handshake. A `mesh.tailscale` connection is one TCP stream, so
//! a client that wants a particular protocol names it in the **first sealed
//! record** after the handshake, and the server answers before anything else
//! is exchanged:
//!
//! ```text
//! C -> S : sealed [ "ETSP" ‖ 0x01 ‖ name_len(1) ‖ name (1..=64 bytes) ]
//! S -> C : sealed [ "ETSP" ‖ 0x01 ‖ status(1) ]
//!          status: 0x01 served, 0x00 not served (the server then closes)
//! ```
//!
//! * Both records are sealed under the session keys, so a relaying tailnet
//!   node can neither change which protocol was asked for nor turn a refusal
//!   into an acceptance.
//! * Both are read under a small fixed cap (70 bytes) that is compared with the
//!   declared length before anything is allocated, and under the handshake
//!   timeout, so a silent peer cannot hold the connection open at this step.
//! * The server re-checks its allowlist (`entangle-on-top`) before parsing
//!   the selection, as it does before every request.
//! * A server built before protocol selection existed answers the selection
//!   record as if it were a request; the client sees an answer without the
//!   `ETSP` magic and reports that the peer does not serve the protocol, a
//!   connection-setup failure the caller may retry on another transport.

use crate::error::MeshTailscaleError;

/// Magic prefix of a selection record and of its answer.
pub const PROTOCOL_MAGIC: &[u8; 4] = b"ETSP";

/// Version byte of the selection exchange.
pub(crate) const PROTOCOL_VERSION: u8 = 1;

/// Longest protocol name a selection may carry.
pub const MAX_PROTOCOL_NAME: usize = 64;

/// Largest selection (or answer) record, in plaintext bytes.
pub(crate) const SELECT_MAX: usize = PROTOCOL_MAGIC.len() + 2 + MAX_PROTOCOL_NAME;

/// Answer status: the protocol is served on this connection.
pub(crate) const STATUS_SERVED: u8 = 1;
/// Answer status: the protocol is not served here.
pub(crate) const STATUS_NOT_SERVED: u8 = 0;

/// Check a protocol name a local caller passed in.
pub(crate) fn validate_name(name: &[u8]) -> Result<(), MeshTailscaleError> {
    if name.is_empty() || name.len() > MAX_PROTOCOL_NAME {
        return Err(MeshTailscaleError::Protocol(format!(
            "protocol names are 1..={MAX_PROTOCOL_NAME} bytes, got {}",
            name.len()
        )));
    }
    Ok(())
}

/// The selection record for `name` (already validated).
pub(crate) fn encode_select(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROTOCOL_MAGIC.len() + 2 + name.len());
    out.extend_from_slice(PROTOCOL_MAGIC);
    out.push(PROTOCOL_VERSION);
    // `validate_name` bounds the length to 64.
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    out
}

/// Parse a selection record; `None` when it is not one.
pub(crate) fn decode_select(record: &[u8]) -> Option<&[u8]> {
    let rest = record.strip_prefix(PROTOCOL_MAGIC.as_slice())?;
    let (&version, rest) = rest.split_first()?;
    let (&len, name) = rest.split_first()?;
    let len = usize::from(len);
    (version == PROTOCOL_VERSION && len != 0 && len <= MAX_PROTOCOL_NAME && name.len() == len)
        .then_some(name)
}

/// The answer record carrying `status`.
pub(crate) fn encode_answer(status: u8) -> Vec<u8> {
    let mut out = PROTOCOL_MAGIC.to_vec();
    out.push(PROTOCOL_VERSION);
    out.push(status);
    out
}

/// Parse an answer record; `None` when it is not one.
pub(crate) fn decode_answer(record: &[u8]) -> Option<u8> {
    match record.strip_prefix(PROTOCOL_MAGIC.as_slice())? {
        [PROTOCOL_VERSION, status] => Some(*status),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_round_trips_and_rejects_everything_else() {
        let rec = encode_select(b"entangle/scheduler/1");
        assert_eq!(decode_select(&rec), Some(&b"entangle/scheduler/1"[..]));
        assert!(rec.len() <= SELECT_MAX);
        assert_eq!(
            decode_select(&encode_select(&[b'x'; 64])).unwrap().len(),
            64
        );

        // Wrong magic, version, length, trailing bytes, empty name.
        let mut bad = rec.clone();
        bad[0] = b'X';
        assert_eq!(decode_select(&bad), None);
        let mut bad = rec.clone();
        bad[4] = 2;
        assert_eq!(decode_select(&bad), None);
        let mut bad = rec.clone();
        bad.push(0);
        assert_eq!(decode_select(&bad), None);
        assert_eq!(decode_select(b"ETSP\x01\x00"), None);
        assert_eq!(decode_select(b""), None);
        // A plain request payload is not a selection.
        assert_eq!(decode_select(b"entangle-diag-ping"), None);
    }

    #[test]
    fn names_are_bounded() {
        assert!(validate_name(b"").is_err());
        assert!(validate_name(&[b'a'; 65]).is_err());
        assert!(validate_name(&[b'a'; 64]).is_ok());
    }

    #[test]
    fn answers_round_trip_and_a_foreign_reply_is_not_an_answer() {
        assert_eq!(decode_answer(&encode_answer(STATUS_SERVED)), Some(1));
        assert_eq!(decode_answer(&encode_answer(STATUS_NOT_SERVED)), Some(0));
        assert_eq!(
            decode_answer(b"entangle: no service is bound to mesh.tailscale yet"),
            None
        );
        assert_eq!(decode_answer(b"ETSP\x01"), None);
        assert_eq!(decode_answer(b"ETSP\x01\x01\x01"), None);
    }
}
