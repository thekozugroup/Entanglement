use crate::{code::PairingCode, fingerprint::ShortFingerprint};
use entangle_types::peer_id::PeerId;
use serde::{Deserialize, Serialize};

/// Initiator's request to pair, sent over the link-local channel.
///
/// Includes the initiator's identity + a challenge nonce. The challenge is
/// what the responder will sign back to prove key possession.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingRequest {
    /// Stable identifier for the initiating peer.
    pub initiator_peer_id: PeerId,
    /// Initiator's Ed25519 public key, 64 hex chars.
    pub initiator_pubkey_hex: String,
    /// Human-readable display name of the initiating device.
    pub initiator_display_name: String,
    /// `BLAKE3(code_bytes || initiator_pubkey)` — commitment to the short code.
    pub code_commit: [u8; 32],
    /// 32-byte random challenge nonce; the responder signs over this.
    pub nonce: [u8; 32],
    /// Unix timestamp (seconds) when this request was created.
    pub created_at_secs: u64,
}

/// Responder's reply: their pubkey + signature over `(request.nonce || code)`.
///
/// Initiator verifies and, if matched, sends a final [`PairingFinalize`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingAccept {
    /// Stable identifier for the responding peer.
    pub responder_peer_id: PeerId,
    /// Responder's Ed25519 public key, 64 hex chars.
    pub responder_pubkey_hex: String,
    /// Human-readable display name of the responding device.
    pub responder_display_name: String,
    /// Ed25519 signature over `signing_payload(code, nonce)`, 128 hex chars.
    pub signature_hex: String,
    /// Unix timestamp (seconds) when this accept was created.
    pub created_at_secs: u64,
}

/// Final mutual confirmation: initiator signs `(responder.nonce || code)` too.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingFinalize {
    /// Ed25519 signature by the initiator, 128 hex chars.
    pub signature_hex: String,
    /// Unix timestamp (seconds) when this finalization was created.
    pub created_at_secs: u64,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Compute the code commitment: `BLAKE3(code_le_bytes || initiator_pubkey)`.
///
/// Including the initiator's public key binds the commitment to the specific
/// session and prevents commitment reuse across sessions.
pub fn make_code_commit(code: PairingCode, initiator_pubkey: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&code.as_u32().to_le_bytes());
    hasher.update(initiator_pubkey);
    *hasher.finalize().as_bytes()
}

/// Build the canonical 64-byte payload that both sides sign.
///
/// Layout: `nonce[0..32] || code_le[0..4] || zeros[4..32]`.
/// The zero padding makes the total a clean 64 bytes and is specified so both
/// sides produce identical input to the signature function.
pub fn signing_payload(code: PairingCode, nonce: &[u8; 32]) -> [u8; 64] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(nonce);
    buf[32..36].copy_from_slice(&code.as_u32().to_le_bytes());
    // Remaining bytes left zero — the payload is canonical.
    buf
}

/// Derive a [`ShortFingerprint`] from the hex-encoded public key in an
/// envelope, returning a [`crate::PairingError`] on malformed input.
pub fn fingerprint_from_hex(pubkey_hex: &str) -> Result<ShortFingerprint, crate::PairingError> {
    let bytes = hex::decode(pubkey_hex).map_err(|e| crate::PairingError::Hex(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(crate::PairingError::Envelope(format!(
            "pubkey_hex must decode to 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(ShortFingerprint::from_public_key(&arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zeroed_key() -> [u8; 32] {
        [0u8; 32]
    }

    fn one_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = 1;
        k
    }

    fn zeroed_nonce() -> [u8; 32] {
        [0u8; 32]
    }

    #[test]
    fn code_commit_includes_pubkey() {
        let code = PairingCode::from_u32(123_456).unwrap();
        let c1 = make_code_commit(code, &zeroed_key());
        let c2 = make_code_commit(code, &one_key());
        assert_ne!(c1, c2, "commit must differ when pubkey differs");
    }

    #[test]
    fn code_commit_includes_code() {
        let c1 = PairingCode::from_u32(100_001).unwrap();
        let c2 = PairingCode::from_u32(100_002).unwrap();
        let key = zeroed_key();
        assert_ne!(
            make_code_commit(c1, &key),
            make_code_commit(c2, &key),
            "commit must differ when code differs"
        );
    }

    #[test]
    fn signing_payload_includes_code() {
        let c1 = PairingCode::from_u32(111_111).unwrap();
        let c2 = PairingCode::from_u32(222_222).unwrap();
        let nonce = zeroed_nonce();
        assert_ne!(
            signing_payload(c1, &nonce),
            signing_payload(c2, &nonce),
            "payload must differ when code differs"
        );
    }

    #[test]
    fn signing_payload_includes_nonce() {
        let code = PairingCode::from_u32(123_456).unwrap();
        let n1 = zeroed_nonce();
        let mut n2 = zeroed_nonce();
        n2[0] = 1;
        assert_ne!(
            signing_payload(code, &n1),
            signing_payload(code, &n2),
            "payload must differ when nonce differs"
        );
    }
}
