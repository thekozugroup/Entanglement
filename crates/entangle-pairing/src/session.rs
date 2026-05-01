//! High-level `PairingSession` state machine.
//!
//! Drives the full Initiator/Responder flow without depending on any
//! transport. Feed-in events (envelopes) advance the state; the caller
//! is responsible for sending and receiving those envelopes over the mesh.
//!
//! See `docs/architecture.md` §6.3 for the protocol design.

use crate::{
    code::PairingCode,
    envelope::{make_code_commit, signing_payload, PairingAccept, PairingFinalize, PairingRequest},
    errors::PairingError,
    fingerprint::ShortFingerprint,
};
use entangle_signing::{IdentityKeyPair, IdentityPublicKey, Signature};
use entangle_types::peer_id::PeerId;
use rand_core::{OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

const PAIRING_TIMEOUT_SECS: u64 = 300; // 5 minutes per spec §6.3

// ── Shared output type ────────────────────────────────────────────────────────

/// A successfully paired peer record produced at the end of the flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairedPeer {
    /// Stable identifier for the remote peer.
    pub peer_id: PeerId,
    /// Remote peer's Ed25519 public key, hex-encoded.
    pub pubkey_hex: String,
    /// Human-readable display name of the remote device.
    pub display_name: String,
    /// Short fingerprint for future verification.
    pub fingerprint: ShortFingerprint,
}

// ── Initiator ─────────────────────────────────────────────────────────────────

/// Initiator side of the pairing flow.
///
/// # Lifecycle
/// 1. [`Initiator::start`] returns the session and the [`PairingCode`] to display.
/// 2. [`Initiator::request`] returns the [`PairingRequest`] envelope to send.
/// 3. [`Initiator::handle_accept`] validates the responder's reply, returns
///    the [`PairingFinalize`] envelope to send. Errors on bad signature or expiry.
/// 4. After step 3, [`Initiator::completed`] returns the validated [`PairedPeer`].
pub struct Initiator {
    keypair: IdentityKeyPair,
    display_name: String,
    code: PairingCode,
    nonce: [u8; 32],
    created_at: u64,
    state: InitiatorState,
}

enum InitiatorState {
    Pending,
    Completed(PairedPeer),
    #[allow(dead_code)]
    Failed(String),
}

impl std::fmt::Debug for InitiatorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Completed(_) => write!(f, "Completed(..)"),
            Self::Failed(m) => write!(f, "Failed({m:?})"),
        }
    }
}

impl std::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Initiator")
            .field("display_name", &self.display_name)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Initiator {
    /// Start a new pairing session as the initiator side.
    pub fn start(keypair: IdentityKeyPair, display_name: String) -> Self {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        Self {
            keypair,
            display_name,
            code: PairingCode::generate(),
            nonce,
            created_at: now_secs(),
            state: InitiatorState::Pending,
        }
    }

    /// The short code to display out-of-band to the user.
    pub fn code(&self) -> PairingCode {
        self.code
    }

    /// The initiator's own short fingerprint (to compare with responder's display).
    pub fn local_fingerprint(&self) -> ShortFingerprint {
        ShortFingerprint::from_public_key(self.keypair.public().as_bytes())
    }

    /// Build the [`PairingRequest`] envelope to broadcast over mesh.
    pub fn request(&self) -> PairingRequest {
        PairingRequest {
            initiator_peer_id: PeerId::from_public_key_bytes(self.keypair.public().as_bytes()),
            initiator_pubkey_hex: hex::encode(self.keypair.public().as_bytes()),
            initiator_display_name: self.display_name.clone(),
            code_commit: make_code_commit(self.code, self.keypair.public().as_bytes()),
            nonce: self.nonce,
            created_at_secs: self.created_at,
        }
    }

    /// Validate the responder's [`PairingAccept`] and return the
    /// [`PairingFinalize`] envelope to send back.
    ///
    /// # Errors
    /// - [`PairingError::Expired`] if the session has timed out.
    /// - [`PairingError::Hex`] if the accept contains malformed hex.
    /// - [`PairingError::Envelope`] if key/sig lengths are wrong or peer_id
    ///   does not match the claimed pubkey.
    /// - [`PairingError::VerifyFailed`] if the responder's signature is invalid.
    pub fn handle_accept(
        &mut self,
        accept: &PairingAccept,
    ) -> Result<PairingFinalize, PairingError> {
        // 1. Time check
        let now = now_secs();
        if now.saturating_sub(self.created_at) > PAIRING_TIMEOUT_SECS {
            self.state = InitiatorState::Failed("expired".into());
            return Err(PairingError::Expired(now - self.created_at));
        }

        // 2. Decode responder pubkey
        let pub_bytes_vec = hex::decode(&accept.responder_pubkey_hex)
            .map_err(|e| PairingError::Hex(e.to_string()))?;
        if pub_bytes_vec.len() != 32 {
            return Err(PairingError::Envelope(format!(
                "pubkey wrong length: {}",
                pub_bytes_vec.len()
            )));
        }
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&pub_bytes_vec);
        let responder_pub = IdentityPublicKey::from_bytes(&pub_bytes)
            .map_err(|e| PairingError::Envelope(format!("pubkey: {e}")))?;

        // 3. Verify responder's signature over (nonce || code)
        let payload = signing_payload(self.code, &self.nonce);
        let sig_bytes_vec =
            hex::decode(&accept.signature_hex).map_err(|e| PairingError::Hex(e.to_string()))?;
        if sig_bytes_vec.len() != 64 {
            return Err(PairingError::Envelope(format!(
                "sig wrong length: {}",
                sig_bytes_vec.len()
            )));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&sig_bytes_vec);
        let sig = Signature::from_bytes(&sig_bytes)
            .map_err(|e| PairingError::Envelope(format!("sig: {e}")))?;

        responder_pub
            .verify(&payload, &sig)
            .map_err(|_| PairingError::VerifyFailed)?;

        // 4. Verify peer_id consistency
        let responder_peer_id = PeerId::from_public_key_bytes(&pub_bytes);
        if responder_peer_id != accept.responder_peer_id {
            return Err(PairingError::Envelope(
                "responder peer_id != fingerprint(pubkey)".into(),
            ));
        }

        // 5. Sign the same payload on behalf of initiator (mutual proof of key
        //    possession) and record the completed state.
        let our_sig = self.keypair.sign(&payload);
        self.state = InitiatorState::Completed(PairedPeer {
            peer_id: responder_peer_id,
            pubkey_hex: accept.responder_pubkey_hex.clone(),
            display_name: accept.responder_display_name.clone(),
            fingerprint: ShortFingerprint::from_public_key(&pub_bytes),
        });
        Ok(PairingFinalize {
            signature_hex: hex::encode(our_sig.as_bytes()),
            created_at_secs: now_secs(),
        })
    }

    /// Returns `Some(&PairedPeer)` after a successful [`Initiator::handle_accept`],
    /// `None` otherwise.
    pub fn completed(&self) -> Option<&PairedPeer> {
        match &self.state {
            InitiatorState::Completed(p) => Some(p),
            _ => None,
        }
    }

    /// Returns `Some(&str)` failure message if the session failed.
    pub fn failed(&self) -> Option<&str> {
        match &self.state {
            InitiatorState::Failed(m) => Some(m.as_str()),
            _ => None,
        }
    }
}

// ── Responder ─────────────────────────────────────────────────────────────────

/// Responder side of the pairing flow.
///
/// # Lifecycle
/// 1. [`Responder::receive`] validates the incoming [`PairingRequest`].
/// 2. User compares fingerprints on both devices.
/// 3. [`Responder::accept`] verifies the typed code against the commitment and
///    returns the [`PairingAccept`] envelope.
/// 4. [`Responder::handle_finalize`] validates the initiator's final signature
///    and returns the completed [`PairedPeer`].
pub struct Responder {
    keypair: IdentityKeyPair,
    display_name: String,
    request: PairingRequest,
    state: ResponderState,
}

enum ResponderState {
    Pending,
    Accepted {
        payload: [u8; 64],
    },
    Completed(PairedPeer),
    #[allow(dead_code)]
    Failed(String),
}

impl std::fmt::Debug for ResponderState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Accepted { .. } => write!(f, "Accepted(..)"),
            Self::Completed(_) => write!(f, "Completed(..)"),
            Self::Failed(m) => write!(f, "Failed({m:?})"),
        }
    }
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder")
            .field("display_name", &self.display_name)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Responder {
    /// Validate an incoming [`PairingRequest`] and create a responder session.
    ///
    /// # Errors
    /// - [`PairingError::Expired`] if the request is older than 5 minutes.
    /// - [`PairingError::Envelope`] if the peer_id does not match the pubkey.
    pub fn receive(
        keypair: IdentityKeyPair,
        display_name: String,
        request: PairingRequest,
    ) -> Result<Self, PairingError> {
        let now = now_secs();
        if now.saturating_sub(request.created_at_secs) > PAIRING_TIMEOUT_SECS {
            return Err(PairingError::Expired(now - request.created_at_secs));
        }
        // Validate peer_id matches the claimed pubkey.
        let pub_bytes_vec = hex::decode(&request.initiator_pubkey_hex)
            .map_err(|e| PairingError::Hex(e.to_string()))?;
        if pub_bytes_vec.len() != 32 {
            return Err(PairingError::Envelope(
                "initiator pubkey wrong length".into(),
            ));
        }
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&pub_bytes_vec);
        if PeerId::from_public_key_bytes(&pub_bytes) != request.initiator_peer_id {
            return Err(PairingError::Envelope(
                "initiator peer_id != fingerprint(pubkey)".into(),
            ));
        }
        Ok(Self {
            keypair,
            display_name,
            request,
            state: ResponderState::Pending,
        })
    }

    /// Compute the initiator's short fingerprint from the request.
    pub fn initiator_fingerprint(&self) -> Result<ShortFingerprint, PairingError> {
        let pub_bytes_vec = hex::decode(&self.request.initiator_pubkey_hex)
            .map_err(|e| PairingError::Hex(e.to_string()))?;
        if pub_bytes_vec.len() != 32 {
            return Err(PairingError::Envelope("len".into()));
        }
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&pub_bytes_vec);
        Ok(ShortFingerprint::from_public_key(&pub_bytes))
    }

    /// The responder's own short fingerprint (to display to the user).
    pub fn local_fingerprint(&self) -> ShortFingerprint {
        ShortFingerprint::from_public_key(self.keypair.public().as_bytes())
    }

    /// Verify `typed_code` against the commitment in the request and return the
    /// [`PairingAccept`] envelope to send back.
    ///
    /// # Errors
    /// - [`PairingError::CodeMismatch`] if the code does not match the commitment.
    pub fn accept(&mut self, typed_code: PairingCode) -> Result<PairingAccept, PairingError> {
        let pub_bytes_vec = hex::decode(&self.request.initiator_pubkey_hex)
            .map_err(|e| PairingError::Hex(e.to_string()))?;
        if pub_bytes_vec.len() != 32 {
            return Err(PairingError::Envelope("len".into()));
        }
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&pub_bytes_vec);

        // Verify the typed code matches the initiator's commitment.
        let expected_commit = make_code_commit(typed_code, &pub_bytes);
        if expected_commit != self.request.code_commit {
            self.state = ResponderState::Failed("code mismatch".into());
            return Err(PairingError::CodeMismatch);
        }

        let payload = signing_payload(typed_code, &self.request.nonce);
        let sig = self.keypair.sign(&payload);
        let responder_peer_id = PeerId::from_public_key_bytes(self.keypair.public().as_bytes());

        self.state = ResponderState::Accepted { payload };
        Ok(PairingAccept {
            responder_peer_id,
            responder_pubkey_hex: hex::encode(self.keypair.public().as_bytes()),
            responder_display_name: self.display_name.clone(),
            signature_hex: hex::encode(sig.as_bytes()),
            created_at_secs: now_secs(),
        })
    }

    /// Validate the initiator's [`PairingFinalize`] and return the completed
    /// [`PairedPeer`].
    ///
    /// # Errors
    /// - [`PairingError::Envelope`] if called before [`Responder::accept`] or
    ///   if the signature is malformed.
    /// - [`PairingError::VerifyFailed`] if the initiator's signature is invalid.
    pub fn handle_finalize(
        &mut self,
        finalize: &PairingFinalize,
    ) -> Result<PairedPeer, PairingError> {
        let payload = match &self.state {
            ResponderState::Accepted { payload } => *payload,
            _ => return Err(PairingError::Envelope("not in Accepted state".into())),
        };

        // Decode and verify initiator's public key.
        let pub_bytes_vec = hex::decode(&self.request.initiator_pubkey_hex)
            .map_err(|e| PairingError::Hex(e.to_string()))?;
        if pub_bytes_vec.len() != 32 {
            return Err(PairingError::Envelope("len".into()));
        }
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&pub_bytes_vec);
        let initiator_pub = IdentityPublicKey::from_bytes(&pub_bytes)
            .map_err(|e| PairingError::Envelope(format!("pub: {e}")))?;

        // Decode and verify signature.
        let sig_bytes_vec =
            hex::decode(&finalize.signature_hex).map_err(|e| PairingError::Hex(e.to_string()))?;
        if sig_bytes_vec.len() != 64 {
            return Err(PairingError::Envelope("sig len".into()));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&sig_bytes_vec);
        let sig = Signature::from_bytes(&sig_bytes)
            .map_err(|e| PairingError::Envelope(format!("sig: {e}")))?;

        initiator_pub
            .verify(&payload, &sig)
            .map_err(|_| PairingError::VerifyFailed)?;

        let paired = PairedPeer {
            peer_id: self.request.initiator_peer_id,
            pubkey_hex: self.request.initiator_pubkey_hex.clone(),
            display_name: self.request.initiator_display_name.clone(),
            fingerprint: ShortFingerprint::from_public_key(&pub_bytes),
        };
        self.state = ResponderState::Completed(paired.clone());
        Ok(paired)
    }

    /// Returns `Some(&PairedPeer)` after a successful [`Responder::handle_finalize`].
    pub fn completed(&self) -> Option<&PairedPeer> {
        match &self.state {
            ResponderState::Completed(p) => Some(p),
            _ => None,
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keypair() -> IdentityKeyPair {
        IdentityKeyPair::generate()
    }

    /// Full happy-path: both sides end up with matching peer_ids and fingerprints.
    #[test]
    fn pairing_happy_path_yields_matching_pairs() {
        let init_kp = make_keypair();
        let resp_kp = make_keypair();

        let mut initiator = Initiator::start(init_kp, "Alice".into());
        let request = initiator.request();

        let mut responder =
            Responder::receive(resp_kp, "Bob".into(), request).expect("receive should succeed");

        let accept = responder
            .accept(initiator.code())
            .expect("accept with correct code should succeed");

        let finalize = initiator
            .handle_accept(&accept)
            .expect("handle_accept should succeed");

        let responder_paired = responder
            .handle_finalize(&finalize)
            .expect("handle_finalize should succeed");

        let initiator_paired = initiator
            .completed()
            .expect("initiator should be completed");

        // Each side records the OTHER peer's identity.
        // initiator_paired.peer_id == responder's peer_id
        // responder_paired.peer_id == initiator's peer_id
        // Verify cross-symmetry via fingerprint equality.
        assert_eq!(
            initiator_paired.fingerprint,
            responder.local_fingerprint(),
            "initiator's view of responder fingerprint should match responder's local fingerprint"
        );
        assert_eq!(
            responder_paired.fingerprint,
            initiator.local_fingerprint(),
            "responder's view of initiator fingerprint should match initiator's local fingerprint"
        );

        // Also ensure the peer_ids stored are consistent with the pubkeys.
        assert_eq!(
            initiator_paired.peer_id, accept.responder_peer_id,
            "initiator's paired peer_id should match what the responder declared"
        );
    }

    /// Responder rejects a wrong pairing code.
    #[test]
    fn wrong_code_fails_at_responder_accept() {
        let init_kp = make_keypair();
        let resp_kp = make_keypair();

        let initiator = Initiator::start(init_kp, "Alice".into());
        let request = initiator.request();
        let mut responder =
            Responder::receive(resp_kp, "Bob".into(), request).expect("receive should succeed");

        // Generate a different code that almost certainly != initiator's code.
        let wrong_code = loop {
            let c = PairingCode::generate();
            if c != initiator.code() {
                break c;
            }
        };

        let err = responder.accept(wrong_code).unwrap_err();
        assert!(
            matches!(err, PairingError::CodeMismatch),
            "expected CodeMismatch, got {err:?}"
        );
    }

    /// Mutated initiator pubkey in the request is rejected by Responder::receive.
    #[test]
    fn tampered_initiator_pubkey_fails_responder_receive() {
        let init_kp = make_keypair();
        let resp_kp = make_keypair();

        let initiator = Initiator::start(init_kp, "Alice".into());
        let mut request = initiator.request();

        // Flip the first byte of the hex-encoded pubkey.
        let mut hex_bytes = request.initiator_pubkey_hex.into_bytes();
        hex_bytes[0] = if hex_bytes[0] == b'a' { b'b' } else { b'a' };
        request.initiator_pubkey_hex = String::from_utf8(hex_bytes).unwrap();

        let result = Responder::receive(resp_kp, "Bob".into(), request);
        assert!(
            result.is_err(),
            "tampered pubkey should cause receive to fail"
        );
    }

    /// Flipping a byte in the accept signature causes VerifyFailed.
    #[test]
    fn tampered_signature_fails_initiator_handle_accept() {
        let init_kp = make_keypair();
        let resp_kp = make_keypair();

        let mut initiator = Initiator::start(init_kp, "Alice".into());
        let request = initiator.request();
        let mut responder = Responder::receive(resp_kp, "Bob".into(), request).expect("receive ok");
        let mut accept = responder
            .accept(initiator.code())
            .expect("accept with correct code ok");

        // Tamper with the first hex char of the signature.
        let mut sig_hex = accept.signature_hex.into_bytes();
        sig_hex[0] = if sig_hex[0] == b'a' { b'b' } else { b'a' };
        accept.signature_hex = String::from_utf8(sig_hex).unwrap();

        let err = initiator.handle_accept(&accept).unwrap_err();
        assert!(
            matches!(err, PairingError::VerifyFailed),
            "expected VerifyFailed, got {err:?}"
        );
    }

    /// A request older than PAIRING_TIMEOUT_SECS is rejected by Responder::receive.
    #[test]
    fn expired_request_rejected_at_responder() {
        let init_kp = make_keypair();
        let resp_kp = make_keypair();

        let initiator = Initiator::start(init_kp, "Alice".into());
        let mut request = initiator.request();

        // Backdate the timestamp beyond the timeout.
        request.created_at_secs = now_secs().saturating_sub(PAIRING_TIMEOUT_SECS + 1);

        let err = Responder::receive(resp_kp, "Bob".into(), request).unwrap_err();
        assert!(
            matches!(err, PairingError::Expired(_)),
            "expected Expired, got {err:?}"
        );

        let _ = initiator.code(); // consume the initiator
    }

    /// Debug output for PairingCode must not contain any digits.
    #[test]
    fn code_redacted_in_debug() {
        let code = PairingCode::generate();
        let s = format!("{:?}", code);
        assert!(
            !s.chars().any(|c| c.is_ascii_digit()),
            "Debug must not expose digits, got: {s}"
        );
    }
}
