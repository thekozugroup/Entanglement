//! Transport-independent state machines for **pairing over a network link**.
//!
//! [`session`](crate::session) drives the copy-paste flow, where a human moves
//! three blobs between two machines. This module drives the same cryptography
//! over a live connection, where the two sides can talk to each other but the
//! only authenticated channel between them is the 6-digit code a human reads
//! off one screen and types into the other.
//!
//! Nothing here knows about QUIC: a *host* turns request frames into response
//! frames ([`HostSession::handle`]) and a *dialer* produces the frames to send
//! ([`Dialer`]). [`crate::mesh`] wires both onto `entangle-mesh-iroh`.
//!
//! # Roles
//!
//! ```text
//!   host  (entangle pair --responder)        dialer (entangle pair)
//!   ── displays the code ──                  ── types the code ──
//!
//!        <───────────────  Hello { version }
//!   Offer { identity, nonce }  ───────────>
//!        <───────────────  Accept { identity, Sign_d(nonce ‖ code) }
//!                                            (host verifies with ITS code)
//!   Finalize { Sign_h(nonce ‖ code) }  ────>
//!                                            (dialer verifies with the
//!                                             code the user typed)
//! ```
//!
//! The signed payload, the fingerprints and the TOFU outcome are the same ones
//! [`crate::session`] produces — [`envelope::signing_payload`] is the single
//! definition of what gets signed, and both sides must arrive at identical
//! bytes or neither signature verifies.
//!
//! # Why the code commitment is not on the wire
//!
//! In the copy-paste flow the initiator's blob carries
//! `code_commit = BLAKE3(code ‖ pubkey)` so the other side can check a typed
//! code before signing. That blob only ever travels through a human.
//!
//! A network listener is different: *anyone on the LAN can dial it*. Handing an
//! unauthenticated caller a commitment to a 6-digit code would let them recover
//! the code offline — 900 000 BLAKE3 evaluations, well under a second — and
//! then complete the pairing without ever having seen the screen. That would
//! silently reduce the out-of-band authenticator to nothing.
//!
//! So the order is inverted here: **the dialer proves knowledge of the code
//! first**, with a signature the host verifies against the code it generated,
//! and the host only reveals its own proof afterwards. A caller that does not
//! know the code learns nothing but the host's public identity (which mDNS
//! already broadcasts) and a random nonce, and every wrong guess is counted
//! against [`HostConfig::max_attempts`] and expires with the session.
//!
//! # Residual weakness (unchanged from the copy-paste flow)
//!
//! A 6-digit code is 20 bits: an attacker who receives a *valid proof* can
//! brute-force it offline. Here that means an impostor host — one the user
//! actively chose to dial — can recover the code from the dialer's `Accept`.
//! It cannot then reuse it against the real host, because every signature is
//! bound to the QUIC-authenticated key of the peer that sent it (see
//! [`HostSession::handle`]), but it does mean the code alone is not a defence
//! against a device the user deliberately connected to. That is what the
//! mandatory fingerprint comparison is for, and only a PAKE (e.g. SPAKE2)
//! would remove it. Documented in `docs/architecture.md` §11.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use entangle_signing::{IdentityKeyPair, IdentityPublicKey, Signature};
use entangle_types::peer_id::PeerId;

use crate::envelope::{signing_payload, PairingAccept, PairingFinalize};
use crate::{PairedPeer, PairingCode, ShortFingerprint};

/// Wire-protocol version. Bumped when the frame grammar changes; a mismatch is
/// refused rather than guessed at.
pub const PAIRING_PROTOCOL_VERSION: u16 = 1;

/// Hard cap on one pairing frame. The largest legal frame is an `Accept`
/// (two hex keys, a hex signature, a display name) — a few hundred bytes — so
/// 8 KiB is generous. Enforced before deserialisation, and also handed to the
/// transport as its frame cap.
pub const MAX_PAIRING_FRAME_BYTES: usize = 8 * 1024;

/// How long a pairing session stays open. Spec §6.3: codes are short-lived.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(300);

/// How many failed code attempts a session tolerates before it is destroyed.
///
/// The code space is 900 000. Five guesses is a 1-in-180 000 chance of a blind
/// hit; without a cap an attacker on the LAN would simply enumerate.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Bound on a display name accepted from the far side, in bytes.
const MAX_DISPLAY_NAME_LEN: usize = 64;

// ── Wire ─────────────────────────────────────────────────────────────────────

/// The host's answer to `Hello`: who it is, and the nonce to sign.
///
/// Deliberately contains **no** function of the pairing code — see the module
/// docs. Everything in it is public information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingOffer {
    /// Stable identifier of the host (the device showing the code).
    pub host_peer_id: PeerId,
    /// Host's Ed25519 public key, 64 hex chars.
    pub host_pubkey_hex: String,
    /// Human-readable name of the host device.
    pub host_display_name: String,
    /// 32-byte random challenge; both sides sign over it.
    pub nonce: [u8; 32],
    /// Unix seconds when the session was created. Advisory only — it is not
    /// covered by any signature, so expiry is enforced by the host's own
    /// monotonic clock, not by this field.
    pub created_at_secs: u64,
}

/// One frame of the pairing protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum PairingWire {
    /// Dialer → host: open a session.
    Hello {
        /// Protocol version the dialer speaks.
        version: u16,
    },
    /// Host → dialer: identity + challenge.
    Offer(PairingOffer),
    /// Dialer → host: identity + proof of knowledge of the code.
    Accept(PairingAccept),
    /// Host → dialer: its own proof; the exchange is complete.
    Finalize(PairingFinalize),
    /// Host → dialer: refusal, with a machine-readable reason.
    Rejected {
        /// Why the frame was refused.
        reason: RejectReason,
    },
}

impl PairingWire {
    /// Encode to a frame.
    pub fn encode(&self) -> Result<Vec<u8>, PairingNetError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|e| PairingNetError::Protocol(format!("encode: {e}")))?;
        if bytes.len() > MAX_PAIRING_FRAME_BYTES {
            return Err(PairingNetError::Protocol("frame too large".into()));
        }
        Ok(bytes)
    }

    /// Decode a frame, refusing anything over [`MAX_PAIRING_FRAME_BYTES`]
    /// before it is parsed.
    pub fn decode(frame: &[u8]) -> Result<Self, PairingNetError> {
        if frame.len() > MAX_PAIRING_FRAME_BYTES {
            return Err(PairingNetError::Protocol(format!(
                "frame of {} bytes exceeds the {MAX_PAIRING_FRAME_BYTES}-byte cap",
                frame.len()
            )));
        }
        serde_json::from_slice(frame).map_err(|e| PairingNetError::Protocol(format!("decode: {e}")))
    }
}

/// Why a host refused a frame. Sent on the wire, so it must stay coarse: it is
/// told to an unauthenticated caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// The proof did not verify against the code this host is displaying.
    BadCode,
    /// The session's time window has passed.
    Expired,
    /// Too many failed attempts; the session is destroyed.
    TooManyAttempts,
    /// This session already paired. Codes are single-use.
    AlreadyPaired,
    /// Frame was unparseable, out of sequence, or the wrong protocol version.
    Malformed,
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::BadCode => "the code did not match the one displayed on the other device",
            Self::Expired => "the pairing session expired",
            Self::TooManyAttempts => "too many wrong codes; the session was destroyed",
            Self::AlreadyPaired => "that session has already paired (codes are single-use)",
            Self::Malformed => "the other device rejected the message as malformed",
        };
        f.write_str(s)
    }
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Failures of a networked pairing exchange.
#[derive(Debug, thiserror::Error)]
pub enum PairingNetError {
    /// The peer refused, with its stated reason.
    #[error("peer refused: {0}")]
    Rejected(RejectReason),
    /// Framing/encoding problem or an out-of-sequence message.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The identity in an envelope did not match the transport-authenticated
    /// identity of the peer that sent it.
    #[error("identity: {0}")]
    Identity(String),
    /// A signature did not verify. On the dialer this means the host does not
    /// know the code that was typed — i.e. the wrong device, or the wrong code.
    #[error("verification failed: the other device could not prove it knows this code")]
    VerifyFailed,
    /// The local session ran out of time.
    #[error("the pairing session expired")]
    Expired,
    /// The host stopped listening without pairing.
    #[error("no device completed pairing")]
    NoPeer,
    /// Wraps the crypto-layer errors.
    #[error(transparent)]
    Pairing(#[from] crate::PairingError),
}

// ── Host ─────────────────────────────────────────────────────────────────────

/// Tuning for a [`HostSession`].
#[derive(Clone, Debug)]
pub struct HostConfig {
    /// Name shown to the dialer and stored in its peer list.
    pub display_name: String,
    /// Lifetime of the session and of the code it displays.
    pub ttl: Duration,
    /// Failed code attempts tolerated before the session self-destructs.
    pub max_attempts: u32,
}

impl HostConfig {
    /// Config with the spec defaults ([`DEFAULT_SESSION_TTL`],
    /// [`DEFAULT_MAX_ATTEMPTS`]).
    pub fn new(display_name: impl Into<String>) -> Self {
        Self {
            display_name: display_name.into(),
            ttl: DEFAULT_SESSION_TTL,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }
}

/// How a session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// A peer proved knowledge of the code and both sides signed.
    Paired,
    /// The TTL elapsed.
    Expired,
    /// The attempt cap was reached.
    AttemptsExhausted,
}

/// The waiting side of a networked pairing: it generates the code, shows it to
/// a human, and answers frames until someone proves they can read that screen.
///
/// Thread-safe and shareable: [`HostSession::handle`] takes `&self` so one
/// session can be driven from an accept loop.
pub struct HostSession {
    keypair: IdentityKeyPair,
    display_name: String,
    code: PairingCode,
    nonce: [u8; 32],
    created_at_secs: u64,
    /// Monotonic start, so expiry cannot be moved by a wall-clock change.
    started: Instant,
    ttl: Duration,
    max_attempts: u32,
    state: Mutex<HostState>,
}

#[derive(Default)]
struct HostState {
    attempts: u32,
    outcome: Option<PairedPeer>,
    ended: Option<SessionEnd>,
}

impl std::fmt::Debug for HostSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the code: `PairingCode`'s own Debug redacts it, and this type
        // must not become the place it leaks into a log.
        f.debug_struct("HostSession")
            .field("display_name", &self.display_name)
            .field("ttl", &self.ttl)
            .field("max_attempts", &self.max_attempts)
            .field("ended", &self.ended())
            .finish_non_exhaustive()
    }
}

impl HostSession {
    /// Start a session: generate a fresh code and challenge nonce.
    pub fn new(keypair: IdentityKeyPair, config: HostConfig) -> Self {
        use rand_core::{OsRng, RngCore};
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        Self {
            keypair,
            display_name: sanitize_display_name(&config.display_name),
            code: PairingCode::generate(),
            nonce,
            created_at_secs: now_secs(),
            started: Instant::now(),
            ttl: config.ttl,
            max_attempts: config.max_attempts.max(1),
            state: Mutex::new(HostState::default()),
        }
    }

    /// The code to display out-of-band. Never sent on the wire.
    pub fn code(&self) -> PairingCode {
        self.code
    }

    /// This device's fingerprint, for the user to compare.
    pub fn local_fingerprint(&self) -> ShortFingerprint {
        ShortFingerprint::from_public_key(self.keypair.public().as_bytes())
    }

    /// The (sanitized) name this device announces.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// This device's peer id.
    pub fn local_peer_id(&self) -> PeerId {
        PeerId::from_public_key_bytes(self.keypair.public().as_bytes())
    }

    /// This device's raw public key.
    pub fn local_public_key(&self) -> [u8; 32] {
        *self.keypair.public().as_bytes()
    }

    /// Session lifetime.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Time left before the session expires; zero once it has.
    pub fn time_remaining(&self) -> Duration {
        self.ttl.saturating_sub(self.started.elapsed())
    }

    /// The peer this session paired with, once it has.
    pub fn outcome(&self) -> Option<PairedPeer> {
        self.lock().outcome.clone()
    }

    /// How the session ended, or `None` while it is still live.
    pub fn ended(&self) -> Option<SessionEnd> {
        self.lock().ended
    }

    /// Failed code attempts so far.
    pub fn attempts(&self) -> u32 {
        self.lock().attempts
    }

    /// True once no further frames will be usefully processed.
    pub fn is_finished(&self) -> bool {
        self.ended().is_some() || self.expire_if_due()
    }

    /// Process one inbound frame and produce the frame to send back.
    ///
    /// `remote_key` is the peer's **transport-authenticated** public key — for
    /// QUIC, the key it proved possession of during the handshake. Binding the
    /// envelope to it is what stops a relay attack: an attacker cannot forward
    /// a signature it collected from an honest dialer, because the envelope
    /// identity would then disagree with the key on its own connection.
    ///
    /// Always returns a frame; refusals are [`PairingWire::Rejected`].
    pub fn handle(&self, remote_key: [u8; 32], frame: &[u8]) -> Vec<u8> {
        let response = match self.handle_inner(remote_key, frame) {
            Ok(wire) => wire,
            Err(reason) => PairingWire::Rejected { reason },
        };
        response.encode().unwrap_or_else(|_| {
            // Encoding a `Rejected` cannot overflow the cap; this is belt and
            // braces so the accept loop always has something to send.
            br#"{"msg":"rejected","reason":"malformed"}"#.to_vec()
        })
    }

    fn handle_inner(
        &self,
        remote_key: [u8; 32],
        frame: &[u8],
    ) -> Result<PairingWire, RejectReason> {
        if self.expire_if_due() {
            return Err(RejectReason::Expired);
        }
        if let Some(end) = self.ended() {
            return Err(match end {
                SessionEnd::Paired => RejectReason::AlreadyPaired,
                SessionEnd::Expired => RejectReason::Expired,
                SessionEnd::AttemptsExhausted => RejectReason::TooManyAttempts,
            });
        }

        let wire = PairingWire::decode(frame).map_err(|_| RejectReason::Malformed)?;
        match wire {
            PairingWire::Hello { version } => {
                if version != PAIRING_PROTOCOL_VERSION {
                    return Err(RejectReason::Malformed);
                }
                Ok(PairingWire::Offer(self.offer()))
            }
            PairingWire::Accept(accept) => match self.verify_accept(remote_key, &accept) {
                Ok(finalize) => Ok(PairingWire::Finalize(finalize)),
                Err(reason) => Err(self.record_failed_attempt(reason)),
            },
            // A dialer has no business sending these.
            PairingWire::Offer(_) | PairingWire::Finalize(_) | PairingWire::Rejected { .. } => {
                Err(RejectReason::Malformed)
            }
        }
    }

    fn offer(&self) -> PairingOffer {
        PairingOffer {
            host_peer_id: self.local_peer_id(),
            host_pubkey_hex: hex::encode(self.keypair.public().as_bytes()),
            host_display_name: self.display_name.clone(),
            nonce: self.nonce,
            created_at_secs: self.created_at_secs,
        }
    }

    /// The whole security decision of the host side.
    fn verify_accept(
        &self,
        remote_key: [u8; 32],
        accept: &PairingAccept,
    ) -> Result<PairingFinalize, RejectReason> {
        // 1. The claimed key must be the one QUIC authenticated. Anything else
        //    is a relay or a forged envelope.
        let claimed = decode_key(&accept.responder_pubkey_hex).ok_or(RejectReason::BadCode)?;
        if claimed != remote_key {
            return Err(RejectReason::BadCode);
        }
        // 2. …and the peer id must be that key's fingerprint.
        if accept.responder_peer_id != PeerId::from_public_key_bytes(&claimed) {
            return Err(RejectReason::BadCode);
        }

        // 3. The proof: a signature over (nonce ‖ our code). Only a device that
        //    was shown the code can produce it. This is the rate-limited,
        //    online-only code check.
        let payload = signing_payload(self.code, &self.nonce);
        let their_key =
            IdentityPublicKey::from_bytes(&claimed).map_err(|_| RejectReason::BadCode)?;
        let sig = decode_signature(&accept.signature_hex).ok_or(RejectReason::BadCode)?;
        their_key
            .verify(&payload, &sig)
            .map_err(|_| RejectReason::BadCode)?;

        // 4. Proven. Record the peer and counter-sign so the dialer can verify
        //    that *we* know the code too (mutual proof, mutual TOFU).
        let paired = PairedPeer {
            peer_id: accept.responder_peer_id,
            pubkey_hex: hex::encode(claimed),
            display_name: sanitize_display_name(&accept.responder_display_name),
            fingerprint: ShortFingerprint::from_public_key(&claimed),
        };
        let our_sig = self.keypair.sign(&payload);

        let mut state = self.lock();
        if state.ended.is_some() {
            return Err(RejectReason::AlreadyPaired);
        }
        state.outcome = Some(paired);
        state.ended = Some(SessionEnd::Paired);
        drop(state);

        Ok(PairingFinalize {
            signature_hex: hex::encode(our_sig.as_bytes()),
            created_at_secs: now_secs(),
        })
    }

    /// Count a failed attempt and destroy the session once the cap is hit.
    fn record_failed_attempt(&self, reason: RejectReason) -> RejectReason {
        let mut state = self.lock();
        state.attempts = state.attempts.saturating_add(1);
        if state.attempts >= self.max_attempts && state.ended.is_none() {
            state.ended = Some(SessionEnd::AttemptsExhausted);
            return RejectReason::TooManyAttempts;
        }
        reason
    }

    /// Mark the session expired if its TTL has elapsed. Returns whether it is
    /// expired (including from an earlier call).
    fn expire_if_due(&self) -> bool {
        if self.started.elapsed() <= self.ttl {
            return false;
        }
        let mut state = self.lock();
        if state.ended.is_none() {
            state.ended = Some(SessionEnd::Expired);
        }
        matches!(state.ended, Some(SessionEnd::Expired))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HostState> {
        // A panic inside a handler must not wedge the listener; the state is
        // plain data with no invariant a panic could have broken.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// ── Dialer ───────────────────────────────────────────────────────────────────

/// The side that types the code: it builds the proof and checks the host's.
pub struct Dialer<'a> {
    keypair: &'a IdentityKeyPair,
    display_name: String,
    code: PairingCode,
}

impl std::fmt::Debug for Dialer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dialer")
            .field("display_name", &self.display_name)
            .finish_non_exhaustive()
    }
}

impl<'a> Dialer<'a> {
    /// Build a dialer for one attempt with one code.
    pub fn new(
        keypair: &'a IdentityKeyPair,
        display_name: impl Into<String>,
        code: PairingCode,
    ) -> Self {
        Self {
            keypair,
            display_name: sanitize_display_name(&display_name.into()),
            code,
        }
    }

    /// The opening frame.
    pub fn hello(&self) -> PairingWire {
        PairingWire::Hello {
            version: PAIRING_PROTOCOL_VERSION,
        }
    }

    /// This device's fingerprint, for the user to read out.
    pub fn local_fingerprint(&self) -> ShortFingerprint {
        ShortFingerprint::from_public_key(self.keypair.public().as_bytes())
    }

    /// Validate an offer against the transport-authenticated key of the peer
    /// that sent it.
    ///
    /// `remote_key` comes from the connection, not the message, so a host
    /// cannot announce an identity it does not hold the secret key for.
    pub fn check_offer(
        &self,
        remote_key: [u8; 32],
        offer: &PairingOffer,
    ) -> Result<(), PairingNetError> {
        let claimed = decode_key(&offer.host_pubkey_hex).ok_or_else(|| {
            PairingNetError::Identity("host public key is not 32 hex-encoded bytes".into())
        })?;
        if claimed != remote_key {
            return Err(PairingNetError::Identity(
                "host announced a public key that is not the one it authenticated with".into(),
            ));
        }
        if offer.host_peer_id != PeerId::from_public_key_bytes(&claimed) {
            return Err(PairingNetError::Identity(
                "host peer id is not the fingerprint of its public key".into(),
            ));
        }
        Ok(())
    }

    /// Build the proof-of-code frame for `offer`.
    pub fn accept_for(&self, offer: &PairingOffer) -> PairingAccept {
        let payload = signing_payload(self.code, &offer.nonce);
        let sig = self.keypair.sign(&payload);
        PairingAccept {
            responder_peer_id: PeerId::from_public_key_bytes(self.keypair.public().as_bytes()),
            responder_pubkey_hex: hex::encode(self.keypair.public().as_bytes()),
            responder_display_name: self.display_name.clone(),
            signature_hex: hex::encode(sig.as_bytes()),
            created_at_secs: now_secs(),
        }
    }

    /// Verify the host's counter-signature and produce the peer record.
    ///
    /// Failure here means the host could not prove it knows the code that was
    /// typed: either the code is wrong or the device is not the one that
    /// displayed it.
    pub fn finish(
        &self,
        remote_key: [u8; 32],
        offer: &PairingOffer,
        finalize: &PairingFinalize,
    ) -> Result<PairedPeer, PairingNetError> {
        self.check_offer(remote_key, offer)?;
        let payload = signing_payload(self.code, &offer.nonce);
        let host_key = IdentityPublicKey::from_bytes(&remote_key)
            .map_err(|e| PairingNetError::Identity(format!("host key: {e}")))?;
        let sig = decode_signature(&finalize.signature_hex)
            .ok_or_else(|| PairingNetError::Protocol("malformed host signature".into()))?;
        host_key
            .verify(&payload, &sig)
            .map_err(|_| PairingNetError::VerifyFailed)?;

        Ok(PairedPeer {
            peer_id: offer.host_peer_id,
            pubkey_hex: hex::encode(remote_key),
            display_name: sanitize_display_name(&offer.host_display_name),
            fingerprint: ShortFingerprint::from_public_key(&remote_key),
        })
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Strip control characters and bound the length of a name supplied by the far
/// side. It is printed to a terminal and written into `peers.toml`, so it is
/// treated exactly like the mDNS TXT labels: untrusted.
pub fn sanitize_display_name(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_DISPLAY_NAME_LEN));
    for c in input.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_DISPLAY_NAME_LEN {
            break;
        }
        out.push(c);
    }
    out
}

fn decode_key(hex_str: &str) -> Option<[u8; 32]> {
    if hex_str.len() != 64 {
        return None;
    }
    hex::decode(hex_str).ok()?.try_into().ok()
}

fn decode_signature(hex_str: &str) -> Option<Signature> {
    if hex_str.len() != 128 {
        return None;
    }
    let bytes: [u8; 64] = hex::decode(hex_str).ok()?.try_into().ok()?;
    Signature::from_bytes(&bytes).ok()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ttl: Duration, max_attempts: u32) -> HostSession {
        HostSession::new(
            IdentityKeyPair::generate(),
            HostConfig {
                display_name: "studio".into(),
                ttl,
                max_attempts,
            },
        )
    }

    /// Drive one full exchange in-process and return both sides' records.
    fn exchange(
        host: &HostSession,
        dialer_kp: &IdentityKeyPair,
        code: PairingCode,
    ) -> Result<PairedPeer, PairingNetError> {
        let dialer = Dialer::new(dialer_kp, "laptop", code);
        let dialer_key = *dialer_kp.public().as_bytes();
        let host_key = host.local_public_key();

        let reply = host.handle(dialer_key, &dialer.hello().encode().unwrap());
        let offer = match PairingWire::decode(&reply)? {
            PairingWire::Offer(o) => o,
            PairingWire::Rejected { reason } => return Err(PairingNetError::Rejected(reason)),
            other => return Err(PairingNetError::Protocol(format!("{other:?}"))),
        };
        dialer.check_offer(host_key, &offer)?;

        let accept = PairingWire::Accept(dialer.accept_for(&offer));
        let reply = host.handle(dialer_key, &accept.encode().unwrap());
        let finalize = match PairingWire::decode(&reply)? {
            PairingWire::Finalize(f) => f,
            PairingWire::Rejected { reason } => return Err(PairingNetError::Rejected(reason)),
            other => return Err(PairingNetError::Protocol(format!("{other:?}"))),
        };
        dialer.finish(host_key, &offer, &finalize)
    }

    fn other_code(than: PairingCode) -> PairingCode {
        loop {
            let c = PairingCode::generate();
            if c != than {
                return c;
            }
        }
    }

    #[test]
    fn correct_code_pairs_both_sides_mutually() {
        let h = host(DEFAULT_SESSION_TTL, DEFAULT_MAX_ATTEMPTS);
        let dialer_kp = IdentityKeyPair::generate();

        let dialer_view = exchange(&h, &dialer_kp, h.code()).expect("correct code must pair");
        let host_view = h.outcome().expect("host must record the peer");

        // Each side stored the *other* device.
        assert_eq!(dialer_view.peer_id, h.local_peer_id());
        assert_eq!(
            host_view.peer_id,
            PeerId::from_public_key_bytes(dialer_kp.public().as_bytes())
        );
        // …and the fingerprints they will show the user agree with what the
        // other device shows for itself.
        assert_eq!(dialer_view.fingerprint, h.local_fingerprint());
        assert_eq!(
            host_view.fingerprint,
            ShortFingerprint::from_public_key(dialer_kp.public().as_bytes())
        );
        assert_eq!(h.ended(), Some(SessionEnd::Paired));
    }

    #[test]
    fn wrong_code_is_refused_by_the_host() {
        let h = host(DEFAULT_SESSION_TTL, DEFAULT_MAX_ATTEMPTS);
        let err = exchange(&h, &IdentityKeyPair::generate(), other_code(h.code()))
            .expect_err("wrong code must not pair");
        assert!(matches!(
            err,
            PairingNetError::Rejected(RejectReason::BadCode)
        ));
        assert!(h.outcome().is_none(), "nothing may be recorded");
        assert_eq!(h.attempts(), 1);
        assert_eq!(h.ended(), None, "one wrong guess must not end the session");
    }

    #[test]
    fn attempts_are_capped_and_the_session_dies() {
        let h = host(DEFAULT_SESSION_TTL, 3);
        let wrong = other_code(h.code());
        for _ in 0..2 {
            assert!(exchange(&h, &IdentityKeyPair::generate(), wrong).is_err());
        }
        assert_eq!(h.ended(), None);

        let err = exchange(&h, &IdentityKeyPair::generate(), wrong).unwrap_err();
        assert!(matches!(
            err,
            PairingNetError::Rejected(RejectReason::TooManyAttempts)
        ));
        assert_eq!(h.ended(), Some(SessionEnd::AttemptsExhausted));

        // And the door stays shut even for the right code.
        let err = exchange(&h, &IdentityKeyPair::generate(), h.code()).unwrap_err();
        assert!(matches!(
            err,
            PairingNetError::Rejected(RejectReason::TooManyAttempts)
        ));
        assert!(h.outcome().is_none());
    }

    #[test]
    fn expired_session_refuses_even_the_correct_code() {
        let h = host(Duration::from_millis(30), DEFAULT_MAX_ATTEMPTS);
        std::thread::sleep(Duration::from_millis(60));
        let err = exchange(&h, &IdentityKeyPair::generate(), h.code()).unwrap_err();
        assert!(matches!(
            err,
            PairingNetError::Rejected(RejectReason::Expired)
        ));
        assert_eq!(h.ended(), Some(SessionEnd::Expired));
        assert!(h.outcome().is_none());
    }

    #[test]
    fn code_is_single_use() {
        let h = host(DEFAULT_SESSION_TTL, DEFAULT_MAX_ATTEMPTS);
        exchange(&h, &IdentityKeyPair::generate(), h.code()).expect("first pairing succeeds");
        let err = exchange(&h, &IdentityKeyPair::generate(), h.code())
            .expect_err("a used session must not pair twice");
        assert!(matches!(
            err,
            PairingNetError::Rejected(RejectReason::AlreadyPaired)
        ));
    }

    /// The relay defence: a valid `Accept` collected from an honest dialer is
    /// worthless on a connection the attacker authenticated with its own key.
    #[test]
    fn accept_replayed_on_another_connection_is_refused() {
        let h = host(DEFAULT_SESSION_TTL, DEFAULT_MAX_ATTEMPTS);
        let honest = IdentityKeyPair::generate();
        let dialer = Dialer::new(&honest, "laptop", h.code());

        let reply = h.handle(
            *honest.public().as_bytes(),
            &dialer.hello().encode().unwrap(),
        );
        let offer = match PairingWire::decode(&reply).unwrap() {
            PairingWire::Offer(o) => o,
            other => panic!("expected Offer, got {other:?}"),
        };
        let accept = PairingWire::Accept(dialer.accept_for(&offer))
            .encode()
            .unwrap();

        // The attacker forwards those exact bytes over its own connection.
        let attacker_key = *IdentityKeyPair::generate().public().as_bytes();
        let reply = h.handle(attacker_key, &accept);
        assert!(matches!(
            PairingWire::decode(&reply).unwrap(),
            PairingWire::Rejected {
                reason: RejectReason::BadCode
            }
        ));
        assert!(h.outcome().is_none(), "a relayed proof must not pair");
    }

    /// A dialer must not accept a host that announces someone else's identity.
    #[test]
    fn dialer_rejects_offer_whose_key_is_not_the_connection_key() {
        let h = host(DEFAULT_SESSION_TTL, DEFAULT_MAX_ATTEMPTS);
        let kp = IdentityKeyPair::generate();
        let dialer = Dialer::new(&kp, "laptop", h.code());
        let reply = h.handle(*kp.public().as_bytes(), &dialer.hello().encode().unwrap());
        let offer = match PairingWire::decode(&reply).unwrap() {
            PairingWire::Offer(o) => o,
            other => panic!("expected Offer, got {other:?}"),
        };
        let impostor = *IdentityKeyPair::generate().public().as_bytes();
        assert!(matches!(
            dialer.check_offer(impostor, &offer),
            Err(PairingNetError::Identity(_))
        ));
    }

    /// The reason the commitment is not on the wire: an unauthenticated caller
    /// must not be able to take anything code-derived away from a `Hello`.
    #[test]
    fn offer_carries_nothing_derived_from_the_code() {
        let h = host(DEFAULT_SESSION_TTL, DEFAULT_MAX_ATTEMPTS);
        let reply = h.handle(
            [9u8; 32],
            &PairingWire::Hello {
                version: PAIRING_PROTOCOL_VERSION,
            }
            .encode()
            .unwrap(),
        );
        let json: serde_json::Value = serde_json::from_slice(&reply).unwrap();
        let obj = json.as_object().expect("offer is a JSON object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "created_at_secs",
                "host_display_name",
                "host_peer_id",
                "host_pubkey_hex",
                "msg",
                "nonce"
            ],
            "an offer must expose only public identity + a nonce — adding any \
             code-derived field here makes the 6-digit code brute-forceable \
             offline by anyone who can dial this listener"
        );

        // Belt and braces: the digits themselves never appear either.
        let text = String::from_utf8_lossy(&reply);
        assert!(!text.contains(&h.code().as_u32().to_string()));
    }

    #[test]
    fn oversize_and_malformed_frames_are_refused_not_parsed() {
        let h = host(DEFAULT_SESSION_TTL, DEFAULT_MAX_ATTEMPTS);
        let huge = vec![b'x'; MAX_PAIRING_FRAME_BYTES + 1];
        assert!(PairingWire::decode(&huge).is_err());
        let reply = h.handle([1u8; 32], &huge);
        assert!(matches!(
            PairingWire::decode(&reply).unwrap(),
            PairingWire::Rejected {
                reason: RejectReason::Malformed
            }
        ));

        let reply = h.handle([1u8; 32], b"{not json");
        assert!(matches!(
            PairingWire::decode(&reply).unwrap(),
            PairingWire::Rejected {
                reason: RejectReason::Malformed
            }
        ));
        assert_eq!(h.attempts(), 0, "malformed frames are not code guesses");
    }

    #[test]
    fn wrong_protocol_version_is_refused() {
        let h = host(DEFAULT_SESSION_TTL, DEFAULT_MAX_ATTEMPTS);
        let frame = PairingWire::Hello {
            version: PAIRING_PROTOCOL_VERSION + 1,
        }
        .encode()
        .unwrap();
        assert!(matches!(
            PairingWire::decode(&h.handle([1u8; 32], &frame)).unwrap(),
            PairingWire::Rejected {
                reason: RejectReason::Malformed
            }
        ));
    }

    #[test]
    fn display_names_from_the_wire_are_sanitized() {
        assert_eq!(sanitize_display_name("lap\u{1b}[31mtop\n"), "lap[31mtop");
        assert!(sanitize_display_name(&"x".repeat(1000)).len() <= MAX_DISPLAY_NAME_LEN);
        assert!(sanitize_display_name(&"é".repeat(1000)).len() <= MAX_DISPLAY_NAME_LEN);

        let h = HostSession::new(
            IdentityKeyPair::generate(),
            HostConfig::new("host\u{0}name"),
        );
        assert_eq!(h.offer().host_display_name, "hostname");
    }

    #[test]
    fn debug_never_leaks_the_code() {
        let h = host(DEFAULT_SESSION_TTL, DEFAULT_MAX_ATTEMPTS);
        let text = format!("{h:?}");
        assert!(!text.contains(&h.code().as_u32().to_string()));
    }
}
