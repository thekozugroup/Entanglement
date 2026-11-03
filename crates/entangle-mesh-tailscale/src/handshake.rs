//! Authenticated key exchange, run over plain TCP inside the tailnet.
//!
//! WireGuard authenticates *hosts*. That is not enough on its own: a tailnet
//! node can sit between two Entanglement nodes (discovery can hand it that
//! position) and relay their bytes, and WireGuard then ends at the relay on
//! both legs. This handshake therefore does two things:
//!
//! * authenticates the *Entanglement identity* (the Ed25519 key behind a
//!   `PeerId`) of each end, which is what trust decisions are made on; and
//! * agrees a fresh session key that only the two authenticated ends know.
//!   Every byte after the handshake, starting with the admission answer, is a
//!   sealed record (see `framing`), so a relay can forward traffic but can
//!   neither read it nor inject, alter, replay or drop-and-replace a record.
//!
//! ```text
//! C -> S : "ETSH" ‖ 0x02 ‖ client_pk(32) ‖ client_nonce(32) ‖ client_eph(32)   (101 B)
//! S -> C : server_pk(32) ‖ server_nonce(32) ‖ server_eph(32) ‖ sig_S(64)        (160 B)
//! C -> S : sig_C(64)                                                            (64 B)
//! S -> C : sealed record [admission(1)]                                         (21 B)
//!
//! T      = "ETSH" ‖ 0x02 ‖ client_pk ‖ client_nonce ‖ client_eph
//!                        ‖ server_pk ‖ server_nonce ‖ server_eph
//! sig_S  = Sign_S("entangle/ts-hs/v2/server" ‖ T)
//! sig_C  = Sign_C("entangle/ts-hs/v2/client" ‖ T)
//! ikm    = X25519(client_eph, server_eph)
//! prk    = HKDF-SHA256-Extract(salt = SHA-256(T), ikm)
//! k_c2s  = HKDF-Expand(prk, "entangle/ts-hs/v2/c2s")   ChaCha20-Poly1305
//! k_s2c  = HKDF-Expand(prk, "entangle/ts-hs/v2/s2c")   ChaCha20-Poly1305
//! ```
//!
//! * Each signature covers both identities and both ephemeral shares. A relay
//!   cannot swap in a share of its own without a signature it cannot make, and
//!   neither side can be led to bind the session to a third identity.
//! * Distinct role labels: a signature made for one role never verifies for
//!   the other, so a peer cannot be tricked into signing something that is
//!   then replayed back at it (reflection, including a "client" that claims
//!   the server's own key).
//! * Fresh nonces and ephemeral shares on both sides, so nothing recorded can
//!   be replayed into a new session.
//! * Identity keys that are small-order points are refused and signatures are
//!   checked with strict Ed25519 verification, so no `PeerId` can be claimed
//!   without its secret key.
//! * Every field is fixed-size, so there is nothing to allocate or parse
//!   unboundedly; the whole exchange runs under a timeout.
//! * The admission answer exists so that a client rejected by the server's
//!   allowlist can tell that apart from a network failure. It is sealed, so
//!   it cannot be flipped in transit.

use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use rand_core::{OsRng, RngCore};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::{aead, digest, hkdf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::MeshTailscaleError;
use crate::framing::{read_sealed, write_sealed, Opener, Sealer};

pub(crate) const MAGIC: &[u8; 4] = b"ETSH";
pub(crate) const VERSION: u8 = 2;
pub(crate) const LABEL_SERVER: &[u8] = b"entangle/ts-hs/v2/server";
pub(crate) const LABEL_CLIENT: &[u8] = b"entangle/ts-hs/v2/client";
const INFO_C2S: &[u8] = b"entangle/ts-hs/v2/c2s";
const INFO_S2C: &[u8] = b"entangle/ts-hs/v2/s2c";

/// `MAGIC ‖ VERSION ‖ client_pk ‖ client_nonce ‖ client_eph`.
pub(crate) const CLIENT_HELLO_LEN: usize = 4 + 1 + 32 * 3;
/// `server_pk ‖ server_nonce ‖ server_eph ‖ sig_S`.
pub(crate) const SERVER_HELLO_LEN: usize = 32 * 3 + 64;

/// Admission answer: admitted.
pub(crate) const ADMIT_OK: u8 = 1;
/// Admission answer: authenticated, but not allowed by the server's ACL.
pub(crate) const ADMIT_DENIED: u8 = 0;

/// The authenticated remote identity.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Remote {
    pub public_key: [u8; 32],
    pub peer_id: PeerId,
}

/// Everything both signatures and the key schedule cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Transcript {
    pub client_pk: [u8; 32],
    pub client_nonce: [u8; 32],
    pub client_eph: [u8; 32],
    pub server_pk: [u8; 32],
    pub server_nonce: [u8; 32],
    pub server_eph: [u8; 32],
}

impl Transcript {
    /// `T` from the module docs.
    pub(crate) fn bytes(&self) -> Vec<u8> {
        let mut t = Vec::with_capacity(5 + 32 * 6);
        t.extend_from_slice(MAGIC);
        t.push(VERSION);
        for part in [
            &self.client_pk,
            &self.client_nonce,
            &self.client_eph,
            &self.server_pk,
            &self.server_nonce,
            &self.server_eph,
        ] {
            t.extend_from_slice(part);
        }
        t
    }

    /// The message a party signs for `label`'s role.
    pub(crate) fn signed(&self, label: &[u8]) -> Vec<u8> {
        let body = self.bytes();
        let mut m = Vec::with_capacity(label.len() + body.len());
        m.extend_from_slice(label);
        m.extend_from_slice(&body);
        m
    }
}

/// Which end of the session we are (decides which key seals and which opens).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Client,
    Server,
}

/// The per-direction keys of one established session.
#[derive(Debug)]
pub(crate) struct Session {
    pub sealer: Sealer,
    pub opener: Opener,
}

/// One side's ephemeral X25519 share.
pub(crate) struct Ephemeral {
    secret: EphemeralPrivateKey,
    public: [u8; 32],
}

impl Ephemeral {
    pub(crate) fn generate() -> Result<Self, MeshTailscaleError> {
        let rng = ring::rand::SystemRandom::new();
        let secret = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|_| hs_err("cannot generate an ephemeral key"))?;
        let pk = secret
            .compute_public_key()
            .map_err(|_| hs_err("cannot compute an ephemeral public key"))?;
        let public: [u8; 32] = pk
            .as_ref()
            .try_into()
            .map_err(|_| hs_err("unexpected X25519 public key length"))?;
        Ok(Self { secret, public })
    }

    pub(crate) fn public(&self) -> [u8; 32] {
        self.public
    }

    /// Agree with the peer's share and derive this side's session keys.
    pub(crate) fn agree(
        self,
        peer_eph: &[u8; 32],
        t: &Transcript,
        role: Role,
    ) -> Result<Session, MeshTailscaleError> {
        let th = digest::digest(&digest::SHA256, &t.bytes());
        let peer = UnparsedPublicKey::new(&X25519, peer_eph);
        // ring rejects shares that yield the all-zero secret (low-order points).
        let (c2s, s2c) = agreement::agree_ephemeral(self.secret, &peer, |ikm| {
            let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, th.as_ref()).extract(ikm);
            let key = |info: &[u8]| {
                prk.expand(&[info], &aead::CHACHA20_POLY1305)
                    .map(aead::UnboundKey::from)
            };
            (key(INFO_C2S), key(INFO_S2C))
        })
        .map_err(|_| hs_err("key agreement failed (invalid ephemeral share)"))?;
        let derive_err = |_| hs_err("session key derivation failed");
        let (c2s, s2c) = (c2s.map_err(derive_err)?, s2c.map_err(derive_err)?);
        Ok(match role {
            Role::Client => Session {
                sealer: Sealer::new(c2s),
                opener: Opener::new(s2c),
            },
            Role::Server => Session {
                sealer: Sealer::new(s2c),
                opener: Opener::new(c2s),
            },
        })
    }
}

fn hs_err(msg: impl Into<String>) -> MeshTailscaleError {
    MeshTailscaleError::Handshake(msg.into())
}

async fn read_exact<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut [u8],
    what: &str,
) -> Result<(), MeshTailscaleError> {
    s.read_exact(buf).await.map(|_| ()).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            hs_err(format!("peer closed the connection while sending {what}"))
        } else {
            hs_err(format!("reading {what}: {e}"))
        }
    })
}

async fn write_all<S: AsyncWrite + Unpin>(
    s: &mut S,
    buf: &[u8],
    what: &str,
) -> Result<(), MeshTailscaleError> {
    s.write_all(buf)
        .await
        .map_err(|e| hs_err(format!("writing {what}: {e}")))?;
    s.flush()
        .await
        .map_err(|e| hs_err(format!("flushing {what}: {e}")))
}

fn fresh_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    n
}

/// Parse a peer's identity key, refusing small-order ("weak") points: under
/// such a key a constant signature verifies for any message, so the
/// resulting `PeerId` would not be bound to any secret.
fn parse_key(bytes: &[u8; 32]) -> Result<VerifyingKey, MeshTailscaleError> {
    let key = VerifyingKey::from_bytes(bytes)
        .map_err(|_| hs_err("peer presented an invalid public key"))?;
    if key.is_weak() {
        return Err(hs_err("peer presented a weak (small-order) public key"));
    }
    Ok(key)
}

/// Strict Ed25519 verification (rejects non-canonical and small-order `R`).
fn verify(key: &VerifyingKey, msg: &[u8], sig: &[u8; 64]) -> bool {
    key.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig))
        .is_ok()
}

fn split64(b: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&b[..64]);
    out
}

fn split32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&b[..32]);
    out
}

fn with_timeout_err(after: Duration) -> MeshTailscaleError {
    hs_err(format!("timed out after {}ms", after.as_millis()))
}

/// Run the client side. Returns the authenticated server identity, whether
/// the server admitted us, and the session keys.
///
/// `expected` pins the server key: a different key aborts *before* the client
/// signs anything.
pub(crate) async fn client_handshake<S>(
    stream: &mut S,
    identity: &IdentityKeyPair,
    expected: Option<&[u8; 32]>,
    timeout: Duration,
) -> Result<(Remote, bool, Session), MeshTailscaleError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, client_inner(stream, identity, expected))
        .await
        .map_err(|_| with_timeout_err(timeout))?
}

async fn client_inner<S>(
    s: &mut S,
    identity: &IdentityKeyPair,
    expected: Option<&[u8; 32]>,
) -> Result<(Remote, bool, Session), MeshTailscaleError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let eph = Ephemeral::generate()?;
    let client_pk = *identity.public().as_bytes();
    let client_nonce = fresh_nonce();
    let client_eph = eph.public();
    let mut hello = Vec::with_capacity(CLIENT_HELLO_LEN);
    hello.extend_from_slice(MAGIC);
    hello.push(VERSION);
    hello.extend_from_slice(&client_pk);
    hello.extend_from_slice(&client_nonce);
    hello.extend_from_slice(&client_eph);
    write_all(s, &hello, "client hello").await?;

    let mut resp = [0u8; SERVER_HELLO_LEN];
    read_exact(s, &mut resp, "server hello").await?;
    let server_pk = split32(&resp[..32]);
    let server_nonce = split32(&resp[32..64]);
    let server_eph = split32(&resp[64..96]);
    let sig_s = split64(&resp[96..]);

    if let Some(exp) = expected {
        if *exp != server_pk {
            return Err(hs_err("server identity is not the peer we dialled"));
        }
    }
    let spk = parse_key(&server_pk)?;
    let t = Transcript {
        client_pk,
        client_nonce,
        client_eph,
        server_pk,
        server_nonce,
        server_eph,
    };
    if !verify(&spk, &t.signed(LABEL_SERVER), &sig_s) {
        return Err(hs_err("server signature does not verify"));
    }
    let mut session = eph.agree(&server_eph, &t, Role::Client)?;

    let sig_c = identity.sign(&t.signed(LABEL_CLIENT));
    write_all(s, sig_c.as_bytes(), "client signature").await?;

    let admission = read_sealed(s, &mut session.opener, 1)
        .await
        .map_err(|e| hs_err(format!("reading the admission answer: {e}")))?;
    let admitted = match admission.as_slice() {
        [ADMIT_OK] => true,
        [ADMIT_DENIED] => false,
        other => return Err(hs_err(format!("invalid admission answer {other:02x?}"))),
    };
    Ok((
        Remote {
            public_key: server_pk,
            peer_id: PeerId::from_public_key_bytes(&server_pk),
        },
        admitted,
        session,
    ))
}

/// Run the server side. `admit` is consulted only after the client has proven
/// possession of its key; when it returns `false` the client is told (one
/// sealed byte) and `PeerNotAllowed` is returned so the caller drops the
/// connection without ever reading a request.
pub(crate) async fn server_handshake<S, F>(
    stream: &mut S,
    identity: &IdentityKeyPair,
    timeout: Duration,
    admit: F,
) -> Result<(Remote, Session), MeshTailscaleError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&PeerId) -> bool,
{
    tokio::time::timeout(timeout, server_inner(stream, identity, admit))
        .await
        .map_err(|_| with_timeout_err(timeout))?
}

async fn server_inner<S, F>(
    s: &mut S,
    identity: &IdentityKeyPair,
    admit: F,
) -> Result<(Remote, Session), MeshTailscaleError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&PeerId) -> bool,
{
    let mut hello = [0u8; CLIENT_HELLO_LEN];
    read_exact(s, &mut hello, "client hello").await?;
    if &hello[..4] != MAGIC {
        return Err(hs_err(
            "bad magic (not an Entanglement mesh.tailscale client)",
        ));
    }
    if hello[4] != VERSION {
        return Err(hs_err(format!(
            "unsupported handshake version {}",
            hello[4]
        )));
    }
    let client_pk = split32(&hello[5..37]);
    let client_nonce = split32(&hello[37..69]);
    let client_eph = split32(&hello[69..101]);
    let cpk = parse_key(&client_pk)?;

    let eph = Ephemeral::generate()?;
    let t = Transcript {
        client_pk,
        client_nonce,
        client_eph,
        server_pk: *identity.public().as_bytes(),
        server_nonce: fresh_nonce(),
        server_eph: eph.public(),
    };
    let sig_s = identity.sign(&t.signed(LABEL_SERVER));
    let mut resp = Vec::with_capacity(SERVER_HELLO_LEN);
    resp.extend_from_slice(&t.server_pk);
    resp.extend_from_slice(&t.server_nonce);
    resp.extend_from_slice(&t.server_eph);
    resp.extend_from_slice(sig_s.as_bytes());
    write_all(s, &resp, "server hello").await?;

    let mut sig = [0u8; 64];
    read_exact(s, &mut sig, "client signature").await?;
    if !verify(&cpk, &t.signed(LABEL_CLIENT), &sig) {
        return Err(hs_err("client signature does not verify"));
    }
    let mut session = eph.agree(&client_eph, &t, Role::Server)?;

    let peer_id = PeerId::from_public_key_bytes(&client_pk);
    if !admit(&peer_id) {
        // Best effort: tell the client why, then the caller drops the socket.
        let _ = write_sealed(s, &mut session.sealer, &[ADMIT_DENIED], 1).await;
        return Err(MeshTailscaleError::PeerNotAllowed(peer_id));
    }
    write_sealed(s, &mut session.sealer, &[ADMIT_OK], 1)
        .await
        .map_err(|e| hs_err(format!("writing the admission answer: {e}")))?;
    Ok((
        Remote {
            public_key: client_pk,
            peer_id,
        },
        session,
    ))
}
