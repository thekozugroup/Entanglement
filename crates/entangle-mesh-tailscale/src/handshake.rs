//! Mutual Ed25519 identity handshake, run over plain TCP inside the tailnet.
//!
//! WireGuard authenticates *hosts*; this handshake authenticates the
//! *Entanglement identity* (the Ed25519 key behind a `PeerId`) of the process
//! on the other end, which is what trust decisions are made on.
//!
//! ```text
//! C -> S : "ETSH" ‖ version(1) ‖ client_pk(32) ‖ client_nonce(32)           (69 B)
//! S -> C : server_pk(32) ‖ server_nonce(32) ‖ sig_S(64)                     (128 B)
//! C -> S : sig_C(64)                                                        (64 B)
//! S -> C : admit(1)   0x01 admitted, 0x00 rejected by the server's ACL      (1 B)
//!
//! T      = client_pk ‖ client_nonce ‖ server_pk ‖ server_nonce
//! sig_S  = Sign_S("entangle/ts-hs/v1/server" ‖ T)
//! sig_C  = Sign_C("entangle/ts-hs/v1/client" ‖ T)
//! ```
//!
//! * Distinct role labels: a signature made for one role never verifies for
//!   the other, so a peer cannot be tricked into signing something that is
//!   then replayed back at it (reflection).
//! * Each side's signature covers both fresh nonces, so a recorded handshake
//!   cannot be replayed against a new session.
//! * Every field is fixed-size, so there is nothing to allocate or parse
//!   unboundedly; the whole exchange runs under a timeout.
//!
//! The one addition over the minimal protocol in the design brief is the
//! trailing `admit` byte: without it a client rejected by the server's
//! allowlist could not tell that apart from a network failure. The byte is
//! unauthenticated, but forging it gains an attacker nothing (the server has
//! already closed the connection when it is `0x00`), it can only turn a
//! success into a spurious failure, which an on-path attacker can do anyway
//! by dropping packets.

use std::time::Duration;

use entangle_signing::{IdentityKeyPair, IdentityPublicKey, Signature};
use entangle_types::peer_id::PeerId;
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::MeshTailscaleError;

pub(crate) const MAGIC: &[u8; 4] = b"ETSH";
pub(crate) const VERSION: u8 = 1;
pub(crate) const LABEL_SERVER: &[u8] = b"entangle/ts-hs/v1/server";
pub(crate) const LABEL_CLIENT: &[u8] = b"entangle/ts-hs/v1/client";

/// The authenticated remote identity.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Remote {
    pub public_key: [u8; 32],
    pub peer_id: PeerId,
}

pub(crate) fn transcript(
    label: &[u8],
    client_pk: &[u8; 32],
    client_nonce: &[u8; 32],
    server_pk: &[u8; 32],
    server_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(label.len() + 128);
    t.extend_from_slice(label);
    t.extend_from_slice(client_pk);
    t.extend_from_slice(client_nonce);
    t.extend_from_slice(server_pk);
    t.extend_from_slice(server_nonce);
    t
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

fn parse_key(bytes: &[u8; 32]) -> Result<IdentityPublicKey, MeshTailscaleError> {
    IdentityPublicKey::from_bytes(bytes).map_err(|_| hs_err("peer presented an invalid public key"))
}

fn with_timeout_err(after: Duration) -> MeshTailscaleError {
    hs_err(format!("timed out after {}ms", after.as_millis()))
}

/// Run the client side. Returns the authenticated server identity and whether
/// the server admitted us.
///
/// `expected` pins the server key: a different key aborts *before* the client
/// signs anything.
pub(crate) async fn client_handshake<S>(
    stream: &mut S,
    identity: &IdentityKeyPair,
    expected: Option<&[u8; 32]>,
    timeout: Duration,
) -> Result<(Remote, bool), MeshTailscaleError>
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
) -> Result<(Remote, bool), MeshTailscaleError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client_pk = *identity.public().as_bytes();
    let client_nonce = fresh_nonce();
    let mut hello = Vec::with_capacity(69);
    hello.extend_from_slice(MAGIC);
    hello.push(VERSION);
    hello.extend_from_slice(&client_pk);
    hello.extend_from_slice(&client_nonce);
    write_all(s, &hello, "client hello").await?;

    let mut resp = [0u8; 128];
    read_exact(s, &mut resp, "server hello").await?;
    let mut server_pk = [0u8; 32];
    let mut server_nonce = [0u8; 32];
    server_pk.copy_from_slice(&resp[..32]);
    server_nonce.copy_from_slice(&resp[32..64]);
    let sig_s = Signature::from_bytes(&resp[64..]).map_err(|_| hs_err("malformed signature"))?;

    if let Some(exp) = expected {
        if *exp != server_pk {
            return Err(hs_err("server identity is not the peer we dialled"));
        }
    }
    let spk = parse_key(&server_pk)?;
    let t_server = transcript(
        LABEL_SERVER,
        &client_pk,
        &client_nonce,
        &server_pk,
        &server_nonce,
    );
    spk.verify(&t_server, &sig_s)
        .map_err(|_| hs_err("server signature does not verify"))?;

    let t_client = transcript(
        LABEL_CLIENT,
        &client_pk,
        &client_nonce,
        &server_pk,
        &server_nonce,
    );
    let sig_c = identity.sign(&t_client);
    write_all(s, sig_c.as_bytes(), "client signature").await?;

    let mut admit = [0u8; 1];
    read_exact(s, &mut admit, "admission byte").await?;
    let admitted = match admit[0] {
        1 => true,
        0 => false,
        other => return Err(hs_err(format!("invalid admission byte {other:#x}"))),
    };
    Ok((
        Remote {
            public_key: server_pk,
            peer_id: PeerId::from_public_key_bytes(&server_pk),
        },
        admitted,
    ))
}

/// Run the server side. `admit` is consulted only after the client has proven
/// possession of its key; when it returns `false` the client is told (one
/// byte) and `PeerNotAllowed` is returned so the caller drops the connection
/// without ever reading a request.
pub(crate) async fn server_handshake<S, F>(
    stream: &mut S,
    identity: &IdentityKeyPair,
    timeout: Duration,
    admit: F,
) -> Result<Remote, MeshTailscaleError>
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
) -> Result<Remote, MeshTailscaleError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&PeerId) -> bool,
{
    let mut hello = [0u8; 69];
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
    let mut client_pk = [0u8; 32];
    let mut client_nonce = [0u8; 32];
    client_pk.copy_from_slice(&hello[5..37]);
    client_nonce.copy_from_slice(&hello[37..69]);
    let cpk = parse_key(&client_pk)?;

    let server_pk = *identity.public().as_bytes();
    let server_nonce = fresh_nonce();
    let t_server = transcript(
        LABEL_SERVER,
        &client_pk,
        &client_nonce,
        &server_pk,
        &server_nonce,
    );
    let sig_s = identity.sign(&t_server);
    let mut resp = Vec::with_capacity(128);
    resp.extend_from_slice(&server_pk);
    resp.extend_from_slice(&server_nonce);
    resp.extend_from_slice(sig_s.as_bytes());
    write_all(s, &resp, "server hello").await?;

    let mut sig = [0u8; 64];
    read_exact(s, &mut sig, "client signature").await?;
    let sig_c = Signature::from_bytes(&sig).map_err(|_| hs_err("malformed signature"))?;
    let t_client = transcript(
        LABEL_CLIENT,
        &client_pk,
        &client_nonce,
        &server_pk,
        &server_nonce,
    );
    cpk.verify(&t_client, &sig_c)
        .map_err(|_| hs_err("client signature does not verify"))?;

    let peer_id = PeerId::from_public_key_bytes(&client_pk);
    if !admit(&peer_id) {
        // Best effort: tell the client why, then the caller drops the socket.
        let _ = write_all(s, &[0u8], "admission byte").await;
        return Err(MeshTailscaleError::PeerNotAllowed(peer_id));
    }
    write_all(s, &[1u8], "admission byte").await?;
    Ok(Remote {
        public_key: client_pk,
        peer_id,
    })
}
