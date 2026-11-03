//! Loopback tests of the handshake, ACL modes, framing and discovery.
//!
//! Attack tests speak the wire protocol by hand (`raw_*` helpers) so they can
//! send things an honest client never would.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::framing::{read_frame, write_frame};
use crate::handshake::{transcript, LABEL_CLIENT, LABEL_SERVER, MAGIC, VERSION};
use crate::*;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn cfg(mode: AclMode, allow: Option<Arc<dyn PeerAllowlist>>) -> MeshTailscaleConfig {
    MeshTailscaleConfig {
        acl_mode: mode,
        allowlist: allow,
        port: 0,
        bind_ip: LO,
        handshake_timeout: Duration::from_millis(400),
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(5),
        ..MeshTailscaleConfig::default()
    }
}

fn id_of(kp: &IdentityKeyPair) -> PeerId {
    PeerId::from_public_key_bytes(kp.public().as_bytes())
}

async fn node(
    mode: AclMode,
    allow: Option<Arc<dyn PeerAllowlist>>,
) -> (MeshTailscale, IdentityKeyPair) {
    let kp = IdentityKeyPair::generate();
    let t = MeshTailscale::start(&kp, cfg(mode, allow)).await.unwrap();
    (t, kp)
}

fn peer_of(t: &MeshTailscale) -> TailscalePeer {
    TailscalePeer::new(t.local_public_key(), t.local_addr())
}

fn allow(ids: &[PeerId]) -> Option<Arc<dyn PeerAllowlist>> {
    Some(Arc::new(StaticAllowlist::new(ids.iter().copied())))
}

/// Client hello; returns (client_nonce, server_pk, server_nonce, sig_s).
async fn raw_hello(
    s: &mut TcpStream,
    client_pk: &[u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 64]) {
    let nonce = [7u8; 32];
    let mut hello = Vec::new();
    hello.extend_from_slice(MAGIC);
    hello.push(VERSION);
    hello.extend_from_slice(client_pk);
    hello.extend_from_slice(&nonce);
    s.write_all(&hello).await.unwrap();
    let mut r = [0u8; 128];
    s.read_exact(&mut r).await.unwrap();
    let mut spk = [0u8; 32];
    let mut sn = [0u8; 32];
    let mut sig = [0u8; 64];
    spk.copy_from_slice(&r[..32]);
    sn.copy_from_slice(&r[32..64]);
    sig.copy_from_slice(&r[64..]);
    (nonce, spk, sn, sig)
}

/// After a failed handshake the server must close without admitting.
async fn expect_closed_without_admission(s: &mut TcpStream) {
    let mut buf = [0u8; 1];
    let n = timeout(Duration::from_secs(2), s.read(&mut buf)).await;
    match n {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("server should close without an admit byte, got {other:?}"),
    }
}

async fn assert_no_conn(t: &MeshTailscale) {
    assert!(
        timeout(Duration::from_millis(300), t.accept())
            .await
            .is_err(),
        "no connection may reach accept()"
    );
}

struct Echo(AtomicUsize);

#[async_trait::async_trait]
impl RequestHandler for Echo {
    async fn handle(&self, _peer: PeerId, mut payload: Vec<u8>) -> Vec<u8> {
        self.0.fetch_add(1, Ordering::SeqCst);
        payload.reverse();
        payload
    }
}

#[tokio::test]
async fn handshake_succeeds_both_directions_with_correct_peer_ids() {
    let (a, ka) = node(AclMode::TrustTailnet, None).await;
    let (b, kb) = node(AclMode::TrustTailnet, None).await;

    let target = peer_of(&b);
    let (client, server) = tokio::join!(a.connect(&target), b.accept());
    let client = client.unwrap();
    let server = server.unwrap();
    assert_eq!(client.remote_peer_id(), id_of(&kb));
    assert_eq!(client.remote_public_key(), *kb.public().as_bytes());
    assert_eq!(server.remote_peer_id(), id_of(&ka));
    assert_eq!(server.remote_public_key(), *ka.public().as_bytes());
}

#[tokio::test]
async fn request_response_round_trip_via_serve() {
    let (a, _) = node(AclMode::TrustTailnet, None).await;
    let (b, _) = node(AclMode::TrustTailnet, None).await;
    let handler = Arc::new(Echo(AtomicUsize::new(0)));
    let b2 = b.clone();
    let h2 = Arc::clone(&handler);
    let srv = tokio::spawn(async move { b2.serve(h2).await });

    let resp = a.request(&peer_of(&b), b"hello").await.unwrap();
    assert_eq!(resp, b"olleh");
    // Several requests on one connection.
    let mut conn = a.connect(&peer_of(&b)).await.unwrap();
    assert_eq!(conn.request(b"ab").await.unwrap(), b"ba");
    assert_eq!(conn.request(b"").await.unwrap(), b"");
    assert_eq!(handler.0.load(Ordering::SeqCst), 3);

    b.shutdown().await;
    timeout(Duration::from_secs(2), srv).await.unwrap().unwrap();
    assert!(b.accept().await.is_none());
}

#[tokio::test]
async fn dialling_with_the_wrong_pinned_key_is_rejected() {
    let (a, _) = node(AclMode::TrustTailnet, None).await;
    let (b, _) = node(AclMode::TrustTailnet, None).await;
    let impostor_key = *IdentityKeyPair::generate().public().as_bytes();
    let wrong = TailscalePeer::new(impostor_key, b.local_addr());
    let err = a.connect(&wrong).await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0644");
    assert_no_conn(&b).await;
}

#[tokio::test]
async fn wrong_client_signature_is_rejected() {
    let (b, _) = node(AclMode::TrustTailnet, None).await;
    let kp = IdentityKeyPair::generate();
    let mut s = TcpStream::connect(b.local_addr()).await.unwrap();
    raw_hello(&mut s, kp.public().as_bytes()).await;
    s.write_all(&[0xAB; 64]).await.unwrap();
    expect_closed_without_admission(&mut s).await;
    assert_no_conn(&b).await;
}

#[tokio::test]
async fn claiming_anothers_pubkey_without_its_key_is_rejected() {
    let victim = IdentityKeyPair::generate();
    let attacker = IdentityKeyPair::generate();
    // Even though the victim is allowlisted, the claim cannot be proven.
    let (b, _) = node(AclMode::EntangleOnTop, allow(&[id_of(&victim)])).await;

    let mut s = TcpStream::connect(b.local_addr()).await.unwrap();
    let (cn, spk, sn, _) = raw_hello(&mut s, victim.public().as_bytes()).await;
    let t = transcript(LABEL_CLIENT, victim.public().as_bytes(), &cn, &spk, &sn);
    s.write_all(attacker.sign(&t).as_bytes()).await.unwrap();
    expect_closed_without_admission(&mut s).await;
    assert_no_conn(&b).await;
}

#[tokio::test]
async fn reflecting_the_server_signature_as_client_signature_is_rejected() {
    let kp = IdentityKeyPair::generate();
    let (b, _) = node(AclMode::TrustTailnet, None).await;
    let mut s = TcpStream::connect(b.local_addr()).await.unwrap();
    let (_, _, _, sig_s) = raw_hello(&mut s, kp.public().as_bytes()).await;
    // Replay the server's own signature in the client slot.
    s.write_all(&sig_s).await.unwrap();
    expect_closed_without_admission(&mut s).await;
    assert_no_conn(&b).await;
}

#[tokio::test]
async fn role_labels_differ() {
    assert_ne!(LABEL_SERVER, LABEL_CLIENT);
    let k = [1u8; 32];
    let n = [2u8; 32];
    assert_ne!(
        transcript(LABEL_SERVER, &k, &n, &k, &n),
        transcript(LABEL_CLIENT, &k, &n, &k, &n)
    );
}

/// A fake server on loopback whose reply is produced by `f(client_pk,
/// client_nonce)`; it then swallows the client signature and sends admit.
async fn fake_server<F>(f: F) -> SocketAddr
where
    F: FnOnce([u8; 32], [u8; 32]) -> Vec<u8> + Send + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut h = [0u8; 69];
        s.read_exact(&mut h).await.unwrap();
        let mut cpk = [0u8; 32];
        let mut cn = [0u8; 32];
        cpk.copy_from_slice(&h[5..37]);
        cn.copy_from_slice(&h[37..]);
        s.write_all(&f(cpk, cn)).await.unwrap();
        let mut sig = [0u8; 64];
        let _ = s.read_exact(&mut sig).await;
        let _ = s.write_all(&[1]).await;
    });
    addr
}

fn server_reply(
    kp: &IdentityKeyPair,
    label: &[u8],
    cpk: [u8; 32],
    cn: [u8; 32],
    sn: [u8; 32],
) -> Vec<u8> {
    let spk = *kp.public().as_bytes();
    let sig = kp.sign(&transcript(label, &cpk, &cn, &spk, &sn));
    [&spk[..], &sn[..], &sig.0[..]].concat()
}

#[tokio::test]
async fn client_rejects_a_server_that_signs_with_the_client_role_label() {
    let skp = IdentityKeyPair::generate();
    let addr = fake_server({
        let skp = skp.clone();
        move |cpk, cn| server_reply(&skp, LABEL_CLIENT, cpk, cn, [9; 32])
    })
    .await;
    let (a, _) = node(AclMode::TrustTailnet, None).await;
    let peer = TailscalePeer::new(*skp.public().as_bytes(), addr);
    let err = a.connect(&peer).await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0644");
}

#[tokio::test]
async fn client_rejects_a_replayed_server_signature_over_a_stale_nonce() {
    let skp = IdentityKeyPair::generate();
    let addr = fake_server({
        let skp = skp.clone();
        // Signature computed for a different (old) client nonce.
        move |cpk, _cn| server_reply(&skp, LABEL_SERVER, cpk, [0xEE; 32], [9; 32])
    })
    .await;
    let (a, _) = node(AclMode::TrustTailnet, None).await;
    let peer = TailscalePeer::new(*skp.public().as_bytes(), addr);
    assert_eq!(a.connect(&peer).await.unwrap_err().code(), "ENTANGLE-E0644");
}

#[tokio::test]
async fn client_accepts_a_well_formed_fake_server_control() {
    // Control for the two tests above: the same fake server with a correct
    // signature is accepted, so the rejections are about the signature.
    let skp = IdentityKeyPair::generate();
    let addr = fake_server({
        let skp = skp.clone();
        move |cpk, cn| server_reply(&skp, LABEL_SERVER, cpk, cn, [9; 32])
    })
    .await;
    let (a, _) = node(AclMode::TrustTailnet, None).await;
    let peer = TailscalePeer::new(*skp.public().as_bytes(), addr);
    let conn = a.connect(&peer).await.unwrap();
    assert_eq!(conn.remote_peer_id(), id_of(&skp));
}

#[tokio::test]
async fn bad_magic_and_version_are_rejected() {
    let (b, _) = node(AclMode::TrustTailnet, None).await;
    for (magic, version) in [(*b"HTTP", VERSION), (*MAGIC, VERSION + 1)] {
        let mut s = TcpStream::connect(b.local_addr()).await.unwrap();
        let mut hello = Vec::new();
        hello.extend_from_slice(&magic);
        hello.push(version);
        hello.extend_from_slice(&[0u8; 64]);
        s.write_all(&hello).await.unwrap();
        expect_closed_without_admission(&mut s).await;
    }
    assert_no_conn(&b).await;
}

#[tokio::test]
async fn silent_peer_times_out_server_side() {
    let (b, _) = node(AclMode::TrustTailnet, None).await;
    let mut s = TcpStream::connect(b.local_addr()).await.unwrap();
    // Send nothing; the 400 ms handshake timeout must close the socket.
    let mut buf = [0u8; 1];
    let r = timeout(Duration::from_secs(3), s.read(&mut buf)).await;
    assert!(
        matches!(r, Ok(Ok(0)) | Ok(Err(_))),
        "server should hang up: {r:?}"
    );
    assert_no_conn(&b).await;
}

#[tokio::test]
async fn silent_server_times_out_client_side() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let _hold = tokio::spawn(async move {
        let (_s, _) = l.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    });
    let (a, _) = node(AclMode::TrustTailnet, None).await;
    let peer = TailscalePeer::new([5; 32], addr);
    let started = std::time::Instant::now();
    let err = a.connect(&peer).await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0644");
    assert!(err.to_string().contains("timed out"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn oversize_request_is_rejected_by_the_server() {
    let kb = IdentityKeyPair::generate();
    let mut sc = cfg(AclMode::TrustTailnet, None);
    sc.max_frame_bytes = 1024;
    let b = MeshTailscale::start(&kb, sc).await.unwrap();
    let (a, _) = node(AclMode::TrustTailnet, None).await;

    let mut conn = a.connect(&peer_of(&b)).await.unwrap();
    // Our own cap is 16 MiB, so the client happily sends 2000 bytes.
    let client = tokio::spawn(async move { conn.request(&[1u8; 2000]).await });
    let mut server_conn = b.accept().await.unwrap();
    let err = server_conn.accept_request().await.unwrap_err();
    assert!(
        matches!(
            err,
            MeshTailscaleError::FrameTooLarge {
                declared: 2000,
                max: 1024
            }
        ),
        "{err}"
    );
    drop(server_conn);
    assert!(client.await.unwrap().is_err());
}

#[tokio::test]
async fn oversize_header_is_rejected_before_any_body_is_read() {
    // Header declares u32::MAX; no body ever follows. If the reader tried to
    // read (or allocate) the body it would block / fail differently, so an
    // immediate FrameTooLarge proves the check precedes allocation.
    let (mut tx, mut rx) = tokio::io::duplex(64);
    tx.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    let err = timeout(Duration::from_secs(1), read_frame(&mut rx, 1024))
        .await
        .expect("must not wait for a body")
        .unwrap_err();
    assert!(matches!(
        err,
        MeshTailscaleError::FrameTooLarge { declared, max: 1024 } if declared == u64::from(u32::MAX)
    ));
    // Writing an oversize local payload fails without touching the stream.
    let mut sink = Vec::new();
    let err = write_frame(&mut sink, &[0; 10], 5).await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0645");
    assert!(sink.is_empty());
}

#[tokio::test]
async fn truncated_frame_is_a_protocol_error() {
    let (mut tx, mut rx) = tokio::io::duplex(64);
    tx.write_all(&10u32.to_be_bytes()).await.unwrap();
    tx.write_all(b"abc").await.unwrap();
    drop(tx);
    let err = read_frame(&mut rx, 1024).await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0646");
}

#[tokio::test]
async fn entangle_on_top_rejects_unlisted_peer_before_any_request() {
    let (a, ka) = node(AclMode::TrustTailnet, None).await;
    let other = IdentityKeyPair::generate();
    let (b, _) = node(AclMode::EntangleOnTop, allow(&[id_of(&other)])).await;
    let handler = Arc::new(Echo(AtomicUsize::new(0)));
    let b2 = b.clone();
    let h2 = Arc::clone(&handler);
    tokio::spawn(async move { b2.serve(h2).await });

    let err = a.request(&peer_of(&b), b"let me in").await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0644");
    assert!(err.to_string().contains("allowlist"), "{err}");
    assert_eq!(
        handler.0.load(Ordering::SeqCst),
        0,
        "handler must never run"
    );
    let _ = ka;
}

#[tokio::test]
async fn entangle_on_top_without_allowlist_fails_closed() {
    let (a, _) = node(AclMode::TrustTailnet, None).await;
    let (b, _) = node(AclMode::EntangleOnTop, None).await;
    assert!(a.connect(&peer_of(&b)).await.is_err());
    assert_no_conn(&b).await;
}

#[tokio::test]
async fn entangle_on_top_accepts_listed_peer() {
    let ka = IdentityKeyPair::generate();
    let a = MeshTailscale::start(&ka, cfg(AclMode::TrustTailnet, None))
        .await
        .unwrap();
    let (b, _) = node(AclMode::EntangleOnTop, allow(&[id_of(&ka)])).await;
    let b2 = b.clone();
    tokio::spawn(async move { b2.serve(Arc::new(Echo(AtomicUsize::new(0)))).await });
    assert_eq!(a.request(&peer_of(&b), b"xyz").await.unwrap(), b"zyx");
}

#[tokio::test]
async fn trust_tailnet_accepts_unlisted_but_authenticated_peer() {
    let (a, ka) = node(AclMode::TrustTailnet, None).await;
    // Allowlist exists and does not contain A; TrustTailnet ignores it.
    let (b, _) = node(AclMode::TrustTailnet, allow(&[])).await;
    let target = peer_of(&b);
    let (conn, server) = tokio::join!(a.connect(&target), b.accept());
    conn.unwrap();
    assert_eq!(server.unwrap().remote_peer_id(), id_of(&ka));
}

#[tokio::test]
async fn trust_tailnet_still_rejects_bad_identity_proof() {
    let (b, _) = node(AclMode::TrustTailnet, None).await;
    let kp = IdentityKeyPair::generate();
    let mut s = TcpStream::connect(b.local_addr()).await.unwrap();
    raw_hello(&mut s, kp.public().as_bytes()).await;
    s.write_all(&[0u8; 64]).await.unwrap();
    expect_closed_without_admission(&mut s).await;
    assert_no_conn(&b).await;
}

#[tokio::test]
async fn discovery_probes_online_peers_and_records_candidates() {
    let (a, _) = node(AclMode::TrustTailnet, None).await;
    let (b, kb) = node(AclMode::EntangleOnTop, None).await; // rejects us, still answers
    let port = b.local_addr().port();
    let json = r#"{"BackendState":"Running","Self":{"Online":true,"TailscaleIPs":["100.64.0.1"]},
      "Peer":{
        "k1":{"Online":true,"DNSName":"bob.tail.ts.net.","TailscaleIPs":["127.0.0.1"]},
        "k2":{"Online":false,"DNSName":"off.tail.ts.net.","TailscaleIPs":["127.0.0.1"]},
        "k3":{"Online":true,"DNSName":"nothing-listens.tail.ts.net.","TailscaleIPs":["127.0.0.2"]}
      }}"#;
    let st = TailscaleStatus::parse(json).unwrap();
    let found = a.discover_on_port(&st, port).await;
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].peer_id, id_of(&kb));
    assert_eq!(found[0].public_key, *kb.public().as_bytes());
    assert_eq!(found[0].magic_dns, "bob.tail.ts.net");
    assert_eq!(found[0].addr, SocketAddr::new(LO, port));
    assert_eq!(a.candidates(), found);
}

#[tokio::test]
async fn probe_does_not_disclose_the_real_identity() {
    // The probing side presents a throw-away key: in TrustTailnet the target
    // sees an authenticated peer that is not us.
    let (a, ka) = node(AclMode::TrustTailnet, None).await;
    let (b, _) = node(AclMode::TrustTailnet, None).await;
    let (probe, server) = tokio::join!(a.probe(b.local_addr()), b.accept());
    probe.unwrap();
    assert_ne!(server.unwrap().remote_peer_id(), id_of(&ka));
}
