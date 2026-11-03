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

use crate::framing::{read_frame, write_frame, write_sealed};
use crate::handshake::{
    Ephemeral, Role, Transcript, ADMIT_OK, CLIENT_HELLO_LEN, LABEL_CLIENT, LABEL_SERVER, MAGIC,
    SERVER_HELLO_LEN, VERSION,
};
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

fn arr32(b: &[u8]) -> [u8; 32] {
    b[..32].try_into().unwrap()
}

/// Client hello claiming `client_pk`, with a fresh ephemeral share. Returns
/// the transcript as the server built it and the server's signature.
async fn raw_hello(s: &mut TcpStream, client_pk: &[u8; 32]) -> (Transcript, [u8; 64]) {
    let eph = Ephemeral::generate().unwrap();
    let nonce = [7u8; 32];
    let mut hello = Vec::new();
    hello.extend_from_slice(MAGIC);
    hello.push(VERSION);
    hello.extend_from_slice(client_pk);
    hello.extend_from_slice(&nonce);
    hello.extend_from_slice(&eph.public());
    assert_eq!(hello.len(), CLIENT_HELLO_LEN);
    s.write_all(&hello).await.unwrap();
    let mut r = [0u8; SERVER_HELLO_LEN];
    s.read_exact(&mut r).await.unwrap();
    let t = Transcript {
        client_pk: *client_pk,
        client_nonce: nonce,
        client_eph: eph.public(),
        server_pk: arr32(&r[..32]),
        server_nonce: arr32(&r[32..64]),
        server_eph: arr32(&r[64..96]),
    };
    (t, r[96..].try_into().unwrap())
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
    let (t, _) = raw_hello(&mut s, victim.public().as_bytes()).await;
    s.write_all(attacker.sign(&t.signed(LABEL_CLIENT)).as_bytes())
        .await
        .unwrap();
    expect_closed_without_admission(&mut s).await;
    assert_no_conn(&b).await;
}

#[tokio::test]
async fn reflecting_the_server_signature_as_client_signature_is_rejected() {
    let kp = IdentityKeyPair::generate();
    let (b, _) = node(AclMode::TrustTailnet, None).await;
    let mut s = TcpStream::connect(b.local_addr()).await.unwrap();
    let (_, sig_s) = raw_hello(&mut s, kp.public().as_bytes()).await;
    // Replay the server's own signature in the client slot.
    s.write_all(&sig_s).await.unwrap();
    expect_closed_without_admission(&mut s).await;
    assert_no_conn(&b).await;
}

#[tokio::test]
async fn role_labels_differ() {
    assert_ne!(LABEL_SERVER, LABEL_CLIENT);
    let t = Transcript {
        client_pk: [1; 32],
        client_nonce: [2; 32],
        client_eph: [3; 32],
        server_pk: [1; 32],
        server_nonce: [2; 32],
        server_eph: [3; 32],
    };
    assert_ne!(t.signed(LABEL_SERVER), t.signed(LABEL_CLIENT));
}

/// A fake server on loopback that runs the server side by hand as `kp`,
/// signing with `label` and (optionally) over a different client nonce than
/// the one it received; it then swallows the client signature and admits.
async fn fake_server(
    kp: IdentityKeyPair,
    label: &'static [u8],
    signed_client_nonce: Option<[u8; 32]>,
) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut h = [0u8; CLIENT_HELLO_LEN];
        s.read_exact(&mut h).await.unwrap();
        let eph = Ephemeral::generate().unwrap();
        let t = Transcript {
            client_pk: arr32(&h[5..]),
            client_nonce: arr32(&h[37..]),
            client_eph: arr32(&h[69..]),
            server_pk: *kp.public().as_bytes(),
            server_nonce: [9; 32],
            server_eph: eph.public(),
        };
        let signed = Transcript {
            client_nonce: signed_client_nonce.unwrap_or(t.client_nonce),
            ..t
        };
        let sig = kp.sign(&signed.signed(label));
        let reply = [&t.server_pk[..], &t.server_nonce, &t.server_eph, &sig.0].concat();
        s.write_all(&reply).await.unwrap();
        let mut sig_c = [0u8; 64];
        if s.read_exact(&mut sig_c).await.is_err() {
            return;
        }
        let mut session = eph.agree(&t.client_eph, &t, Role::Server).unwrap();
        let _ = write_sealed(&mut s, &mut session.sealer, &[ADMIT_OK], 1).await;
    });
    addr
}

#[tokio::test]
async fn client_rejects_a_server_that_signs_with_the_client_role_label() {
    let skp = IdentityKeyPair::generate();
    let addr = fake_server(skp.clone(), LABEL_CLIENT, None).await;
    let (a, _) = node(AclMode::TrustTailnet, None).await;
    let peer = TailscalePeer::new(*skp.public().as_bytes(), addr);
    let err = a.connect(&peer).await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0644");
}

#[tokio::test]
async fn client_rejects_a_replayed_server_signature_over_a_stale_nonce() {
    let skp = IdentityKeyPair::generate();
    // Signature computed for a different (old) client nonce.
    let addr = fake_server(skp.clone(), LABEL_SERVER, Some([0xEE; 32])).await;
    let (a, _) = node(AclMode::TrustTailnet, None).await;
    let peer = TailscalePeer::new(*skp.public().as_bytes(), addr);
    assert_eq!(a.connect(&peer).await.unwrap_err().code(), "ENTANGLE-E0644");
}

#[tokio::test]
async fn client_accepts_a_well_formed_fake_server_control() {
    // Control for the two tests above: the same fake server with a correct
    // signature is accepted, so the rejections are about the signature.
    let skp = IdentityKeyPair::generate();
    let addr = fake_server(skp.clone(), LABEL_SERVER, None).await;
    let (a, _) = node(AclMode::TrustTailnet, None).await;
    let peer = TailscalePeer::new(*skp.public().as_bytes(), addr);
    let conn = a.connect(&peer).await.unwrap();
    assert_eq!(conn.remote_peer_id(), id_of(&skp));
}

#[tokio::test]
async fn bad_magic_and_version_are_rejected() {
    let (b, _) = node(AclMode::TrustTailnet, None).await;
    // Everything but the magic/version is a well-formed hello (a real key and
    // ephemeral share), so only those two fields can cause the rejection.
    let kp = IdentityKeyPair::generate();
    let eph = Ephemeral::generate().unwrap();
    for (magic, version) in [(*b"HTTP", VERSION), (*MAGIC, VERSION + 1), (*MAGIC, 1)] {
        let mut s = TcpStream::connect(b.local_addr()).await.unwrap();
        let mut hello = Vec::new();
        hello.extend_from_slice(&magic);
        hello.push(version);
        hello.extend_from_slice(kp.public().as_bytes());
        hello.extend_from_slice(&[7u8; 32]);
        hello.extend_from_slice(&eph.public());
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

// ------------------------------------------------------------ relay (MITM) --

type SharedWriter = Arc<tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>>;

/// A tailnet node that relays TCP byte-for-byte to `upstream`: the position a
/// malicious tailnet peer gets by answering discovery for somebody else.
struct Relay {
    addr: SocketAddr,
    /// Every byte the client sent towards the server.
    c2s_seen: Arc<std::sync::Mutex<Vec<u8>>>,
    /// Write half of the most recent upstream (server-side) leg.
    upstream: Arc<std::sync::Mutex<Option<SharedWriter>>>,
}

impl Relay {
    /// `tamper_s2c`: XOR `mask` into the server->client byte at `offset`.
    /// `delay_s2c`: hold the server's first reply bytes this long.
    async fn start(
        upstream: SocketAddr,
        listen: SocketAddr,
        tamper_s2c: Option<(usize, u8)>,
        delay_s2c: Duration,
    ) -> Self {
        let l = TcpListener::bind(listen).await.unwrap();
        let addr = l.local_addr().unwrap();
        let c2s_seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let slot: Arc<std::sync::Mutex<Option<SharedWriter>>> = Arc::default();
        let (seen, slot2) = (Arc::clone(&c2s_seen), Arc::clone(&slot));
        tokio::spawn(async move {
            loop {
                let Ok((client, _)) = l.accept().await else {
                    return;
                };
                let Ok(server) = TcpStream::connect(upstream).await else {
                    continue;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, sw) = server.into_split();
                let sw: SharedWriter = Arc::new(tokio::sync::Mutex::new(sw));
                *slot2.lock().unwrap() = Some(Arc::clone(&sw));
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = cr.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        seen.lock().unwrap().extend_from_slice(&buf[..n]);
                        if sw.lock().await.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut off = 0usize;
                    let mut first = true;
                    while let Ok(n) = sr.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if std::mem::take(&mut first) {
                            tokio::time::sleep(delay_s2c).await;
                        }
                        if let Some((at, mask)) = tamper_s2c {
                            if (off..off + n).contains(&at) {
                                buf[at - off] ^= mask;
                            }
                        }
                        off += n;
                        if cw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Self {
            addr,
            c2s_seen,
            upstream: slot,
        }
    }

    /// Write raw bytes into the server-side leg, as if the client sent them.
    async fn inject_to_server(&self, bytes: &[u8]) {
        let w = self
            .upstream
            .lock()
            .unwrap()
            .clone()
            .expect("a relayed leg");
        w.lock().await.write_all(bytes).await.unwrap();
    }

    fn client_bytes(&self) -> Vec<u8> {
        self.c2s_seen.lock().unwrap().clone()
    }
}

/// Records every payload the server dispatches.
#[derive(Default)]
struct Recorder(std::sync::Mutex<Vec<(PeerId, Vec<u8>)>>);

#[async_trait::async_trait]
impl RequestHandler for Recorder {
    async fn handle(&self, peer: PeerId, payload: Vec<u8>) -> Vec<u8> {
        self.0.lock().unwrap().push((peer, payload.clone()));
        payload
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn a_relaying_tailnet_node_can_neither_read_nor_inject_traffic() {
    // C is allowlisted at S. M relays C's connection to S unchanged, which is
    // the position discovery can hand a malicious tailnet node.
    let kc = IdentityKeyPair::generate();
    let c = MeshTailscale::start(&kc, cfg(AclMode::TrustTailnet, None))
        .await
        .unwrap();
    let (s, _) = node(AclMode::EntangleOnTop, allow(&[id_of(&kc)])).await;
    let rec = Arc::new(Recorder::default());
    let (s2, r2) = (s.clone(), Arc::clone(&rec));
    tokio::spawn(async move { s2.serve(r2).await });
    let m = Relay::start(
        s.local_addr(),
        "127.0.0.1:0".parse().unwrap(),
        None,
        Duration::ZERO,
    )
    .await;

    let via_m = TailscalePeer::new(s.local_public_key(), m.addr);
    let mut conn = c.connect(&via_m).await.unwrap();
    assert_eq!(
        conn.request(b"secret-biscuit").await.unwrap(),
        b"secret-biscuit"
    );
    assert!(
        !contains(&m.client_bytes(), b"secret-biscuit"),
        "the relay must not see request plaintext"
    );

    // M now forges a request "from C" on the server leg.
    let forged = b"INJECTED-BY-M";
    let mut frame = (forged.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(forged);
    m.inject_to_server(&frame).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let seen = rec.0.lock().unwrap().clone();
    assert!(
        seen.iter().all(|(_, p)| p.as_slice() != forged),
        "a frame forged by the relay was dispatched as if C sent it: {seen:?}"
    );
}

/// First ciphertext byte of the sealed admission record in the
/// server->client stream (after the server hello and the record header).
/// ChaCha20 is a stream cipher, so XOR-ing 0x01 here flips the admission
/// plaintext from "denied" (0) to "admitted" (1); only the tag stops it.
const ADMIT_AT: usize = SERVER_HELLO_LEN + 4;

#[tokio::test]
async fn a_relay_cannot_turn_a_rejection_into_an_admission() {
    // C is NOT allowlisted at S; M flips the admission reply in transit.
    let (c, _) = node(AclMode::TrustTailnet, None).await;
    let other = IdentityKeyPair::generate();
    let (s, _) = node(AclMode::EntangleOnTop, allow(&[id_of(&other)])).await;
    let m = Relay::start(
        s.local_addr(),
        "127.0.0.1:0".parse().unwrap(),
        Some((ADMIT_AT, 0x01)),
        Duration::ZERO,
    )
    .await;
    let via_m = TailscalePeer::new(s.local_public_key(), m.addr);
    let r = c.connect(&via_m).await;
    assert!(
        r.is_err(),
        "a tampered rejection must not read as admission"
    );
}

#[tokio::test]
async fn discovery_does_not_let_a_relay_take_over_a_peer() {
    // S listens on 127.0.0.1:P; M relays 127.0.0.2:P -> S and answers last.
    let mut long = cfg(AclMode::TrustTailnet, None);
    long.handshake_timeout = Duration::from_secs(3);
    let a = MeshTailscale::start(&IdentityKeyPair::generate(), long)
        .await
        .unwrap();
    let (s, ks) = node(AclMode::TrustTailnet, None).await;
    let port = s.local_addr().port();
    let m_ip: IpAddr = "127.0.0.2".parse().unwrap();
    let m = Relay::start(
        s.local_addr(),
        SocketAddr::new(m_ip, port),
        None,
        Duration::from_millis(200),
    )
    .await;
    assert_eq!(m.addr.port(), port);
    let json = r#"{"BackendState":"Running","Self":{"Online":true},
      "Peer":{
        "s":{"Online":true,"DNSName":"s.tail.ts.net.","TailscaleIPs":["127.0.0.1"]},
        "m":{"Online":true,"DNSName":"m.tail.ts.net.","TailscaleIPs":["127.0.0.2"]}
      }}"#;
    let st = TailscaleStatus::parse(json).unwrap();
    let found = a.discover_on_port(&st, port).await;
    assert!(
        !found
            .iter()
            .any(|p| p.peer_id == id_of(&ks) && p.addr.ip() == m_ip),
        "the relay's address must not become S's candidate: {found:?}"
    );
    // Neither address can be preferred on evidence, so S is left out of
    // this round altogether (and a warning is logged).
    assert!(found.is_empty(), "{found:?}");
    assert!(a.candidates().is_empty());
}

// ------------------------------------------------------- small-order keys --

/// The Ed25519 identity point: a valid encoding of a small-order key.
const WEAK_PK: [u8; 32] = {
    let mut k = [0u8; 32];
    k[0] = 1;
    k
};

/// R = identity, s = 0. Under cofactorless, non-strict verification this
/// "verifies" for *any* message under `WEAK_PK`, without any secret.
const WEAK_SIG: [u8; 64] = {
    let mut s = [0u8; 64];
    s[0] = 1;
    s
};

#[tokio::test]
async fn a_small_order_client_key_cannot_authenticate() {
    let (b, _) = node(AclMode::TrustTailnet, None).await;
    let mut s = TcpStream::connect(b.local_addr()).await.unwrap();
    let eph = Ephemeral::generate().unwrap();
    let hello = [&MAGIC[..], &[VERSION], &WEAK_PK, &[7u8; 32], &eph.public()].concat();
    s.write_all(&hello).await.unwrap();
    // The server may refuse at once; if it answers, the forged signature
    // must still not get the weak identity admitted.
    let mut r = [0u8; SERVER_HELLO_LEN];
    if s.read_exact(&mut r).await.is_ok() {
        let _ = s.write_all(&WEAK_SIG).await;
    }
    expect_closed_without_admission(&mut s).await;
    assert_no_conn(&b).await;
}

#[tokio::test]
async fn a_small_order_server_key_cannot_authenticate() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut h = [0u8; CLIENT_HELLO_LEN];
        s.read_exact(&mut h).await.unwrap();
        let eph = Ephemeral::generate().unwrap();
        let t = Transcript {
            client_pk: arr32(&h[5..]),
            client_nonce: arr32(&h[37..]),
            client_eph: arr32(&h[69..]),
            server_pk: WEAK_PK,
            server_nonce: [9; 32],
            server_eph: eph.public(),
        };
        let reply = [&t.server_pk[..], &t.server_nonce, &t.server_eph, &WEAK_SIG].concat();
        s.write_all(&reply).await.unwrap();
        let mut sig_c = [0u8; 64];
        if s.read_exact(&mut sig_c).await.is_err() {
            return;
        }
        let mut session = eph.agree(&t.client_eph, &t, Role::Server).unwrap();
        let _ = write_sealed(&mut s, &mut session.sealer, &[ADMIT_OK], 1).await;
    });
    let (a, _) = node(AclMode::TrustTailnet, None).await;
    let err = a.probe(addr).await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0644");
    assert!(err.to_string().contains("weak"), "{err}");
}
