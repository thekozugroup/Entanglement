//! Loopback tests of sub-protocol selection and the sealed stream mode.
//!
//! Attack tests write records by hand with the connection's own session key
//! (`write_sealed` on a [`SealedSend`]'s fields), i.e. what an
//! authenticated-but-hostile peer could send.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use tokio::time::timeout;

use crate::framing::write_sealed;
use crate::*;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const P1: &[u8] = b"entangle/scheduler/1";
const P2: &[u8] = b"entangle/stream/1";

fn cfg(mode: AclMode, allow: Option<Arc<dyn PeerAllowlist>>) -> MeshTailscaleConfig {
    MeshTailscaleConfig {
        acl_mode: mode,
        allowlist: allow,
        port: 0,
        bind_ip: LO,
        address_policy: AddressPolicy::Any,
        handshake_timeout: Duration::from_secs(10),
        request_timeout: Duration::from_secs(5),
        ..MeshTailscaleConfig::default()
    }
}

async fn node(mode: AclMode, allow: Option<Arc<dyn PeerAllowlist>>) -> MeshTailscale {
    MeshTailscale::start(&IdentityKeyPair::generate(), cfg(mode, allow))
        .await
        .unwrap()
}

fn peer_of(t: &MeshTailscale) -> TailscalePeer {
    TailscalePeer::new(t.local_public_key(), t.local_addr())
}

/// Reverses each request and counts them.
struct Echo(AtomicUsize);

#[async_trait::async_trait]
impl RequestHandler for Echo {
    async fn handle(&self, _peer: PeerId, mut payload: Vec<u8>) -> Vec<u8> {
        self.0.fetch_add(1, Ordering::SeqCst);
        payload.reverse();
        payload
    }
}

/// Counts the connections it is handed; holds each until the peer closes.
struct Count(AtomicUsize);

#[async_trait::async_trait]
impl ProtocolHandler for Count {
    async fn serve(&self, mut conn: MeshConn) {
        self.0.fetch_add(1, Ordering::SeqCst);
        while let Ok(Some(req)) = conn.accept_request().await {
            let _ = req.respond(b"counted").await;
        }
    }
}

#[derive(Debug, Default)]
struct LiveAllowlist(std::sync::Mutex<std::collections::HashSet<PeerId>>);

impl PeerAllowlist for LiveAllowlist {
    fn is_allowed(&self, peer: &PeerId) -> bool {
        self.0.lock().unwrap().contains(peer)
    }
}

// ───────────────────────────────────────────────────── protocol selection ──

#[tokio::test]
async fn each_connection_reaches_the_handler_of_the_protocol_it_selects() {
    let b = node(AclMode::TrustTailnet, None).await;
    let echo = Arc::new(Echo(AtomicUsize::new(0)));
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let handlers: Vec<(Vec<u8>, Arc<dyn ProtocolHandler>)> = vec![
        (P1.to_vec(), Arc::new(RequestProtocol(Arc::clone(&echo)))),
        (P2.to_vec(), count.clone()),
    ];
    let b2 = b.clone();
    let srv = tokio::spawn(async move { b2.serve_protocols(handlers).await });
    let a = node(AclMode::TrustTailnet, None).await;

    let mut c1 = a.connect_protocol(&peer_of(&b), P1).await.unwrap();
    assert_eq!(c1.protocol(), Some(P1));
    assert_eq!(c1.request(b"abc").await.unwrap(), b"cba");
    assert_eq!(c1.request(b"xy").await.unwrap(), b"yx");
    let mut c2 = a.connect_protocol(&peer_of(&b), P2).await.unwrap();
    assert_eq!(c2.request(b"abc").await.unwrap(), b"counted");
    assert_eq!(echo.0.load(Ordering::SeqCst), 2);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);

    // A protocol nobody serves: refused during setup, before any request.
    let err = a
        .connect_protocol(&peer_of(&b), b"entangle/agent/1")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0644", "{err}");
    assert!(err.to_string().contains("does not serve"), "{err}");
    assert_eq!(echo.0.load(Ordering::SeqCst), 2);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);

    b.shutdown().await;
    timeout(Duration::from_secs(2), srv).await.unwrap().unwrap();
}

#[tokio::test]
async fn a_peer_without_protocol_selection_is_a_setup_failure() {
    // A legacy server: every frame is a request (the old "no service bound"
    // reply looked like this).
    let b = node(AclMode::TrustTailnet, None).await;
    let b2 = b.clone();
    tokio::spawn(async move { b2.serve(Arc::new(Echo(AtomicUsize::new(0)))).await });
    let a = node(AclMode::TrustTailnet, None).await;
    let err = a.connect_protocol(&peer_of(&b), P1).await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0644", "{err}");
    assert!(err.to_string().contains("not a protocol answer"), "{err}");
}

#[tokio::test]
async fn a_connection_that_selects_nothing_reaches_no_handler() {
    let b = node(AclMode::TrustTailnet, None).await;
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let b2 = b.clone();
    let handlers: Vec<(Vec<u8>, Arc<dyn ProtocolHandler>)> = vec![(P1.to_vec(), count.clone())];
    tokio::spawn(async move { b2.serve_protocols(handlers).await });
    let a = node(AclMode::TrustTailnet, None).await;

    // A protocol-less request where the selection belongs.
    let mut conn = a.connect(&peer_of(&b)).await.unwrap();
    assert!(conn.request(b"entangle/scheduler/1").await.is_err());
    // A selection record that is too long to be one: refused from its header.
    let mut conn = a.connect(&peer_of(&b)).await.unwrap();
    assert!(conn.request(&[0u8; 4096]).await.is_err());
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_peer_revoked_after_the_handshake_cannot_select_a_protocol() {
    let ka = IdentityKeyPair::generate();
    let a = MeshTailscale::start(&ka, cfg(AclMode::TrustTailnet, None))
        .await
        .unwrap();
    let list = Arc::new(LiveAllowlist::default());
    list.0
        .lock()
        .unwrap()
        .insert(PeerId::from_public_key_bytes(ka.public().as_bytes()));
    let as_dyn: Arc<dyn PeerAllowlist> = list.clone();
    let b = node(AclMode::EntangleOnTop, Some(as_dyn)).await;
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let b2 = b.clone();
    let handlers: Vec<(Vec<u8>, Arc<dyn ProtocolHandler>)> = vec![(P1.to_vec(), count.clone())];
    tokio::spawn(async move { b2.serve_protocols(handlers).await });

    let mut conn = a.connect(&peer_of(&b)).await.unwrap();
    list.0.lock().unwrap().clear();
    assert!(conn.select_protocol(P1).await.is_err());
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
}

// ─────────────────────────────────────────────────────────── sealed streams ──

/// A connected stream pair: (client end, server end).
async fn stream_pair(
    server_cfg: MeshTailscaleConfig,
    client: &MeshTailscale,
) -> (SealedStream, SealedStream, MeshTailscale) {
    let b = MeshTailscale::start(&IdentityKeyPair::generate(), server_cfg)
        .await
        .unwrap();
    let target = peer_of(&b);
    let (c, s) = tokio::join!(client.connect(&target), async {
        timeout(Duration::from_secs(20), b.accept())
            .await
            .unwrap()
            .unwrap()
    });
    (
        c.unwrap().into_stream().unwrap(),
        s.into_stream().unwrap(),
        b,
    )
}

#[tokio::test]
async fn frames_of_every_size_cross_both_ways_and_finish_is_a_clean_end() {
    let a = node(AclMode::TrustTailnet, None).await;
    let mut sc = cfg(AclMode::TrustTailnet, None);
    sc.max_frame_bytes = 4 * FRAGMENT_BYTES + 3;
    let (client, server, _b) = stream_pair(sc, &a).await;
    assert_eq!(server.remote_public_key(), a.local_public_key());
    assert_eq!(server.remote_peer_id(), a.local_peer_id());
    let (mut c_send, mut c_recv) = client.split();
    let (mut s_send, mut s_recv) = server.split();

    let sizes = [
        0,
        1,
        FRAGMENT_BYTES - 1,
        FRAGMENT_BYTES,
        FRAGMENT_BYTES + 1,
        3 * FRAGMENT_BYTES + 7,
        4 * FRAGMENT_BYTES + 3,
    ];
    let frame = |n: usize| -> Vec<u8> { (0..n).map(|i| (i % 251) as u8).collect() };
    let writer = tokio::spawn(async move {
        for n in sizes {
            c_send.send(&frame(n)).await.unwrap();
        }
        c_send.finish().await.unwrap();
        c_send
    });
    // The other direction at the same time.
    s_send.send(b"from the server").await.unwrap();
    s_send.finish().await.unwrap();
    for n in sizes {
        let got = s_recv.recv().await.unwrap().expect("a frame");
        assert_eq!(got.len(), n);
        assert_eq!(got, frame(n));
    }
    assert!(
        s_recv.recv().await.unwrap().is_none(),
        "finish ends cleanly"
    );
    assert!(s_recv.recv().await.unwrap().is_none(), "and stays ended");
    assert_eq!(
        c_recv.recv().await.unwrap().as_deref(),
        Some(&b"from the server"[..])
    );
    assert!(c_recv.recv().await.unwrap().is_none());

    let mut c_send = writer.await.unwrap();
    assert!(c_send.send(b"late").await.is_err(), "nothing after finish");
    // Over the cap: refused locally, before a byte is written.
    assert!(matches!(
        s_send.send(&frame(4 * FRAGMENT_BYTES + 4)).await,
        Err(MeshTailscaleError::FrameTooLarge { .. })
    ));
}

#[tokio::test]
async fn an_over_cap_frame_is_refused_from_its_first_record() {
    let a = node(AclMode::TrustTailnet, None).await;
    let (client, server, _b) = stream_pair(cfg(AclMode::TrustTailnet, None), &a).await;
    let (mut c_send, _c_recv) = client.split();
    let (_s_send, mut s_recv) = server.split();

    // In cap for the sender, over the receiver's per-call cap.
    c_send.send(&[7u8; 200]).await.unwrap();
    match s_recv.recv_capped(100).await {
        Err(MeshTailscaleError::FrameTooLarge { declared, max }) => {
            assert_eq!((declared, max), (200, 100));
        }
        other => panic!("expected FrameTooLarge, got {other:?}"),
    }
    assert!(
        s_recv.recv().await.is_err(),
        "the stream is out of step now"
    );

    // A hostile first record declaring 1 GiB and then nothing: refused at
    // once from that record, without waiting for (or allocating) the rest.
    let (client, server, _b) = stream_pair(cfg(AclMode::TrustTailnet, None), &a).await;
    let (mut c_send, _c_recv) = client.split();
    let (_s_send, mut s_recv) = server.split();
    let mut first = vec![0x01];
    first.extend_from_slice(&(1u32 << 30).to_be_bytes());
    first.extend_from_slice(&[0u8; FRAGMENT_BYTES]);
    write_sealed(
        &mut c_send.write,
        &mut c_send.sealer,
        &first,
        5 + FRAGMENT_BYTES,
    )
    .await
    .unwrap();
    match timeout(Duration::from_secs(5), s_recv.recv()).await {
        Ok(Err(MeshTailscaleError::FrameTooLarge { declared, max })) => {
            assert_eq!(declared, 1 << 30);
            assert_eq!(max, MeshTailscaleConfig::default().max_frame_bytes);
        }
        other => panic!("expected an immediate FrameTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn a_per_frame_cap_is_chosen_from_authenticated_leading_bytes() {
    let a = node(AclMode::TrustTailnet, None).await;
    let (client, server, _b) = stream_pair(cfg(AclMode::TrustTailnet, None), &a).await;
    let (mut c_send, _c_recv) = client.split();
    let (_s_send, mut s_recv) = server.split();
    let cap = |p: &[u8]| if p.first() == Some(&b'd') { 10 } else { 100 };
    c_send
        .send(b"control frame, more than ten bytes")
        .await
        .unwrap();
    c_send.send(b"d-ten-ok!!").await.unwrap();
    c_send.send(b"d over the cap, never read").await.unwrap();
    assert_eq!(
        s_recv.recv_capped_by(1024, 1, cap).await.unwrap().unwrap(),
        b"control frame, more than ten bytes"
    );
    assert_eq!(
        s_recv.recv_capped_by(1024, 1, cap).await.unwrap().unwrap(),
        b"d-ten-ok!!"
    );
    match s_recv.recv_capped_by(1024, 1, cap).await {
        Err(MeshTailscaleError::FrameTooLarge { declared, max }) => {
            assert_eq!((declared, max), (26, 10));
        }
        other => panic!("expected FrameTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn closing_without_finish_is_an_error_not_a_clean_end() {
    let a = node(AclMode::TrustTailnet, None).await;
    let (client, server, _b) = stream_pair(cfg(AclMode::TrustTailnet, None), &a).await;
    let (mut c_send, c_recv) = client.split();
    let (_s_send, mut s_recv) = server.split();
    c_send.send(b"one").await.unwrap();
    drop(c_send);
    drop(c_recv);
    assert_eq!(s_recv.recv().await.unwrap().as_deref(), Some(&b"one"[..]));
    let err = s_recv.recv().await.unwrap_err();
    assert!(err.to_string().contains("without finishing"), "{err}");
}

#[tokio::test]
async fn malformed_records_are_protocol_errors() {
    let a = node(AclMode::TrustTailnet, None).await;
    for bad in [
        // Unknown kind.
        vec![0x09, 0, 0, 0, 1, b'x'],
        // A first record shorter than the frame it declares (and not a
        // whole fragment).
        vec![0x01, 0, 0, 0, 9, b'x'],
        // A finish record carrying data.
        vec![0x02, 0, 0, 0, 0, b'x'],
        // Shorter than the header.
        vec![0x01, 0],
    ] {
        let (client, server, _b) = stream_pair(cfg(AclMode::TrustTailnet, None), &a).await;
        let (mut c_send, _c_recv) = client.split();
        let (_s_send, mut s_recv) = server.split();
        write_sealed(&mut c_send.write, &mut c_send.sealer, &bad, 64)
            .await
            .unwrap();
        let err = s_recv.recv().await.unwrap_err();
        assert_eq!(err.code(), "ENTANGLE-E0646", "{bad:?}: {err}");
    }
}

#[tokio::test]
async fn a_revoked_peer_s_stream_stops_at_its_next_frame() {
    let ka = IdentityKeyPair::generate();
    let a = MeshTailscale::start(&ka, cfg(AclMode::TrustTailnet, None))
        .await
        .unwrap();
    let list = Arc::new(LiveAllowlist::default());
    list.0
        .lock()
        .unwrap()
        .insert(PeerId::from_public_key_bytes(ka.public().as_bytes()));
    let as_dyn: Arc<dyn PeerAllowlist> = list.clone();
    let (client, server, _b) = stream_pair(cfg(AclMode::EntangleOnTop, Some(as_dyn)), &a).await;
    let (mut c_send, _c_recv) = client.split();
    let (_s_send, mut s_recv) = server.split();
    c_send.send(b"before").await.unwrap();
    assert_eq!(
        s_recv.recv().await.unwrap().as_deref(),
        Some(&b"before"[..])
    );
    list.0.lock().unwrap().clear();
    c_send.send(b"after").await.unwrap();
    let err = s_recv.recv().await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0648", "{err}");
}

#[tokio::test]
async fn a_stream_keeps_its_connection_slot_until_both_halves_are_gone() {
    let a = node(AclMode::TrustTailnet, None).await;
    let mut sc = cfg(AclMode::TrustTailnet, None);
    sc.max_connections_per_peer = 1;
    let (client, server, b) = stream_pair(sc, &a).await;
    let target = peer_of(&b);
    let err = a.connect(&target).await.unwrap_err();
    assert!(err.to_string().contains("connection limit"), "{err}");
    let (_s_send, s_recv) = server.split();
    drop(client);
    drop(s_recv);
    // One half still holds the slot.
    assert!(a.connect(&target).await.is_err());
    drop(_s_send);
    let mut ok = false;
    for _ in 0..40 {
        if a.connect(&target).await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ok, "the slot is released once the stream is gone");
}
