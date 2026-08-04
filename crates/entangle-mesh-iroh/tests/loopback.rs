//! End-to-end tests for the `mesh.iroh` transport over real QUIC on loopback.
//!
//! Every test here opens two genuine iroh endpoints in one process, bound to
//! `127.0.0.1:0` with relays disabled, and moves real packets between them.
//! Nothing is mocked: if these pass, two Entanglement daemons can talk.
//!
//! Relays are disabled precisely so the suite is hermetic — no DNS, no pkarr,
//! no n0 infrastructure. The one test that would need external infrastructure
//! is `#[ignore]`d and says so.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use entangle_mesh_iroh::{
    parse_node_addr, DynMeshTransport, IrohPeer, MeshConn, MeshIroh, MeshIrohConfig, MeshIrohError,
    MeshTransport, ALPN_CONTROL, ALPN_SCHEDULER,
};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use tokio::sync::mpsc;

/// Ceiling on how long any single test may take. Every await in this file is
/// wrapped in it, so a regression that hangs shows up as a failure with a
/// message rather than as a CI timeout with no explanation.
const TEST_DEADLINE: Duration = Duration::from_secs(30);

async fn deadline<F: std::future::Future>(what: &str, fut: F) -> F::Output {
    match tokio::time::timeout(TEST_DEADLINE, fut).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {TEST_DEADLINE:?}"),
    }
}

fn loopback_config() -> MeshIrohConfig {
    MeshIrohConfig {
        // Short enough that "unreachable" tests finish quickly, long enough
        // that a loopback handshake never trips it.
        connect_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(5),
        ..MeshIrohConfig::loopback()
    }
}

async fn start(identity: &IdentityKeyPair) -> Arc<MeshIroh> {
    Arc::new(
        MeshIroh::start(loopback_config(), identity)
            .await
            .expect("loopback endpoint must bind"),
    )
}

/// The loopback socket a peer is reachable on.
fn loopback_addr(t: &MeshIroh) -> SocketAddr {
    t.local_addrs()
        .into_iter()
        .find(|a| a.ip().is_loopback())
        .expect("a loopback-bound endpoint must report a loopback socket")
}

/// A dialable descriptor for `t`, as a peer would learn it from pairing.
fn peer_of(t: &MeshIroh) -> IrohPeer {
    IrohPeer::new(t.local_public_key(), loopback_addr(t))
}

/// Serve `handler` for every inbound request until the transport shuts down.
fn spawn_echo(transport: Arc<MeshIroh>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(entangle_mesh_iroh::serve(
        transport,
        |_peer, bytes| async move { bytes },
    ))
}

// ---------------------------------------------------------------------------
// 1. A real round-trip.
// ---------------------------------------------------------------------------

/// Two endpoints, one process, real QUIC: A dials B, sends a payload, B echoes
/// it, A gets exactly those bytes back.
#[tokio::test]
async fn payload_round_trips_over_real_quic() {
    let (id_a, id_b) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let a = start(&id_a).await;
    let b = start(&id_b).await;
    let _server = spawn_echo(Arc::clone(&b));

    // Deliberately not a tidy ASCII string: any framing bug that assumed
    // text, or that lost the length prefix, shows up here.
    let payload: Vec<u8> = (0u8..=255).cycle().take(9_999).collect();

    let reply = deadline("request", a.request(&peer_of(&b), &payload))
        .await
        .expect("round trip must succeed");
    assert_eq!(reply, payload, "echo must be byte-identical");

    deadline("shutdown", async {
        a.shutdown().await;
        b.shutdown().await;
    })
    .await;
}

/// An empty payload is a legal frame, not an end-of-stream marker.
#[tokio::test]
async fn empty_payload_round_trips() {
    let (id_a, id_b) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let a = start(&id_a).await;
    let b = start(&id_b).await;
    let _server = spawn_echo(Arc::clone(&b));

    let reply = deadline("request", a.request(&peer_of(&b), b""))
        .await
        .expect("empty round trip must succeed");
    assert!(reply.is_empty());
}

/// One connection, many requests: each round-trip uses its own QUIC stream, so
/// they must not interfere.
#[tokio::test]
async fn one_connection_serves_many_requests() {
    let (id_a, id_b) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let a = start(&id_a).await;
    let b = start(&id_b).await;
    let _server = spawn_echo(Arc::clone(&b));

    let conn: MeshConn = deadline("connect", a.connect(&peer_of(&b)))
        .await
        .expect("connect must succeed");

    for i in 0..8u8 {
        let payload = vec![i; 64];
        let reply = deadline("request", conn.request(&payload))
            .await
            .expect("request must succeed");
        assert_eq!(reply, payload, "request {i} came back wrong");
    }
}

/// The trait is what the dispatcher will hold; exercise the whole flow through
/// a `dyn` handle so an accidental loss of object-safety is caught here too.
#[tokio::test]
async fn works_through_the_boxed_trait_object() {
    let (id_a, id_b) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let a = start(&id_a).await;
    let b = start(&id_b).await;
    let _server = spawn_echo(Arc::clone(&b));

    let peer = peer_of(&b);
    let boxed: DynMeshTransport = a;
    let reply = deadline("request", boxed.request(&peer, b"through the trait"))
        .await
        .expect("round trip must succeed");
    assert_eq!(reply, b"through the trait");
}

// ---------------------------------------------------------------------------
// 2. Identity binding — the trust model rests on this.
// ---------------------------------------------------------------------------

/// B must observe A's `PeerId`, and that `PeerId` must be exactly the one
/// derived from A's Ed25519 public key.
///
/// This is the load-bearing assertion of the whole crate: if iroh's node
/// identity and our `PeerId` could ever disagree, every peer-allowlist and
/// biscuit check downstream would be checking the wrong subject.
#[tokio::test]
async fn observed_peer_id_matches_ed25519_identity() {
    let id_a = IdentityKeyPair::generate();
    let id_b = IdentityKeyPair::generate();
    let a = start(&id_a).await;
    let b = start(&id_b).await;

    // The identity we expect the far side to see, computed only from the
    // signing keypair — no transport involved.
    let expected_key: [u8; 32] = *id_a.public().as_bytes();
    let expected_peer_id = PeerId::from_public_key_bytes(&expected_key);

    // The local endpoint must already agree.
    assert_eq!(
        a.local_public_key(),
        expected_key,
        "iroh EndpointId must be the identity's Ed25519 public key verbatim"
    );
    assert_eq!(a.local_peer_id(), expected_peer_id);

    let (tx, mut rx) = mpsc::channel::<(PeerId, [u8; 32])>(1);
    let server = Arc::clone(&b);
    tokio::spawn(async move {
        let conn = server
            .accept()
            .await
            .expect("accept must not error")
            .expect("a connection must arrive");
        // Observed at the QUIC layer: the peer proved possession of the
        // secret key during the handshake.
        let observed = (conn.remote_peer_id(), conn.remote_public_key());
        let req = conn
            .accept_request()
            .await
            .expect("request must arrive")
            .expect("stream must not be closed");
        assert_eq!(req.peer_id(), observed.0, "request must carry the same id");
        req.respond(b"ok").await.expect("respond must succeed");
        let _ = tx.send(observed).await;
        // Hold the connection open until the requester is done with it;
        // dropping it here would discard the response still in flight.
        conn.closed().await;
    });

    let reply = deadline("request", a.request(&peer_of(&b), b"who am i"))
        .await
        .expect("round trip must succeed");
    assert_eq!(reply, b"ok");

    let (observed_peer_id, observed_key) = deadline("observation", rx.recv())
        .await
        .expect("server must report what it saw");

    assert_eq!(
        observed_key, expected_key,
        "B must observe A's raw Ed25519 public key"
    );
    assert_eq!(
        observed_peer_id, expected_peer_id,
        "B's observed PeerId must equal PeerId::from_public_key_bytes(A's pubkey)"
    );
    assert_eq!(
        observed_peer_id,
        PeerId::from_public_key_bytes(&observed_key),
        "observed id and key must be self-consistent"
    );
}

/// The long address a node advertises must round-trip back into a descriptor
/// that dials that same node. This is the pairing copy-paste path.
#[tokio::test]
async fn advertised_node_addr_round_trips_and_dials() {
    let (id_a, id_b) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let a = start(&id_a).await;
    let b = start(&id_b).await;
    let _server = spawn_echo(Arc::clone(&b));

    let advertised = b
        .node_addrs()
        .into_iter()
        .find(|s| s.contains("127.0.0.1"))
        .expect("a loopback node-addr must be advertised");

    let parsed = parse_node_addr(&advertised).expect("advertised addr must parse");
    assert_eq!(parsed.public_key, b.local_public_key());
    assert_eq!(parsed.peer_id, b.local_peer_id());

    let reply = deadline("request", a.request(&parsed, b"paired"))
        .await
        .expect("dialling the parsed addr must work");
    assert_eq!(reply, b"paired");
}

/// The same seed must always produce the same network identity — otherwise
/// backup/restore (§ disaster recovery) would silently change a node's id.
#[tokio::test]
async fn identity_is_deterministic_in_the_seed() {
    let seed = [0x42u8; 32];
    let first = MeshIroh::start_with_seed(loopback_config(), &seed)
        .await
        .expect("bind");
    let second = MeshIroh::start_with_seed(loopback_config(), &seed)
        .await
        .expect("bind");
    assert_eq!(first.local_public_key(), second.local_public_key());
    assert_eq!(first.local_peer_id(), second.local_peer_id());
    assert_eq!(
        first.local_peer_id(),
        PeerId::from_public_key_bytes(IdentityKeyPair::from_seed(&seed).public().as_bytes()),
        "the seed must yield the same PeerId as entangle-signing computes"
    );
    assert_ne!(
        loopback_addr(&first),
        loopback_addr(&second),
        "two endpoints must still get distinct sockets"
    );
}

// ---------------------------------------------------------------------------
// 3. Oversize frames — untrusted remote input.
// ---------------------------------------------------------------------------

/// A frame whose declared length exceeds the receiver's cap is rejected on the
/// header, before the body is read or allocated.
///
/// The sender here is a *real remote peer* over real QUIC: the client is
/// configured with a larger cap than the server, so it happily emits a frame
/// the server must refuse. That is exactly the hostile-peer shape.
#[tokio::test]
async fn oversize_frame_from_a_peer_is_rejected_on_the_header() {
    const SERVER_CAP: usize = 1024;
    const CLIENT_PAYLOAD: usize = 512 * 1024;

    let (id_a, id_b) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());

    let a = Arc::new(
        MeshIroh::start(
            MeshIrohConfig {
                max_frame_bytes: 4 * 1024 * 1024,
                ..loopback_config()
            },
            &id_a,
        )
        .await
        .expect("bind"),
    );
    let b = Arc::new(
        MeshIroh::start(
            MeshIrohConfig {
                max_frame_bytes: SERVER_CAP,
                ..loopback_config()
            },
            &id_b,
        )
        .await
        .expect("bind"),
    );
    assert_eq!(b.config().max_frame_bytes, SERVER_CAP);

    let (tx, mut rx) = mpsc::channel::<MeshIrohError>(1);
    let server = Arc::clone(&b);
    tokio::spawn(async move {
        let conn = server
            .accept()
            .await
            .expect("accept must not error")
            .expect("a connection must arrive");
        let err = conn
            .accept_request()
            .await
            .expect_err("an oversize frame must not be accepted");
        let _ = tx.send(err).await;
    });

    // The client's own cap is high enough that it sends this happily.
    let _ = deadline(
        "oversize request",
        a.request(&peer_of(&b), &vec![0u8; CLIENT_PAYLOAD]),
    )
    .await;

    let err = deadline("server rejection", rx.recv())
        .await
        .expect("server must report the rejection");
    match err {
        MeshIrohError::FrameTooLarge { declared, max } => {
            assert_eq!(declared, CLIENT_PAYLOAD as u64);
            assert_eq!(max, SERVER_CAP);
        }
        other => panic!("expected FrameTooLarge, got {other}"),
    }
}

/// The symmetric local guard: a payload over our own cap fails before any
/// bytes reach the wire.
#[tokio::test]
async fn oversize_local_payload_is_refused_before_sending() {
    let (id_a, id_b) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let a = Arc::new(
        MeshIroh::start(
            MeshIrohConfig {
                max_frame_bytes: 256,
                ..loopback_config()
            },
            &id_a,
        )
        .await
        .expect("bind"),
    );
    let b = start(&id_b).await;
    let _server = spawn_echo(Arc::clone(&b));

    let err = deadline("oversize request", a.request(&peer_of(&b), &[0u8; 1024]))
        .await
        .expect_err("must be refused");
    match err {
        MeshIrohError::FrameTooLarge { declared, max } => {
            assert_eq!(declared, 1024);
            assert_eq!(max, 256);
        }
        other => panic!("expected FrameTooLarge, got {other}"),
    }
    assert!(err.to_string().contains("ENTANGLE-E0636"));
}

// ---------------------------------------------------------------------------
// 4. Failure modes must be typed errors, not hangs.
// ---------------------------------------------------------------------------

/// Dialling a peer that does not exist fails with a typed error inside the
/// configured deadline. The outer `deadline` is the anti-hang assertion.
#[tokio::test]
async fn unreachable_peer_fails_with_a_typed_error_not_a_hang() {
    let id_a = IdentityKeyPair::generate();
    let a = Arc::new(
        MeshIroh::start(
            MeshIrohConfig {
                connect_timeout: Duration::from_secs(2),
                ..loopback_config()
            },
            &id_a,
        )
        .await
        .expect("bind"),
    );

    // A syntactically valid identity nobody holds, at a port nobody serves.
    let ghost = IdentityKeyPair::generate();
    let peer = IrohPeer::new(
        *ghost.public().as_bytes(),
        "127.0.0.1:1".parse().expect("addr"),
    );

    let err = deadline("connect to nowhere", a.connect(&peer))
        .await
        .expect_err("dialling nowhere must fail");
    match err {
        MeshIrohError::Connect { peer: p, .. } | MeshIrohError::ConnectTimeout { peer: p, .. } => {
            assert_eq!(p, peer.peer_id, "the error must name the peer we dialled");
        }
        other => panic!("expected Connect/ConnectTimeout, got {other}"),
    }
}

/// A peer speaking a different ALPN is refused rather than half-connected.
/// This is what keeps §6.7's protocol multiplexing honest.
#[tokio::test]
async fn alpn_mismatch_is_refused() {
    let (id_a, id_b) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let a = Arc::new(
        MeshIroh::start(
            MeshIrohConfig {
                alpn: ALPN_CONTROL.to_vec(),
                connect_timeout: Duration::from_secs(3),
                ..loopback_config()
            },
            &id_a,
        )
        .await
        .expect("bind"),
    );
    let b = Arc::new(
        MeshIroh::start(
            MeshIrohConfig {
                alpn: ALPN_SCHEDULER.to_vec(),
                ..loopback_config()
            },
            &id_b,
        )
        .await
        .expect("bind"),
    );
    let server = Arc::clone(&b);
    tokio::spawn(async move {
        let _ = server.accept().await;
    });

    let err = deadline("alpn mismatch", a.connect(&peer_of(&b)))
        .await
        .expect_err("mismatched ALPN must not connect");
    assert!(
        matches!(
            err,
            MeshIrohError::Connect { .. } | MeshIrohError::ConnectTimeout { .. }
        ),
        "got {err}"
    );
}

/// After shutdown, the accept loop terminates instead of spinning.
#[tokio::test]
async fn accept_returns_none_after_shutdown() {
    let id = IdentityKeyPair::generate();
    let t = start(&id).await;
    let listener = Arc::clone(&t);
    let handle = tokio::spawn(async move { listener.accept().await });
    deadline("shutdown", t.shutdown()).await;
    let result = deadline("accept", handle)
        .await
        .expect("task must not panic");
    assert!(
        matches!(result, Ok(None)),
        "accept after shutdown must yield Ok(None)"
    );
}

// ---------------------------------------------------------------------------
// 5. Needs infrastructure we cannot exercise offline.
// ---------------------------------------------------------------------------

/// Relay-assisted connectivity (`allow_derp_relay: true`) needs the n0 relay
/// fleet and DNS, so it cannot run in a hermetic test environment: it would
/// depend on the public internet and on third-party uptime. Run manually with
/// `cargo test -p entangle-mesh-iroh -- --ignored` on a networked machine.
#[tokio::test]
#[ignore = "requires public relay infrastructure and outbound internet access"]
async fn relay_assisted_connect_reaches_a_relay() {
    let id = IdentityKeyPair::generate();
    let t = MeshIroh::start(MeshIrohConfig::default(), &id)
        .await
        .expect("bind");
    tokio::time::timeout(Duration::from_secs(30), t.endpoint().online())
        .await
        .expect("endpoint must reach a relay within 30s");
    assert!(!t.local_addrs().is_empty());
}
