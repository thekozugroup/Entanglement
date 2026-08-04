//! Two devices pairing over the real QUIC transport, in one process.
//!
//! Every test here binds two genuine `entangle-mesh-iroh` endpoints on
//! `127.0.0.1:0` with relays disabled and moves real packets between them.
//! Nothing about the pairing exchange is mocked: if these pass, two machines
//! on a LAN can pair by typing a 6-digit code.
//!
//! mDNS is *not* exercised here — multicast is unreliable in sandboxes, and
//! discovery is only how the two ends find each other, not how they
//! authenticate. The one test that needs real multicast is `#[ignore]`d and
//! says so.

use std::sync::Arc;
use std::time::Duration;

use entangle_pairing::mesh::{
    dial_and_pair, loopback_pairing_config, start_pairing_transport_with, IrohPeer,
    PairingListener, PairingMeshError,
};
use entangle_pairing::net::{HostConfig, PairingNetError, RejectReason, SessionEnd};
use entangle_pairing::{PairedPeer, PairingCode};
use entangle_peers::TrustedPeer;
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;

use entangle_mesh_iroh::{MeshIroh, MeshTransport};

/// Ceiling on any single await, so a regression that hangs fails with a
/// message instead of stalling CI.
const DEADLINE: Duration = Duration::from_secs(30);

async fn deadline<F: std::future::Future>(what: &str, fut: F) -> F::Output {
    match tokio::time::timeout(DEADLINE, fut).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {DEADLINE:?}"),
    }
}

async fn transport(identity: &IdentityKeyPair) -> Arc<MeshIroh> {
    start_pairing_transport_with(identity, loopback_pairing_config())
        .await
        .expect("loopback endpoint must bind")
}

/// A listener bound to a fresh loopback endpoint, with no mDNS beacon.
async fn listener(ttl: Duration, max_attempts: u32) -> PairingListener {
    let identity = IdentityKeyPair::generate();
    let transport = transport(&identity).await;
    PairingListener::with_transport(
        transport,
        identity,
        HostConfig {
            display_name: "studio".into(),
            ttl,
            max_attempts,
        },
        false,
    )
    .expect("listener must build")
}

/// The descriptor the other device would have learned from mDNS: the raw
/// public key plus a loopback address.
fn dialable(listener: &PairingListener) -> IrohPeer {
    let addr = listener
        .node_addrs()
        .into_iter()
        .find(|a| a.contains("127.0.0.1"))
        .expect("a loopback listener must advertise a loopback address");
    entangle_pairing::mesh::parse_node_addr(&addr).expect("advertised addr must parse")
}

fn other_code(than: PairingCode) -> PairingCode {
    loop {
        let c = PairingCode::generate();
        if c != than {
            return c;
        }
    }
}

/// Run one dial against a live listener, returning both sides' results.
async fn pair_once(
    listener: &PairingListener,
    dialer_identity: &IdentityKeyPair,
    code: PairingCode,
) -> Result<PairedPeer, PairingMeshError> {
    let peer = dialable(listener);
    let dialer = transport(dialer_identity).await;
    let result = deadline(
        "dial_and_pair",
        dial_and_pair(&dialer, &peer, dialer_identity, "laptop", code),
    )
    .await;
    dialer.shutdown().await;
    result
}

// ---------------------------------------------------------------------------
// 1. The happy path: a correct code pairs both devices.
// ---------------------------------------------------------------------------

/// The whole feature in one test: a device shows a code, another device types
/// it over the wire, and both end up holding the other as a trusted peer with
/// fingerprints that agree.
#[tokio::test]
async fn correct_code_pairs_both_devices_over_quic() {
    let host = listener(Duration::from_secs(30), 5).await;
    let code = host.code();
    let host_peer_id = host.session().local_peer_id();
    let host_fingerprint = host.local_fingerprint();

    let dialer_identity = IdentityKeyPair::generate();
    let dialer_key = *dialer_identity.public().as_bytes();
    let peer = dialable(&host);

    // The listener serves in the background, exactly as `entangle pair
    // --responder` does.
    let waiting = tokio::spawn(async move {
        let outcome = host.wait().await;
        (outcome, host)
    });

    let dialer_transport = transport(&dialer_identity).await;
    let dialer_view = deadline(
        "dial_and_pair",
        dial_and_pair(&dialer_transport, &peer, &dialer_identity, "laptop", code),
    )
    .await
    .expect("the correct code must pair");

    let (host_result, host) = deadline("listener", waiting)
        .await
        .expect("listener task must not panic");
    let host_view = host_result.expect("the listener must report the paired peer");

    // ── Each side recorded the *other* device ────────────────────────────
    assert_eq!(dialer_view.peer_id, host_peer_id);
    assert_eq!(
        host_view.peer_id,
        PeerId::from_public_key_bytes(&dialer_key)
    );
    assert_eq!(dialer_view.display_name, "studio");
    assert_eq!(host_view.display_name, "laptop");

    // ── The fingerprints shown on the two screens match ──────────────────
    assert_eq!(
        dialer_view.fingerprint, host_fingerprint,
        "the dialer must show the host's own fingerprint"
    );
    assert_eq!(
        host_view.fingerprint,
        entangle_pairing::ShortFingerprint::from_public_key(&dialer_key),
        "the host must show the dialer's own fingerprint"
    );
    assert_ne!(dialer_view.fingerprint, host_view.fingerprint);

    // ── Both records survive the validating peer-store constructor ───────
    // This is what `entangle pair` persists; `new_validated` re-derives the
    // peer id from the key, so it fails loudly if either side recorded a
    // key/id pair that does not correspond.
    let stored_by_dialer = TrustedPeer::new_validated(
        dialer_view.peer_id,
        dialer_view.pubkey_hex.clone(),
        dialer_view.display_name.clone(),
    )
    .expect("dialer's record must pass id/key validation");
    let stored_by_host = TrustedPeer::new_validated(
        host_view.peer_id,
        host_view.pubkey_hex.clone(),
        host_view.display_name.clone(),
    )
    .expect("host's record must pass id/key validation");

    // …and each stored key is the key the *other* endpoint authenticated with
    // at the QUIC layer.
    assert_eq!(
        stored_by_dialer.public_key_hex,
        hex::encode(peer.public_key)
    );
    assert_eq!(stored_by_host.public_key_hex, hex::encode(dialer_key));

    assert_eq!(host.session().ended(), Some(SessionEnd::Paired));
    assert_eq!(host.session().attempts(), 0);

    host.shutdown().await;
    dialer_transport.shutdown().await;
}

// ---------------------------------------------------------------------------
// 2. A wrong code is refused.
// ---------------------------------------------------------------------------

/// The out-of-band authenticator has to actually authenticate: a device that
/// guesses the code is refused, and nothing is recorded on either side.
#[tokio::test]
async fn wrong_code_is_refused_over_quic() {
    let host = listener(Duration::from_secs(30), 5).await;
    let wrong = other_code(host.code());

    let dialer_identity = IdentityKeyPair::generate();
    let err = pair_once(&host, &dialer_identity, wrong)
        .await
        .expect_err("a wrong code must not pair");

    match err {
        PairingMeshError::Net(PairingNetError::Rejected(RejectReason::BadCode)) => {}
        other => panic!("expected a BadCode rejection, got {other}"),
    }
    assert!(
        host.session().outcome().is_none(),
        "the host must not record a peer it never authenticated"
    );
    assert_eq!(host.session().attempts(), 1);
    assert_eq!(
        host.session().ended(),
        None,
        "one wrong guess must not destroy the session"
    );
    host.shutdown().await;
}

// ---------------------------------------------------------------------------
// 3. Attempts are capped.
// ---------------------------------------------------------------------------

/// The code space is only 900 000, so an uncapped listener is enumerable.
/// After the cap the session is destroyed — and stays destroyed even for the
/// correct code.
#[tokio::test]
async fn wrong_codes_are_capped_and_burn_the_session() {
    const CAP: u32 = 3;
    let host = listener(Duration::from_secs(30), CAP).await;
    let correct = host.code();
    let wrong = other_code(correct);

    for attempt in 1..CAP {
        let err = pair_once(&host, &IdentityKeyPair::generate(), wrong)
            .await
            .expect_err("wrong code must fail");
        assert!(
            matches!(
                err,
                PairingMeshError::Net(PairingNetError::Rejected(RejectReason::BadCode))
            ),
            "attempt {attempt}: got {err}"
        );
        assert_eq!(host.session().attempts(), attempt);
    }

    // The last permitted guess burns the session.
    let err = pair_once(&host, &IdentityKeyPair::generate(), wrong)
        .await
        .expect_err("the capped attempt must fail");
    assert!(
        matches!(
            err,
            PairingMeshError::Net(PairingNetError::Rejected(RejectReason::TooManyAttempts))
        ),
        "got {err}"
    );
    assert_eq!(host.session().ended(), Some(SessionEnd::AttemptsExhausted));

    // Even the right code cannot revive it.
    let err = pair_once(&host, &IdentityKeyPair::generate(), correct)
        .await
        .expect_err("a burned session must refuse the correct code too");
    assert!(
        matches!(
            err,
            PairingMeshError::Net(PairingNetError::Rejected(RejectReason::TooManyAttempts))
        ),
        "got {err}"
    );
    assert!(host.session().outcome().is_none());
    host.shutdown().await;
}

// ---------------------------------------------------------------------------
// 4. Sessions expire.
// ---------------------------------------------------------------------------

/// Codes are short-lived per spec §6.3. Past the TTL the listener refuses the
/// correct code, so a code left on a screen overnight is worthless.
#[tokio::test]
async fn expired_session_refuses_the_correct_code_over_quic() {
    let host = listener(Duration::from_millis(150), 5).await;
    let correct = host.code();

    tokio::time::sleep(Duration::from_millis(300)).await;

    let err = pair_once(&host, &IdentityKeyPair::generate(), correct)
        .await
        .expect_err("an expired session must refuse even the correct code");
    assert!(
        matches!(
            err,
            PairingMeshError::Net(PairingNetError::Rejected(RejectReason::Expired))
        ),
        "got {err}"
    );
    assert_eq!(host.session().ended(), Some(SessionEnd::Expired));
    assert!(host.session().outcome().is_none());
    host.shutdown().await;
}

/// A listener that nobody pairs with gives up on its own rather than waiting
/// forever, and reports the timeout.
#[tokio::test]
async fn listener_gives_up_when_the_session_expires() {
    let host = listener(Duration::from_millis(200), 5).await;
    let err = deadline("wait", host.wait())
        .await
        .expect_err("an unattended listener must time out");
    assert!(
        matches!(err, PairingMeshError::Timeout(_)),
        "expected a timeout, got {err}"
    );
    host.shutdown().await;
}

// ---------------------------------------------------------------------------
// 5. Codes are single-use.
// ---------------------------------------------------------------------------

/// One code pairs one device. A second dialer with the same (correct) code is
/// refused, so a shoulder-surfer cannot reuse a code they read off the screen.
#[tokio::test]
async fn a_code_pairs_only_one_device() {
    let host = listener(Duration::from_secs(30), 5).await;
    let code = host.code();

    pair_once(&host, &IdentityKeyPair::generate(), code)
        .await
        .expect("the first device pairs");
    let first = host.session().outcome().expect("host recorded the first");

    let err = pair_once(&host, &IdentityKeyPair::generate(), code)
        .await
        .expect_err("the same code must not pair a second device");
    assert!(
        matches!(
            err,
            PairingMeshError::Net(PairingNetError::Rejected(RejectReason::AlreadyPaired))
        ),
        "got {err}"
    );
    assert_eq!(
        host.session().outcome().map(|p| p.peer_id),
        Some(first.peer_id),
        "the recorded peer must not be overwritten"
    );
    host.shutdown().await;
}

// ---------------------------------------------------------------------------
// 6. Dialing the wrong device.
// ---------------------------------------------------------------------------

/// Dialing an endpoint that is not running a pairing listener fails as a
/// typed error rather than hanging or half-pairing.
#[tokio::test]
async fn dialing_a_non_listener_fails_cleanly() {
    let bystander_identity = IdentityKeyPair::generate();
    let bystander = transport(&bystander_identity).await;
    let addr = bystander
        .local_addrs()
        .into_iter()
        .find(|a| a.ip().is_loopback())
        .expect("bound socket");
    let peer = IrohPeer::new(bystander.local_public_key(), addr);

    let dialer_identity = IdentityKeyPair::generate();
    let dialer = transport(&dialer_identity).await;
    let err = deadline(
        "dial",
        dial_and_pair(
            &dialer,
            &peer,
            &dialer_identity,
            "laptop",
            PairingCode::generate(),
        ),
    )
    .await
    .expect_err("a device that is not pairing must not pair");
    // Either the connection is never answered or the frame never comes back;
    // both are typed failures, and neither yields a peer.
    assert!(
        matches!(
            err,
            PairingMeshError::Transport(_) | PairingMeshError::Net(_)
        ),
        "got {err}"
    );

    dialer.shutdown().await;
    bystander.shutdown().await;
}

// ---------------------------------------------------------------------------
// 7. Needs real multicast.
// ---------------------------------------------------------------------------

/// mDNS discovery needs a live multicast-capable interface, which sandboxed CI
/// generally does not have — and when it does, other machines on the LAN can
/// pollute the result. Run manually on a real network with:
/// `cargo test -p entangle-pairing --test loopback_pairing -- --ignored`.
///
/// The pairing exchange itself is covered without multicast by the tests
/// above; this only checks that a beacon is visible and, crucially, that the
/// sighting carries enough to *dial* (a `peer_id` alone cannot be dialled).
#[tokio::test]
#[ignore = "requires real multicast mDNS on a live interface"]
async fn a_pairing_beacon_is_discoverable_and_dialable() {
    let identity = IdentityKeyPair::generate();
    let transport = transport(&identity).await;
    let host_key = transport.local_public_key();
    let host =
        PairingListener::with_transport(transport, identity, HostConfig::new("beacon-host"), true)
            .expect("listener must build");
    assert!(host.is_announcing(), "the beacon must have registered");

    let seeker = PeerId::from_public_key_bytes(&[0x5c; 32]);
    let found = entangle_pairing::mesh::discover_pairing_hosts(seeker, Duration::from_secs(4))
        .await
        .expect("browse must not error");

    let candidate = found
        .iter()
        .find(|c| c.public_key == host_key)
        .expect("the announcing host must be discovered");
    assert_eq!(candidate.display_name, "beacon-host");
    assert_eq!(candidate.fingerprint(), host.local_fingerprint());
    candidate
        .to_peer()
        .expect("a discovered candidate must be dialable");
    host.shutdown().await;
}
