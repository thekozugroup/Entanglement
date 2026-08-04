//! The daemon's cross-node scheduler wiring.
//!
//! `entangle-scheduler`'s own suite proves the protocol; this file proves the
//! *daemon's* half of it: that the thing gating remote execution really is the
//! persisted `PeerStore`, over a real QUIC endpoint, and that a daemon which
//! has not been configured for it serves nothing at all.

use std::sync::Arc;
use std::time::Duration;

use entangle_bin::config::{Config, SchedulerConfig};
use entangle_bin::remote::{
    directory_from_config, scheduler_transport_enabled, spawn_task_server,
    start_scheduler_transport, PeerStoreAllowlist,
};
use entangle_mesh_iroh::{
    IrohPeer, MeshIroh, MeshIrohConfig, MeshTransport, ALPN_CONTROL, ALPN_SCHEDULER,
};
use entangle_peers::{PeerStore, TrustLevel, TrustedPeer};
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::wire::{decode_response, encode_request, RemoteTaskRequest};
use entangle_scheduler::{PeerAllowlist, RemoteErrorCode, RemoteOutcome};
use entangle_signing::{IdentityKeyPair, Keyring};
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::task::OneShotTask;

const DEADLINE: Duration = Duration::from_secs(30);

async fn deadline<F: std::future::Future>(what: &str, fut: F) -> F::Output {
    match tokio::time::timeout(DEADLINE, fut).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {DEADLINE:?}"),
    }
}

fn loopback_scheduler_config() -> MeshIrohConfig {
    MeshIrohConfig {
        alpn: ALPN_SCHEDULER.to_vec(),
        connect_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(10),
        ..MeshIrohConfig::loopback()
    }
}

async fn start_node(cfg: MeshIrohConfig, identity: &IdentityKeyPair) -> Arc<MeshIroh> {
    Arc::new(MeshIroh::start(cfg, identity).await.expect("bind"))
}

fn address_of(t: &MeshIroh) -> IrohPeer {
    let addr = t
        .local_addrs()
        .into_iter()
        .find(|a| a.ip().is_loopback())
        .expect("loopback socket");
    IrohPeer::new(t.local_public_key(), addr)
}

fn empty_kernel() -> Arc<Kernel> {
    Arc::new(Kernel::new(KernelConfig::default(), Keyring::new()).expect("kernel"))
}

fn demo_plugin() -> PluginId {
    "0123456789abcdef0123456789abcdef/demo@1.0.0"
        .parse()
        .expect("plugin id")
}

/// Ask `server` to run something, over the wire, and return its answer.
async fn ask(client: &MeshIroh, server: &MeshIroh) -> RemoteOutcome {
    let task = OneShotTask::with_defaults(demo_plugin(), b"world".to_vec());
    let frame = encode_request(&RemoteTaskRequest::for_task(&task)).expect("encode");
    let raw = deadline("request", client.request(&address_of(server), &frame))
        .await
        .expect("transport round trip");
    decode_response(&raw, u64::MAX)
        .expect("the daemon must answer with a valid envelope")
        .outcome
}

// ── the authorization gate, over a real transport ────────────────────────────

/// A peer absent from the daemon's `peers.toml` allowlist is refused, over a
/// real QUIC connection, before anything is executed.
///
/// This is the daemon-level restatement of the security property: what stands
/// between the network and this machine's plugin runtime is the operator's
/// peer store, nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn an_unpaired_peer_is_refused_by_the_daemon() {
    let (id_a, id_b) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let client = start_node(loopback_scheduler_config(), &id_a).await;
    let server = start_node(loopback_scheduler_config(), &id_b).await;

    // The daemon's store is empty: nobody has been paired with.
    let store = PeerStore::new();
    spawn_task_server(
        Arc::clone(&server),
        empty_kernel(),
        store,
        server.local_peer_id(),
    );

    match ask(&client, &server).await {
        RemoteOutcome::Err { code, .. } => assert_eq!(
            code,
            RemoteErrorCode::NotAuthorized,
            "an unpaired peer must be refused as unauthorized"
        ),
        RemoteOutcome::Ok { .. } => panic!("the daemon executed work for an unpaired peer"),
    }
}

/// A peer in the store gets past the gate — proving the refusal above is the
/// allowlist doing its job, not the endpoint being broken.
///
/// The plugin is deliberately absent, so a peer that passes authorization is
/// distinguishable by the *different* error it receives.
#[tokio::test(flavor = "multi_thread")]
async fn a_paired_peer_gets_past_the_gate() {
    let (id_a, id_b) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let client = start_node(loopback_scheduler_config(), &id_a).await;
    let server = start_node(loopback_scheduler_config(), &id_b).await;

    let store = PeerStore::new();
    store
        .add(TrustedPeer::new(
            client.local_peer_id(),
            hex::encode(client.local_public_key()),
            "node-a".into(),
        ))
        .expect("add");

    spawn_task_server(
        Arc::clone(&server),
        empty_kernel(),
        store,
        server.local_peer_id(),
    );

    match ask(&client, &server).await {
        RemoteOutcome::Err { code, .. } => assert_eq!(
            code,
            RemoteErrorCode::PluginNotLoaded,
            "a paired peer must pass authorization and fail on the missing plugin instead"
        ),
        RemoteOutcome::Ok { .. } => {
            panic!("a plugin that is not loaded cannot have produced output")
        }
    }
}

/// Revoking a peer takes effect immediately for remote execution — the
/// allowlist is consulted per request, not cached at startup.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_peer_stops_it_mid_session() {
    let (id_a, id_b) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let client = start_node(loopback_scheduler_config(), &id_a).await;
    let server = start_node(loopback_scheduler_config(), &id_b).await;

    let store = PeerStore::new();
    store
        .add(TrustedPeer::new(
            client.local_peer_id(),
            hex::encode(client.local_public_key()),
            "node-a".into(),
        ))
        .expect("add");

    spawn_task_server(
        Arc::clone(&server),
        empty_kernel(),
        store.clone(),
        server.local_peer_id(),
    );

    // Trusted: gets past the gate.
    assert!(matches!(
        ask(&client, &server).await,
        RemoteOutcome::Err {
            code: RemoteErrorCode::PluginNotLoaded,
            ..
        }
    ));

    // Revoked: refused from the very next request onward.
    store.revoke(&client.local_peer_id()).expect("revoke");
    assert_eq!(
        store
            .get(&client.local_peer_id())
            .expect("still listed")
            .trust,
        TrustLevel::Revoked
    );

    match ask(&client, &server).await {
        RemoteOutcome::Err { code, .. } => assert_eq!(
            code,
            RemoteErrorCode::NotAuthorized,
            "a revoked peer must lose the right to submit work immediately"
        ),
        RemoteOutcome::Ok { .. } => panic!("a revoked peer got work executed"),
    }
}

/// The allowlist adapter itself, unit-checked against the three states a peer
/// can be in.
#[test]
fn the_allowlist_reflects_the_peer_store_and_fails_closed() {
    let store = PeerStore::new();
    let known = PeerId::from_public_key_bytes(&[1; 32]);
    let unknown = PeerId::from_public_key_bytes(&[2; 32]);
    store
        .add(TrustedPeer::new(
            known,
            hex::encode([1u8; 32]),
            "known".into(),
        ))
        .expect("add");

    let allow = PeerStoreAllowlist::new(store.clone());
    assert!(allow.is_authorized(&known), "a paired peer is authorized");
    assert!(
        !allow.is_authorized(&unknown),
        "an unknown peer is refused (fail closed)"
    );

    store.revoke(&known).expect("revoke");
    assert!(
        !allow.is_authorized(&known),
        "a revoked peer is refused (fail closed)"
    );
}

// ── off by default ───────────────────────────────────────────────────────────

/// A stock config leaves cross-node dispatch entirely off, so an unconfigured
/// daemon is exactly the single-machine daemon it always was.
#[test]
fn cross_node_dispatch_is_off_in_a_default_config() {
    let cfg = Config::default();
    assert!(
        !scheduler_transport_enabled(&cfg.mesh.transports),
        "a default config must not open a scheduler endpoint"
    );
    assert!(cfg.scheduler.peers.is_empty());
    assert_eq!(cfg.scheduler.bind, "0.0.0.0:0");
}

/// A config file written without a `[scheduler]` section — everything the CLI
/// has ever written — still parses, and still leaves remote dispatch off.
#[test]
fn a_config_without_a_scheduler_section_still_parses() {
    let toml_src = r#"
[mesh]
transports = ["local"]
multi_node = true

[security]
max_tier_allowed = 3
"#;
    let cfg: Config = toml::from_str(toml_src).expect("a scheduler-less config must parse");
    assert!(!scheduler_transport_enabled(&cfg.mesh.transports));
    assert!(cfg.scheduler.peers.is_empty());
    assert!(cfg.scheduler.relay, "relay defaults on");
}

/// Naming `"iroh"` in `[mesh] transports` is what turns the feature on.
#[test]
fn the_transport_is_selected_by_name() {
    let toml_src = r#"
[mesh]
transports = ["local", "iroh"]

[scheduler]
bind = "127.0.0.1:0"
relay = false
peers = ["aa@bb"]
"#;
    let cfg: Config = toml::from_str(toml_src).expect("parse");
    assert!(scheduler_transport_enabled(&cfg.mesh.transports));
    assert_eq!(cfg.scheduler.bind, "127.0.0.1:0");
    assert!(!cfg.scheduler.relay);
    assert_eq!(cfg.scheduler.peers, vec!["aa@bb".to_owned()]);
}

/// Configuring a peer address does not by itself make that peer a dispatch
/// target: it must also be trusted in the peer store.
#[test]
fn a_configured_address_alone_grants_nothing() {
    let store = PeerStore::new();
    let stranger_key = [0xde; 32];
    let cfg = SchedulerConfig {
        peers: vec![format!("{}@127.0.0.1:4001", hex::encode(stranger_key))],
        ..SchedulerConfig::default()
    };

    let dir = directory_from_config(&cfg, &store, PeerId::from_public_key_bytes(&[0; 32]));
    assert!(
        dir.is_empty(),
        "an address for an unpaired peer must not become a dispatch target"
    );
}

// ── endpoint hygiene ─────────────────────────────────────────────────────────

/// The daemon's scheduler endpoint speaks the scheduler ALPN, so a peer
/// dialling the control protocol is refused at the transport rather than
/// being served work by accident.
#[tokio::test(flavor = "multi_thread")]
async fn the_scheduler_endpoint_does_not_answer_the_control_alpn() {
    let identity = IdentityKeyPair::generate();
    let cfg = SchedulerConfig {
        bind: "127.0.0.1:0".to_owned(),
        relay: false,
        ..SchedulerConfig::default()
    };
    let server = start_scheduler_transport(&cfg, &identity)
        .await
        .expect("the scheduler transport must bind");

    spawn_task_server(
        Arc::clone(&server),
        empty_kernel(),
        PeerStore::new(),
        server.local_peer_id(),
    );

    let control_peer = IdentityKeyPair::generate();
    let control_client = start_node(
        MeshIrohConfig {
            alpn: ALPN_CONTROL.to_vec(),
            connect_timeout: Duration::from_secs(3),
            ..MeshIrohConfig::loopback()
        },
        &control_peer,
    )
    .await;

    let err = deadline(
        "control-alpn dial",
        control_client.connect(&address_of(&server)),
    )
    .await
    .expect_err("a control-ALPN peer must not connect to the scheduler endpoint");
    assert!(
        !err.to_string().is_empty(),
        "the refusal must be a typed error"
    );
}

/// A bad `bind` is a startup error naming the offending value, not a panic.
#[tokio::test(flavor = "multi_thread")]
async fn an_unparseable_bind_is_a_typed_startup_error() {
    let identity = IdentityKeyPair::generate();
    let cfg = SchedulerConfig {
        bind: "not-a-socket-addr".to_owned(),
        ..SchedulerConfig::default()
    };
    let err = start_scheduler_transport(&cfg, &identity)
        .await
        .expect_err("an unparseable bind must fail");
    assert!(
        err.to_string().contains("not-a-socket-addr"),
        "the error should name the offending value: {err}"
    );
}
