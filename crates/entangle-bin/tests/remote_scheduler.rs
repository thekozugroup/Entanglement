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
    capability_gate, directory_from_config, scheduler_transport_enabled, spawn_stream_server,
    spawn_task_server, start_scheduler_transport, PeerStoreAllowlist, PeerStoreTokens,
};
use entangle_mesh_iroh::{
    IrohPeer, MeshIroh, MeshIrohConfig, MeshTransport, ALPN_CONTROL, ALPN_SCHEDULER,
};
use entangle_peers::{PeerStore, RevocationStore, TrustLevel, TrustedPeer, REVOCATIONS_FILE};
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::capability::{task_binding, CapabilityGate, CapabilityTokens, HeldToken};
use entangle_scheduler::wire::{decode_response, encode_request, RemoteRequest};
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

/// The daemon's capability gate for `identity`, tokens required, no
/// revocations yet.
fn daemon_gate(identity: &IdentityKeyPair, store: &PeerStore) -> Arc<CapabilityGate> {
    capability_gate(
        identity,
        true,
        Arc::new(RevocationStore::new()),
        store,
        None,
    )
    .expect("gate")
}

/// The `mesh.peer` token the daemon `daemon` would mint for `client` while
/// pairing (the shared helper: a real token, minted with the daemon's key).
fn issued(daemon: &IdentityKeyPair, client: &MeshIroh) -> HeldToken {
    HeldToken::minted(daemon, client.local_peer_id()).expect("mint")
}

/// Ask `server` to run something, over the wire, presenting `token` (a
/// per-request attenuation of it), and return its answer.
async fn ask(client: &MeshIroh, server: &MeshIroh, token: Option<&HeldToken>) -> RemoteOutcome {
    let task = OneShotTask::with_defaults(demo_plugin(), b"world".to_vec());
    let mut request = RemoteRequest::for_task(&task).expect("seal");
    if let (entangle_scheduler::RequestFrame::Task(body), Some(held)) = (&mut request.frame, token)
    {
        body.capability = Some(held.present(task_binding(body)).expect("present"));
    }
    let frame = encode_request(&request).expect("encode");
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
    let gate = daemon_gate(&id_b, &store);
    spawn_task_server(Arc::clone(&server), empty_kernel(), store, gate);

    match ask(&client, &server, Some(&issued(&id_b, &client))).await {
        RemoteOutcome::Err { code, .. } => assert_eq!(
            code,
            RemoteErrorCode::NotAuthorized,
            "an unpaired peer must be refused as unauthorized"
        ),
        RemoteOutcome::Ok { .. } | RemoteOutcome::Ack { .. } => {
            panic!("the daemon executed work for an unpaired peer")
        }
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

    let gate = daemon_gate(&id_b, &store);
    spawn_task_server(Arc::clone(&server), empty_kernel(), store, gate);

    match ask(&client, &server, Some(&issued(&id_b, &client))).await {
        RemoteOutcome::Err { code, .. } => assert_eq!(
            code,
            RemoteErrorCode::PluginNotLoaded,
            "a paired peer must pass authorization and fail on the missing plugin instead"
        ),
        RemoteOutcome::Ok { .. } | RemoteOutcome::Ack { .. } => {
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
        daemon_gate(&id_b, &store),
    );

    // Trusted: gets past the gate.
    assert!(matches!(
        ask(&client, &server, Some(&issued(&id_b, &client))).await,
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

    match ask(&client, &server, Some(&issued(&id_b, &client))).await {
        RemoteOutcome::Err { code, .. } => assert_eq!(
            code,
            RemoteErrorCode::NotAuthorized,
            "a revoked peer must lose the right to submit work immediately"
        ),
        RemoteOutcome::Ok { .. } | RemoteOutcome::Ack { .. } => {
            panic!("a revoked peer got work executed")
        }
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
        daemon_gate(&identity, &PeerStore::new()),
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

// ── streaming tasks (entangle/stream/1) ─────────────────────────────────────

/// Open a stream to `server` as `client`, presenting `tokens`, and return
/// how it ended.
async fn stream_outcome(
    client: &MeshIroh,
    server: &MeshIroh,
    tokens: Option<Arc<dyn CapabilityTokens>>,
) -> entangle_scheduler::stream::StreamOutcome {
    let task = entangle_types::task::StreamingTask::with_defaults(demo_plugin(), b"x".to_vec());
    let handle = deadline(
        "open stream",
        entangle_scheduler::open_stream(
            client,
            &address_of(server),
            &task,
            entangle_scheduler::stream::StreamOptions {
                capability: tokens,
                ..entangle_scheduler::stream::StreamOptions::default()
            },
        ),
    )
    .await
    .expect("the daemon endpoint accepts entangle/stream/1");
    deadline("stream", handle.collect()).await.outcome
}

/// The daemon serves streaming tasks on its scheduler endpoint — same port,
/// second ALPN — behind the same peer-store gate as one-shot tasks: an
/// unpaired peer is refused as unauthorized, a paired one gets past the gate
/// (and then learns the plugin is not loaded), and one-shot traffic on the
/// same endpoint is unaffected.
#[tokio::test(flavor = "multi_thread")]
async fn the_daemon_serves_streams_behind_the_peer_store_gate() {
    let (id_client, id_daemon) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let cfg = SchedulerConfig {
        bind: "127.0.0.1:0".to_owned(),
        relay: false,
        ..SchedulerConfig::default()
    };
    let daemon = start_scheduler_transport(&cfg, &id_daemon)
        .await
        .expect("daemon transport");
    let store = PeerStore::new();
    let gate = daemon_gate(&id_daemon, &store);
    spawn_task_server(
        Arc::clone(&daemon),
        empty_kernel(),
        store.clone(),
        Arc::clone(&gate),
    );
    spawn_stream_server(
        Arc::clone(&daemon),
        empty_kernel(),
        store.clone(),
        id_daemon.clone(),
        gate,
    );
    let client = start_node(loopback_scheduler_config(), &id_client).await;
    let tokens: Arc<dyn CapabilityTokens> = {
        let t = entangle_scheduler::StaticTokens::new();
        t.insert(daemon.local_peer_id(), issued(&id_daemon, &client));
        Arc::new(t)
    };

    use entangle_scheduler::stream::{Reason, StreamError, StreamOutcome};
    match stream_outcome(&client, &daemon, Some(tokens.clone())).await {
        StreamOutcome::Interrupted(StreamError::PeerAborted { reason, .. }) => {
            assert_eq!(reason, Reason::NotAuthorized)
        }
        other => panic!("an unpaired peer must be refused, got {other:?}"),
    }

    store
        .add(TrustedPeer::new(
            client.local_peer_id(),
            hex::encode(client.local_public_key()),
            "client".into(),
        ))
        .expect("add");
    match stream_outcome(&client, &daemon, Some(tokens.clone())).await {
        StreamOutcome::Interrupted(StreamError::PeerAborted { reason, .. }) => {
            assert_eq!(reason, Reason::PluginNotLoaded, "past the gate")
        }
        other => panic!("expected PluginNotLoaded, got {other:?}"),
    }

    // One-shot dispatch still answers on the very same endpoint.
    match ask(&client, &daemon, Some(&issued(&id_daemon, &client))).await {
        RemoteOutcome::Err { code, .. } => assert_eq!(code, RemoteErrorCode::PluginNotLoaded),
        other => panic!("unexpected {other:?}"),
    }

    store.revoke(&client.local_peer_id()).expect("revoke");
    assert!(matches!(
        stream_outcome(&client, &daemon, Some(tokens.clone())).await,
        StreamOutcome::Interrupted(StreamError::PeerAborted {
            reason: Reason::NotAuthorized,
            ..
        })
    ));
}

// ── capability tokens and revocation, as the daemon wires them ─────────────

/// `entangle peers remove` revokes the token the daemon issued to the peer;
/// re-adding the peer by hand (`entangle mesh trust`) puts it back on the
/// allowlist but does not revive that token — while the daemon runs, from
/// the files the CLI writes.
#[tokio::test(flavor = "multi_thread")]
async fn a_removed_then_re_added_peer_cannot_use_its_old_token() {
    let dir = tempfile::tempdir().unwrap();
    let (id_client, id_daemon) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let daemon = start_node(loopback_scheduler_config(), &id_daemon).await;
    let client = start_node(loopback_scheduler_config(), &id_client).await;

    // Pairing left the daemon with the client's record, carrying the
    // revocation ids of the token the daemon minted for it.
    let minted =
        entangle_biscuits::templates::mint_mesh_peer(&id_daemon, client.local_peer_id(), None)
            .unwrap();
    let store = PeerStore::open(dir.path().join("peers.toml")).unwrap();
    let cli_revocations = RevocationStore::open(dir.path().join(REVOCATIONS_FILE)).unwrap();
    let record = || {
        TrustedPeer::new_validated(
            client.local_peer_id(),
            hex::encode(client.local_public_key()),
            "client".into(),
        )
        .unwrap()
    };
    store
        .add_paired(
            record().with_tokens(None, &minted.revocation_ids),
            &cli_revocations,
        )
        .unwrap();

    // The daemon reads the revocation set through its own handle, as it does
    // in `main` (`RevocationStore::at`).
    let gate = capability_gate(
        &id_daemon,
        true,
        Arc::new(RevocationStore::at(dir.path().join(REVOCATIONS_FILE))),
        &store,
        None,
    )
    .unwrap();
    spawn_task_server(Arc::clone(&daemon), empty_kernel(), store.clone(), gate);
    let held = HeldToken {
        token: minted.bytes.clone(),
        issuer_public_key: *id_daemon.public().as_bytes(),
    };
    assert!(
        matches!(
            ask(&client, &daemon, Some(&held)).await,
            RemoteOutcome::Err {
                code: RemoteErrorCode::PluginNotLoaded,
                ..
            }
        ),
        "the paired peer's token gets it past both gates"
    );

    // `entangle peers remove`, then `entangle mesh trust` by hand.
    store
        .remove_revoking(&client.local_peer_id(), &cli_revocations)
        .unwrap();
    store.add_keeping_tokens(record()).unwrap();
    assert!(PeerStoreAllowlist::new(store.clone()).is_authorized(&client.local_peer_id()));

    match ask(&client, &daemon, Some(&held)).await {
        RemoteOutcome::Err { code, message } => {
            assert_eq!(code, RemoteErrorCode::CapabilityRejected, "{message}");
            assert!(message.contains("ENTANGLE-E0460"), "{message}");
        }
        other => panic!("a revoked token must stay dead after a re-add, got {other:?}"),
    }
    // Re-pairing mints a new token, which works.
    assert!(matches!(
        ask(&client, &daemon, Some(&issued(&id_daemon, &client))).await,
        RemoteOutcome::Err {
            code: RemoteErrorCode::PluginNotLoaded,
            ..
        }
    ));
}

/// A daemon that requires tokens refuses a paired peer that presents none
/// with the re-pair message; with `[trust] require_capability_tokens =
/// false` it accepts it.
#[tokio::test(flavor = "multi_thread")]
async fn a_tokenless_request_needs_the_migration_setting() {
    for require in [true, false] {
        let (id_client, id_daemon) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
        let daemon = start_node(loopback_scheduler_config(), &id_daemon).await;
        let client = start_node(loopback_scheduler_config(), &id_client).await;
        let store = PeerStore::new();
        store
            .add(TrustedPeer::new(
                client.local_peer_id(),
                hex::encode(client.local_public_key()),
                "pre-token peer".into(),
            ))
            .unwrap();
        let gate = capability_gate(
            &id_daemon,
            require,
            Arc::new(RevocationStore::new()),
            &store,
            None,
        )
        .unwrap();
        spawn_task_server(Arc::clone(&daemon), empty_kernel(), store, gate);
        match ask(&client, &daemon, None).await {
            RemoteOutcome::Err { code, message } if require => {
                assert_eq!(code, RemoteErrorCode::CapabilityRequired);
                assert!(message.contains("entangle pair"), "{message}");
            }
            RemoteOutcome::Err { code, .. } => {
                assert_eq!(
                    code,
                    RemoteErrorCode::PluginNotLoaded,
                    "admitted without a token"
                )
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// Outbound, the daemon presents the token a peer minted for it, from
/// `peers.toml` — none for a revoked peer or one paired before tokens.
#[test]
fn outbound_tokens_come_from_the_peer_store() {
    let store = PeerStore::new();
    let (peer_key, me) = (
        IdentityKeyPair::generate(),
        PeerId::from_public_key_bytes(&[5; 32]),
    );
    let peer = PeerId::from_public_key_bytes(peer_key.public().as_bytes());
    let minted = entangle_biscuits::templates::mint_mesh_peer(&peer_key, me, None).unwrap();
    let record =
        TrustedPeer::new_validated(peer, hex::encode(peer_key.public().as_bytes()), "p".into())
            .unwrap();
    let tokens = PeerStoreTokens::new(store.clone());
    store.add(record.clone()).unwrap();
    assert!(tokens.token_for(&peer).is_none(), "paired before tokens");
    store
        .add(record.with_tokens(Some(&minted.bytes), &[]))
        .unwrap();
    let held = tokens.token_for(&peer).expect("the stored token");
    assert_eq!(held.token, minted.bytes);
    assert_eq!(&held.issuer_public_key, peer_key.public().as_bytes());
    store.revoke(&peer).unwrap();
    assert!(
        tokens.token_for(&peer).is_none(),
        "a revoked peer gets nothing"
    );
}
