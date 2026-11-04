//! `diag/mesh`: the mesh triage report behind `entangle diag mesh`.
//!
//! The report answers "why can't I reach peer X?" from the daemon's point of
//! view: which transports are configured and which actually started, the
//! addresses this node can be reached at, whether the tailnet is up, and, for
//! every trusted peer, each path a transport currently knows (mDNS sighting,
//! iroh address-book entry, tailscale candidate). With `probe`, it also
//! measures a round trip on every path that can carry one.
//!
//! # How a probe works
//!
//! * **iroh** — a scheduler *control frame* naming a task that does not
//!   exist. The peer authenticates the connection, checks its allowlist and
//!   answers `UnknownTask` without running anything. Receiving any answer
//!   proves the path end to end (dial, handshake, authorization, framing);
//!   `NotAuthorized` is reported as reachable-but-not-trusted-by-them.
//! * **tailscale** — one request over the identity-bound tailnet session.
//! * **mDNS** — a sighting is passive; it has no round trip to measure.
//!
//! Probes run concurrently, one task per `(peer, path)`, each bounded by the
//! caller's timeout (clamped to [`MAX_PROBE_TIMEOUT`]).

use crate::state::DaemonState;
use entangle_peers::TrustLevel;
use entangle_rpc::methods::{DiagEndpoint, DiagMeshResult, DiagPath, DiagPeer, DiagTailscale};
use entangle_scheduler::work_unit::hash_canonical;
use entangle_scheduler::{ControlAction, ControlFrame, DispatchError, RemoteErrorCode};
use entangle_types::peer_id::PeerId;
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

/// Upper bound on a client-supplied probe timeout.
pub const MAX_PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Probe timeout when the caller sends `0`.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Payload of a tailscale probe request (the peer's handler ignores it).
const TAILSCALE_PING: &[u8] = b"entangle-diag-ping";

/// Build the mesh report. See the module docs.
pub async fn mesh_report(
    state: &DaemonState,
    probe: bool,
    probe_timeout: Duration,
) -> DiagMeshResult {
    let timeout = if probe_timeout.is_zero() {
        DEFAULT_PROBE_TIMEOUT
    } else {
        probe_timeout.min(MAX_PROBE_TIMEOUT)
    };
    let diag = &state.diag;

    // ── transports and local endpoints ─────────────────────────────────────
    let mut active = Vec::new();
    let mut endpoints = Vec::new();
    if state.discovery.is_some() {
        active.push("local".to_owned());
    }
    if let Some(iroh) = &diag.iroh {
        active.push("iroh".to_owned());
        for address in iroh.node_addrs() {
            endpoints.push(DiagEndpoint {
                transport: "iroh".into(),
                address,
            });
        }
    }
    let tailscale = diag.tailscale.as_ref().map(|ts| {
        active.push("tailscale".to_owned());
        endpoints.push(DiagEndpoint {
            transport: "tailscale".into(),
            address: ts.transport.local_addr().to_string(),
        });
        let snap = ts.liveness.borrow().clone();
        DiagTailscale {
            state: snap
                .state
                .as_ref()
                .map_or("unknown", |s| s.label())
                .to_owned(),
            reason: snap
                .state
                .as_ref()
                .and_then(|s| s.reason())
                .map(str::to_owned),
            since_secs: snap
                .since
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .map(|d| d.as_secs()),
            transitions: snap.transitions,
            candidates: ts.transport.candidates().len(),
        }
    });
    if let Some(addr) = diag.metrics_listen {
        endpoints.push(DiagEndpoint {
            transport: "metrics".into(),
            address: addr.to_string(),
        });
    }

    // ── per-peer paths ─────────────────────────────────────────────────────
    let sightings: HashMap<PeerId, _> = match &state.discovery {
        Some(d) => d
            .snapshot_peers()
            .await
            .into_iter()
            .map(|p| (p.peer_id, p))
            .collect(),
        None => HashMap::new(),
    };
    let candidates: HashMap<PeerId, _> = diag
        .tailscale
        .as_ref()
        .map(|ts| {
            ts.transport
                .candidates()
                .into_iter()
                .map(|c| (c.peer_id, c))
                .collect()
        })
        .unwrap_or_default();

    let mut trusted: Vec<_> = state
        .peer_store
        .list()
        .into_iter()
        .filter(|p| p.trust != TrustLevel::Revoked)
        .collect();
    trusted.sort_by_key(|p| p.peer_id.to_hex());

    let mut peers = Vec::with_capacity(trusted.len());
    // (peer index, path index, future) for probes, collected then joined.
    let mut probes = tokio::task::JoinSet::new();
    for (pi, tp) in trusted.iter().enumerate() {
        let mut paths = Vec::new();
        if let Some(seen) = sightings.get(&tp.peer_id) {
            let ago = seen.last_seen.elapsed().map(|d| d.as_secs()).unwrap_or(0);
            let ips: Vec<String> = seen.addresses.iter().map(|a| a.to_string()).collect();
            paths.push(DiagPath {
                transport: "mdns".into(),
                address: ips.first().map(|ip| format!("{ip}:{}", seen.port)),
                detail: format!(
                    "sighted {ago}s ago ({} address{}; unauthenticated, passive)",
                    ips.len(),
                    if ips.len() == 1 { "" } else { "es" }
                ),
                rtt_ms: None,
                probe_error: None,
            });
        }
        if let Some(iroh_peer) = diag.iroh_directory.as_ref().and_then(|d| {
            use entangle_scheduler::PeerAddressBook as _;
            d.lookup(&tp.peer_id)
        }) {
            let pi_path = paths.len();
            paths.push(DiagPath {
                transport: "iroh".into(),
                address: Some(iroh_peer.addr.to_string()),
                detail: "address book ([scheduler] peers)".into(),
                rtt_ms: None,
                probe_error: None,
            });
            if probe {
                match state.dispatcher.remote().cloned() {
                    Some(remote) => {
                        let peer = tp.peer_id;
                        probes.spawn(async move {
                            (pi, pi_path, probe_iroh(&remote, peer, timeout).await)
                        });
                    }
                    None => paths[pi_path].probe_error = Some("no iroh transport running".into()),
                }
            }
        }
        if let Some(cand) = candidates.get(&tp.peer_id) {
            let pi_path = paths.len();
            paths.push(DiagPath {
                transport: "tailscale".into(),
                address: Some(cand.addr.to_string()),
                detail: if cand.magic_dns.is_empty() {
                    "tailnet candidate".into()
                } else {
                    format!("tailnet candidate ({})", cand.magic_dns)
                },
                rtt_ms: None,
                probe_error: None,
            });
            if probe {
                if let Some(ts) = &diag.tailscale {
                    let (transport, cand) = (ts.transport.clone(), cand.clone());
                    probes.spawn(async move {
                        (
                            pi,
                            pi_path,
                            probe_tailscale(&transport, &cand, timeout).await,
                        )
                    });
                }
            }
        }
        peers.push(DiagPeer {
            peer_id: tp.peer_id.to_hex(),
            display_name: tp.display_name.clone(),
            trust: match tp.trust {
                TrustLevel::Trusted => "trusted",
                TrustLevel::Observer => "observer",
                TrustLevel::Revoked => "revoked",
            }
            .into(),
            paths,
        });
    }

    while let Some(joined) = probes.join_next().await {
        if let Ok((pi, path, outcome)) = joined {
            let slot = &mut peers[pi].paths[path];
            match outcome {
                ProbeOutcome::Rtt(ms) => slot.rtt_ms = Some(ms),
                ProbeOutcome::ReachedButRefused(ms, why) => {
                    slot.rtt_ms = Some(ms);
                    slot.probe_error = Some(why);
                }
                ProbeOutcome::Failed(why) => slot.probe_error = Some(why),
            }
        }
    }

    let trusted_ids: std::collections::HashSet<PeerId> =
        trusted.iter().map(|p| p.peer_id).collect();
    DiagMeshResult {
        local_peer_id: state.local_peer_id.to_hex(),
        local_display_name: state.local_display_name.clone(),
        transports_configured: diag.configured_transports.clone(),
        transports_active: active,
        endpoints,
        tailscale,
        peers,
        untrusted_sightings: sightings
            .keys()
            .filter(|id| !trusted_ids.contains(id) && **id != state.local_peer_id)
            .count(),
        probed: probe,
    }
}

enum ProbeOutcome {
    /// An answer arrived after this many milliseconds.
    Rtt(f64),
    /// The peer answered but declined us.
    ReachedButRefused(f64, String),
    /// No answer.
    Failed(String),
}

fn ms(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

async fn probe_iroh(
    remote: &entangle_scheduler::RemoteDispatch,
    peer: PeerId,
    timeout: Duration,
) -> ProbeOutcome {
    // A control frame about a task that does not exist: answered with
    // `UnknownTask` after authentication and authorization, executing nothing.
    let frame = ControlFrame {
        task_id: *uuid::Uuid::new_v4().as_bytes(),
        action: ControlAction::SetPolicy {
            policy: Vec::new(),
            policy_hash: hash_canonical(&[]),
        },
    };
    let started = Instant::now();
    match remote.send_control(peer, frame, timeout).await {
        // Not expected (the task id is random) but still an answer.
        Ok(_) => ProbeOutcome::Rtt(ms(started)),
        Err(DispatchError::RemoteRejected {
            code: RemoteErrorCode::UnknownTask,
            ..
        }) => ProbeOutcome::Rtt(ms(started)),
        Err(DispatchError::RemoteRejected {
            code: RemoteErrorCode::NotAuthorized,
            ..
        }) => ProbeOutcome::ReachedButRefused(
            ms(started),
            "reached, but that peer does not trust this node (NotAuthorized)".into(),
        ),
        Err(DispatchError::RemoteRejected { code, .. }) => {
            ProbeOutcome::ReachedButRefused(ms(started), format!("reached; peer answered {code}"))
        }
        Err(e) => ProbeOutcome::Failed(e.to_string()),
    }
}

async fn probe_tailscale(
    transport: &entangle_mesh_tailscale::MeshTailscale,
    peer: &entangle_mesh_tailscale::TailscalePeer,
    timeout: Duration,
) -> ProbeOutcome {
    let started = Instant::now();
    match tokio::time::timeout(timeout, transport.request(peer, TAILSCALE_PING)).await {
        Ok(Ok(_)) => ProbeOutcome::Rtt(ms(started)),
        Ok(Err(e)) => ProbeOutcome::Failed(e.to_string()),
        Err(_) => ProbeOutcome::Failed(format!("no answer within {}ms", timeout.as_millis())),
    }
}
