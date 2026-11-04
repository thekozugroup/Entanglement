//! `entangle mesh routes` — per-peer reachability across transports (spec
//! §6.4).
//!
//! For every trusted peer: which of this node's transports can reach it
//! right now, which one the router tries first, and — when none can — a
//! prescriptive hint naming the literal command to run. Built from the
//! daemon's `diag/mesh` report (the same data as `entangle diag mesh`); with
//! no daemon running, only the configuration is known and the report says
//! so.
//!
//! **No bridging.** A node that shares no transport with a peer cannot reach
//! it; relaying through a third node that has both is deferred (spec §6.4
//! "Opt-in bridging" is not implemented), and the output says so.

use std::collections::HashMap;
use std::fmt::Write as _;

use entangle_rpc::methods::{DiagMeshParams, DiagMeshResult};
use entangle_rpc::{Client as RpcClient, RpcError};
use serde::Serialize;

/// What the output says about bridging.
pub const NO_BRIDGING: &str = "transport bridging is not supported (deferred, spec §6.4): a peer \
                               that shares no transport with this node cannot be reached through \
                               another node";

/// One trusted peer.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RouteRow {
    /// Peer id (hex).
    pub peer_id: String,
    /// Display name from the peer store.
    pub display_name: String,
    /// Short fingerprint of its key, when known.
    pub fingerprint: Option<String>,
    /// This node's transports that currently know a path to it (`local`,
    /// `iroh`, `tailscale`); with `--probe`, only those that answered.
    pub reachable: Vec<String>,
    /// The order the router would try (first = its pick).
    pub route: Vec<String>,
    /// Transports the router skips, each `transport: reason`.
    pub skipped: Vec<String>,
    /// The router's first choice.
    pub picked: Option<String>,
    /// The transport that last carried traffic to it.
    pub last_used: Option<String>,
    /// Seconds since then.
    pub last_used_secs: Option<u64>,
    /// What to do when it is not reachable.
    pub hints: Vec<String>,
}

/// The whole report (`--json`).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RoutesReport {
    /// This node's label.
    pub label: String,
    /// This node's peer id, when known.
    pub peer_id: Option<String>,
    /// `[mesh] transports`.
    pub transports_configured: Vec<String>,
    /// Transports actually running (`None` when the daemon is not running).
    pub transports_running: Option<Vec<String>>,
    /// Whether the data came from a running daemon.
    pub daemon_running: bool,
    /// Trusted peers.
    pub peers: Vec<RouteRow>,
    /// The bridging statement.
    pub bridging: &'static str,
}

const ALL: [&str; 3] = ["local", "tailscale", "iroh"];

/// Hints for a peer no running transport can reach.
fn hints_for(
    name: &str,
    configured: &[String],
    running: &[String],
    tailnet: Option<&str>,
) -> Vec<String> {
    let has = |list: &[String], t: &str| list.iter().any(|x| x == t);
    let mut out = Vec::new();
    for t in ALL {
        if !has(configured, t) {
            out.push(format!(
                "if {name} uses mesh.{t}, enable it here: entangle config set mesh.{t}.enabled true"
            ));
        } else if !has(running, t) {
            out.push(format!(
                "mesh.{t} is configured but not running on this node: see the daemon log and \
                 `entangle diag mesh`"
            ));
        }
    }
    if has(running, "local") {
        out.push(format!(
            "mesh.local: is {name} on this LAN, running entangled, with mDNS allowed? (carrying \
             work to a LAN peer also needs mesh.iroh)"
        ));
    }
    if has(running, "iroh") {
        out.push(format!(
            "mesh.iroh: add {name}'s <pubkey-hex>@host:port address to [scheduler] peers \
             (`entangle config get scheduler.peers`, then `entangle config set scheduler.peers \
             <list>`)"
        ));
    }
    if has(running, "tailscale") {
        match tailnet {
            Some(state) if state != "active" => out.push(format!(
                "mesh.tailscale: the tailnet is {state} on this node: run `tailscale up`"
            )),
            _ => out.push(format!(
                "mesh.tailscale: is {name} online in the tailnet with mesh.tailscale enabled?"
            )),
        }
    }
    if !running.is_empty() {
        out.push(format!(
            "or ask {name} to enable a transport this node runs ({}), or pair over one you share",
            running.join(", ")
        ));
    }
    out.push(NO_BRIDGING.to_owned());
    out
}

fn fingerprint_of(keys: &HashMap<String, String>, peer_id: &str) -> Option<String> {
    let key: [u8; 32] = hex::decode(keys.get(peer_id)?).ok()?.try_into().ok()?;
    Some(entangle_pairing::ShortFingerprint::from_public_key(&key).to_string())
}

/// Build the report from the daemon's `diag/mesh` answer. `keys` maps peer
/// id to public key (from `peers.toml`), for the fingerprints.
pub fn from_diag(r: &DiagMeshResult, keys: &HashMap<String, String>) -> RoutesReport {
    let tailnet = r.tailscale.as_ref().map(|t| t.state.as_str());
    let peers = r
        .peers
        .iter()
        .map(|p| {
            let mut reachable: Vec<String> = Vec::new();
            for path in &p.paths {
                let t = if path.transport == "mdns" {
                    "local"
                } else {
                    path.transport.as_str()
                };
                let answered = !r.probed || (path.rtt_ms.is_some() && path.probe_error.is_none());
                if answered && !reachable.iter().any(|x| x == t) {
                    reachable.push(t.to_owned());
                }
            }
            let route = p.route.clone().unwrap_or_default();
            let name = if p.display_name.is_empty() {
                p.peer_id.clone()
            } else {
                p.display_name.clone()
            };
            let hints = if reachable.is_empty() {
                hints_for(
                    &name,
                    &r.transports_configured,
                    &r.transports_active,
                    tailnet,
                )
            } else {
                Vec::new()
            };
            RouteRow {
                peer_id: p.peer_id.clone(),
                display_name: p.display_name.clone(),
                fingerprint: fingerprint_of(keys, &p.peer_id),
                reachable,
                picked: route.order.first().cloned(),
                route: route.order,
                skipped: route.skipped,
                last_used: route.last_used,
                last_used_secs: route.last_used_secs,
                hints,
            }
        })
        .collect();
    RoutesReport {
        label: r.local_display_name.clone(),
        peer_id: Some(r.local_peer_id.clone()),
        transports_configured: r.transports_configured.clone(),
        transports_running: Some(r.transports_active.clone()),
        daemon_running: true,
        peers,
        bridging: NO_BRIDGING,
    }
}

/// The configuration-only report (no daemon): reachability is unknown.
pub fn offline(
    label: String,
    peer_id: Option<String>,
    configured: Vec<String>,
    peers: &[entangle_peers::TrustedPeer],
) -> RoutesReport {
    let mut peers: Vec<_> = peers
        .iter()
        .filter(|p| p.trust != entangle_peers::TrustLevel::Revoked)
        .collect();
    peers.sort_by_key(|p| p.peer_id.to_hex());
    let keys: HashMap<String, String> = peers
        .iter()
        .map(|p| (p.peer_id.to_hex(), p.public_key_hex.clone()))
        .collect();
    let rows = peers
        .iter()
        .map(|p| {
            let id = p.peer_id.to_hex();
            let hints = if configured.is_empty() {
                hints_for(&p.display_name, &configured, &[], None)
            } else {
                vec!["start the daemon (`entangled run`) to see which transports reach it".into()]
            };
            RouteRow {
                fingerprint: fingerprint_of(&keys, &id),
                peer_id: id,
                display_name: p.display_name.clone(),
                reachable: Vec::new(),
                route: Vec::new(),
                skipped: Vec::new(),
                picked: None,
                last_used: None,
                last_used_secs: None,
                hints,
            }
        })
        .collect();
    RoutesReport {
        label,
        peer_id,
        transports_configured: configured,
        transports_running: None,
        daemon_running: false,
        peers: rows,
        bridging: NO_BRIDGING,
    }
}

/// Render for a terminal.
pub fn render_text(r: &RoutesReport) -> String {
    let mut out = String::new();
    let list = |v: &[String]| {
        if v.is_empty() {
            "-".to_owned()
        } else {
            v.join(", ")
        }
    };
    let rows: Vec<[String; 5]> = std::iter::once([
        format!("{}  (this node)", r.label),
        String::new(),
        r.transports_running
            .as_deref()
            .map_or_else(|| list(&r.transports_configured), list),
        "-".into(),
        "-".into(),
    ])
    .chain(r.peers.iter().map(|p| {
        let name = if p.display_name.is_empty() {
            "(unnamed)".to_owned()
        } else {
            p.display_name.clone()
        };
        let reach = if !r.daemon_running {
            "unknown (daemon not running)".to_owned()
        } else if p.reachable.is_empty() {
            "NOT REACHABLE".to_owned()
        } else {
            list(&p.reachable)
        };
        let last = match (&p.last_used, p.last_used_secs) {
            (Some(t), Some(s)) => format!("{s}s ago ({t})"),
            (Some(t), None) => t.clone(),
            _ => "-".into(),
        };
        [
            name,
            p.fingerprint.clone().unwrap_or_else(|| p.peer_id.clone()),
            reach,
            p.picked.clone().unwrap_or_else(|| "-".into()),
            last,
        ]
    }))
    .collect();
    let header = [
        "PEER",
        "FINGERPRINT",
        "TRANSPORT(S) REACHABLE",
        "PICKS",
        "LAST USED",
    ];
    let mut w = header.map(str::len);
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            w[i] = w[i].max(cell.chars().count());
        }
    }
    let line = |cells: [&str; 5]| {
        let mut s = String::new();
        for (i, c) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                s.push_str(c);
            } else {
                let _ = write!(s, "{c:<width$}  ", width = w[i]);
            }
        }
        s.trim_end().to_owned()
    };
    let _ = writeln!(out, "{}", line(header));
    for (i, row) in rows.iter().enumerate() {
        let _ = writeln!(
            out,
            "{}",
            line([&row[0], &row[1], &row[2], &row[3], &row[4]])
        );
        if i == 0 {
            continue;
        }
        let p = &r.peers[i - 1];
        if p.route.len() > 1 {
            let _ = writeln!(out, "    route: {}", p.route.join(" -> "));
        }
        for s in &p.skipped {
            let _ = writeln!(out, "    skipped {s}");
        }
        for (j, h) in p.hints.iter().enumerate() {
            let _ = writeln!(out, "    {} {h}", if j == 0 { "hint:" } else { "     " });
        }
    }
    if r.peers.is_empty() {
        let _ = writeln!(
            out,
            "(no trusted peers — pair one with `entangle pair --print-code`)"
        );
    }
    if !r.daemon_running {
        let _ = writeln!(
            out,
            "\nThe daemon is not running, so reachability is unknown; configured transports: {}.",
            list(&r.transports_configured)
        );
    }
    let _ = writeln!(out, "\nNote: {}.", r.bridging);
    out
}

/// `entangle mesh routes`.
pub async fn run(json: bool, probe: bool, timeout_ms: u64) -> anyhow::Result<()> {
    let store = crate::cmd::peers::open_peer_store()?;
    let peers = store.list();
    let keys: HashMap<String, String> = peers
        .iter()
        .map(|p| (p.peer_id.to_hex(), p.public_key_hex.clone()))
        .collect();
    let client = RpcClient::new(RpcClient::default_socket());
    let report = match client
        .diag_mesh(DiagMeshParams {
            probe,
            probe_timeout_ms: timeout_ms,
        })
        .await
    {
        Ok(r) => from_diag(&r, &keys),
        Err(RpcError::DaemonNotRunning(_)) => {
            let cfg = entangle_bin::config::load_config(&crate::config::config_path())?;
            let peer_id = std::fs::read_to_string(crate::config::identity_path())
                .ok()
                .and_then(|pem| entangle_signing::IdentityKeyPair::from_pem(&pem).ok())
                .map(|kp| {
                    entangle_types::peer_id::PeerId::from_public_key_bytes(kp.public().as_bytes())
                        .to_hex()
                });
            offline(
                crate::config::device_label(),
                peer_id,
                cfg.mesh.transports,
                &peers,
            )
        }
        Err(e) => return Err(e.into()),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_text(&report));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_rpc::methods::{DiagPath, DiagPeer, DiagRoute, DiagTailscale};

    fn peer(id: &str, name: &str, paths: Vec<(&str, Option<f64>)>, order: &[&str]) -> DiagPeer {
        DiagPeer {
            peer_id: id.into(),
            display_name: name.into(),
            trust: "trusted".into(),
            paths: paths
                .into_iter()
                .map(|(t, rtt)| DiagPath {
                    transport: t.into(),
                    address: Some("10.0.0.9:1".into()),
                    detail: String::new(),
                    rtt_ms: rtt,
                    probe_error: None,
                })
                .collect(),
            route: Some(DiagRoute {
                order: order.iter().map(|s| (*s).to_owned()).collect(),
                skipped: Vec::new(),
                last_used: order.first().map(|s| (*s).to_owned()),
                last_used_secs: Some(3),
                overridden: false,
            }),
        }
    }

    fn sample(configured: &[&str], running: &[&str]) -> DiagMeshResult {
        DiagMeshResult {
            local_peer_id: "aa11".into(),
            local_display_name: "alice-laptop".into(),
            transports_configured: configured.iter().map(|s| (*s).to_owned()).collect(),
            transports_active: running.iter().map(|s| (*s).to_owned()).collect(),
            endpoints: Vec::new(),
            tailscale: None,
            peers: vec![
                peer(
                    "bb22",
                    "bob-desktop",
                    vec![("mdns", None), ("iroh", None)],
                    &["local", "iroh"],
                ),
                peer("cc33", "charlie-server", vec![], &[]),
            ],
            untrusted_sightings: 0,
            probed: false,
        }
    }

    #[test]
    fn reachable_transports_pick_and_a_prescriptive_hint() {
        let r = from_diag(
            &sample(&["local", "iroh"], &["local", "iroh"]),
            &HashMap::new(),
        );
        let bob = &r.peers[0];
        assert_eq!(bob.reachable, ["local", "iroh"]);
        assert_eq!(bob.picked.as_deref(), Some("local"));
        assert!(bob.hints.is_empty());
        let charlie = &r.peers[1];
        assert!(charlie.reachable.is_empty());
        assert!(
            charlie.hints.iter().any(|h| h
                == "if charlie-server uses mesh.tailscale, enable it here: entangle config set \
                    mesh.tailscale.enabled true"),
            "{:?}",
            charlie.hints
        );
        assert!(charlie
            .hints
            .iter()
            .any(|h| h.contains("ask charlie-server")));
        assert!(charlie
            .hints
            .iter()
            .any(|h| h.contains("bridging is not supported")));
        let text = render_text(&r);
        for needle in [
            "alice-laptop  (this node)",
            "bob-desktop",
            "local, iroh",
            "3s ago (local)",
            "charlie-server",
            "NOT REACHABLE",
            "hint: if charlie-server uses mesh.tailscale",
            "Note: transport bridging is not supported",
        ] {
            assert!(text.contains(needle), "missing {needle:?}:\n{text}");
        }
    }

    #[test]
    fn a_probe_counts_only_paths_that_answered_and_a_stopped_tailnet_is_named() {
        let mut d = sample(&["tailscale"], &["tailscale"]);
        d.probed = true;
        d.peers[0] = peer("bb22", "bob", vec![("tailscale", None)], &["tailscale"]);
        d.tailscale = Some(DiagTailscale {
            state: "stopped".into(),
            reason: Some("NeedsLogin".into()),
            since_secs: None,
            transitions: 1,
            candidates: 0,
        });
        let r = from_diag(&d, &HashMap::new());
        assert!(r.peers[0].reachable.is_empty(), "no rtt: not reachable");
        assert!(r.peers[0]
            .hints
            .iter()
            .any(|h| h.contains("the tailnet is stopped") && h.contains("tailscale up")));
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["peers"][0]["reachable"], serde_json::json!([]));
        assert!(json["bridging"].as_str().unwrap().contains("deferred"));
    }

    #[test]
    fn configured_but_not_running_is_reported_as_such() {
        let r = from_diag(
            &sample(&["local", "tailscale"], &["local"]),
            &HashMap::new(),
        );
        assert!(r.peers[1]
            .hints
            .iter()
            .any(|h| h.contains("mesh.tailscale is configured but not running")));
    }
}
