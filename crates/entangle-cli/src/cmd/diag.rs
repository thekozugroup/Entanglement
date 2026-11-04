//! `entangle diag` — operator triage reports (spec §9.6).
//!
//! `entangle diag mesh` asks the running daemon for its view of the mesh:
//! configured and running transports, the addresses it can be reached at, the
//! tailnet state, and for every trusted peer each path a transport knows.
//! `--probe` additionally measures a round trip to each trusted peer.
//!
//! `entangle diag pair` needs no daemon: it checks what `entangle pair` can
//! use on this host (spec §6.3 "No reachability … suggests `entangle diag
//! pair`") — mDNS browsing, a QUIC endpoint and its relay setting, the
//! tailnet, the configured transports — and shows the last pairing
//! attempts.

use clap::{Args, Subcommand};
use entangle_rpc::methods::{DiagMeshParams, DiagMeshResult};
use entangle_rpc::{Client as RpcClient, RpcError};
use std::fmt::Write as _;

use crate::daemon_not_running_error;

/// Arguments for the `diag` top-level subcommand.
#[derive(Args)]
pub struct DiagArgs {
    #[command(subcommand)]
    pub cmd: DiagCmd,
}

/// `entangle diag` subcommands.
#[derive(Subcommand)]
pub enum DiagCmd {
    /// Mesh triage: transports, local endpoints, trusted peers and how each is reachable.
    Mesh {
        /// Emit machine-readable JSON instead of the text report.
        #[arg(long)]
        json: bool,
        /// Measure a round trip to each trusted peer through the daemon.
        #[arg(long)]
        probe: bool,
        /// Per-peer probe timeout in milliseconds.
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,
    },
    /// What pairing can use on this host: mDNS, QUIC endpoint and relay,
    /// tailnet, configured transports, and the last pairing attempts.
    Pair {
        /// Emit machine-readable JSON instead of the text report.
        #[arg(long)]
        json: bool,
        /// Seconds to browse mDNS for devices in pairing mode.
        #[arg(long, default_value_t = 2)]
        mdns_secs: u64,
        /// Skip the mDNS check.
        #[arg(long)]
        no_mdns: bool,
        /// Bind the test QUIC endpoint here (default 0.0.0.0:0, as `entangle pair`).
        #[arg(long, value_name = "ADDR")]
        bind: Option<String>,
    },
}

pub async fn run(args: DiagArgs) -> anyhow::Result<()> {
    match args.cmd {
        DiagCmd::Mesh {
            json,
            probe,
            timeout_ms,
        } => mesh(json, probe, timeout_ms).await,
        DiagCmd::Pair {
            json,
            mdns_secs,
            no_mdns,
            bind,
        } => crate::cmd::diagpair::run(json, mdns_secs, no_mdns, bind.as_deref()).await,
    }
}

async fn mesh(json: bool, probe: bool, timeout_ms: u64) -> anyhow::Result<()> {
    let client = RpcClient::new(RpcClient::default_socket());
    let report = match client
        .diag_mesh(DiagMeshParams {
            probe,
            probe_timeout_ms: timeout_ms,
        })
        .await
    {
        Ok(r) => r,
        Err(RpcError::DaemonNotRunning(_)) => return Err(daemon_not_running_error()),
        Err(e) => return Err(e.into()),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_text(&report));
    }
    Ok(())
}

/// Render the report for a terminal.
pub fn render_text(r: &DiagMeshResult) -> String {
    let mut out = String::new();
    // Writing to a String cannot fail.
    let _ = writeln!(
        out,
        "Mesh diagnostics for {} ({})",
        r.local_display_name, r.local_peer_id
    );

    let list = |v: &[String]| {
        if v.is_empty() {
            "(none)".to_owned()
        } else {
            v.join(", ")
        }
    };
    let _ = writeln!(out, "\nTransports");
    let _ = writeln!(out, "  configured: {}", list(&r.transports_configured));
    let _ = writeln!(out, "  running:    {}", list(&r.transports_active));
    for t in &r.transports_configured {
        let running = r.transports_active.iter().any(|a| a == t);
        if !running {
            let _ = writeln!(
                out,
                "  ! {t} is configured but not running (see the daemon log for why)"
            );
        }
    }

    let _ = writeln!(out, "\nLocal endpoints");
    if r.endpoints.is_empty() {
        let _ = writeln!(out, "  (none)");
    }
    for e in &r.endpoints {
        let _ = writeln!(out, "  {:<10}  {}", e.transport, e.address);
    }

    if let Some(ts) = &r.tailscale {
        let _ = write!(out, "\nTailscale\n  state: {}", ts.state);
        if let Some(reason) = &ts.reason {
            let _ = write!(out, " ({reason})");
        }
        if let Some(secs) = ts.since_secs {
            let _ = write!(out, ", for {secs}s");
        }
        let _ = writeln!(
            out,
            "; {} transition(s); {} peer candidate(s)",
            ts.transitions, ts.candidates
        );
        if ts.state != "active" {
            let _ = writeln!(
                out,
                "  ! the tailnet is not active, so no peer is reachable over mesh.tailscale"
            );
        }
    }

    let _ = writeln!(out, "\nTrusted peers ({})", r.peers.len());
    if r.peers.is_empty() {
        let _ = writeln!(out, "  (none) — pair a device with `entangle pair`");
    }
    for p in &r.peers {
        let name = if p.display_name.is_empty() {
            "(unnamed)"
        } else {
            &p.display_name
        };
        let _ = writeln!(out, "  {name}  {}  [{}]", p.peer_id, p.trust);
        if p.paths.is_empty() {
            let _ = writeln!(
                out,
                "    no path: no transport currently knows how to reach this peer"
            );
            let _ = writeln!(out, "    {}", hint_for_unreachable(r));
        }
        for path in &p.paths {
            let addr = path.address.as_deref().unwrap_or("-");
            let _ = write!(
                out,
                "    {:<9}  {addr:<24}  {}",
                path.transport, path.detail
            );
            match (path.rtt_ms, &path.probe_error) {
                (Some(ms), None) => {
                    let _ = write!(out, "  rtt {ms:.1} ms");
                }
                (Some(ms), Some(why)) => {
                    let _ = write!(out, "  rtt {ms:.1} ms, but: {why}");
                }
                (None, Some(why)) => {
                    let _ = write!(out, "  probe failed: {why}");
                }
                (None, None) => {}
            }
            let _ = writeln!(out);
        }
        if let Some(route) = &p.route {
            let order = if route.order.is_empty() {
                "none (no usable transport)".to_owned()
            } else {
                route.order.join(" -> ")
            };
            let _ = write!(out, "    route: {order}");
            if route.overridden {
                let _ = write!(out, "  [mesh.overrides]");
            }
            match (&route.last_used, route.last_used_secs) {
                (Some(t), Some(secs)) => {
                    let _ = write!(out, "  (last used: {t}, {secs}s ago)");
                }
                (Some(t), None) => {
                    let _ = write!(out, "  (last used: {t})");
                }
                _ => {}
            }
            let _ = writeln!(out);
            for skip in &route.skipped {
                let _ = writeln!(out, "      skipped {skip}");
            }
        }
    }
    if r.probed {
        let reachable = r
            .peers
            .iter()
            .filter(|p| {
                p.paths
                    .iter()
                    .any(|x| x.rtt_ms.is_some() && x.probe_error.is_none())
            })
            .count();
        let _ = writeln!(
            out,
            "\nProbe: {reachable} of {} trusted peer(s) answered",
            r.peers.len()
        );
    }
    if r.untrusted_sightings > 0 {
        let _ = writeln!(
            out,
            "\n{} untrusted mDNS sighting(s) (see `entangle mesh peers`)",
            r.untrusted_sightings
        );
    }
    out
}

/// What to try when a trusted peer has no known path.
fn hint_for_unreachable(r: &DiagMeshResult) -> String {
    let has = |t: &str| r.transports_configured.iter().any(|x| x == t);
    let mut tips = Vec::new();
    if !has("local") && !has("iroh") && !has("tailscale") {
        tips.push("no transport is configured: set [mesh] transports".to_owned());
    }
    if has("local") {
        tips.push("is the peer on the same LAN with mDNS allowed?".to_owned());
    }
    if has("iroh") {
        tips.push("add its address under [scheduler] peers".to_owned());
    }
    if has("tailscale") {
        tips.push("is it online in the tailnet and running entangled?".to_owned());
    }
    format!("hint: {}", tips.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_rpc::methods::{DiagEndpoint, DiagPath, DiagPeer, DiagRoute, DiagTailscale};

    fn sample() -> DiagMeshResult {
        DiagMeshResult {
            local_peer_id: "aa11".into(),
            local_display_name: "laptop".into(),
            transports_configured: vec!["local".into(), "iroh".into(), "tailscale".into()],
            transports_active: vec!["local".into(), "iroh".into()],
            endpoints: vec![DiagEndpoint {
                transport: "iroh".into(),
                address: "10.0.0.2:41641".into(),
            }],
            tailscale: Some(DiagTailscale {
                state: "stopped".into(),
                reason: Some("NeedsLogin".into()),
                since_secs: Some(12),
                transitions: 2,
                candidates: 0,
            }),
            peers: vec![
                DiagPeer {
                    peer_id: "bb22".into(),
                    display_name: "desk".into(),
                    trust: "trusted".into(),
                    paths: vec![DiagPath {
                        transport: "iroh".into(),
                        address: Some("10.0.0.9:41641".into()),
                        detail: "address book".into(),
                        rtt_ms: Some(4.25),
                        probe_error: None,
                    }],
                    route: Some(DiagRoute {
                        order: vec!["iroh".into()],
                        skipped: vec!["tailscale: tailnet stopped (NeedsLogin)".into()],
                        last_used: Some("iroh".into()),
                        last_used_secs: Some(3),
                        overridden: false,
                    }),
                },
                DiagPeer {
                    peer_id: "cc33".into(),
                    display_name: String::new(),
                    trust: "observer".into(),
                    paths: vec![],
                    route: None,
                },
            ],
            untrusted_sightings: 1,
            probed: true,
        }
    }

    #[test]
    fn text_report_covers_every_section() {
        let t = render_text(&sample());
        for needle in [
            "Mesh diagnostics for laptop (aa11)",
            "configured: local, iroh, tailscale",
            "running:    local, iroh",
            "! tailscale is configured but not running",
            "10.0.0.2:41641",
            "state: stopped (NeedsLogin), for 12s",
            "the tailnet is not active",
            "Trusted peers (2)",
            "desk  bb22  [trusted]",
            "rtt 4.2 ms",
            "(unnamed)  cc33  [observer]",
            "no path: no transport currently knows",
            "[scheduler] peers",
            "Probe: 1 of 2 trusted peer(s) answered",
            "1 untrusted mDNS sighting(s)",
            "route: iroh  (last used: iroh, 3s ago)",
            "skipped tailscale: tailnet stopped (NeedsLogin)",
        ] {
            assert!(t.contains(needle), "missing {needle:?} in:\n{t}");
        }
    }
}
