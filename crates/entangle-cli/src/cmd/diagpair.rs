//! `entangle diag pair` — what pairing can use on this host (spec §6.3).
//!
//! No daemon is needed (pairing does not use it either). The report checks,
//! live, the pieces `entangle pair` relies on and says what to do about each
//! one that fails:
//!
//! * **mDNS** (`mesh.local` discovery): browse for devices in pairing mode;
//! * **QUIC endpoint** (`mesh.iroh`, the pairing transport): bind one as
//!   `entangle pair` would, list the addresses it can be reached at and
//!   whether relay fallback is on;
//! * **Tailscale**: `tailscale status --json`, the version and its 1.62.0
//!   floor, the login profiles;
//! * the transports configured in `config.toml`, the pairing port, and the
//!   last pairing attempts (`pairing-attempts.json`, written by `entangle
//!   pair`).

use std::time::Duration;

use anyhow::Result;
use entangle_pairing::mesh::{
    discover_pairing_hosts, start_pairing_transport, PairingTransportExt as _,
};
use entangle_pairing::ShortFingerprint;
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use serde::Serialize;

use crate::cmd::pairlog;
use crate::config;

/// One check.
#[derive(Debug, Serialize)]
pub struct Check {
    /// `ok`, `failed`, `skipped` or `warning`.
    pub status: &'static str,
    /// What was found.
    pub detail: String,
}

impl Check {
    fn new(status: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
        }
    }
}

/// The QUIC endpoint check.
#[derive(Debug, Serialize)]
pub struct QuicCheck {
    /// The check.
    #[serde(flatten)]
    pub check: Check,
    /// `<pubkey-hex>@ip:port` addresses the endpoint was reachable at.
    pub addresses: Vec<String>,
    /// Whether relay fallback is on for pairing.
    pub relay: bool,
}

/// The Tailscale check.
#[derive(Debug, Serialize)]
pub struct TailscaleCheck {
    /// The check.
    #[serde(flatten)]
    pub check: Check,
    /// `tailscale version`, when it could be read.
    pub version: Option<String>,
    /// At least the supported minimum.
    pub version_supported: Option<bool>,
    /// `active`, `stopped` or `uninstalled`.
    pub state: String,
    /// The active tailnet's name.
    pub tailnet: Option<String>,
    /// Number of login profiles.
    pub profiles: usize,
}

/// The whole report (`--json`).
#[derive(Debug, Serialize)]
pub struct PairDiag {
    /// This device's label.
    pub label: String,
    /// Peer id (hex), when an identity exists.
    pub peer_id: Option<String>,
    /// Short fingerprint, when an identity exists.
    pub fingerprint: Option<String>,
    /// `SHA256:<hex>`, when an identity exists.
    pub sha256: Option<String>,
    /// `[mesh] transports` from config.toml.
    pub transports: Vec<String>,
    /// `[mesh.tailscale] enabled`.
    pub tailscale_enabled: bool,
    /// config.toml could not be read as the daemon reads it.
    pub config_error: Option<String>,
    /// mDNS browse.
    pub mdns: Check,
    /// QUIC endpoint.
    pub quic: QuicCheck,
    /// Tailnet.
    pub tailscale: TailscaleCheck,
    /// How the pairing port is chosen.
    pub pairing_port: String,
    /// The last attempts, newest first.
    pub last_attempts: Vec<pairlog::Attempt>,
    /// What to do.
    pub hints: Vec<String>,
}

/// How many recorded attempts the report shows.
const SHOWN_ATTEMPTS: usize = 5;

/// Build the report.
pub async fn build(mdns_secs: u64, no_mdns: bool, bind: Option<&str>) -> Result<PairDiag> {
    let identity = std::fs::read_to_string(config::identity_path())
        .ok()
        .and_then(|pem| IdentityKeyPair::from_pem(&pem).ok());
    let (peer_id, fingerprint, sha256) = match &identity {
        Some(kp) => {
            let pk = kp.public();
            (
                Some(PeerId::from_public_key_bytes(pk.as_bytes()).to_hex()),
                Some(ShortFingerprint::from_public_key(pk.as_bytes()).to_string()),
                Some(crate::cmd::pair::sha256_fingerprint(pk.as_bytes())),
            )
        }
        None => (None, None, None),
    };
    // A throw-away key when there is no identity: diag never creates one.
    let key = identity.unwrap_or_else(IdentityKeyPair::generate);
    let local_id = PeerId::from_public_key_bytes(key.public().as_bytes());

    let (cfg, config_error) = match entangle_bin::config::load_config(&config::config_path()) {
        Ok(c) => (c, None),
        Err(e) => (
            entangle_bin::config::Config::default(),
            Some(format!("{e:#}")),
        ),
    };
    let transports = cfg.mesh.transports.clone();
    let tailscale_enabled = entangle_bin::tailscale::enabled(&cfg.mesh);

    let mdns = if no_mdns {
        Check::new("skipped", "--no-mdns")
    } else {
        let window = Duration::from_secs(mdns_secs.clamp(1, 30));
        match discover_pairing_hosts(local_id, window).await {
            Ok(found) => Check::new(
                "ok",
                format!(
                    "browsed {}s: {} device(s) in pairing mode",
                    window.as_secs(),
                    found.len()
                ),
            ),
            Err(e) => Check::new("failed", format!("cannot browse: {e}")),
        }
    };

    let bind_raw = bind.unwrap_or(entangle_pairing::mesh::DEFAULT_PAIRING_BIND);
    let quic = match bind_raw.parse() {
        Err(e) => QuicCheck {
            check: Check::new("failed", format!("--bind {bind_raw}: {e}")),
            addresses: Vec::new(),
            relay: false,
        },
        Ok(addr) => match start_pairing_transport(&key, addr).await {
            Ok(t) => {
                let addresses = t.node_addrs();
                let relay = t.config().allow_derp_relay;
                t.shutdown().await;
                QuicCheck {
                    check: Check::new("ok", format!("bound {bind_raw}")),
                    addresses,
                    relay,
                }
            }
            Err(e) => QuicCheck {
                check: Check::new("failed", format!("cannot bind {bind_raw}: {e}")),
                addresses: Vec::new(),
                relay: false,
            },
        },
    };

    let cli = if cfg.mesh.tailscale.tailscale_cli.is_empty() {
        "tailscale".to_owned()
    } else {
        cfg.mesh.tailscale.tailscale_cli.clone()
    };
    let ts = crate::cmd::init::detect_tailscale(&cli).await;
    let version = ts.version.as_ref().ok().copied();
    let tailscale = TailscaleCheck {
        check: match (&ts.state, version) {
            (_, Some(v)) if !v.is_supported() => Check::new(
                "warning",
                format!(
                    "{}; below the supported minimum {}",
                    ts.summary(),
                    entangle_mesh_tailscale::MIN_SUPPORTED_VERSION
                ),
            ),
            (entangle_mesh_tailscale::TailnetState::Active, _) => Check::new("ok", ts.summary()),
            (entangle_mesh_tailscale::TailnetState::Uninstalled, _) => {
                Check::new("skipped", "tailscale is not installed")
            }
            _ => Check::new("warning", ts.summary()),
        },
        version: version.map(|v| v.to_string()),
        version_supported: version.map(|v| v.is_supported()),
        state: ts.state.label().to_owned(),
        tailnet: ts
            .status
            .as_ref()
            .and_then(|s| s.tailnet_name.clone())
            .or_else(|| {
                ts.profiles
                    .iter()
                    .find(|p| p.active)
                    .map(|p| p.tailnet.clone())
            }),
        profiles: ts.profiles.len(),
    };

    let mut last_attempts = pairlog::load(&pairlog::path_next_to(
        &config::entangle_dir().join("peers.toml"),
    ));
    last_attempts.reverse();
    last_attempts.truncate(SHOWN_ATTEMPTS);

    let mut report = PairDiag {
        label: config::device_label(),
        peer_id,
        fingerprint,
        sha256,
        transports,
        tailscale_enabled,
        config_error,
        mdns,
        quic,
        tailscale,
        pairing_port: "a random UDP port per run, printed by `entangle pair --print-code`; fix \
                       it with `entangle pair --print-code --bind 0.0.0.0:<port>` to allow it \
                       through a firewall"
            .to_owned(),
        last_attempts,
        hints: Vec::new(),
    };
    report.hints = hints(&report, &ts);
    Ok(report)
}

fn hints(r: &PairDiag, ts: &crate::cmd::init::TsReport) -> Vec<String> {
    let mut out = Vec::new();
    if r.peer_id.is_none() {
        out.push("no identity yet: `entangle init` creates one (`entangle pair` would too)".into());
    }
    if let Some(e) = &r.config_error {
        out.push(format!(
            "config.toml is invalid ({e}); fix it, then check it with `entangle config \
             validate`, which reads it as the daemon does"
        ));
    }
    if r.mdns.status == "failed" {
        out.push(
            "mDNS does not work here (multicast blocked?): pair with `entangle pair --peer \
             <address>` using a direct address the other device prints"
                .into(),
        );
    }
    if r.quic.check.status == "failed" {
        out.push(
            "pairing cannot open its QUIC endpoint: try another --bind address, or pair with \
             `entangle pair --manual` (copy-paste, no network)"
                .into(),
        );
    }
    if let Ok(v) = &ts.version {
        if let Err(e) = v.check_supported() {
            out.push(e.to_string());
        }
    }
    if ts.active() && !r.tailscale_enabled {
        out.push(
            "this host is on a tailnet: to pair across networks, give the other device's \
             tailnet address to `entangle pair --peer`; to carry work over the tailnet: \
             `entangle config set mesh.tailscale.enabled true`"
                .into(),
        );
    }
    if r.tailscale_enabled && !ts.active() {
        out.push(format!(
            "mesh.tailscale is enabled but the tailnet is not active ({}): run `tailscale up`",
            ts.state
        ));
    }
    if r.transports.is_empty() {
        out.push(
            "no transport is configured: pairing works (it opens its own endpoint), but paired \
             devices reach each other only once one is, e.g. `entangle config set \
             mesh.local.enabled true` and `entangle config set mesh.iroh.enabled true`"
                .into(),
        );
    }
    if let Some(last) = r.last_attempts.first() {
        if last.outcome != "paired" {
            out.push(
                "the last pairing attempt failed; its steps are listed above. Run this on the \
                 other device too and compare."
                    .into(),
            );
        }
    }
    out
}

/// Render the report for a terminal.
pub fn render_text(r: &PairDiag) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Pairing diagnostics for {} ({})",
        r.label,
        r.peer_id.as_deref().unwrap_or("no identity yet")
    );
    if let (Some(fp), Some(sha)) = (&r.fingerprint, &r.sha256) {
        let _ = writeln!(out, "  fingerprint: {fp}\n  {sha}");
    }
    let transports = if r.transports.is_empty() {
        "(none)".to_owned()
    } else {
        r.transports.join(", ")
    };
    let _ = writeln!(
        out,
        "\nConfigured transports: {transports} (mesh.tailscale {})",
        if r.tailscale_enabled { "on" } else { "off" }
    );
    if let Some(e) = &r.config_error {
        let _ = writeln!(out, "  ! config.toml: {e}");
    }
    let line = |out: &mut String, name: &str, c: &Check| {
        let _ = writeln!(out, "  {name:<24} {:<8} {}", c.status, c.detail);
    };
    let _ = writeln!(out, "\nChecks");
    line(&mut out, "mDNS (mesh.local)", &r.mdns);
    line(&mut out, "QUIC endpoint (iroh)", &r.quic.check);
    for a in &r.quic.addresses {
        let _ = writeln!(out, "  {:<24}          reachable at {a}", "");
    }
    if r.quic.check.status == "ok" {
        let _ = writeln!(
            out,
            "  {:<24}          relay fallback {}",
            "",
            if r.quic.relay { "on" } else { "off" }
        );
    }
    line(&mut out, "Tailscale", &r.tailscale.check);
    let _ = writeln!(out, "\nPairing port: {}", r.pairing_port);

    let _ = writeln!(out, "\nLast pairing attempts (newest first)");
    if r.last_attempts.is_empty() {
        let _ = writeln!(out, "  (none recorded)");
    }
    let now = pairlog::now();
    for a in &r.last_attempts {
        let _ = writeln!(
            out,
            "  {}s ago  {:<10}  {}{}",
            now.saturating_sub(a.at_unix),
            a.role,
            a.outcome,
            a.peer
                .as_deref()
                .map(|p| format!("  with {p}"))
                .unwrap_or_default()
        );
        for t in &a.tried {
            let _ = writeln!(
                out,
                "      tried {}: {} -> {}",
                t.transport, t.target, t.result
            );
        }
        if let Some(e) = &a.error {
            let first = e.lines().next().unwrap_or("");
            let _ = writeln!(out, "      error: {first}");
        }
    }
    if !r.hints.is_empty() {
        let _ = writeln!(out, "\nHints");
        for h in &r.hints {
            let _ = writeln!(out, "  - {h}");
        }
    }
    out
}

/// `entangle diag pair`.
pub async fn run(json: bool, mdns_secs: u64, no_mdns: bool, bind: Option<&str>) -> Result<()> {
    let report = build(mdns_secs, no_mdns, bind).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_text(&report));
    }
    Ok(())
}
