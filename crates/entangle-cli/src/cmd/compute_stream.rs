//! `entangle compute stream` — run a streaming task and write its chunks to
//! stdout as they arrive (spec §7.1).
//!
//! # Direct, not through the daemon
//!
//! Unlike `compute dispatch`, this command does **not** go through the
//! running `entangled`. It is itself the submitter: it opens its own
//! `mesh.iroh` endpoint with the node identity (`~/.entangle/identity.key`)
//! and dials the executor under `entangle/stream/1`. Why:
//!
//! * **End-to-end backpressure.** Credit is granted as *this process*
//!   consumes chunks — i.e. as fast as stdout drains. Relaying through the
//!   daemon would put a second buffer and a second flow-control layer
//!   between the executor and the terminal: the daemon's RPC
//!   (`entangle-rpc`) is one JSON request / one JSON response, with no
//!   server push, so the daemon would have to buffer the stream or
//!   re-implement credit over polling. Either way the executor would be
//!   paced by the daemon, not by the reader.
//! * **Attribution where it is used.** Each chunk is verified against the
//!   executor's transport-authenticated key in the process that prints it,
//!   and `--json` reports that per chunk.
//! * **Same identity, same trust.** The executor admits peers by `PeerId`;
//!   using the node identity means the executor's allowlist entry for this
//!   node covers the CLI too. The command dispatches only to peers this
//!   node has paired with (`~/.entangle/peers.toml`), like the daemon.
//!
//! The cost is that the CLI needs the identity key (the same file the
//! daemon reads, readable only by its owner) and its own sockets while the
//! stream runs.
//!
//! # Choosing a transport
//!
//! The executor is reached through the scheduler's [`TransportRouter`],
//! built by the same [`build_router`] the daemon's dispatcher uses, from the
//! same `config.toml` (spec §6.1): candidates in the order `local` →
//! `tailscale` → `iroh`, `[mesh] preferred` first, a `[mesh.overrides]`
//! entry for the peer as the exact list; a candidate that fails to
//! *connect* falls back to the next one, and nothing is retried once the
//! stream's `Open` frame may have been sent. The CLI starts only what the
//! order for this peer can use:
//!
//! * `local` — `"local"` in `[mesh] transports`: a short mDNS browse for the
//!   peer's LAN sighting (its advertised key and mesh port), dialled over
//!   this process's iroh endpoint;
//! * `tailscale` — `[mesh.tailscale] enabled` and `"tailscale"` listed: one
//!   `tailscale status` and one discovery round on `[mesh.tailscale] port`,
//!   dialled from a client-only tailnet transport (its listener is bound to
//!   loopback and serves nothing);
//! * `iroh` — the peer has a long address (`--peer <key>@host:port`, or its
//!   `[scheduler] peers` entry), as before.
//!
//! Without `--peer`, `--allow-local` runs the plugin in this process — the
//! same protocol over an in-memory stream, chunks signed by the node
//! identity (or a throwaway key if there is none).

use std::io::Write as _;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use std::time::Duration;

use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::Args;
use entangle_mesh_iroh::{parse_node_addr, IrohPeer, MeshIroh, MeshIrohConfig, ALPN_STREAM};
use entangle_mesh_tailscale::{
    LivenessSnapshot, MeshTailscale, MeshTailscaleConfig, StaticAllowlist as TailnetAllowlist,
};
use entangle_peers::{PeerStore, TrustLevel};
use entangle_runtime::Kernel;
use entangle_scheduler::stream::{
    ChunkPoll, StreamError, StreamHandle, StreamOptions, StreamServer, TRUSTED_EXECUTOR_HINT,
};
use entangle_scheduler::transport::{build_router, RouterInputs};
use entangle_scheduler::{
    HeldToken, PeerDirectory, RoutePolicy, StaticAllowlist, StaticTokens, TransportKind,
    TransportRouter,
};
use entangle_signing::{IdentityKeyPair, Keyring};
use entangle_types::{
    peer_id::PeerId,
    plugin_id::PluginId,
    task::{IntegrityPolicy, PartialResultPolicy, StreamingTask},
};
use tokio::sync::watch;

use crate::config;

/// `entangle compute stream` flags.
#[derive(Args)]
pub struct StreamArgs {
    /// Stream plugin ID in `<publisher>/<name>@<version>` format.
    pub plugin_id: String,

    /// Inline initial input (UTF-8). Mutually exclusive with --input-file.
    #[arg(long, conflicts_with = "input_file")]
    pub input: Option<String>,

    /// Path to a file whose contents are the initial input.
    #[arg(long, conflicts_with = "input")]
    pub input_file: Option<String>,

    /// The executor: a peer id, or a long address `<pubkey-hex>@host:port`.
    /// It is reached over the transports ~/.entangle/config.toml enables, in
    /// the daemon's order (`[mesh] preferred`, `[mesh.overrides]`); its iroh
    /// address comes from the long address or `[scheduler] peers`. The peer
    /// must be paired (`entangle mesh trust`). Omit it, with --allow-local,
    /// to run the plugin in this process.
    #[arg(long)]
    pub peer: Option<String>,

    /// Integrity policy: none | trusted-executor. Streams cannot be
    /// replicated, so deterministic and semantic-equivalent are refused.
    #[arg(long, default_value = "none")]
    pub integrity: String,

    /// trusted-executor: peer ids the executor must be one of. May be repeated.
    #[arg(long = "allow")]
    pub allow: Vec<String>,

    /// What an interrupted stream leaves: keep | keep-signed | discard.
    /// `discard` holds all output back until the stream completes.
    #[arg(long, default_value = "keep")]
    pub partial: String,

    /// Wall-clock timeout for the whole stream, in milliseconds.
    #[arg(long, default_value_t = StreamingTask::DEFAULT_TIMEOUT_MS)]
    pub timeout_ms: u64,

    /// Credit window: chunks the executor may send ahead of this reader.
    #[arg(long, default_value_t = 16)]
    pub credit_window: u32,

    /// --allow-local only: the plugin's signed package directory. Defaults to
    /// `~/.entangle/plugins/<plugin-name>`.
    #[arg(long)]
    pub plugin_dir: Option<PathBuf>,

    /// Write one JSON object per chunk (seq, bytes, text/base64, signature
    /// status) and a final status object, instead of the raw bytes.
    #[arg(long)]
    pub json: bool,
}

fn parse_partial(s: &str) -> anyhow::Result<PartialResultPolicy> {
    match s {
        "keep" => Ok(PartialResultPolicy::Keep),
        "keep-signed" => Ok(PartialResultPolicy::KeepSigned),
        "discard" => Ok(PartialResultPolicy::Discard),
        other => {
            anyhow::bail!("unknown --partial '{other}'; expected keep, keep-signed or discard")
        }
    }
}

fn parse_integrity(a: &StreamArgs) -> anyhow::Result<IntegrityPolicy> {
    match a.integrity.as_str() {
        "none" => {
            if !a.allow.is_empty() {
                anyhow::bail!("--allow only applies with --integrity trusted-executor");
            }
            Ok(IntegrityPolicy::None)
        }
        "trusted-executor" => {
            let allowlist = a
                .allow
                .iter()
                .map(|h| {
                    PeerId::from_hex(h)
                        .map_err(|e| anyhow::anyhow!("invalid --allow peer id '{h}': {e}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            if allowlist.is_empty() {
                anyhow::bail!("--integrity trusted-executor needs at least one --allow <peer-id>");
            }
            Ok(IntegrityPolicy::TrustedExecutor { allowlist })
        }
        // Let the scheduler's own submit-time check explain the refusal
        // (ENTANGLE-E0350, ATC-INT-4), so the CLI says exactly what the
        // library would.
        "deterministic" => Ok(IntegrityPolicy::Deterministic { replicas: 3 }),
        other => anyhow::bail!(
            "--integrity {other} cannot be used for a stream; streams accept none or \
             trusted-executor. hint: {TRUSTED_EXECUTOR_HINT}"
        ),
    }
}

fn read_input(a: &StreamArgs) -> anyhow::Result<Vec<u8>> {
    Ok(match (a.input.as_deref(), a.input_file.as_deref()) {
        (Some(s), _) => s.as_bytes().to_vec(),
        (_, Some(path)) => {
            std::fs::read(path).with_context(|| format!("reading --input-file {path}"))?
        }
        (None, None) => Vec::new(),
    })
}

/// The node identity, if this machine has one.
fn node_identity() -> anyhow::Result<Option<IdentityKeyPair>> {
    let path = config::identity_path();
    if !path.exists() {
        return Ok(None);
    }
    let pem =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let key = IdentityKeyPair::from_pem(&pem)
        .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
    Ok(Some(key))
}

/// The raw `~/.entangle/config.toml`, read leniently: this command needs
/// only `[mesh]` and `[scheduler]` (the daemon's routing settings), which the
/// CLI's own schema does not fully model.
fn raw_config() -> anyhow::Result<toml::Value> {
    let path = config::config_path();
    if !path.exists() {
        return Ok(toml::Value::Table(Default::default()));
    }
    let text = std::fs::read_to_string(&path)?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// How long a `local` lookup listens for the peer's mDNS sighting.
const LAN_BROWSE: Duration = Duration::from_millis(1500);

/// The most one tailnet discovery round may take.
const TAILNET_DISCOVERY: Duration = Duration::from_secs(8);

/// The daemon's routing settings, as `config.toml` gives them.
#[derive(Clone, Debug, Default)]
struct Routing {
    /// `[mesh] transports`.
    transports: Vec<String>,
    /// `[mesh] preferred` and `[mesh.overrides]`, validated as the daemon
    /// validates them (`ENTANGLE-E0434` / `E0435`).
    policy: RoutePolicy,
    /// `[scheduler] peers`.
    book: Vec<IrohPeer>,
    /// `[scheduler] relay` (default `true`).
    relay: bool,
    /// `[mesh.tailscale]`, when the tailnet transport is on (enabled **and**
    /// listed in `transports`, as for the daemon).
    tailnet: Option<TailnetSettings>,
}

/// What a client-only tailnet transport needs.
#[derive(Clone, Debug)]
struct TailnetSettings {
    /// `[mesh.tailscale] port`: where peers' listeners are probed.
    port: u16,
    /// `[mesh.tailscale] tailscale-cli` (empty: `tailscale` on `$PATH`).
    cli: String,
}

impl Routing {
    fn from_config(cfg: &toml::Value) -> anyhow::Result<Self> {
        let mesh = cfg.get("mesh");
        let transports: Vec<String> = mesh
            .and_then(|m| m.get("transports"))
            .and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let preferred = mesh
            .and_then(|m| m.get("preferred"))
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| anyhow::anyhow!("[mesh] preferred must be a transport name"))
            })
            .transpose()?;
        let mut overrides: Vec<(&str, Vec<&str>)> = Vec::new();
        if let Some(table) = mesh
            .and_then(|m| m.get("overrides"))
            .and_then(toml::Value::as_table)
        {
            for (key, value) in table {
                let names = match value {
                    toml::Value::String(one) => vec![one.as_str()],
                    toml::Value::Array(list) => list
                        .iter()
                        .map(|v| {
                            v.as_str().ok_or_else(|| {
                                anyhow::anyhow!("[mesh.overrides] {key:?}: not a transport name")
                            })
                        })
                        .collect::<anyhow::Result<_>>()?,
                    _ => anyhow::bail!(
                        "[mesh.overrides] {key:?}: expected a transport name or a list of them"
                    ),
                };
                overrides.push((key.as_str(), names));
            }
        }
        let policy = RoutePolicy::from_names(preferred, overrides)
            .context("[mesh] preferred / [mesh.overrides] in ~/.entangle/config.toml")?;

        let scheduler = cfg.get("scheduler");
        let book = scheduler
            .and_then(|s| s.get("peers"))
            .and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(toml::Value::as_str)
                    .filter_map(|s| parse_node_addr(s).ok())
                    .collect()
            })
            .unwrap_or_default();
        let relay = scheduler
            .and_then(|s| s.get("relay"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(true);

        let section = mesh.and_then(|m| m.get("tailscale"));
        let enabled = section
            .and_then(|t| t.get("enabled"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        let tailnet =
            (enabled && transports.iter().any(|t| t == "tailscale")).then(|| TailnetSettings {
                port: section
                    .and_then(|t| t.get("port"))
                    .and_then(toml::Value::as_integer)
                    .and_then(|p| u16::try_from(p).ok())
                    .unwrap_or(entangle_mesh_tailscale::DEFAULT_PORT),
                cli: section
                    .and_then(|t| t.get("tailscale-cli"))
                    .and_then(toml::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            });
        Ok(Self {
            transports,
            policy,
            book,
            relay,
            tailnet,
        })
    }

    /// Whether `local` may carry a stream to `peer` (`"local"` enabled and
    /// in the peer's order).
    fn wants_local(&self, peer: &PeerId) -> bool {
        self.transports.iter().any(|t| t == "local")
            && self.policy.order_for(peer).contains(&TransportKind::Local)
    }

    /// Whether `tailscale` may carry a stream to `peer`.
    fn wants_tailnet(&self, peer: &PeerId) -> bool {
        self.tailnet.is_some()
            && self
                .policy
                .order_for(peer)
                .contains(&TransportKind::Tailscale)
    }

    /// Whether `iroh` may carry a stream to `peer`, whose long address is
    /// `address`.
    fn wants_iroh(&self, peer: &PeerId, address: Option<&IrohPeer>) -> bool {
        address.is_some() && self.policy.order_for(peer).contains(&TransportKind::Iroh)
    }
}

/// `--peer` as the executor's id plus its iroh address, when the flag (a
/// long address) or `[scheduler] peers` gives one.
fn resolve_target(spec: &str, routing: &Routing) -> anyhow::Result<(PeerId, Option<IrohPeer>)> {
    if spec.contains('@') {
        let peer = parse_node_addr(spec).map_err(|e| anyhow::anyhow!("--peer {spec}: {e}"))?;
        return Ok((peer.peer_id, Some(peer)));
    }
    let id = PeerId::from_hex(spec).map_err(|e| {
        anyhow::anyhow!("--peer must be a peer id or <pubkey-hex>@host:port, got '{spec}': {e}")
    })?;
    Ok((id, routing.book.iter().find(|p| p.peer_id == id).cloned()))
}

/// The transports one run dials with; each is optional.
#[derive(Default)]
struct Dialers {
    /// This process's iroh endpoint (carries `local` and `iroh`).
    iroh: Option<Arc<MeshIroh>>,
    /// The peer's LAN sighting, as a `local` dial target.
    sightings: Option<PeerDirectory>,
    /// The client-only tailnet transport and the tailnet state it saw.
    tailscale: Option<(MeshTailscale, watch::Receiver<LivenessSnapshot>)>,
    /// Why a transport this run wanted did not start (shown if the stream
    /// cannot be opened).
    notes: Vec<String>,
}

impl Dialers {
    async fn shutdown(&self) {
        use entangle_mesh_iroh::MeshTransport as _;
        if let Some(iroh) = &self.iroh {
            iroh.shutdown().await;
        }
        if let Some((tailnet, _)) = &self.tailscale {
            tailnet.shutdown().await;
        }
    }
}

/// Start what `routing` can use to reach `peer` (see the module docs).
async fn start_dialers(
    identity: &IdentityKeyPair,
    store: &PeerStore,
    routing: &Routing,
    peer: PeerId,
    address: Option<&IrohPeer>,
) -> Dialers {
    let mut dialers = Dialers::default();
    let tailnet = async {
        match &routing.tailnet {
            Some(settings) if routing.wants_tailnet(&peer) => {
                Some(start_tailnet(identity, settings).await)
            }
            _ => None,
        }
    };
    let lan = async {
        if routing.wants_local(&peer) {
            Some(browse_lan(peer, store).await)
        } else {
            None
        }
    };
    let (tailnet, lan) = tokio::join!(tailnet, lan);
    match tailnet {
        Some(Ok(t)) => dialers.tailscale = Some(t),
        Some(Err(why)) => dialers.notes.push(format!("tailscale: {why}")),
        None => {}
    }
    match lan {
        Some(Ok(sightings)) => dialers.sightings = Some(sightings),
        Some(Err(why)) => dialers.notes.push(format!("local: {why}")),
        None => {}
    }
    let lan_route = dialers
        .sightings
        .as_ref()
        .is_some_and(|s| s.peers().contains(&peer));
    if routing.wants_iroh(&peer, address) || lan_route {
        let config = MeshIrohConfig {
            alpn: ALPN_STREAM.to_vec(),
            allow_derp_relay: routing.relay,
            ..MeshIrohConfig::default()
        };
        match MeshIroh::start(config, identity).await {
            Ok(iroh) => dialers.iroh = Some(Arc::new(iroh)),
            Err(e) => dialers
                .notes
                .push(format!("iroh: the endpoint did not start: {e}")),
        }
    }
    dialers
}

/// A client-only tailnet transport (listener on loopback, serving nothing),
/// the tailnet state from one `tailscale status`, and — while the tailnet
/// is active — one discovery round on the configured port.
async fn start_tailnet(
    identity: &IdentityKeyPair,
    settings: &TailnetSettings,
) -> Result<(MeshTailscale, watch::Receiver<LivenessSnapshot>), String> {
    let config = MeshTailscaleConfig {
        tailscale_cli: settings.cli.clone(),
        allowlist: Some(Arc::new(TailnetAllowlist::new(Vec::<PeerId>::new()))),
        port: 0,
        bind_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        max_frame_bytes: entangle_mesh_iroh::MAX_FRAME_BYTES,
        ..MeshTailscaleConfig::default()
    };
    let status = config
        .status_source()
        .fetch_status()
        .await
        .map_err(|e| format!("`tailscale status` failed: {e}"))?;
    let transport = MeshTailscale::start(identity, config)
        .await
        .map_err(|e| format!("the client transport did not start: {e}"))?;
    let state = status.classify();
    if matches!(state, entangle_mesh_tailscale::TailnetState::Active)
        && tokio::time::timeout(
            TAILNET_DISCOVERY,
            transport.discover_on_port(&status, settings.port),
        )
        .await
        .is_err()
    {
        tracing::debug!("tailnet discovery did not finish in time");
    }
    let (_, liveness) = watch::channel(LivenessSnapshot {
        state: Some(state),
        since: None,
        transitions: 1,
    });
    Ok((transport, liveness))
}

/// Listen on mDNS for `peer`'s sighting for up to [`LAN_BROWSE`]: its route
/// (advertised key, every resolved address on its mesh port) if it is
/// trusted and dialable.
async fn browse_lan(peer: PeerId, store: &PeerStore) -> Result<PeerDirectory, String> {
    use entangle_mesh_local::{Discovery, DiscoveryConfig, DiscoveryEvent};
    use tokio::sync::broadcast::error::RecvError;
    let discovery = Discovery::new(DiscoveryConfig::default()).map_err(|e| e.to_string())?;
    let mut events = discovery.subscribe();
    discovery.spawn_browser().map_err(|e| e.to_string())?;
    let found = tokio::time::timeout(LAN_BROWSE, async {
        loop {
            match events.recv().await {
                Ok(DiscoveryEvent::PeerAppeared(seen) | DiscoveryEvent::PeerUpdated(seen))
                    if seen.peer_id == peer =>
                {
                    if let Some(route) = lan_route(&seen) {
                        return Some(route);
                    }
                }
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten();
    let _ = discovery.shutdown();
    let sightings = PeerDirectory::new();
    let trusted = matches!(store.get(&peer), Some(p) if p.trust != TrustLevel::Revoked);
    if let Some(route) = found.filter(|_| trusted) {
        sightings.insert(route);
    }
    Ok(sightings)
}

/// The `local` dial target a sighting gives (the daemon's rule): its
/// advertised key and every resolved address on its advertised mesh port.
fn lan_route(seen: &entangle_mesh_local::PeerSeen) -> Option<IrohPeer> {
    let key = seen.public_key?;
    let mut addrs = seen.dial_targets().into_iter();
    let first = addrs.next()?;
    Some(addrs.fold(IrohPeer::new(key, first), IrohPeer::with_addr))
}

/// The router this run dials through: the daemon's [`build_router`] over
/// `dialers`, with `routing`'s policy and address book (plus `address`).
fn stream_router(
    local: PeerId,
    routing: &Routing,
    address: Option<&IrohPeer>,
    dialers: &Dialers,
    tokens: StaticTokens,
) -> Option<TransportRouter> {
    let book = PeerDirectory::new();
    for entry in routing.book.iter().chain(address) {
        book.insert(entry.clone());
    }
    build_router(
        local,
        RouterInputs {
            iroh: dialers.iroh.clone(),
            iroh_directory: Some(book),
            local_sightings: dialers.sightings.clone(),
            tailscale: dialers.tailscale.clone(),
            policy: routing.policy.clone(),
            metrics: None,
            capability_tokens: Some(Arc::new(tokens)),
        },
    )
}

/// Open `task` on `peer` through `router`; also returns the transport that
/// carried it.
async fn open_routed(
    router: &TransportRouter,
    peer: PeerId,
    task: &StreamingTask,
) -> Result<(StreamHandle, Option<TransportKind>), StreamError> {
    let handle = router
        .open_stream(peer, task, StreamOptions::default())
        .await?;
    Ok((handle, router.last_route(&peer).map(|r| r.transport)))
}

pub async fn run(a: StreamArgs) -> anyhow::Result<()> {
    let plugin =
        PluginId::from_str(&a.plugin_id).map_err(|e| anyhow::anyhow!("invalid plugin id: {e}"))?;
    let mut task = StreamingTask::with_defaults(plugin.clone(), read_input(&a)?);
    task.integrity = parse_integrity(&a)?;
    task.partial_result = parse_partial(&a.partial)?;
    // Text mode prints raw bytes, which carry no signatures: `keep-signed`
    // would keep nothing `keep` does not. The signatures are in `--json`.
    if task.partial_result == PartialResultPolicy::KeepSigned && !a.json {
        anyhow::bail!(
            "--partial keep-signed needs --json: the plain byte output carries no signatures,              so nothing attributable would be kept (use --partial keep for the bytes alone)"
        );
    }
    task.timeout_ms = a.timeout_ms;
    task.channel.credit_window = a.credit_window;
    // ATC-INT-4: refused here, before any socket is opened.
    entangle_scheduler::validate_stream_submit(&task)?;

    match &a.peer {
        Some(spec) => run_remote(&a, &task, spec).await,
        None if allow_local() => run_local(&a, &task, &plugin).await,
        None => anyhow::bail!(
            "entangle compute stream runs directly against an executor (not through the \
             daemon): pass --peer <peer-id|pubkey-hex@host:port>, or --allow-local to run the \
             plugin in this process"
        ),
    }
}

fn allow_local() -> bool {
    std::env::var("ENTANGLE_ALLOW_LOCAL")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

async fn run_remote(a: &StreamArgs, task: &StreamingTask, spec: &str) -> anyhow::Result<()> {
    let identity = node_identity()?.ok_or_else(|| {
        anyhow::anyhow!(
            "no node identity at {}: run `entangle init` first (the executor admits this node \
             by its identity)",
            config::identity_path().display()
        )
    })?;
    let routing = Routing::from_config(&raw_config()?)?;
    let (peer, address) = resolve_target(spec, &routing)?;
    let store = PeerStore::open(config::entangle_dir().join("peers.toml"))?;
    if !matches!(store.get(&peer), Some(p) if p.trust != TrustLevel::Revoked) {
        anyhow::bail!(
            "peer {peer} is not trusted: pair it first (`entangle mesh trust` / `entangle pair`)"
        );
    }
    // The Open carries a per-request attenuation of the token the peer
    // minted for this node while pairing (`peers.toml`).
    let tokens = StaticTokens::new();
    match store.get(&peer).and_then(|p| p.presentable_token()) {
        Some((token, issuer_public_key)) => tokens.insert(
            peer,
            HeldToken {
                token,
                issuer_public_key,
            },
        ),
        None => eprintln!(
            "warning: this node holds no capability token for {peer} (paired before tokens \
             existed?); an executor that requires tokens will refuse the stream — re-pair with \
             `entangle pair`"
        ),
    }
    let dialers = start_dialers(&identity, &store, &routing, peer, address.as_ref()).await;
    let local = PeerId::from_public_key_bytes(identity.public().as_bytes());
    let opened = match stream_router(local, &routing, address.as_ref(), &dialers, tokens) {
        Some(router) => open_routed(&router, peer, task)
            .await
            .map_err(|e| with_notes(e.into(), &dialers.notes)),
        None => Err(with_notes(
            anyhow::anyhow!(
                "no transport can reach peer {peer}: give its long address (--peer \
                 <pubkey-hex>@host:port, or [scheduler] peers), or enable \"local\" or \
                 mesh.tailscale in ~/.entangle/config.toml"
            ),
            &dialers.notes,
        )),
    };
    let result = match opened {
        Ok((handle, transport)) => consume(handle, a.json, task.partial_result, transport).await,
        Err(e) => Err(e),
    };
    dialers.shutdown().await;
    result
}

/// `error`, plus why transports this run wanted did not start.
fn with_notes(error: anyhow::Error, notes: &[String]) -> anyhow::Error {
    if notes.is_empty() {
        error
    } else {
        error.context(format!("not available: {}", notes.join("; ")))
    }
}

async fn run_local(a: &StreamArgs, task: &StreamingTask, plugin: &PluginId) -> anyhow::Result<()> {
    let keyring = Keyring::load(&config::keyring_path())?;
    // The same config-honouring kernel as `compute dispatch --allow-local`:
    // a local stream is never more permissive than the daemon would be.
    let kernel = Arc::new(
        Kernel::new(config::kernel_config()?, keyring)
            .map_err(|e| anyhow::anyhow!("failed to build kernel: {e}"))?,
    );
    let dir = match &a.plugin_dir {
        Some(d) => d.clone(),
        None => config::entangle_dir().join("plugins").join(&plugin.name),
    };
    let loaded = kernel
        .load_plugin_from_dir(&dir)
        .await
        .map_err(|e| anyhow::anyhow!("loading plugin from {}: {e}", dir.display()))?;
    if &loaded != plugin {
        anyhow::bail!(
            "the plugin package in {} holds {loaded}, not {plugin}",
            dir.display()
        );
    }
    // The executor is this node (its identity signs the chunks); the
    // submitter end is a throwaway key the in-process executor admits.
    let executor = node_identity()?.unwrap_or_else(IdentityKeyPair::generate);
    let submitter = IdentityKeyPair::generate();
    let submitter_id = PeerId::from_public_key_bytes(submitter.public().as_bytes());
    let server = StreamServer::new(
        kernel,
        Arc::new(StaticAllowlist::new().allow(submitter_id)),
        executor.clone(),
    );
    let (sub_io, exec_io) = entangle_mesh_iroh::duplex_pair(
        *submitter.public().as_bytes(),
        *executor.public().as_bytes(),
        entangle_mesh_iroh::MAX_FRAME_BYTES,
        entangle_mesh_iroh::DEFAULT_DUPLEX_BUFFER,
    );
    // The executor requires a capability token like any other: mint the one
    // it would have issued the submitter while pairing.
    let tokens = StaticTokens::new();
    tokens
        .paired_with(&executor, submitter_id)
        .map_err(|e| anyhow::anyhow!("minting the in-process capability token: {e}"))?;
    let served = tokio::spawn(async move { server.handle(exec_io).await });
    let handle = StreamHandle::start(
        sub_io,
        task,
        StreamOptions {
            capability: Some(Arc::new(tokens)),
            ..StreamOptions::default()
        },
    )?;
    let result = consume(handle, a.json, task.partial_result, None).await;
    let _ = served.await;
    result
}

/// Print chunks as they arrive (or, under `discard`, once the stream is
/// complete), then the outcome.
async fn consume(
    mut handle: StreamHandle,
    json: bool,
    partial: PartialResultPolicy,
    transport: Option<TransportKind>,
) -> anyhow::Result<()> {
    let transport = TransportKind::label(transport);
    // No input beyond the initial one.
    handle.finish_input().await.ok();
    let executor = handle.executor();
    let hold_back = partial == PartialResultPolicy::Discard;
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut out = std::io::stdout();
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let mut cancelled = false;
    let terminal = loop {
        let poll = tokio::select! {
            poll = handle.next() => poll,
            _ = &mut interrupt, if !cancelled => {
                cancelled = true;
                handle.cancel().await;
                continue;
            }
        };
        match poll {
            ChunkPoll::Chunk(chunk) => {
                let line = if json {
                    let mut l = serde_json::to_vec(&serde_json::json!({
                        "seq": chunk.seq,
                        "bytes": chunk.bytes.len(),
                        "text": std::str::from_utf8(&chunk.bytes).ok(),
                        "base64": BASE64.encode(&chunk.bytes),
                        "signature": "verified",
                        "signature_hex": hex::encode(chunk.signature.to_bytes()),
                    }))?;
                    l.push(b'\n');
                    l
                } else {
                    chunk.bytes
                };
                if hold_back {
                    held.push(line);
                } else {
                    out.write_all(&line)?;
                    out.flush()?;
                }
            }
            other => break other,
        }
    };
    let report = handle.finish().await;
    match terminal {
        ChunkPoll::Ended(end) => {
            for line in held {
                out.write_all(&line)?;
            }
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "complete",
                        "executor": executor.to_hex(),
                        "transport": transport,
                        "chunks": end.chunks,
                        "bytes": end.bytes,
                        "transcript": hex::encode(end.transcript),
                        "end_signature_hex": hex::encode(end.signature.to_bytes()),
                    })
                );
            }
            out.flush()?;
            Ok(())
        }
        ChunkPoll::Closed(error) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "interrupted",
                        "executor": executor.to_hex(),
                        "transport": transport,
                        "reason": error.reason().as_str(),
                        "error": error.to_string(),
                        "chunks": report.context.received_chunks,
                        "bytes": report.context.received_bytes,
                        "partial": partial_label(partial),
                    })
                );
            }
            Err(interrupted(error, partial))
        }
        ChunkPoll::Chunk(_) | ChunkPoll::Pending => {
            Err(anyhow::anyhow!("stream ended unexpectedly"))
        }
    }
}

fn partial_label(p: PartialResultPolicy) -> &'static str {
    match p {
        PartialResultPolicy::Discard => "discarded",
        PartialResultPolicy::Keep => "kept",
        PartialResultPolicy::KeepSigned => "kept-signed",
    }
}

fn interrupted(error: StreamError, partial: PartialResultPolicy) -> anyhow::Error {
    anyhow::anyhow!(
        "stream interrupted ({}); partial output {}",
        error,
        partial_label(partial)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> StreamArgs {
        StreamArgs {
            plugin_id: "0123456789abcdef0123456789abcdef/s@0.1.0".into(),
            input: None,
            input_file: None,
            peer: None,
            integrity: "none".into(),
            allow: vec![],
            partial: "keep".into(),
            timeout_ms: 1,
            credit_window: 1,
            plugin_dir: None,
            json: false,
        }
    }

    #[test]
    fn integrity_flags_map_onto_stream_policies() {
        assert_eq!(parse_integrity(&args()).unwrap(), IntegrityPolicy::None);
        let mut a = args();
        a.integrity = "trusted-executor".into();
        assert!(parse_integrity(&a).is_err(), "needs --allow");
        a.allow = vec![PeerId::from_public_key_bytes(&[1; 32]).to_hex()];
        assert!(matches!(
            parse_integrity(&a).unwrap(),
            IntegrityPolicy::TrustedExecutor { allowlist } if allowlist.len() == 1
        ));
        let mut a = args();
        a.integrity = "semantic-equivalent".into();
        let err = parse_integrity(&a).unwrap_err().to_string();
        assert!(err.contains("TrustedExecutor"), "{err}");
    }

    #[test]
    fn peers_resolve_from_long_addresses_or_the_scheduler_section() {
        let key = [0xaa; 32];
        let long = format!("{}@127.0.0.1:4100", hex::encode(key));
        let cfg: toml::Value =
            toml::from_str(&format!("[scheduler]\npeers = [\"{long}\"]\n")).unwrap();
        let routing = Routing::from_config(&cfg).unwrap();
        let (id, by_addr) = resolve_target(&long, &Routing::default()).unwrap();
        let (same, by_id) = resolve_target(&id.to_hex(), &routing).unwrap();
        assert_eq!(id, same);
        assert_eq!(by_addr, by_id);
        assert!(by_id.is_some());
        // A peer without a long address is still a target: the tailnet or
        // the LAN may know it (the router says so if nothing does).
        let other = PeerId::from_public_key_bytes(&[0xbb; 32]);
        assert_eq!(
            resolve_target(&other.to_hex(), &routing).unwrap(),
            (other, None)
        );
        assert!(resolve_target("nonsense", &routing).is_err());
    }

    #[test]
    fn routing_reads_and_validates_the_daemons_mesh_settings() {
        let a = PeerId::from_public_key_bytes(&[1; 32]);
        let b = PeerId::from_public_key_bytes(&[2; 32]);
        let c = PeerId::from_public_key_bytes(&[3; 32]);
        let cfg: toml::Value = toml::from_str(&format!(
            "[mesh]\ntransports = [\"local\", \"tailscale\", \"iroh\"]\npreferred = \"iroh\"\n\
             [mesh.overrides]\n\"{}\" = \"tailscale\"\n\"{}\" = [\"tailscale\", \"local\"]\n\
             [mesh.tailscale]\nenabled = true\nport = 41999\ntailscale-cli = \"/opt/ts\"\n\
             [scheduler]\nrelay = false\n",
            a.to_hex(),
            b.to_hex()
        ))
        .unwrap();
        let r = Routing::from_config(&cfg).unwrap();
        use TransportKind::{Iroh, Local, Tailscale};
        assert_eq!(r.policy.order_for(&a), [Tailscale]);
        assert_eq!(r.policy.order_for(&b), [Tailscale, Local]);
        assert_eq!(r.policy.order_for(&c), [Iroh, Local, Tailscale]);
        assert!(!r.relay);
        let ts = r.tailnet.as_ref().expect("enabled and listed");
        assert_eq!((ts.port, ts.cli.as_str()), (41999, "/opt/ts"));
        // What each peer's order lets this run start.
        let addr = IrohPeer::new([1; 32], "127.0.0.1:1".parse().unwrap());
        assert!(!r.wants_local(&a) && r.wants_tailnet(&a) && !r.wants_iroh(&a, Some(&addr)));
        assert!(r.wants_local(&b) && !r.wants_iroh(&b, Some(&addr)));
        assert!(r.wants_iroh(&c, Some(&addr)) && !r.wants_iroh(&c, None));

        // Enabled but not listed in transports: off, as for the daemon.
        let off: toml::Value =
            toml::from_str("[mesh]\ntransports = [\"iroh\"]\n[mesh.tailscale]\nenabled = true\n")
                .unwrap();
        let r = Routing::from_config(&off).unwrap();
        assert!(r.tailnet.is_none());
        assert!(!r.wants_local(&c));

        // The daemon's load-time validation, with its codes.
        for (bad, code) in [
            ("[mesh]\npreferred = \"carrier-pigeon\"\n", "ENTANGLE-E0434"),
            (
                "[mesh.overrides]\n\"not-a-peer\" = \"iroh\"\n",
                "ENTANGLE-E0435",
            ),
            (
                &*format!(
                    "[mesh.overrides]\n\"{}\" = [\"iroh\", \"iroh\"]\n",
                    a.to_hex()
                ),
                "ENTANGLE-E0435",
            ),
            (
                &*format!("[mesh.overrides]\n\"{}\" = []\n", a.to_hex()),
                "ENTANGLE-E0435",
            ),
        ] {
            let cfg: toml::Value = toml::from_str(bad).unwrap();
            let err = format!("{:#}", Routing::from_config(&cfg).unwrap_err());
            assert!(err.contains(code), "{bad}: {err}");
        }
    }

    // ── a real stream over loopback transports ──────────────────────────────

    mod loopback {
        use super::*;
        use entangle_mesh_iroh::MeshTransport as _;
        use entangle_mesh_tailscale::{AclMode, AddressPolicy, TailnetState, TailscaleStatus};
        use entangle_runtime::KernelConfig;
        use entangle_scheduler::stream::StreamOutcome;
        use entangle_signing::{sign_artifact, TrustEntry};

        const DEADLINE: Duration = Duration::from_secs(30);

        async fn deadline<F: std::future::Future>(what: &str, fut: F) -> F::Output {
            match tokio::time::timeout(DEADLINE, fut).await {
                Ok(v) => v,
                Err(_) => panic!("{what} did not finish within {DEADLINE:?}"),
            }
        }

        fn peer_of(key: &IdentityKeyPair) -> PeerId {
            PeerId::from_public_key_bytes(key.public().as_bytes())
        }

        fn iroh_config() -> MeshIrohConfig {
            MeshIrohConfig {
                alpn: ALPN_STREAM.to_vec(),
                connect_timeout: Duration::from_secs(5),
                request_timeout: Duration::from_secs(10),
                ..MeshIrohConfig::loopback()
            }
        }

        fn tailnet_config(allow: &[PeerId]) -> MeshTailscaleConfig {
            MeshTailscaleConfig {
                acl_mode: AclMode::EntangleOnTop,
                allowlist: Some(Arc::new(TailnetAllowlist::new(allow.iter().copied()))),
                port: 0,
                bind_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                // Loopback is not a tailnet address.
                address_policy: AddressPolicy::Any,
                max_frame_bytes: entangle_mesh_iroh::MAX_FRAME_BYTES,
                handshake_timeout: Duration::from_secs(10),
                request_timeout: Duration::from_secs(10),
                ..MeshTailscaleConfig::default()
            }
        }

        /// An executor serving `stream-lines` on an iroh endpoint and a
        /// tailnet listener (both on loopback), for `submitter` only.
        struct Executor {
            peer_id: PeerId,
            key: IdentityKeyPair,
            iroh: Arc<MeshIroh>,
            tailnet: MeshTailscale,
            plugin: PluginId,
            _dir: tempfile::TempDir,
        }

        impl Executor {
            async fn start(submitter: PeerId) -> Self {
                let publisher = IdentityKeyPair::generate();
                let mut keyring = Keyring::new();
                keyring.add(TrustEntry {
                    fingerprint: publisher.public().fingerprint(),
                    public_key: *publisher.public().as_bytes(),
                    publisher_name: "test".into(),
                    added_at: 0,
                    note: String::new(),
                });
                let kernel = Arc::new(Kernel::new(KernelConfig::default(), keyring).unwrap());
                let dir = tempfile::tempdir().unwrap();
                let wasm = std::fs::read(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../entangle-scheduler/tests/fixtures/stream-lines.wasm"
                ))
                .unwrap();
                let id = format!("{}/stream-lines@0.1.0", publisher.fingerprint_hex());
                let manifest = format!(
                    "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n"
                );
                std::fs::write(dir.path().join("entangle.toml"), &manifest).unwrap();
                std::fs::write(dir.path().join("plugin.wasm"), &wasm).unwrap();
                let bundle = sign_artifact(&wasm, manifest.as_bytes(), &publisher);
                std::fs::write(
                    dir.path().join("plugin.wasm.sig"),
                    toml::to_string(&bundle).unwrap(),
                )
                .unwrap();
                let plugin = kernel.load_plugin_from_dir(dir.path()).await.unwrap();

                let key = IdentityKeyPair::generate();
                let iroh = Arc::new(MeshIroh::start(iroh_config(), &key).await.unwrap());
                let tailnet = MeshTailscale::start(&key, tailnet_config(&[submitter]))
                    .await
                    .unwrap();
                let streams = Arc::new(StreamServer::new(
                    kernel,
                    Arc::new(StaticAllowlist::new().allow(submitter)),
                    key.clone(),
                ));
                tokio::spawn(entangle_scheduler::serve_streams(
                    Arc::clone(&iroh),
                    Arc::clone(&streams),
                ));
                tokio::spawn(entangle_scheduler::serve_tailscale(
                    tailnet.clone(),
                    None,
                    Some(streams),
                ));
                Self {
                    peer_id: peer_of(&key),
                    key,
                    iroh,
                    tailnet,
                    plugin,
                    _dir: dir,
                }
            }

            fn long_address(&self) -> IrohPeer {
                let addr = self
                    .iroh
                    .local_addrs()
                    .into_iter()
                    .find(|a| a.ip().is_loopback())
                    .unwrap();
                IrohPeer::new(self.iroh.local_public_key(), addr)
            }
        }

        fn stopped() -> TailnetState {
            TailnetState::Stopped {
                reason: "NeedsLogin".into(),
            }
        }

        fn liveness(state: TailnetState) -> watch::Receiver<LivenessSnapshot> {
            watch::channel(LivenessSnapshot {
                state: Some(state),
                since: None,
                transitions: 1,
            })
            .1
        }

        /// Run one stream through the router `compute stream` builds and
        /// return its text and the transport that carried it.
        async fn stream_once(
            local: PeerId,
            routing: &Routing,
            dialers: &Dialers,
            exec: &Executor,
        ) -> Result<(String, Option<TransportKind>), String> {
            let address = exec.long_address();
            // What pairing leaves this node holding: the token the executor
            // minted for it.
            let tokens = StaticTokens::new();
            tokens.paired_with(&exec.key, local).unwrap();
            let router = stream_router(local, routing, Some(&address), dialers, tokens)
                .expect("at least one transport is running");
            let task = StreamingTask::with_defaults(exec.plugin.clone(), b"one\ntwo\n".to_vec());
            let (mut handle, transport) =
                deadline("open", open_routed(&router, exec.peer_id, &task))
                    .await
                    .map_err(|e| e.to_string())?;
            handle.finish_input().await.ok();
            let mut text = String::new();
            loop {
                match deadline("next chunk", handle.next()).await {
                    ChunkPoll::Chunk(c) => text.push_str(std::str::from_utf8(&c.bytes).unwrap()),
                    ChunkPoll::Ended(_) => break,
                    other => panic!("unexpected {other:?}"),
                }
            }
            let report = handle.finish().await;
            assert!(matches!(report.outcome, StreamOutcome::Complete(_)));
            Ok((text, transport))
        }

        fn routing(extra: &str) -> Routing {
            let cfg: toml::Value = toml::from_str(&format!(
                "[mesh]\ntransports = [\"local\", \"tailscale\", \"iroh\"]\n{extra}\n\
                 [mesh.tailscale]\nenabled = true\n"
            ))
            .unwrap();
            Routing::from_config(&cfg).unwrap()
        }

        /// `compute stream` picks the executor's transport the way the
        /// daemon's dispatcher does — §6.1 order (`local`, `tailscale`,
        /// `iroh`), `[mesh] preferred`, `[mesh.overrides]` as the exact
        /// list — over real loopback transports, and falls back to the next
        /// candidate when one fails to connect.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn compute_stream_routes_like_the_dispatcher() {
            let key = IdentityKeyPair::generate();
            let me = peer_of(&key);
            let exec = Executor::start(me).await;
            let iroh = Arc::new(MeshIroh::start(iroh_config(), &key).await.unwrap());
            let tailnet = MeshTailscale::start(&key, tailnet_config(&[]))
                .await
                .unwrap();
            // One discovery round, as `start_tailnet` runs it: the status
            // lists one online node at 127.0.0.1, probed on the executor's
            // listener port.
            let status = TailscaleStatus::parse(
                r#"{"BackendState":"Running","Self":{"Online":true},
                  "Peer":{"x":{"Online":true,"DNSName":"x.ts.net.","TailscaleIPs":["127.0.0.1"]}}}"#,
            )
            .unwrap();
            let found = tailnet
                .discover_on_port(&status, exec.tailnet.local_addr().port())
                .await;
            assert_eq!(found.len(), 1, "discovery finds the executor");
            let lan = PeerDirectory::new();
            lan.insert(exec.long_address());
            let dialers = |sightings: Option<PeerDirectory>, state: TailnetState| Dialers {
                iroh: Some(Arc::clone(&iroh)),
                sightings,
                tailscale: Some((tailnet.clone(), liveness(state))),
                notes: Vec::new(),
            };
            let all = routing("");

            // Sighted on the LAN: `local` first.
            let got = stream_once(
                me,
                &all,
                &dialers(Some(lan.clone()), TailnetState::Active),
                &exec,
            )
            .await;
            assert_eq!(got, Ok(("one\ntwo\n".into(), Some(TransportKind::Local))));
            // Not on the LAN: the tailnet comes next.
            let got = stream_once(me, &all, &dialers(None, TailnetState::Active), &exec).await;
            assert_eq!(
                got,
                Ok(("one\ntwo\n".into(), Some(TransportKind::Tailscale)))
            );
            // The tailnet stopped: its candidate is skipped, iroh carries it.
            let got = stream_once(me, &all, &dialers(None, stopped()), &exec).await;
            assert_eq!(got.unwrap().1, Some(TransportKind::Iroh));
            // `[mesh] preferred` moves iroh to the front, even with a sighting.
            let pref = routing("preferred = \"iroh\"");
            let got = stream_once(
                me,
                &pref,
                &dialers(Some(lan.clone()), TailnetState::Active),
                &exec,
            )
            .await;
            assert_eq!(got.unwrap().1, Some(TransportKind::Iroh));
            // An override is the exact list: tailscale only, and while the
            // tailnet is stopped nothing else is tried.
            let only = routing(&format!(
                "[mesh.overrides]\n\"{}\" = \"tailscale\"",
                exec.peer_id.to_hex()
            ));
            let got = stream_once(
                me,
                &only,
                &dialers(Some(lan.clone()), TailnetState::Active),
                &exec,
            )
            .await;
            assert_eq!(got.unwrap().1, Some(TransportKind::Tailscale));
            let err = stream_once(me, &only, &dialers(Some(lan), stopped()), &exec)
                .await
                .expect_err("no other transport is allowed for this peer");
            assert!(err.contains("ENTANGLE-E0430"), "{err}");
            assert!(err.contains("tailscale"), "{err}");

            // Connect failure falls back: the executor's tailnet listener is
            // gone, so the tailnet candidate fails to connect (nothing was
            // sent) and iroh carries the stream.
            exec.tailnet.shutdown().await;
            let got = stream_once(me, &all, &dialers(None, TailnetState::Active), &exec).await;
            assert_eq!(got, Ok(("one\ntwo\n".into(), Some(TransportKind::Iroh))));
        }
    }

    #[test]
    fn partial_policies_parse() {
        assert_eq!(parse_partial("keep").unwrap(), PartialResultPolicy::Keep);
        assert_eq!(
            parse_partial("keep-signed").unwrap(),
            PartialResultPolicy::KeepSigned
        );
        assert_eq!(
            parse_partial("discard").unwrap(),
            PartialResultPolicy::Discard
        );
        assert!(parse_partial("maybe").is_err());
    }
}
