//! Capability grants for wasm plugins: brokered `capability.fetch` handles
//! and the WASI context a plugin's grants realise.
//!
//! # Where authority comes from
//! Only from the [`Broker`]. The kernel resolves a plugin's declared
//! capabilities once at load ([`Broker::grant_declared`]); the grants it
//! issues — the plugin's *standing grants* — are what every new instance's
//! WASI context is built from ([`realise`]). The manifest is never read
//! here: a declared capability the operator denied, or one revoked since,
//! has no standing grant and so realises nothing.
//!
//! # What a grant realises
//! | grant | in the guest |
//! |---|---|
//! | `storage.local { scope = "plugin" }` | preopen [`GUEST_DATA_DIR`] (`/data`) → the plugin's private directory, read-only or read-write per `mode` |
//! | `storage.local { scope = "shared" }` | preopen [`GUEST_SHARED_DIR`] (`/shared`), per `mode` |
//! | `storage.share.<n>` | preopen `/shares/<n>` ([`GUEST_SHARES_DIR`]); `ro` read-only, `rw` / `rw-scoped` read-write |
//! | `net.lan` | TCP/UDP to LAN addresses (see [`crate::net`]); IP literals only, no name lookups |
//! | `net.wan { hosts }` | TCP/UDP to the allowlisted host:port pairs only; lookups of the allowlisted names, answered from the pin |
//! | anything else | nothing in WASI; `fetch` still returns a handle |
//!
//! Directories are laid out by [`crate::storage`] (the same paths the native
//! runtime grants) and created mode 0700, without following symlinks, under
//! the daemon's storage root. Inside the guest, wasmtime-wasi (cap-std)
//! confines every path to its preopen: absolute paths outside a preopen,
//! `..` above it, and symlinks — planted or created — that point out of it
//! all fail. No other directory is ever preopened, and with no network grant
//! TCP, UDP and DNS are all disabled.
//!
//! # `net.wan` hostnames
//! `socket_addr_check` only ever sees an address, never the name the guest
//! resolved, so allowlisted hostnames are resolved **by the host when the
//! instance is created** and the instance may connect to exactly the
//! resulting addresses (each with the entry's port, if any). Resolving at
//! connect time instead would mean trusting the guest's name-to-address
//! mapping, which it controls; pinning at instantiation also makes DNS
//! rebinding during an invocation useless. Because every invocation is a
//! fresh instance, the pin is at most one invocation old. Each distinct name
//! is looked up once, all concurrently; a name that does not resolve within
//! [`DNS_TIMEOUT`] — or, for an invocation, within half its timeout —
//! contributes no address (it is unreachable for that instance, with a
//! warning in the log) rather than holding the invocation up.
//!
//! The guest's own lookups are answered from the same pin
//! ([`WasiGrants::pinned_names`]), never by asking the system resolver
//! again: an allowlisted name resolves to exactly the addresses the socket
//! rules accept, and any other name does not resolve at all — so a grant
//! cannot be used to send arbitrary queries (`<data>.attacker.example`) to
//! upstream name servers. See `crate::lookup`.
//!
//! # Revocation
//! A revoked grant (`Broker::revoke`) is gone from the next instance's
//! context. A tier ceiling lowered below the plugin (spec §9.4.1) has the
//! same effect on all of its grants at once: the broker no longer counts
//! them as live (`Broker::is_live`, `Broker::live_grants`), so everything
//! below applies to them too while the plugin drains and is unloaded. Within a running instance, network access stops at once:
//! every socket check and name lookup re-confirms that the grant it relies
//! on is still live, and an invocation whose `net.lan` or `net.wan` grants
//! are all withdrawn is **stopped** (`ENTANGLE-E0511`) — checked every
//! [`REVOCATION_POLL`] while the guest waits on the host, and at the
//! store's epoch checks while it runs wasm code — because a connection it
//! opened earlier (or a connected UDP socket) is never re-checked by
//! wasmtime-wasi and would otherwise last until the invocation ends.
//! Preopened directories stay open for the rest of the invocation in
//! flight.
//!
//! # `capability.fetch`
//! [`HostState::fetch_capability`] maps the WIT `(kind, name)` to a manifest
//! key (`net.wan`, `storage.share.photos`, `custom.x`, ...) and asks the
//! broker for a fresh grant of that key ([`Broker::grant_by_key`]), which
//! audits and counts the decision. The handle is per instance;
//! [`HostState::release_capability`] releases its grant (idempotently), and
//! any handle still held when the instance ends is released then.

use crate::errors::HostError;
use crate::net::{AddrClass, Classifier, NetRules, WanTarget};
use crate::state::HostState;
use crate::storage;
use entangle_broker::{Broker, BrokerError, GrantId, GrantedCapability};
use entangle_types::capability::{
    is_valid_share_name, CapabilityKind, ShareMode, StorageMode, StorageScope,
};
use entangle_types::plugin_id::PluginId;
use std::collections::BTreeMap;
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// Guest path of the plugin's private data directory (`storage.local`).
pub const GUEST_DATA_DIR: &str = "/data";
/// Guest path of the shared directory (`storage.local { scope = "shared" }`).
pub const GUEST_SHARED_DIR: &str = "/shared";
/// Guest directory under which each `storage.share.<n>` appears as `<n>`.
pub const GUEST_SHARES_DIR: &str = "/shares";

/// Upper bound on resolving a `net.wan` allowlist when an instance is
/// created.
pub const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// How often a running networked invocation re-checks, while the guest
/// waits on the host, that the grants behind its network access are still
/// live (see the module docs on revocation).
pub const REVOCATION_POLL: Duration = Duration::from_millis(25);

/// Most capability handles one instance may hold at once.
pub const MAX_HANDLES_PER_INSTANCE: usize = 256;
/// Most `fetch` calls one instance may make. Each is an audited broker
/// decision, so this bounds how much audit traffic one invocation can cause.
pub const MAX_FETCHES_PER_INSTANCE: u32 = 1024;

/// Resolves a `net.wan` host name to its addresses when an instance is
/// created (see the module docs). Production: the system resolver.
pub type Resolver =
    fn(String) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send>>;

/// The system resolver (`getaddrinfo` through tokio).
fn system_resolver(
    name: String,
) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send>> {
    Box::pin(async move {
        let addrs = tokio::net::lookup_host((name.as_str(), 0)).await?;
        Ok(addrs.map(|a| a.ip()).collect())
    })
}

/// What a plugin's capabilities are decided and realised against: the
/// broker, and the storage root its directories live under.
#[derive(Clone)]
pub struct CapabilityContext {
    broker: Arc<Broker>,
    storage_root: Option<PathBuf>,
    classify: Classifier,
    resolve: Resolver,
}

impl std::fmt::Debug for CapabilityContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityContext")
            .field("storage_root", &self.storage_root)
            .finish_non_exhaustive()
    }
}

impl CapabilityContext {
    /// Decide through `broker`, with no storage root (a storage grant then
    /// fails with `ENTANGLE-E0508`).
    pub fn new(broker: Arc<Broker>) -> Self {
        Self {
            broker,
            storage_root: None,
            classify: crate::net::classify,
            resolve: system_resolver,
        }
    }

    /// Place storage scopes under `root` (the daemon's `<config>/data`,
    /// shared with native plugins).
    #[must_use]
    pub fn with_storage_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.storage_root = Some(root.into());
        self
    }

    /// **Test hook — never set by the daemon or the CLI.** Replace the
    /// address classification the `net.*` rules use (production:
    /// [`crate::net::classify`], under which loopback is neither LAN nor
    /// WAN). Tests use it to stand a `127.0.0.1` listener in for a LAN or WAN
    /// host; the rules themselves are unchanged.
    #[must_use]
    pub fn with_address_classifier(mut self, classify: fn(IpAddr) -> AddrClass) -> Self {
        self.classify = classify;
        self
    }

    /// **Test hook — never set by the daemon or the CLI.** Replace the
    /// resolver that pins `net.wan` host names when an instance is created
    /// (production: the system resolver). Tests use it to give a name an
    /// answer the system resolver does not, or to make resolution slow.
    #[must_use]
    pub fn with_resolver(mut self, resolve: Resolver) -> Self {
        self.resolve = resolve;
        self
    }

    /// The broker.
    pub fn broker(&self) -> &Arc<Broker> {
        &self.broker
    }

    /// The storage root, if configured.
    pub fn storage_root(&self) -> Option<&std::path::Path> {
        self.storage_root.as_deref()
    }
}

/// A directory to preopen for the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preopen {
    /// Host directory (created, canonical root).
    pub host: PathBuf,
    /// Guest path (`/data`, `/shared`, `/shares/<n>`).
    pub guest: String,
    /// Read-write (`true`) or read-only.
    pub writable: bool,
}

/// What a set of grants realises in one instance's WASI context.
#[derive(Debug, Clone, Default)]
pub struct WasiGrants {
    /// Directories to preopen; nothing else is reachable on the filesystem.
    pub preopens: Vec<Preopen>,
    /// Socket rules; with no `net.*` grant, TCP, UDP and DNS are disabled.
    pub net: NetRules,
    /// Grants backing `net.lan` (re-checked for liveness per socket use).
    pub lan_grants: Vec<GrantId>,
    /// Grants backing `net.wan` (re-checked for liveness per socket use).
    pub wan_grants: Vec<GrantId>,
    /// The `net.wan` allowlist's host names and the addresses they were
    /// pinned to: the only names the guest's lookups resolve.
    pub pinned_names: Vec<PinnedName>,
}

/// An allowlisted `net.wan` host name and the addresses it resolved to when
/// the instance was created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedName {
    /// The name, lowercase, without a trailing dot.
    pub name: String,
    /// Its addresses (canonical form, see [`crate::net::canonical`]); empty
    /// when it did not resolve.
    pub addrs: Vec<IpAddr>,
}

/// The broker grants behind an instance's network access, re-checked while
/// it runs (socket checks, name lookups).
#[derive(Clone)]
pub(crate) struct NetLiveness {
    broker: Arc<Broker>,
    plugin: PluginId,
    lan: Vec<GrantId>,
    wan: Vec<GrantId>,
}

impl std::fmt::Debug for NetLiveness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetLiveness")
            .field("plugin", &self.plugin)
            .field("lan", &self.lan)
            .field("wan", &self.wan)
            .finish_non_exhaustive()
    }
}

impl NetLiveness {
    pub(crate) fn new(ctx: &CapabilityContext, plugin: &PluginId, grants: &WasiGrants) -> Self {
        Self {
            broker: Arc::clone(&ctx.broker),
            plugin: plugin.clone(),
            lan: grants.lan_grants.clone(),
            wan: grants.wan_grants.clone(),
        }
    }

    fn live(&self, gids: &[GrantId]) -> bool {
        gids.iter().any(|g| self.broker.is_live(&self.plugin, *g))
    }

    /// A `net.lan` grant behind the instance is still outstanding.
    pub(crate) fn lan_live(&self) -> bool {
        self.live(&self.lan)
    }

    /// A `net.wan` grant behind the instance is still outstanding.
    pub(crate) fn wan_live(&self) -> bool {
        self.live(&self.wan)
    }

    /// Any network grant behind the instance is still outstanding.
    pub(crate) fn any_live(&self) -> bool {
        self.lan_live() || self.wan_live()
    }

    /// The instance has network access at all.
    pub(crate) fn has_net(&self) -> bool {
        !self.lan.is_empty() || !self.wan.is_empty()
    }

    /// The network capability whose every grant behind the instance has
    /// been withdrawn (revoked, or released with the plugin's
    /// registration), if any.
    pub(crate) fn withdrawn(&self) -> Option<&'static str> {
        if !self.lan.is_empty() && !self.lan_live() {
            Some("net.lan")
        } else if !self.wan.is_empty() && !self.wan_live() {
            Some("net.wan")
        } else {
            None
        }
    }

    /// Resolve once [`NetLiveness::withdrawn`] does, checking every
    /// [`REVOCATION_POLL`].
    pub(crate) async fn wait_withdrawn(&self) -> &'static str {
        loop {
            if let Some(capability) = self.withdrawn() {
                return capability;
            }
            tokio::time::sleep(REVOCATION_POLL).await;
        }
    }
}

/// Derive the WASI context for `plugin` from its live broker grants: create
/// the storage directories, resolve the `net.wan` allowlist (each name
/// within [`DNS_TIMEOUT`]).
pub async fn realise(ctx: &CapabilityContext, plugin: &PluginId) -> Result<WasiGrants, HostError> {
    realise_within(ctx, plugin, DNS_TIMEOUT).await
}

/// [`realise`] with the `net.wan` names resolved within `dns_budget`
/// (never more than [`DNS_TIMEOUT`]); a name not resolved in time is
/// unreachable for the instance. An invocation passes a share of its own
/// timeout, so a slow resolver cannot use up the invocation.
pub async fn realise_within(
    ctx: &CapabilityContext,
    plugin: &PluginId,
    dns_budget: Duration,
) -> Result<WasiGrants, HostError> {
    // Nothing while the plugin is above a (lowered) tier ceiling: its grants
    // are suspended there exactly as revoked ones are gone.
    let grants = ctx.broker.live_grants(plugin);
    realise_grants_within(ctx, plugin, &grants, dns_budget).await
}

/// [`realise`] for an explicit grant list (every entry must be a broker
/// grant for `plugin`).
pub async fn realise_grants(
    ctx: &CapabilityContext,
    plugin: &PluginId,
    grants: &[GrantedCapability],
) -> Result<WasiGrants, HostError> {
    realise_grants_within(ctx, plugin, grants, DNS_TIMEOUT).await
}

/// [`realise_grants`] with the `net.wan` names resolved within
/// `dns_budget` (see [`realise_within`]).
pub async fn realise_grants_within(
    ctx: &CapabilityContext,
    plugin: &PluginId,
    grants: &[GrantedCapability],
    dns_budget: Duration,
) -> Result<WasiGrants, HostError> {
    let mut out = WasiGrants {
        net: NetRules {
            classify: ctx.classify,
            ..NetRules::default()
        },
        ..WasiGrants::default()
    };
    // Grants are keyed by id; process them in id order so the result does
    // not depend on hash-map iteration.
    let mut grants: Vec<&GrantedCapability> = grants.iter().collect();
    grants.sort_by_key(|g| g.grant_id);
    let mut wan_hosts = Vec::new();
    for g in grants {
        match &g.kind {
            CapabilityKind::StorageLocal { scope, mode } => {
                let root = trusted_root(ctx, &g.kind)?;
                let (dir, guest) = match scope {
                    StorageScope::Plugin => (
                        storage::plugin_data_dir(&root, plugin).map_err(unsafe_path)?,
                        GUEST_DATA_DIR.to_owned(),
                    ),
                    StorageScope::Shared => {
                        (storage::shared_dir(&root), GUEST_SHARED_DIR.to_owned())
                    }
                };
                add_preopen(&mut out, dir, guest, *mode == StorageMode::Rw)?;
            }
            CapabilityKind::StorageShare { name, mode } => {
                if !is_valid_share_name(name) {
                    return Err(HostError::UnsafeStoragePath(format!(
                        "share name {name:?} is not a safe path component"
                    )));
                }
                let root = trusted_root(ctx, &g.kind)?;
                let dir = match mode {
                    ShareMode::RwScoped => storage::scoped_share_dir(&root, name, plugin),
                    ShareMode::Ro | ShareMode::Rw => storage::share_dir(&root, name),
                }
                .map_err(unsafe_path)?;
                let guest = format!("{GUEST_SHARES_DIR}/{name}");
                add_preopen(&mut out, dir, guest, *mode != ShareMode::Ro)?;
            }
            CapabilityKind::NetLan => {
                out.net.lan = true;
                out.lan_grants.push(g.grant_id);
            }
            CapabilityKind::NetWan { hosts } => {
                out.net.wan = true;
                out.wan_grants.push(g.grant_id);
                // Every grant of the capability carries the same manifest
                // allowlist; keep each entry once however many grants the
                // plugin holds (standing, plus handles fetched by running
                // invocations).
                for h in hosts {
                    if !wan_hosts.contains(h) {
                        wan_hosts.push(h.clone());
                    }
                }
            }
            CapabilityKind::ComputeCpu
            | CapabilityKind::ComputeGpu
            | CapabilityKind::ComputeNpu
            | CapabilityKind::MeshPeer
            | CapabilityKind::AgentInvoke
            | CapabilityKind::HostDockerSocket
            | CapabilityKind::Custom(_) => {}
        }
    }
    let (targets, pinned) = resolve_wan(ctx, plugin, &wan_hosts, dns_budget.min(DNS_TIMEOUT)).await;
    out.net.wan_targets = targets;
    out.pinned_names = pinned;
    Ok(out)
}

fn unsafe_path(e: storage::UnsafeComponent) -> HostError {
    HostError::UnsafeStoragePath(e.to_string())
}

fn trusted_root(ctx: &CapabilityContext, cap: &CapabilityKind) -> Result<PathBuf, HostError> {
    let root = ctx
        .storage_root
        .as_deref()
        .ok_or_else(|| HostError::NoStorageRoot {
            capability: cap.key().into_owned(),
        })?;
    Ok(storage::resolve_trusted(root))
}

fn add_preopen(
    out: &mut WasiGrants,
    host: PathBuf,
    guest: String,
    writable: bool,
) -> Result<(), HostError> {
    storage::create_private_dir(&host).map_err(|source| HostError::StorageScope {
        path: host.clone(),
        source,
    })?;
    // The same directory granted twice (e.g. a fetched grant next to the
    // standing one) is preopened once, with the wider mode.
    if let Some(existing) = out.preopens.iter_mut().find(|p| p.guest == guest) {
        existing.writable |= writable;
        return Ok(());
    }
    out.preopens.push(Preopen {
        host,
        guest,
        writable,
    });
    Ok(())
}

/// The form a `net.wan` host name is pinned and looked up under.
fn pin_key(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Resolve the `net.wan` allowlist to exact addresses (see the module docs),
/// and record each host name's addresses for the guest's own lookups.
/// Each distinct name is looked up once, all of them concurrently, each
/// within `budget`. Wildcards cannot be realised in wasm (they are a tier-4
/// authority and wasm plugins are tier 1–3) and contribute nothing.
async fn resolve_wan(
    ctx: &CapabilityContext,
    plugin: &PluginId,
    hosts: &[entangle_types::capability::NetHost],
    budget: Duration,
) -> (Vec<WanTarget>, Vec<PinnedName>) {
    let mut lookups = tokio::task::JoinSet::new();
    let mut asked: Vec<String> = Vec::new();
    for h in hosts {
        if h.is_wildcard() || h.ip().is_some() {
            continue;
        }
        let key = pin_key(h.host());
        if asked.contains(&key) {
            continue;
        }
        asked.push(key.clone());
        let resolve = ctx.resolve;
        lookups.spawn(async move {
            let answer = tokio::time::timeout(budget, resolve(key.clone())).await;
            (key, answer)
        });
    }
    let mut answers: std::collections::HashMap<String, Result<Vec<IpAddr>, String>> =
        std::collections::HashMap::new();
    while let Some(joined) = lookups.join_next().await {
        // A lookup task that panicked leaves its name unanswered (below).
        if let Ok((key, answer)) = joined {
            let answer = match answer {
                Ok(Ok(addrs)) => Ok(addrs.into_iter().map(crate::net::canonical).collect()),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_elapsed) => Err(format!("no answer within {budget:?}")),
            };
            answers.insert(key, answer);
        }
    }

    let mut pinned: Vec<PinnedName> = Vec::new();
    let mut pin = |name: &str, addrs: &[IpAddr]| {
        let name = pin_key(name);
        let entry = match pinned.iter_mut().find(|p| p.name == name) {
            Some(p) => p,
            None => {
                pinned.push(PinnedName {
                    name,
                    addrs: Vec::new(),
                });
                pinned.last_mut().expect("just pushed")
            }
        };
        for a in addrs {
            if !entry.addrs.contains(a) {
                entry.addrs.push(*a);
            }
        }
    };
    let mut out: Vec<WanTarget> = Vec::new();
    let mut push = |t: WanTarget| {
        if !out.contains(&t) {
            out.push(t);
        }
    };
    for h in hosts {
        if h.is_wildcard() {
            tracing::warn!(plugin = %plugin, entry = %h, "net.wan wildcard cannot be realised for a wasm plugin; ignored");
            continue;
        }
        if let Some(ip) = h.ip() {
            push(WanTarget {
                ip: crate::net::canonical(ip),
                port: h.port(),
            });
            continue;
        }
        let answer = answers
            .get(&pin_key(h.host()))
            .cloned()
            .unwrap_or_else(|| Err("the lookup failed".to_owned()));
        match answer {
            Ok(addrs) => {
                pin(h.host(), &addrs);
                for a in addrs {
                    push(WanTarget {
                        ip: a,
                        port: h.port(),
                    });
                }
            }
            Err(e) => {
                pin(h.host(), &[]);
                tracing::warn!(plugin = %plugin, host = %h, error = %e, "net.wan host did not resolve; unreachable this invocation");
            }
        }
    }
    (out, pinned)
}

/// Why `capability.fetch` refused, in WIT terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchRefusal {
    /// `not-granted(reason)`.
    NotGranted(String),
    /// `invalid-kind`: the `(kind, name)` pair names no capability.
    InvalidKind,
    /// `revoked`.
    Revoked,
}

/// Map a WIT `capability.kind` (its kebab-case name, e.g. `"net-wan"`) and
/// optional name to the manifest key the broker grants (`"net.wan"`,
/// `"storage.share.photos"`, `"custom.telemetry"`).
///
/// `storage-share` and `custom` require a name (a valid share name; a
/// non-empty custom suffix, with or without its `custom.` prefix); every
/// other kind takes none. Anything else is `None` (`invalid-kind`).
pub fn capability_key(kind: &str, name: Option<&str>) -> Option<String> {
    let fixed = match kind {
        "compute-cpu" => "compute.cpu",
        "compute-gpu" => "compute.gpu",
        "compute-npu" => "compute.npu",
        "storage-local" => "storage.local",
        "net-lan" => "net.lan",
        "net-wan" => "net.wan",
        "mesh-peer" => "mesh.peer",
        "agent-invoke" => "agent.invoke",
        "host-docker-socket" => "host.docker-socket",
        "storage-share" => {
            let n = name?;
            return is_valid_share_name(n).then(|| format!("storage.share.{n}"));
        }
        "custom" => {
            let n = name?;
            let suffix = n.strip_prefix("custom.").unwrap_or(n);
            let ok = !suffix.is_empty()
                && suffix.len() <= 128
                && suffix
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
            return ok.then(|| format!("custom.{suffix}"));
        }
        _ => return None,
    };
    name.is_none().then(|| fixed.to_owned())
}

/// Per-instance capability handles (see the module docs).
#[derive(Default)]
pub(crate) struct CapTable {
    ctx: Option<CapabilityContext>,
    plugin: Option<PluginId>,
    /// handle → broker grant id.
    handles: BTreeMap<u32, GrantId>,
    next_handle: u32,
    fetches: u32,
}

impl CapTable {
    pub(crate) fn new(ctx: Option<CapabilityContext>, plugin: PluginId) -> Self {
        Self {
            ctx,
            plugin: Some(plugin),
            handles: BTreeMap::new(),
            next_handle: 1,
            fetches: 0,
        }
    }
}

impl Drop for CapTable {
    /// Release every handle the instance still holds, so an instance cannot
    /// leak grants into the broker by never calling `release`.
    fn drop(&mut self) {
        if let (Some(ctx), Some(plugin)) = (&self.ctx, &self.plugin) {
            for gid in std::mem::take(&mut self.handles).into_values() {
                let _ = ctx.broker.release(plugin, gid);
            }
        }
    }
}

impl HostState {
    /// `capability.fetch` for the manifest key `key` (from
    /// [`capability_key`]): a fresh broker grant behind a per-instance
    /// handle. The broker audits and counts the decision.
    pub fn fetch_capability(&mut self, key: &str) -> Result<u32, FetchRefusal> {
        let plugin = self.plugin_id.clone();
        let caps = &mut self.caps;
        let Some(ctx) = caps.ctx.clone() else {
            return Err(FetchRefusal::NotGranted(
                "no capability broker is attached to this instance".into(),
            ));
        };
        if caps.fetches >= MAX_FETCHES_PER_INSTANCE {
            return Err(FetchRefusal::NotGranted(format!(
                "fetch budget of {MAX_FETCHES_PER_INSTANCE} calls per invocation exhausted"
            )));
        }
        if caps.handles.len() >= MAX_HANDLES_PER_INSTANCE {
            return Err(FetchRefusal::NotGranted(format!(
                "{MAX_HANDLES_PER_INSTANCE} capability handles already held; release some first"
            )));
        }
        caps.fetches += 1;
        match ctx.broker.grant_by_key(&plugin, key) {
            Ok(g) => {
                let h = caps.next_handle;
                caps.next_handle = caps.next_handle.wrapping_add(1).max(1);
                caps.handles.insert(h, g.grant_id);
                Ok(h)
            }
            Err(BrokerError::CapabilityRevoked { .. }) => Err(FetchRefusal::Revoked),
            Err(e) => Err(FetchRefusal::NotGranted(e.to_string())),
        }
    }

    /// `capability.release`: release the handle's grant. Unknown or
    /// already-released handles are ignored (idempotent).
    pub fn release_capability(&mut self, handle: u32) {
        let Some(gid) = self.caps.handles.remove(&handle) else {
            return;
        };
        if let Some(ctx) = &self.caps.ctx {
            let _ = ctx.broker.release(&self.plugin_id, gid);
        }
    }

    /// Number of capability handles this instance holds.
    pub fn capability_handles(&self) -> usize {
        self.caps.handles.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wit_kinds_map_to_manifest_keys() {
        let ok: &[(&str, Option<&str>, &str)] = &[
            ("compute-cpu", None, "compute.cpu"),
            ("storage-local", None, "storage.local"),
            ("net-lan", None, "net.lan"),
            ("net-wan", None, "net.wan"),
            ("host-docker-socket", None, "host.docker-socket"),
            ("storage-share", Some("photos"), "storage.share.photos"),
            ("custom", Some("telemetry"), "custom.telemetry"),
            ("custom", Some("custom.telemetry"), "custom.telemetry"),
        ];
        for (kind, name, key) in ok {
            assert_eq!(
                capability_key(kind, *name).as_deref(),
                Some(*key),
                "{kind} {name:?}"
            );
        }
        let bad: &[(&str, Option<&str>)] = &[
            ("storage-share", None),
            ("storage-share", Some("../etc")),
            ("storage-share", Some("/")),
            ("custom", None),
            ("custom", Some("")),
            ("custom", Some("custom.")),
            ("custom", Some("a b")),
            ("net-wan", Some("api.example.com")),
            ("compute-cpu", Some("x")),
            ("bogus", None),
        ];
        for (kind, name) in bad {
            assert_eq!(capability_key(kind, *name), None, "{kind} {name:?}");
        }
    }
}
