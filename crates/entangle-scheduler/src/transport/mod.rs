//! Multi-transport routing for the scheduler (spec §6.1, §6.1.1, §6.7).
//!
//! A node can reach a peer over up to three transports at once:
//!
//! | Transport | Carried by | Dial targets from |
//! |---|---|---|
//! | `local` | the iroh endpoint, direct LAN addresses only | an mDNS sighting (public key + mesh port) |
//! | `tailscale` | TCP between tailnet IPs, sealed session ([`entangle_mesh_tailscale`]) | tailnet discovery candidates |
//! | `iroh` | the iroh endpoint (QUIC; hole punching, relays) | the `[scheduler] peers` address book |
//!
//! Each is a [`Link`]: it says whether it can carry traffic right now
//! ([`Link::availability`] — `tailscale` is down while the tailnet is not
//! `active`), where it would dial a given [`PeerId`] ([`Link::target`]), and
//! how to send one request or open one stream there. Every connection it
//! makes authenticates the remote `PeerId` (the iroh QUIC handshake, or the
//! tailnet transport's signed key exchange) and pins it to the key it
//! dialled.
//!
//! A [`TransportRouter`] holds the links and a [`RoutePolicy`] and, per
//! peer, builds the candidate list in the §6.1 negotiation order — `local`,
//! then `tailscale`, then `iroh` — with `[mesh] preferred` moved to the
//! front, or exactly the per-peer override's list. It tries the candidates
//! in order:
//!
//! * a failure while **connecting** (dial, handshake, identity, the peer's
//!   ACL admission, protocol selection) delivered nothing, so the next
//!   candidate is tried;
//! * so does a candidate that has not connected by its **connect
//!   deadline**: every candidate but the last gets one
//!   ([`TransportRouter::with_connect_timeout`], shortened to an even share
//!   of what is left of the request's budget), so a dial that hangs — a
//!   stale or spoofed LAN address, a blackholed port — cannot use up the
//!   budget before the later transports are tried. A link reports when its
//!   connection is set up by asking for the frame to send ([`Outbound`]);
//!   the deadline never cuts short a request already sent. It only makes
//!   room for the later candidates: if they all fail too, a candidate it
//!   cut short is tried again without one, as the last candidate would have
//!   been;
//! * a candidate that failed to connect (or ran out its connect deadline)
//!   moves behind the peer's other candidates for a while
//!   ([`TransportRouter::with_connect_backoff`]), so a dead route is not
//!   dialled first, and waited on, by every request. It is demoted, not
//!   dropped: it is still tried when the others fail, and a success over it
//!   restores its place;
//! * anything after that — an application-level answer, even a refusal, or
//!   a transport failure once the request may have been delivered — is
//!   final: it is never retried on another transport, so a request is
//!   carried at most once.
//!
//! A request's frame is built per attempt, when the attempt's link has
//! connected and immediately before the frame is written
//! ([`TransportRouter::request_tracked`], [`Outbound`]); a stream's `Open`
//! is built once its link has opened the stream. So a capability token is
//! attenuated for the attempt that carries it: time spent dialling,
//! including every fallback above, never counts against the token's 60 s,
//! and an attempt that is tried again carries a fresh nonce.
//!
//! The transport that carried the last successful request or stream to a
//! peer is recorded ([`TransportRouter::last_route`]) and shown by
//! `entangle diag mesh`; metrics label remote dispatch and stream opens
//! with it (`transport` ∈ [`TRANSPORT_LABELS`]).
//!
//! Inbound, both transports serve the same [`RemoteTaskServer`] and
//! [`StreamServer`] — the iroh endpoint per ALPN
//! ([`serve_tasks`](crate::serve_tasks), [`serve_streams`](crate::serve_streams)),
//! the tailnet listener per selected sub-protocol ([`serve_tailscale`]) —
//! behind the same peer allowlist, checked before a frame is decoded.
//!
//! [`RemoteTaskServer`]: crate::RemoteTaskServer
//! [`StreamServer`]: crate::StreamServer

mod error;
mod links;
mod serve;
mod stream_io;

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use entangle_mesh_iroh::IrohPeer;
use entangle_mesh_tailscale::TailscalePeer;
use entangle_types::peer_id::PeerId;
use entangle_types::task::StreamingTask;
use parking_lot::Mutex;

pub use error::RouteError;
pub use links::{IrohLink, TailscaleLink};
pub use serve::serve_tailscale;
pub use stream_io::{FrameError, FrameRecv, FrameSend, StreamIo};

use crate::stream::{
    check_executor_allowed, validate_submit, StreamError, StreamHandle, StreamOptions,
};

pub use entangle_observability::catalog::TRANSPORT_LABELS;

/// One of the three mesh transports (spec §6.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TransportKind {
    /// `mesh.local`: LAN addresses from mDNS, over the iroh endpoint.
    Local,
    /// `mesh.tailscale`: the tailnet.
    Tailscale,
    /// `mesh.iroh`: QUIC over the internet (direct, hole-punched or relayed).
    Iroh,
}

impl TransportKind {
    /// The spec §6.1 negotiation order: cheapest first.
    pub const NEGOTIATION_ORDER: [Self; 3] = [Self::Local, Self::Tailscale, Self::Iroh];

    /// Config and metric spelling: `local`, `tailscale` or `iroh`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Tailscale => "tailscale",
            Self::Iroh => "iroh",
        }
    }

    /// The metric label for an optional transport (`none` when absent).
    pub const fn label(kind: Option<Self>) -> &'static str {
        match kind {
            Some(k) => k.as_str(),
            None => "none",
        }
    }

    const fn to_u8(self) -> u8 {
        match self {
            Self::Local => 1,
            Self::Tailscale => 2,
            Self::Iroh => 3,
        }
    }

    const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Local),
            2 => Some(Self::Tailscale),
            3 => Some(Self::Iroh),
            _ => None,
        }
    }
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TransportKind {
    type Err = RouteError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "local" => Ok(Self::Local),
            "tailscale" => Ok(Self::Tailscale),
            "iroh" => Ok(Self::Iroh),
            other => Err(RouteError::UnknownTransport(other.to_owned())),
        }
    }
}

/// Where a link would dial a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialTarget {
    /// An iroh endpoint: public key plus address hints.
    Iroh(IrohPeer),
    /// A tailnet node: public key plus tailnet `ip:port`.
    Tailscale(TailscalePeer),
}

impl DialTarget {
    /// The primary address, for logs and `entangle diag mesh`.
    pub fn address(&self) -> String {
        match self {
            Self::Iroh(p) => p.addr.to_string(),
            Self::Tailscale(p) => p.addr.to_string(),
        }
    }

    /// The peer the target names.
    pub const fn peer_id(&self) -> PeerId {
        match self {
            Self::Iroh(p) => p.peer_id,
            Self::Tailscale(p) => p.peer_id,
        }
    }
}

/// Whether a link can carry traffic right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Availability {
    /// Usable.
    Ready,
    /// Not usable; the reason, for logs and diagnostics.
    Down(String),
}

/// How one attempt on one link failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// Connection setup failed (dial, handshake, identity, the peer's ACL
    /// admission, protocol selection): nothing was delivered, so another
    /// transport may be tried.
    Connect(String),
    /// A frame was over the transport's cap (refused from its header).
    FrameTooLarge {
        /// The declared length.
        declared: u64,
        /// The cap in force.
        max: usize,
    },
    /// The connection was up and the request may have reached the peer.
    /// Never retried elsewhere.
    Transport(String),
}

/// Builds the bytes of one request for one attempt: called by the link
/// once its connection is set up, immediately before writing them (see
/// [`Outbound`]).
pub type BuildFrame<'a> = &'a (dyn Fn() -> Vec<u8> + Send + Sync);

/// One attempt's request, handed to [`Link::request`]. The link asks for the
/// bytes to send with [`Outbound::frame`] once its connection is set up
/// (dialled, authenticated, admitted, protocol selected), immediately before
/// writing them, and at most once.
///
/// **Built per attempt.** The frame is built at that moment, not when the
/// request was made: anything time-sensitive in it — the capability token's
/// expiry and nonce ([`crate::capability`]) — is minted for the attempt
/// that carries it, so connection setup, and the router's fallback from one
/// transport to the next, never use up a token's lifetime, and every
/// attempt is a new request to the peer's replay cache.
///
/// **The end of setup.** Asking for the frame is also the link's report that
/// setup is over. Until then the router may abandon the attempt at its
/// connect deadline — nothing was sent, so another transport may be tried.
/// After it the attempt runs to its end: a request that may have reached
/// the peer is never abandoned for another transport, nor retried on one.
pub struct Outbound<'a> {
    build: BuildFrame<'a>,
    connecting: Connecting,
}

impl std::fmt::Debug for Outbound<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbound")
            .field("connected", &self.is_connected())
            .finish_non_exhaustive()
    }
}

impl<'a> Outbound<'a> {
    /// An attempt whose frame `build` makes.
    pub fn new(build: BuildFrame<'a>) -> Self {
        Self {
            build,
            connecting: Connecting::default(),
        }
    }

    /// The connection is set up and nothing has been sent: build the frame
    /// to send now.
    pub fn frame(&self) -> Vec<u8> {
        self.connecting.connected();
        (self.build)()
    }

    /// Whether the link has asked for the frame (its connection is set up).
    pub fn is_connected(&self) -> bool {
        self.connecting.is_connected()
    }
}

/// Whether an attempt is past connection setup (see [`Outbound`]).
#[derive(Debug, Default)]
struct Connecting(AtomicBool);

impl Connecting {
    /// The connection is set up; nothing has been sent yet.
    fn connected(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether [`Connecting::connected`] was called.
    fn is_connected(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// How long the router waits for a candidate that has a fallback after it to
/// connect before trying the next one; see
/// [`TransportRouter::with_connect_timeout`].
pub const DEFAULT_ATTEMPT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a candidate that failed to connect stays behind the peer's
/// other candidates; see [`TransportRouter::with_connect_backoff`].
pub const DEFAULT_CONNECT_BACKOFF: Duration = Duration::from_secs(30);

/// One transport, as the router uses it. See the module docs.
#[async_trait::async_trait]
pub trait Link: std::fmt::Debug + Send + Sync {
    /// Which transport this is.
    fn kind(&self) -> TransportKind;

    /// Whether the link can carry traffic now.
    fn availability(&self) -> Availability {
        Availability::Ready
    }

    /// Where this link would dial `peer`, if it knows.
    fn target(&self, peer: &PeerId) -> Option<DialTarget>;

    /// Connect to `target` and do one `entangle/scheduler/1`
    /// request/response, sending what `outbound.frame()` returns when called
    /// between the two (see [`Outbound`]).
    async fn request(
        &self,
        target: &DialTarget,
        outbound: &Outbound<'_>,
    ) -> Result<Vec<u8>, LinkError>;

    /// Connect to `target` and open one `entangle/stream/1` stream. Nothing
    /// is sent on it yet, so the whole call is connection setup.
    async fn open_stream(&self, target: &DialTarget) -> Result<StreamIo, LinkError>;
}

/// Which transports to try for a peer, in which order (spec §6.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoutePolicy {
    preferred: Option<TransportKind>,
    overrides: HashMap<PeerId, Vec<TransportKind>>,
}

impl RoutePolicy {
    /// The §6.1 order for every peer.
    pub fn new() -> Self {
        Self::default()
    }

    /// `[mesh] preferred`: try `kind` first for every peer without an
    /// override; the others stay as fallbacks in §6.1 order.
    #[must_use]
    pub fn with_preferred(mut self, kind: Option<TransportKind>) -> Self {
        self.preferred = kind;
        self
    }

    /// A per-peer override: exactly these transports, in this order (one
    /// transport forces it). Repeats are dropped; an empty list removes the
    /// override.
    #[must_use]
    pub fn with_override(mut self, peer: PeerId, order: Vec<TransportKind>) -> Self {
        let mut list: Vec<TransportKind> = Vec::with_capacity(order.len());
        for k in order {
            if !list.contains(&k) {
                list.push(k);
            }
        }
        if list.is_empty() {
            self.overrides.remove(&peer);
        } else {
            self.overrides.insert(peer, list);
        }
        self
    }

    /// The preferred transport, if any.
    pub const fn preferred(&self) -> Option<TransportKind> {
        self.preferred
    }

    /// The order transports are tried in for `peer`.
    pub fn order_for(&self, peer: &PeerId) -> Vec<TransportKind> {
        if let Some(list) = self.overrides.get(peer) {
            return list.clone();
        }
        let mut order = TransportKind::NEGOTIATION_ORDER.to_vec();
        if let Some(p) = self.preferred {
            order.retain(|k| *k != p);
            order.insert(0, p);
        }
        order
    }

    /// Whether `peer` has an override.
    pub fn has_override(&self, peer: &PeerId) -> bool {
        self.overrides.contains_key(peer)
    }

    /// Parse one `[mesh.overrides]` entry: `key` must be a peer id (hex) and
    /// `names` a non-empty list of distinct transport names. This is the
    /// validation the daemon applies when it loads `config.toml`
    /// (`ENTANGLE-E0434` for an unknown name, `ENTANGLE-E0435` otherwise).
    pub fn parse_override(
        key: &str,
        names: &[&str],
    ) -> Result<(PeerId, Vec<TransportKind>), RouteError> {
        let bad = |reason: String| RouteError::BadOverride {
            key: key.to_owned(),
            reason,
        };
        let peer = PeerId::from_hex(key).map_err(|e| bad(format!("not a peer id ({e})")))?;
        if names.is_empty() {
            return Err(bad("the transport list is empty".into()));
        }
        let mut kinds = Vec::with_capacity(names.len());
        for name in names {
            let kind: TransportKind = name.parse()?;
            if kinds.contains(&kind) {
                return Err(bad(format!("{name:?} is listed twice")));
            }
            kinds.push(kind);
        }
        Ok((peer, kinds))
    }

    /// The policy `[mesh] preferred` and `[mesh.overrides]` describe, given
    /// as transport names: `preferred` must name a transport, and each
    /// override passes [`RoutePolicy::parse_override`].
    pub fn from_names<'a>(
        preferred: Option<&str>,
        overrides: impl IntoIterator<Item = (&'a str, Vec<&'a str>)>,
    ) -> Result<Self, RouteError> {
        let preferred = preferred.map(str::parse::<TransportKind>).transpose()?;
        let mut policy = Self::new().with_preferred(preferred);
        for (key, names) in overrides {
            let (peer, kinds) = Self::parse_override(key, &names)?;
            policy = policy.with_override(peer, kinds);
        }
        Ok(policy)
    }
}

/// What [`build_router`] wires together. Every part is optional: a link
/// exists only for a transport that is running. The daemon and
/// `entangle compute stream` build their routers through this one function,
/// so both pick transports the same way.
#[derive(Default)]
pub struct RouterInputs {
    /// The iroh endpoint (carries `local` and `iroh`).
    pub iroh: Option<Arc<entangle_mesh_iroh::MeshIroh>>,
    /// `[scheduler] peers`, for the `iroh` link.
    pub iroh_directory: Option<crate::remote::PeerDirectory>,
    /// Trusted mDNS sightings, for the `local` link (`mesh.local` running).
    pub local_sightings: Option<crate::remote::PeerDirectory>,
    /// The tailnet transport and its liveness.
    pub tailscale: Option<(
        entangle_mesh_tailscale::MeshTailscale,
        tokio::sync::watch::Receiver<entangle_mesh_tailscale::LivenessSnapshot>,
    )>,
    /// `[mesh] preferred` / `[mesh.overrides]`.
    pub policy: RoutePolicy,
    /// Where stream opens are counted.
    pub metrics: Option<entangle_observability::Registry>,
    /// The capability tokens to present to peers (task frames and stream
    /// `Open`s), see [`crate::capability`].
    pub capability_tokens: Option<Arc<dyn crate::capability::CapabilityTokens>>,
}

/// The outbound router for `inputs`, or `None` when no transport is running
/// (a dispatcher then stays local-only). The `local` link exists only with
/// the iroh endpoint (LAN addresses are dialled over it).
pub fn build_router(local_peer_id: PeerId, inputs: RouterInputs) -> Option<TransportRouter> {
    use entangle_mesh_iroh::MeshTransport;
    let mut router = TransportRouter::new(local_peer_id).with_policy(inputs.policy);
    if let Some(registry) = inputs.metrics {
        router = router.with_metrics(registry);
    }
    if let Some(tokens) = inputs.capability_tokens {
        router = router.with_capability_tokens(tokens);
    }
    let mut any = false;
    if let Some(iroh) = &inputs.iroh {
        let dyn_transport = Arc::clone(iroh) as Arc<dyn MeshTransport>;
        if let Some(sightings) = inputs.local_sightings {
            router = router.with_link(Arc::new(
                IrohLink::local(Arc::clone(&dyn_transport), Arc::new(sightings))
                    .with_streams(Arc::clone(iroh)),
            ));
        }
        let book = inputs.iroh_directory.unwrap_or_default();
        router = router.with_link(Arc::new(
            IrohLink::new(dyn_transport, Arc::new(book)).with_streams(Arc::clone(iroh)),
        ));
        any = true;
    }
    if let Some((transport, liveness)) = inputs.tailscale {
        router = router.with_link(Arc::new(TailscaleLink::new(transport, liveness)));
        any = true;
    }
    any.then_some(router)
}

/// The transport that last carried traffic to a peer (the "chosen
/// transport" of §6.1, recorded on the peer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRecord {
    /// The transport.
    pub transport: TransportKind,
    /// Where it dialled.
    pub address: String,
    /// When.
    pub at: SystemTime,
}

/// A candidate the router would try.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedRoute {
    /// The transport.
    pub transport: TransportKind,
    /// Where it would dial.
    pub address: String,
}

/// A transport the router would not try for a peer, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedRoute {
    /// The transport.
    pub transport: TransportKind,
    /// Why (`tailnet stopped (NeedsLogin)`, `not in the address book`, ...).
    pub reason: String,
}

/// What the router would do for one peer right now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoutePlan {
    /// Candidates, in the order they would be tried.
    pub candidates: Vec<PlannedRoute>,
    /// Transports that would not be tried.
    pub skipped: Vec<SkippedRoute>,
}

/// The transport an in-flight request is on, readable by its caller even if
/// the request is abandoned at a deadline.
#[derive(Debug, Default)]
pub struct AttemptCell(AtomicU8);

impl AttemptCell {
    fn set(&self, kind: TransportKind) {
        self.0.store(kind.to_u8(), Ordering::Relaxed);
    }

    /// The transport last attempted, if any.
    pub fn get(&self) -> Option<TransportKind> {
        TransportKind::from_u8(self.0.load(Ordering::Relaxed))
    }
}

type Candidates = (Vec<(Arc<dyn Link>, DialTarget)>, Vec<SkippedRoute>);

/// Picks a transport per peer and carries requests and streams over it. See
/// the module docs.
pub struct TransportRouter {
    local_peer_id: PeerId,
    links: Vec<Arc<dyn Link>>,
    policy: RoutePolicy,
    records: Mutex<HashMap<PeerId, RouteRecord>>,
    metrics: Option<entangle_observability::Registry>,
    connect_timeout: Duration,
    connect_backoff: Duration,
    /// When each (peer, transport) last failed to connect.
    connect_failures: Mutex<HashMap<(PeerId, TransportKind), tokio::time::Instant>>,
    /// The capability tokens presented on task frames and stream `Open`s.
    capability_tokens: Option<Arc<dyn crate::capability::CapabilityTokens>>,
}

impl std::fmt::Debug for TransportRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportRouter")
            .field("local_peer_id", &self.local_peer_id)
            .field("links", &self.links)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl TransportRouter {
    /// A router with no links (every peer is unreachable until links are
    /// added).
    pub fn new(local_peer_id: PeerId) -> Self {
        Self {
            local_peer_id,
            links: Vec::new(),
            policy: RoutePolicy::default(),
            records: Mutex::new(HashMap::new()),
            metrics: None,
            connect_timeout: DEFAULT_ATTEMPT_CONNECT_TIMEOUT,
            connect_backoff: DEFAULT_CONNECT_BACKOFF,
            connect_failures: Mutex::new(HashMap::new()),
            capability_tokens: None,
        }
    }

    /// Present capability tokens from `tokens`: every stream `Open` this
    /// router carries, and every task frame a
    /// [`RemoteDispatch`](crate::RemoteDispatch) over it sends, carries a
    /// per-request attenuation of the token held for its peer.
    #[must_use]
    pub fn with_capability_tokens(
        mut self,
        tokens: Arc<dyn crate::capability::CapabilityTokens>,
    ) -> Self {
        self.capability_tokens = Some(tokens);
        self
    }

    /// The token source, if any.
    pub fn capability_tokens(&self) -> Option<&Arc<dyn crate::capability::CapabilityTokens>> {
        self.capability_tokens.as_ref()
    }

    /// Add a transport.
    #[must_use]
    pub fn with_link(mut self, link: Arc<dyn Link>) -> Self {
        self.links.push(link);
        self
    }

    /// Use `policy` to order the transports.
    #[must_use]
    pub fn with_policy(mut self, policy: RoutePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Count stream opens into `registry`
    /// (`entangle_remote_stream_opens_total{outcome, transport}`).
    #[must_use]
    pub fn with_metrics(mut self, registry: entangle_observability::Registry) -> Self {
        self.metrics = Some(registry);
        self
    }

    /// How long a candidate with a fallback after it may take to connect
    /// before the next one is tried (default
    /// [`DEFAULT_ATTEMPT_CONNECT_TIMEOUT`]). A request with a budget gives
    /// each such candidate at most an even share of what is left of it. The
    /// last candidate has no router deadline: its transport's own timeouts
    /// and the caller's budget bound it.
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// How long a candidate that failed to connect to a peer (or ran out
    /// its connect deadline) is tried after that peer's other candidates
    /// (default [`DEFAULT_CONNECT_BACKOFF`]). Attempts restricted to one
    /// transport (`only`: diagnostics) neither cause nor see the demotion.
    #[must_use]
    pub const fn with_connect_backoff(mut self, backoff: Duration) -> Self {
        self.connect_backoff = backoff;
        self
    }

    /// This node's peer id.
    pub const fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// The transports this router has, in the order they were added.
    pub fn transports(&self) -> Vec<TransportKind> {
        self.links.iter().map(|l| l.kind()).collect()
    }

    /// The policy in force.
    pub const fn policy(&self) -> &RoutePolicy {
        &self.policy
    }

    /// The transport that last carried traffic to `peer`.
    pub fn last_route(&self, peer: &PeerId) -> Option<RouteRecord> {
        self.records.lock().get(peer).cloned()
    }

    /// What the router would try for `peer` right now, and what it would
    /// skip.
    pub fn plan(&self, peer: &PeerId) -> RoutePlan {
        let (candidates, skipped) = self.candidates(peer, None);
        RoutePlan {
            candidates: candidates
                .iter()
                .map(|(link, target)| PlannedRoute {
                    transport: link.kind(),
                    address: target.address(),
                })
                .collect(),
            skipped,
        }
    }

    fn candidates(&self, peer: &PeerId, only: Option<TransportKind>) -> Candidates {
        let order = match only {
            Some(k) => vec![k],
            None => self.policy.order_for(peer),
        };
        let mut out = Vec::new();
        let mut skipped = Vec::new();
        for kind in &order {
            let mut any = false;
            for link in self.links.iter().filter(|l| l.kind() == *kind) {
                any = true;
                if let Availability::Down(reason) = link.availability() {
                    skipped.push(SkippedRoute {
                        transport: *kind,
                        reason,
                    });
                    continue;
                }
                match link.target(peer) {
                    Some(target) if target.peer_id() == *peer => {
                        out.push((Arc::clone(link), target));
                    }
                    Some(_) => skipped.push(SkippedRoute {
                        transport: *kind,
                        reason: "address-book entry names another peer".into(),
                    }),
                    None => skipped.push(SkippedRoute {
                        transport: *kind,
                        reason: no_target_reason(*kind).into(),
                    }),
                }
            }
            if !any {
                skipped.push(SkippedRoute {
                    transport: *kind,
                    reason: "not running on this node".into(),
                });
            }
        }
        if only.is_none() {
            // Stable: the demoted keep their relative order, after the rest.
            let failed = self.recently_failed(peer);
            if !failed.is_empty() {
                out.sort_by_key(|(link, _): &(Arc<dyn Link>, DialTarget)| {
                    failed.contains(&link.kind())
                });
            }
        }
        if only.is_none() && self.policy.has_override(peer) {
            for link in &self.links {
                let kind = link.kind();
                if !order.contains(&kind) && !skipped.iter().any(|s| s.transport == kind) {
                    skipped.push(SkippedRoute {
                        transport: kind,
                        reason: "not in this peer's [mesh.overrides] entry".into(),
                    });
                }
            }
        }
        (out, skipped)
    }

    /// The transports that failed to connect to `peer` within the back-off.
    fn recently_failed(&self, peer: &PeerId) -> Vec<TransportKind> {
        let failures = self.connect_failures.lock();
        TransportKind::NEGOTIATION_ORDER
            .into_iter()
            .filter(|kind| {
                failures
                    .get(&(*peer, *kind))
                    .is_some_and(|at| at.elapsed() < self.connect_backoff)
            })
            .collect()
    }

    /// Note a connect failure, or (`failed == false`) a success that
    /// clears one. Restricted (`only`) attempts are diagnostics and leave
    /// the routing memory alone.
    fn note_connect(
        &self,
        peer: PeerId,
        kind: TransportKind,
        failed: bool,
        only: Option<TransportKind>,
    ) {
        if only.is_some() {
            return;
        }
        let mut failures = self.connect_failures.lock();
        if failed {
            let backoff = self.connect_backoff;
            failures.retain(|_, at| at.elapsed() < backoff);
            failures.insert((peer, kind), tokio::time::Instant::now());
        } else {
            failures.remove(&(peer, kind));
        }
    }

    fn record(&self, peer: PeerId, kind: TransportKind, target: &DialTarget) {
        let address = target.address();
        let previous = self.records.lock().insert(
            peer,
            RouteRecord {
                transport: kind,
                address: address.clone(),
                at: SystemTime::now(),
            },
        );
        if previous.as_ref().map(|r| r.transport) != Some(kind) {
            tracing::info!(
                %peer,
                transport = kind.as_str(),
                %address,
                previous = previous.map_or("none", |r| r.transport.as_str()),
                "mesh: transport chosen for peer"
            );
        }
    }

    /// Send one `entangle/scheduler/1` request to `peer` over the first
    /// candidate that connects, returning the answer and the transport that
    /// carried it. `only` restricts the attempt to one transport.
    ///
    /// Every attempt sends `payload` as is; a request with something
    /// time-sensitive in it builds it per attempt instead
    /// ([`TransportRouter::request_tracked`]).
    pub async fn request(
        &self,
        peer: PeerId,
        payload: &[u8],
        only: Option<TransportKind>,
    ) -> Result<(Vec<u8>, TransportKind), RouteError> {
        self.request_tracked(
            peer,
            &|| payload.to_vec(),
            only,
            &AttemptCell::default(),
            None,
        )
        .await
    }

    /// [`TransportRouter::request`] with the frame built per attempt: each
    /// attempt calls `frame` once its link has connected, immediately before
    /// the frame is written (see [`Outbound`]), so connection setup and
    /// fallbacks never age what it contains. Each attempt's transport is
    /// noted in `attempt` as it starts. `budget` is how long the caller will
    /// wait for the whole request: candidates with a fallback after them
    /// share what is left of it for connecting (see
    /// [`TransportRouter::with_connect_timeout`]).
    pub async fn request_tracked(
        &self,
        peer: PeerId,
        frame: BuildFrame<'_>,
        only: Option<TransportKind>,
        attempt: &AttemptCell,
        budget: Option<Duration>,
    ) -> Result<(Vec<u8>, TransportKind), RouteError> {
        let started = tokio::time::Instant::now();
        let (candidates, skipped) = self.candidates(&peer, only);
        if candidates.is_empty() {
            return Err(RouteError::NoRoute {
                peer,
                detail: render_skipped(&skipped),
            });
        }
        let mut queue = queue(candidates);
        let mut failures = Vec::new();
        while let Some(next) = queue.pop_front() {
            let (link, target) = (next.link, next.target);
            let kind = link.kind();
            attempt.set(kind);
            let left = budget.map(|b| b.saturating_sub(started.elapsed()));
            let limit = self.connect_limit(next.retry, &queue, left);
            let outbound = Outbound::new(frame);
            let sent = link.request(&target, &outbound);
            let result = match within_setup(sent, &outbound.connecting, limit).await {
                Attempted::Done(result) => result,
                Attempted::Cut(limit) => {
                    let why = format!("not connected within {}ms", limit.as_millis());
                    tracing::debug!(%peer, transport = kind.as_str(), error = %why, "mesh: connect deadline passed, trying the next transport");
                    self.note_connect(peer, kind, true, only);
                    failures.push((kind, why));
                    queue.push_back(Next {
                        link,
                        target,
                        retry: true,
                    });
                    continue;
                }
            };
            match result {
                Ok(answer) => {
                    self.note_connect(peer, kind, false, only);
                    // A restricted attempt (`diag mesh --probe`) says what
                    // one path can do, not what dispatch chose.
                    if only.is_none() {
                        self.record(peer, kind, &target);
                    }
                    return Ok((answer, kind));
                }
                Err(LinkError::Connect(why)) => {
                    tracing::debug!(%peer, transport = kind.as_str(), error = %why, "mesh: connect failed, trying the next transport");
                    self.note_connect(peer, kind, true, only);
                    failures.push((kind, why));
                }
                Err(LinkError::FrameTooLarge { declared, max }) => {
                    return Err(RouteError::FrameTooLarge {
                        peer,
                        transport: kind,
                        declared,
                        max,
                    })
                }
                Err(LinkError::Transport(reason)) => {
                    return Err(RouteError::Failed {
                        peer,
                        transport: kind,
                        reason,
                    })
                }
            }
        }
        Err(unreachable(peer, failures))
    }

    /// Validate `task` (ATC-INT-4), check its policy trusts `peer`, and open
    /// it as a stream to `peer` over the first candidate that connects.
    ///
    /// Chunks verify against the key the chosen transport authenticated
    /// for `peer`. Nothing is dialled when validation fails.
    pub async fn open_stream(
        &self,
        peer: PeerId,
        task: &StreamingTask,
        mut options: StreamOptions,
    ) -> Result<StreamHandle, StreamError> {
        if options.capability.is_none() {
            options.capability = self.capability_tokens.clone();
        }
        validate_submit(task)?;
        check_executor_allowed(&task.integrity, &peer)?;
        let (candidates, skipped) = self.candidates(&peer, None);
        if candidates.is_empty() {
            self.count_stream("no_route", None);
            return Err(StreamError::Transport(
                RouteError::NoRoute {
                    peer,
                    detail: render_skipped(&skipped),
                }
                .to_string(),
            ));
        }
        let mut queue = queue(candidates);
        let mut failures = Vec::new();
        while let Some(next) = queue.pop_front() {
            let (link, target) = (next.link, next.target);
            let kind = link.kind();
            let limit = self.connect_limit(next.retry, &queue, None);
            let opening = link.open_stream(&target);
            let result = match within_setup(opening, &Connecting::default(), limit).await {
                Attempted::Done(result) => result,
                Attempted::Cut(limit) => {
                    let why = format!("not connected within {}ms", limit.as_millis());
                    tracing::debug!(%peer, transport = kind.as_str(), error = %why, "mesh: stream connect deadline passed, trying the next transport");
                    self.note_connect(peer, kind, true, None);
                    failures.push((kind, why));
                    queue.push_back(Next {
                        link,
                        target,
                        retry: true,
                    });
                    continue;
                }
            };
            match result {
                Ok(io) => {
                    if io.remote_peer_id() != peer {
                        // Links pin the dialled key; this is a backstop.
                        self.count_stream("transport_error", Some(kind));
                        return Err(StreamError::Transport(format!(
                            "dialled {peer} over mesh.{kind} but the transport authenticated {}",
                            io.remote_peer_id()
                        )));
                    }
                    self.note_connect(peer, kind, false, None);
                    self.record(peer, kind, &target);
                    self.count_stream("ok", Some(kind));
                    return StreamHandle::start(io, task, options);
                }
                Err(LinkError::Connect(why)) => {
                    tracing::debug!(%peer, transport = kind.as_str(), error = %why, "mesh: stream connect failed, trying the next transport");
                    self.note_connect(peer, kind, true, None);
                    failures.push((kind, why));
                }
                Err(LinkError::FrameTooLarge { declared, max }) => {
                    self.count_stream("transport_error", Some(kind));
                    return Err(StreamError::Transport(
                        RouteError::FrameTooLarge {
                            peer,
                            transport: kind,
                            declared,
                            max,
                        }
                        .to_string(),
                    ));
                }
                Err(LinkError::Transport(reason)) => {
                    self.count_stream("transport_error", Some(kind));
                    return Err(StreamError::Transport(
                        RouteError::Failed {
                            peer,
                            transport: kind,
                            reason,
                        }
                        .to_string(),
                    ));
                }
            }
        }
        let err = unreachable(peer, failures);
        self.count_stream("transport_error", err.transport());
        Err(StreamError::Transport(err.to_string()))
    }

    /// The connect deadline of the next attempt, with `queue` still to
    /// try after it: none for the last first-time candidate or for a
    /// second try; otherwise the router's cap, or an even share of `left`
    /// (what remains of the caller's budget) among the first-time
    /// candidates still to try, whichever is shorter.
    fn connect_limit(
        &self,
        retry: bool,
        queue: &VecDeque<Next>,
        left: Option<Duration>,
    ) -> Option<Duration> {
        let after = queue.iter().filter(|n| !n.retry).count();
        if retry || after == 0 {
            return None;
        }
        let still_to_try = after.saturating_add(1);
        let share = left.map_or(self.connect_timeout, |left| {
            left / u32::try_from(still_to_try).unwrap_or(u32::MAX)
        });
        Some(self.connect_timeout.min(share))
    }

    fn count_stream(&self, outcome: &str, kind: Option<TransportKind>) {
        if let Some(reg) = &self.metrics {
            entangle_observability::catalog::remote_stream_open(
                reg,
                outcome,
                TransportKind::label(kind),
            );
        }
    }
}

/// One candidate in the order it will be tried.
struct Next {
    link: Arc<dyn Link>,
    target: DialTarget,
    /// A second try of a candidate the connect deadline cut short: it runs
    /// without one, after every first-time candidate.
    retry: bool,
}

fn queue(candidates: Vec<(Arc<dyn Link>, DialTarget)>) -> VecDeque<Next> {
    candidates
        .into_iter()
        .map(|(link, target)| Next {
            link,
            target,
            retry: false,
        })
        .collect()
}

/// How one attempt ended.
enum Attempted<T> {
    /// The link's own result.
    Done(Result<T, LinkError>),
    /// The connect deadline (given here) passed before the link connected;
    /// nothing was sent.
    Cut(Duration),
}

/// Run one attempt, giving up at `limit` unless the link has reported its
/// connection set up by then: nothing was sent, so the next candidate may be
/// tried. Once set up, the attempt runs to its end.
async fn within_setup<T>(
    attempt: impl Future<Output = Result<T, LinkError>>,
    connecting: &Connecting,
    limit: Option<Duration>,
) -> Attempted<T> {
    let Some(limit) = limit else {
        return Attempted::Done(attempt.await);
    };
    tokio::pin!(attempt);
    tokio::select! {
        biased;
        result = &mut attempt => Attempted::Done(result),
        () = tokio::time::sleep(limit) => {
            if connecting.is_connected() {
                Attempted::Done(attempt.await)
            } else {
                Attempted::Cut(limit)
            }
        }
    }
}

fn no_target_reason(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::Local => "no mDNS sighting with a dialable address",
        TransportKind::Tailscale => "not a tailnet discovery candidate",
        TransportKind::Iroh => "not in the address book ([scheduler] peers)",
    }
}

fn render_skipped(skipped: &[SkippedRoute]) -> String {
    if skipped.is_empty() {
        return "no transport is configured".into();
    }
    skipped
        .iter()
        .map(|s| format!("{}: {}", s.transport, s.reason))
        .collect::<Vec<_>>()
        .join("; ")
}

fn unreachable(peer: PeerId, failures: Vec<(TransportKind, String)>) -> RouteError {
    let last = failures.last().map_or(TransportKind::Iroh, |(k, _)| *k);
    RouteError::Unreachable {
        peer,
        attempts: failures
            .iter()
            .map(|(k, why)| format!("{k}: {why}"))
            .collect::<Vec<_>>()
            .join("; "),
        last,
    }
}

#[cfg(test)]
mod tests;
