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
//!   connection is set up ([`Connecting`]); the deadline never cuts short a
//!   request already sent;
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

use std::collections::HashMap;
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

/// Handed to each [`Link::request`]: the link calls
/// [`Connecting::connected`] once its connection is set up (dialled,
/// authenticated, admitted, protocol selected) and **before** it sends
/// anything.
///
/// Until then the router may abandon the attempt at its connect deadline —
/// nothing was sent, so another transport may be tried. After it the
/// attempt runs to its end: a request that may have reached the peer is
/// never abandoned for another transport.
#[derive(Debug, Default)]
pub struct Connecting(AtomicBool);

impl Connecting {
    /// The connection is set up; nothing has been sent yet.
    pub fn connected(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether [`Connecting::connected`] was called.
    pub fn is_connected(&self) -> bool {
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
    /// request/response, calling `connecting.connected()` between the two
    /// (see [`Connecting`]).
    async fn request(
        &self,
        target: &DialTarget,
        payload: &[u8],
        connecting: &Connecting,
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
        }
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
    pub async fn request(
        &self,
        peer: PeerId,
        payload: &[u8],
        only: Option<TransportKind>,
    ) -> Result<(Vec<u8>, TransportKind), RouteError> {
        self.request_tracked(peer, payload, only, &AttemptCell::default(), None)
            .await
    }

    /// [`TransportRouter::request`], noting each attempt's transport in
    /// `attempt` as it starts. `budget` is how long the caller will wait
    /// for the whole request: candidates with a fallback after them share
    /// what is left of it for connecting (see
    /// [`TransportRouter::with_connect_timeout`]).
    pub async fn request_tracked(
        &self,
        peer: PeerId,
        payload: &[u8],
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
        let count = candidates.len();
        let mut failures = Vec::new();
        for (index, (link, target)) in candidates.into_iter().enumerate() {
            let kind = link.kind();
            attempt.set(kind);
            let left = budget.map(|b| b.saturating_sub(started.elapsed()));
            let limit = self.connect_limit(index, count, left);
            let connecting = Connecting::default();
            let sent = link.request(&target, payload, &connecting);
            match within_setup(sent, &connecting, limit).await {
                Ok(answer) => {
                    self.note_connect(peer, kind, false, only);
                    self.record(peer, kind, &target);
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
        options: StreamOptions,
    ) -> Result<StreamHandle, StreamError> {
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
        let count = candidates.len();
        let mut failures = Vec::new();
        for (index, (link, target)) in candidates.into_iter().enumerate() {
            let kind = link.kind();
            let limit = self.connect_limit(index, count, None);
            let opening = link.open_stream(&target);
            match within_setup(opening, &Connecting::default(), limit).await {
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

    /// The connect deadline of candidate `index` of `count`: none for the
    /// last; otherwise the router's cap, or an even share of `left` (what
    /// remains of the caller's budget) among the candidates still to try,
    /// whichever is shorter.
    fn connect_limit(
        &self,
        index: usize,
        count: usize,
        left: Option<Duration>,
    ) -> Option<Duration> {
        let still_to_try = count.saturating_sub(index);
        if still_to_try <= 1 {
            return None;
        }
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

/// Run one attempt, giving up at `limit` unless the link has reported its
/// connection set up by then: nothing was sent, so the next candidate may be
/// tried. Once set up, the attempt runs to its end.
async fn within_setup<T>(
    attempt: impl Future<Output = Result<T, LinkError>>,
    connecting: &Connecting,
    limit: Option<Duration>,
) -> Result<T, LinkError> {
    let Some(limit) = limit else {
        return attempt.await;
    };
    tokio::pin!(attempt);
    tokio::select! {
        biased;
        result = &mut attempt => result,
        () = tokio::time::sleep(limit) => {
            if connecting.is_connected() {
                attempt.await
            } else {
                Err(LinkError::Connect(format!(
                    "not connected within {}ms",
                    limit.as_millis()
                )))
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
