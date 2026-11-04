//! Distributed compute scheduler.
//!
//! Placement decides *which machine* runs a task; dispatch makes it happen.
//!
//! * [`placement`] — greedy multi-criteria scoring over a [`WorkerPool`].
//! * [`dispatcher`] — the [`Dispatcher`]: place, then execute locally or on
//!   the chosen peer.
//! * [`remote`] — cross-node dispatch over a mesh transport: the
//!   [`RemoteDispatch`] client and the [`RemoteTaskServer`] executor.
//! * [`wire`] — the versioned binary envelope the two exchange.
//! * [`work_unit`] — the integrity-policy envelope: canonical encoding and
//!   `policy_hash` (INV-INT-1).
//! * [`integrity`] — the submitter-side acceptance pipeline: submit-time
//!   validation, the output-size short-circuit (INV-INT-2), hash quorum and
//!   `SemanticEquivalent` metric verification (spec §7.5).
//! * [`reputation`] — per-peer, per-policy-variant correctness reputation.
//! * [`spot_check`] — the Layer-2 spot-check (spec §7.5): a sample of
//!   accepted `Deterministic` / `SemanticEquivalent` tasks re-run on another
//!   executor after the result is returned; a mismatch downranks the
//!   replicas behind the accepted output.
//! * [`stream`] — streaming tasks (spec §7.1): the `entangle/stream/1`
//!   protocol, credit flow control, heartbeats, chunk signing, and the
//!   [`StreamServer`] executor.
//! * [`transport`] — multi-transport routing (spec §6.1): `local`,
//!   `tailscale` and `iroh` as [`transport::Link`]s, the per-peer
//!   [`TransportRouter`] with the §6.1 order, `[mesh] preferred` and
//!   per-peer overrides, fallback on connect failure, and serving the
//!   scheduler protocols over the tailnet ([`serve_tailscale`]).
//!
//! # Remote execution is opt-in
//!
//! A [`Dispatcher`] built with [`Dispatcher::new`] has no transport and runs
//! everything locally, exactly as a single-machine node always has. Only
//! [`Dispatcher::with_remote`] turns on cross-node dispatch.
//!
//! Symmetrically, a node executes work *for* others only if it is running a
//! [`RemoteTaskServer`], and then only for peers its [`PeerAllowlist`]
//! authorizes **and** that present a capability token it issued to them
//! ([`capability`]: a `mesh.peer` biscuit, attenuated per request).
//! Nothing here executes anything for an unauthenticated peer.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod capability;
pub mod dispatcher;
pub mod errors;
pub mod integrity;
pub mod placement;
pub mod remote;
pub mod reputation;
pub mod spot_check;
pub mod stream;
pub mod transport;
pub mod wire;
pub mod work_unit;
pub mod worker;

pub use capability::{CapabilityGate, CapabilityTokens, HeldToken, StaticTokens};
pub use dispatcher::{DispatchError, DispatchResult, Dispatcher};
pub use integrity::{
    IntegrityVerifier, OutputSizeExceededWarning, ReplicaReport, ReplicaStatus, TELEMETRY_TARGET,
};
pub use placement::{choose, rank, PlacementChoice, PlacementError};
pub use remote::{
    send_control_over, serve_tasks, PeerAddressBook, PeerAllowlist, PeerDirectory, RemoteDispatch,
    RemoteReplica, RemoteTaskServer, StaticAllowlist, MAX_REMOTE_TASK_TIMEOUT_MS,
};
pub use reputation::{ReputationReason, ReputationStore, ReputationTier};
pub use spot_check::{
    SpotCheck, SpotCheckConfig, SpotCheckHandle, SpotCheckRecord, SpotCheckVerdict, SpotChecker,
    TieBreak,
};
pub use stream::{
    open_stream, serve_streams, validate_submit as validate_stream_submit, StreamError,
    StreamHandle, StreamServer,
};
pub use transport::{
    serve_tailscale, IrohLink, RouteError, RoutePolicy, StreamIo, TailscaleLink, TransportKind,
    TransportRouter,
};
pub use wire::{
    ControlAction, ControlFrame, RemoteErrorCode, RemoteOutcome, RemoteRequest, RemoteTaskRequest,
    RemoteTaskResponse, RequestFrame, WireError,
};
pub use work_unit::{PolicyEnvelope, PolicyHash};
pub use worker::{WorkerInfo, WorkerPool};
