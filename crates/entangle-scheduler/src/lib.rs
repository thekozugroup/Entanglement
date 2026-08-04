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
//!
//! # Remote execution is opt-in
//!
//! A [`Dispatcher`] built with [`Dispatcher::new`] has no transport and runs
//! everything locally, exactly as a single-machine node always has. Only
//! [`Dispatcher::with_remote`] turns on cross-node dispatch.
//!
//! Symmetrically, a node executes work *for* others only if it is running a
//! [`RemoteTaskServer`], and then only for peers its [`PeerAllowlist`]
//! authorizes. Nothing here executes anything for an unauthenticated peer.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod dispatcher;
pub mod errors;
pub mod placement;
pub mod remote;
pub mod wire;
pub mod worker;

pub use dispatcher::{DispatchError, DispatchResult, Dispatcher};
pub use placement::{choose, PlacementChoice, PlacementError};
pub use remote::{
    serve_tasks, PeerAddressBook, PeerAllowlist, PeerDirectory, RemoteDispatch, RemoteTaskServer,
    StaticAllowlist, MAX_REMOTE_TASK_TIMEOUT_MS,
};
pub use wire::{RemoteErrorCode, RemoteOutcome, RemoteTaskRequest, RemoteTaskResponse, WireError};
pub use worker::{WorkerInfo, WorkerPool};
