//! Distributed compute scheduler.
//!
//! Phase 1: local-only dispatch with worker pool placement scoring. The full
//! cross-node dispatch path (Iroh streams + biscuit auth) lands in Phase 2.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod dispatcher;
pub mod errors;
pub mod placement;
pub mod worker;

pub use dispatcher::{DispatchError, DispatchResult, Dispatcher};
pub use placement::{choose, PlacementChoice, PlacementError};
pub use worker::{WorkerInfo, WorkerPool};
