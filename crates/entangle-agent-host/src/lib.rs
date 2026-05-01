//! Agent-host plugin scaffold (spec §8).
//!
//! Phase 1 ships the **configuration adapter** layer: snapshot / rewrite /
//! restore the agent's MCP config so all the agent's tool calls route through
//! a Strata-managed gateway. The gateway itself (forwarding tool calls into
//! the kernel + biscuit verification) is in a follow-up iteration.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adapters;
pub mod errors;
pub mod session;

pub use adapters::{find_adapter, registry, Adapter, ConfigFormat, Snapshot};
pub use errors::{AdapterError, SessionError};
pub use session::AgentSession;
