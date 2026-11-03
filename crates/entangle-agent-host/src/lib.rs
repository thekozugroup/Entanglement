//! Agent-host layer (spec §8.3): per-agent config adapters, session-scoped
//! config rewriting, and the MCP gateway HTTP server.
//!
//! Adapters snapshot (read-only) and rewrite an agent's MCP config into a
//! session-scoped copy so all the agent's tool calls route through
//! the [`gateway`]; the user's own config is never modified.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adapters;
pub mod errors;
pub mod gateway;
pub mod session;

pub use adapters::{
    find_adapter, known_adapter_names, registry, Adapter, ConfigFormat, LaunchPlan, McpServerSpec,
    Snapshot,
};
pub use errors::{AdapterError, SessionError};
pub use gateway::{
    generate_bearer_token, AuditDecision, AuditOutcome, AuditRecord, Decision, Gateway,
    GatewayConfig, GatewayError, GatewayHandle, GatewayHooks, Policy, ToolCall,
};
pub use session::AgentSession;
