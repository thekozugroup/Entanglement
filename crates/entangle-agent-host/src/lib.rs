//! Agent-host layer (spec §8.3): per-agent config adapters, session-scoped
//! config rewriting, and the MCP gateway HTTP server.
//!
//! Adapters snapshot (read-only) and rewrite an agent's MCP config into a
//! session-scoped copy so all the agent's tool calls route through
//! the [`gateway`]; the user's own config is never modified.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adapters;
pub mod builtin;
pub mod errors;
pub mod gateway;
mod http_downstream;
pub mod session;

pub use adapters::{
    find_adapter, find_deferred, known_adapter_names, registry, Adapter, ConfigFormat,
    DeferredAdapter, LaunchPlan, McpServerSpec, SandboxPaths, Snapshot, DEFERRED_ADAPTERS,
};
pub use builtin::{BuiltinServer, EntangleTools, PluginBackend, PluginTool, ENTANGLE_SERVER_NAME};
pub use errors::{AdapterError, SessionError};
pub use gateway::{
    generate_bearer_token, AuditDecision, AuditOutcome, AuditRecord, Decision, Gateway,
    GatewayConfig, GatewayError, GatewayHandle, GatewayHooks, Policy, ToolCall,
};
pub use session::AgentSession;
