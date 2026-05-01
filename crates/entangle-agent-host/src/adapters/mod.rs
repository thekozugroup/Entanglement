//! Adapter trait + registry. Each supported agent has its own adapter that
//! knows where the agent stores its MCP server list and how to splice in a
//! Strata-managed entry without disturbing the user's existing config.

use crate::errors::AdapterError;
use camino::Utf8PathBuf;

pub mod claude_code;
pub mod codex;
pub mod opencode;

/// Trait implemented by each supported AI coding agent adapter.
pub trait Adapter: Send + Sync {
    /// Human-readable agent identifier (e.g. `"claude-code"`).
    fn name(&self) -> &'static str;

    /// Canonical path to the agent's MCP config file.
    fn config_path(&self) -> Result<Utf8PathBuf, AdapterError>;

    /// Snapshot the existing config to memory.
    fn snapshot(&self, path: &Utf8PathBuf) -> Result<Snapshot, AdapterError>;

    /// Splice in a new MCP server entry pointing at the gateway URL.
    /// Returns the modified config text.
    fn rewrite(
        &self,
        original: &Snapshot,
        gateway_url: &str,
        server_name: &str,
    ) -> Result<String, AdapterError>;

    /// Restore from a [`Snapshot`] (writes the original bytes back).
    fn restore(&self, path: &Utf8PathBuf, snap: &Snapshot) -> Result<(), AdapterError>;
}

/// In-memory snapshot of an agent's original config file.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// Raw bytes of the original config, or empty if the file did not exist.
    pub original_bytes: Vec<u8>,
    /// Detected serialisation format.
    pub format: ConfigFormat,
}

/// Serialisation format of an agent config file.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigFormat {
    /// Standard JSON.
    Json,
    /// TOML.
    Toml,
    /// JSON with comments (not yet fully parsed — treated as JSON for now).
    Jsonc,
}

/// Returns one adapter instance per supported agent.
pub fn registry() -> Vec<Box<dyn Adapter>> {
    vec![
        Box::new(claude_code::ClaudeCodeAdapter),
        Box::new(codex::CodexAdapter),
        Box::new(opencode::OpenCodeAdapter),
    ]
}

/// Look up an adapter by name (case-insensitive).
pub fn find_adapter(name: &str) -> Option<Box<dyn Adapter>> {
    registry()
        .into_iter()
        .find(|a| a.name().eq_ignore_ascii_case(name))
}
