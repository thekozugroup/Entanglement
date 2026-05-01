//! [`AgentSession`] — owns the per-session MCP config patch + cleanup.

use crate::{
    adapters::{find_adapter, Adapter, Snapshot},
    errors::SessionError,
};
use camino::Utf8PathBuf;

/// A live agent-host session.
///
/// On construction, snapshots the agent's existing MCP config, splices in the
/// Strata gateway URL, and writes the patched config to disk.  On drop (or
/// explicit [`restore`](Self::restore)), the original config is restored.
pub struct AgentSession {
    adapter: Box<dyn Adapter>,
    config_path: Utf8PathBuf,
    snapshot: Snapshot,
}

impl AgentSession {
    /// Start a new session for `agent_name`.
    ///
    /// * `agent_name`   — case-insensitive agent identifier (e.g. `"claude-code"`).
    /// * `gateway_url`  — base URL of the Strata MCP gateway.
    /// * `server_name`  — key used for the injected entry in the config.
    pub fn start(
        agent_name: &str,
        gateway_url: &str,
        server_name: &str,
    ) -> Result<Self, SessionError> {
        let adapter = find_adapter(agent_name)
            .ok_or_else(|| SessionError::UnknownAgent(agent_name.into()))?;
        let path = adapter.config_path()?;
        let snap = adapter.snapshot(&path)?;
        let new_config = adapter.rewrite(&snap, gateway_url, server_name)?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, new_config.as_bytes())
            .map_err(|e| SessionError::Adapter(crate::errors::AdapterError::Io(e.to_string())))?;

        tracing::debug!(
            agent = agent_name,
            path = %path,
            gateway_url,
            server_name,
            "agent-host session started"
        );

        Ok(Self {
            adapter,
            config_path: path,
            snapshot: snap,
        })
    }

    /// The name of the agent this session manages.
    pub fn agent(&self) -> &str {
        self.adapter.name()
    }

    /// Path to the config file that was patched.
    pub fn config_path(&self) -> &Utf8PathBuf {
        &self.config_path
    }

    /// Explicitly restore the original config and consume the session.
    ///
    /// Prefer this over relying on [`Drop`] because it surfaces errors.
    pub fn restore(self) -> Result<(), SessionError> {
        self.adapter
            .restore(&self.config_path, &self.snapshot)
            .map_err(Into::into)
    }
}

impl Drop for AgentSession {
    fn drop(&mut self) {
        // Best-effort restore — explicit `restore()` is preferred because it
        // surfaces errors.  We log a warning on Drop failure but never panic.
        if let Err(e) = self.adapter.restore(&self.config_path, &self.snapshot) {
            tracing::warn!(
                error = %e,
                path = %self.config_path,
                "agent-host session restore on Drop failed"
            );
        }
    }
}
