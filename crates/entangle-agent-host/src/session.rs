//! [`AgentSession`] — owns the per-session MCP config and its cleanup.
//!
//! Spec §8.3: the user's own agent config is **never modified**. A session
//! snapshots it (read-only), extracts the declared MCP servers (which the
//! gateway launches itself), writes a rewritten config under a session
//! directory, and tells the caller how to launch the agent against it
//! ([`LaunchPlan`]). Cleanup removes the session directory and verifies the
//! original is byte-for-byte unchanged.

use crate::{
    adapters::{find_adapter, Adapter, LaunchPlan, McpServerSpec, Snapshot},
    errors::{AdapterError, SessionError},
};
use camino::{Utf8Path, Utf8PathBuf};
use std::collections::BTreeMap;

/// A live agent-host session.
///
/// Two phases, because the gateway needs the server list before it can bind
/// and the rewritten config needs the gateway's port:
/// [`prepare`](Self::prepare) (read-only) then [`activate`](Self::activate).
pub struct AgentSession {
    adapter: Box<dyn Adapter>,
    source_path: Utf8PathBuf,
    snapshot: Snapshot,
    servers: BTreeMap<String, McpServerSpec>,
    unmediated: BTreeMap<String, Utf8PathBuf>,
    /// The config is the adapter's project-scoped default (no explicit source).
    project_scoped: bool,
    /// The session directory handed to [`activate`](Self::activate). Recorded
    /// before any filesystem work so that a failed activation, a second
    /// activation, [`cleanup`](Self::cleanup) and [`Drop`] all remove it.
    session_dir: Option<Utf8PathBuf>,
    active: Option<LaunchPlan>,
    finished: bool,
}

impl AgentSession {
    /// Snapshot `agent_name`'s config (read-only) and extract its MCP servers.
    ///
    /// `source` overrides the adapter's default config location.
    pub fn prepare(agent_name: &str, source: Option<&Utf8Path>) -> Result<Self, SessionError> {
        let adapter = find_adapter(agent_name)
            .ok_or_else(|| SessionError::UnknownAgent(agent_name.into()))?;
        Self::with_adapter(adapter, source)
    }

    /// Like [`prepare`](Self::prepare), with an explicit adapter instead of
    /// one looked up by name in the [registry](crate::registry).
    pub fn with_adapter(
        adapter: Box<dyn Adapter>,
        source: Option<&Utf8Path>,
    ) -> Result<Self, SessionError> {
        let source_path = match source {
            Some(p) => p.to_path_buf(),
            None => adapter.config_path()?,
        };
        let snapshot = adapter.snapshot(&source_path)?;
        let servers = adapter.servers(&snapshot)?;
        let unmediated = adapter.unmediated_servers(&snapshot)?;
        let project_scoped = source.is_none() && adapter.default_config_is_project_scoped();
        Ok(Self {
            adapter,
            source_path,
            snapshot,
            servers,
            unmediated,
            project_scoped,
            session_dir: None,
            active: None,
            finished: false,
        })
    }

    /// Write the session-scoped config under `session_dir` pointing every
    /// server at `<gateway_base_url>/<name>`.
    ///
    /// `token_env` is the environment variable that carries the bearer token.
    ///
    /// `session_dir` must not exist yet: it is created with mode `0700`
    /// (missing parents too) so other users cannot list or read the session
    /// config. An existing directory is refused, so the session never takes
    /// over (and later deletes) a directory it did not create.
    ///
    /// The session owns the directory it created: if activation fails it is
    /// removed before the error is returned, and otherwise
    /// [`cleanup`](Self::cleanup) or [`Drop`] removes it. Activating again
    /// replaces the previous activation and removes its directory first.
    pub fn activate(
        &mut self,
        session_dir: &Utf8Path,
        gateway_base_url: &str,
        token_env: &str,
    ) -> Result<&LaunchPlan, SessionError> {
        self.active = None;
        self.remove_session_dir();
        let text = self
            .adapter
            .rewrite_for_gateway(&self.snapshot, gateway_base_url, token_env)?;
        create_private_dir(session_dir)?;
        self.session_dir = Some(session_dir.to_path_buf());
        let plan = match self
            .adapter
            .launch_plan(session_dir, &self.source_path, &text)
        {
            Ok(plan) => plan,
            Err(e) => {
                self.remove_session_dir();
                return Err(e.into());
            }
        };
        tracing::debug!(
            agent = self.adapter.name(),
            config = %plan.config_path,
            servers = self.servers.len(),
            "agent-host session activated"
        );
        Ok(self.active.insert(plan))
    }

    /// The name of the agent this session manages.
    pub fn agent(&self) -> &str {
        self.adapter.name()
    }

    /// Executable name of the agent.
    pub fn binary(&self) -> &str {
        self.adapter.binary()
    }

    /// The user's original config path (read-only).
    pub fn source_path(&self) -> &Utf8Path {
        &self.source_path
    }

    /// The MCP servers declared in the user's config.
    pub fn servers(&self) -> &BTreeMap<String, McpServerSpec> {
        &self.servers
    }

    /// The stdio servers declared in a project-scoped config that was picked
    /// up from the current directory (the adapter's default, e.g. Claude
    /// Code's `.mcp.json`), as opposed to a file the caller named. These are
    /// commands that came with the repository; the gateway runs them when
    /// the agent first connects, so the caller must get the user's consent
    /// before starting the gateway with them (spec §11). Empty when the
    /// config was named explicitly.
    pub fn project_stdio_servers(&self) -> BTreeMap<&str, &McpServerSpec> {
        if !self.project_scoped {
            return BTreeMap::new();
        }
        self.servers
            .iter()
            .filter(|(_, s)| matches!(s, McpServerSpec::Stdio { .. }))
            .map(|(n, s)| (n.as_str(), s))
            .collect()
    }

    /// Servers the agent would also load from configs other than
    /// [`source_path`](Self::source_path), mapped to the declaring file. The
    /// session config overrides them so they cannot bypass the gateway, and
    /// the gateway does not run them, so they are unavailable in the session.
    pub fn unmediated_servers(&self) -> &BTreeMap<String, Utf8PathBuf> {
        &self.unmediated
    }

    /// How to launch the agent. Errors before [`activate`](Self::activate).
    pub fn launch_plan(&self) -> Result<&LaunchPlan, SessionError> {
        self.active.as_ref().ok_or(SessionError::NotActivated)
    }

    /// Path to the session-scoped config file, once activated.
    pub fn config_path(&self) -> Option<&Utf8Path> {
        self.active.as_ref().map(|p| p.config_path.as_path())
    }

    fn original_unchanged(&self) -> bool {
        let now = std::fs::read(&self.source_path).unwrap_or_default();
        now == self.snapshot.original_bytes
    }

    fn remove_session_dir(&mut self) {
        if let Some(dir) = self.session_dir.take() {
            // remove_dir_all does not follow symlinks (codex home links).
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Delete the session directory and verify the user's original config
    /// is unchanged. Prefer this over relying on [`Drop`] (which cleans up
    /// but cannot report).
    pub fn cleanup(mut self) -> Result<(), SessionError> {
        self.finished = true;
        self.remove_session_dir();
        if self.original_unchanged() {
            Ok(())
        } else {
            Err(SessionError::OriginalModified(self.source_path.to_string()))
        }
    }
}

/// Create `dir` with mode `0700` (unix), and any missing parents likewise.
/// Fails if `dir` itself already exists.
fn create_private_dir(dir: &Utf8Path) -> Result<(), AdapterError> {
    fn builder(recursive: bool) -> std::fs::DirBuilder {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(recursive);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b
    }
    if let Some(parent) = dir.parent().filter(|p| !p.as_str().is_empty()) {
        builder(true)
            .create(parent)
            .map_err(|e| AdapterError::Io(format!("creating {parent}: {e}")))?;
    }
    builder(false).create(dir).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            AdapterError::Io(format!("session directory {dir} already exists"))
        } else {
            AdapterError::Io(format!("creating session directory {dir}: {e}"))
        }
    })
}

impl Drop for AgentSession {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.remove_session_dir();
        if !self.original_unchanged() {
            tracing::warn!(path = %self.source_path, "original agent config changed during session");
        }
    }
}
