//! Adapter trait + registry. Each supported agent has its own adapter that
//! knows where the agent stores its MCP server list and how to splice in a
//! Strata-managed entry without disturbing the user's existing config.

use crate::errors::AdapterError;
use camino::{Utf8Path, Utf8PathBuf};
use serde_json::Value;
use std::collections::BTreeMap;

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
    ///
    /// Legacy in-place model. [`crate::AgentSession`] no longer uses
    /// `rewrite` + `restore` (spec §8.3 forbids modifying the user's config);
    /// it uses [`Adapter::rewrite_for_gateway`] and [`Adapter::launch_plan`].
    fn restore(&self, path: &Utf8PathBuf, snap: &Snapshot) -> Result<(), AdapterError>;

    /// Name of the agent's executable (looked up on `PATH`).
    fn binary(&self) -> &'static str;

    /// Extract every MCP server the user's config declares.
    fn servers(&self, snap: &Snapshot) -> Result<BTreeMap<String, McpServerSpec>, AdapterError>;

    /// Produce the session config: the user's config with **every** MCP
    /// server entry replaced by one pointing at
    /// `<gateway_base_url>/<server-name>`. The bearer token is never written
    /// out; the entry references the environment variable `token_env`
    /// through the agent's own mechanism.
    fn rewrite_for_gateway(
        &self,
        original: &Snapshot,
        gateway_base_url: &str,
        token_env: &str,
    ) -> Result<String, AdapterError>;

    /// Write `config_text` under `session_dir` and describe how to launch
    /// the agent so that it reads it (CLI args and environment variables).
    /// `source` is the user's config the session was prepared from (the
    /// adapter's default location or an explicit path). Must not touch the
    /// user's own config.
    fn launch_plan(
        &self,
        session_dir: &Utf8Path,
        source: &Utf8Path,
        config_text: &str,
    ) -> Result<LaunchPlan, AdapterError>;
}

/// A downstream MCP server declared in an agent config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpServerSpec {
    /// A stdio server the gateway launches itself.
    Stdio {
        /// Executable.
        command: String,
        /// Arguments.
        args: Vec<String>,
        /// Extra environment variables.
        env: BTreeMap<String, String>,
    },
    /// A remote HTTP server (`url`). The gateway reports these as
    /// unsupported (error `ENTANGLE-E0664`).
    Http {
        /// The server URL.
        url: String,
    },
}

/// How to start an agent against a session-scoped config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchPlan {
    /// The session-scoped config file that was written.
    pub config_path: Utf8PathBuf,
    /// Arguments to put before the user's own agent arguments.
    pub args: Vec<String>,
    /// Environment variables to set for the agent process.
    pub env: Vec<(String, String)>,
}

/// URL of one gateway route: `<base>/<percent-encoded name>`.
pub fn gateway_route_url(base: &str, name: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        encode_server_name(name)
    )
}

/// Percent-encode a server name for use as a URL path segment.
pub fn encode_server_name(name: &str) -> String {
    let mut out = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Inverse of [`encode_server_name`]. Returns `None` for malformed escapes
/// or non-UTF-8 results.
pub fn decode_server_name(seg: &str) -> Option<String> {
    let bytes = seg.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = seg.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Parse one server entry (as JSON) into a [`McpServerSpec`].
///
/// Understands `command` as a string (+ `args`) or as an array (OpenCode
/// style), `env` / `environment` maps, and `url`. Returns `None` for entries
/// with neither a command nor a url.
pub(crate) fn parse_server_entry(v: &Value) -> Option<McpServerSpec> {
    let obj = v.as_object()?;
    if let Some(cmd) = obj.get("command") {
        let (command, mut args) = match cmd {
            Value::String(s) => (s.clone(), Vec::new()),
            Value::Array(a) => {
                let mut it = a.iter().filter_map(|x| x.as_str().map(str::to_string));
                (it.next()?, it.collect())
            }
            _ => return None,
        };
        if let Some(Value::Array(extra)) = obj.get("args") {
            args.extend(extra.iter().filter_map(|x| x.as_str().map(str::to_string)));
        }
        let mut env = BTreeMap::new();
        for key in ["env", "environment"] {
            if let Some(Value::Object(m)) = obj.get(key) {
                for (k, val) in m {
                    if let Some(s) = val.as_str() {
                        env.insert(k.clone(), s.to_string());
                    }
                }
            }
        }
        return Some(McpServerSpec::Stdio { command, args, env });
    }
    obj.get("url")
        .and_then(Value::as_str)
        .map(|u| McpServerSpec::Http { url: u.to_string() })
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

/// Comma-separated list of all known adapter names (for error messages).
pub fn known_adapter_names() -> String {
    registry()
        .iter()
        .map(|a| a.name().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_adapter_names_lists_all_three_phase1_adapters() {
        let names = known_adapter_names();
        for n in ["claude-code", "codex", "opencode"] {
            assert!(
                names.contains(n),
                "missing adapter {n} in known_adapter_names: {names}"
            );
        }
    }

    #[test]
    fn find_adapter_is_case_insensitive() {
        assert!(find_adapter("Claude-Code").is_some());
        assert!(find_adapter("CODEX").is_some());
        assert!(find_adapter("nope-not-an-agent").is_none());
    }
}
