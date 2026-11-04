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

    /// Whether the default config ([`config_path`](Self::config_path)) is a
    /// project-scoped file read from the current directory, i.e. one that
    /// ships with whatever repository the agent is started in. Its stdio
    /// servers are commands from that repository: the agent itself asks
    /// before starting them (Claude Code does for a project `.mcp.json`),
    /// but in a session the gateway starts them instead, so the caller must
    /// get the user's consent (see [`crate::AgentSession::project_stdio_servers`]).
    /// Default: false.
    fn default_config_is_project_scoped(&self) -> bool {
        false
    }

    /// The user's own (not project-scoped) config files of this agent,
    /// whether or not they exist. Entanglement never writes them (spec
    /// §8.3); `entangle install` records their checksums and `entangle
    /// uninstall` verifies they are unchanged. Default: the
    /// [`config_path`](Self::config_path), unless it is project-scoped.
    fn user_config_files(&self) -> Vec<Utf8PathBuf> {
        if self.default_config_is_project_scoped() {
            return Vec::new();
        }
        self.config_path().map(|p| vec![p]).unwrap_or_default()
    }

    /// MCP servers the agent would also load from config files other than
    /// `original` (it merges several), mapped to the file declaring each.
    /// The session config overrides them so they cannot run outside the
    /// gateway, but the gateway does not run them: they are unavailable in
    /// the session. Default: none (the agent reads only one config).
    fn unmediated_servers(
        &self,
        original: &Snapshot,
    ) -> Result<BTreeMap<String, Utf8PathBuf>, AdapterError> {
        let _ = original;
        Ok(BTreeMap::new())
    }

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
#[derive(Clone, PartialEq, Eq)]
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
    /// A remote HTTP server (`url`), proxied by the gateway over MCP
    /// Streamable HTTP (see [`crate::gateway`]).
    Http {
        /// The server URL.
        url: String,
        /// Request headers from the user's config (`headers`, `http_headers`,
        /// `env_http_headers`, `bearer_token_env_var`), environment references
        /// already expanded. Credentials: never printed by `Debug`.
        headers: BTreeMap<String, String>,
    },
    /// A remote server using the deprecated HTTP+SSE transport (Claude Code
    /// `"type": "sse"`). The gateway speaks only Streamable HTTP, so it
    /// refuses this route (`ENTANGLE-E0664`) without contacting the server.
    LegacySse {
        /// The server's SSE endpoint URL.
        url: String,
    },
}

impl std::fmt::Debug for McpServerSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdio { command, args, env } => f
                .debug_struct("Stdio")
                .field("command", command)
                .field("args", args)
                .field("env", env)
                .finish(),
            // Header values are credentials: names only.
            Self::Http { url, headers } => f
                .debug_struct("Http")
                .field("url", url)
                .field("headers", &headers.keys().collect::<Vec<_>>())
                .finish(),
            Self::LegacySse { url } => f.debug_struct("LegacySse").field("url", url).finish(),
        }
    }
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
/// style), `env` / `environment` maps, and `url` (`"type": "sse"` marks the
/// legacy HTTP+SSE transport). Returns `None` for entries with neither a
/// command nor a url.
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
    let url = obj.get("url").and_then(Value::as_str)?.to_string();
    // Claude Code's `type` for a url entry is `http` (Streamable HTTP) or
    // `sse` (the deprecated HTTP+SSE transport of MCP 2024-11-05).
    if obj.get("type").and_then(Value::as_str) == Some("sse") {
        return Some(McpServerSpec::LegacySse { url });
    }
    let mut headers = BTreeMap::new();
    // Claude Code `headers`, Codex `http_headers`: literal values, which may
    // reference the environment.
    for key in ["headers", "http_headers"] {
        if let Some(Value::Object(m)) = obj.get(key) {
            for (k, val) in m {
                if let Some(s) = val.as_str() {
                    headers.insert(k.clone(), expand_env(s));
                }
            }
        }
    }
    // Codex `env_http_headers`: header name -> environment variable; a header
    // whose variable is unset is left out, as Codex does.
    if let Some(Value::Object(m)) = obj.get("env_http_headers") {
        for (k, var) in m {
            if let Some(v) = var.as_str().and_then(|v| std::env::var(v).ok()) {
                headers.insert(k.clone(), v);
            }
        }
    }
    // Codex `bearer_token_env_var`.
    if let Some(v) = obj
        .get("bearer_token_env_var")
        .and_then(Value::as_str)
        .and_then(|v| std::env::var(v).ok())
    {
        headers.insert("Authorization".into(), format!("Bearer {v}"));
    }
    Some(McpServerSpec::Http { url, headers })
}

/// Expand `${VAR}`, `${VAR:-default}` (Claude Code) and `{env:VAR}`
/// (OpenCode) references; an unset variable becomes the default or empty.
pub(crate) fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(['$', '{']) {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let (open, close_prefix) = if tail.starts_with("${") {
            ("${", false)
        } else if tail.starts_with("{env:") {
            ("{env:", true)
        } else {
            out.push_str(&tail[..1]);
            rest = &tail[1..];
            continue;
        };
        let inner = &tail[open.len()..];
        match inner.find('}') {
            Some(j) if j > 0 => {
                let spec = &inner[..j];
                let (name, default) = if close_prefix {
                    (spec, "")
                } else {
                    spec.split_once(":-").unwrap_or((spec, ""))
                };
                out.push_str(&std::env::var(name).unwrap_or_else(|_| default.to_string()));
                rest = &inner[j + 1..];
            }
            _ => {
                out.push_str(open);
                rest = inner;
            }
        }
    }
    out.push_str(rest);
    out
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
    /// JSON with comments and trailing commas (OpenCode's `.jsonc`).
    Jsonc,
}

/// Returns one adapter instance per supported agent.
pub fn registry() -> Vec<Box<dyn Adapter>> {
    vec![
        Box::new(claude_code::ClaudeCodeAdapter),
        Box::new(codex::CodexAdapter),
        Box::new(opencode::OpenCodeAdapter::default()),
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
    fn user_config_files_name_each_agents_own_configs() {
        let home = std::env::var("HOME").unwrap_or_default();
        let files: Vec<(String, Vec<Utf8PathBuf>)> = registry()
            .iter()
            .map(|a| (a.name().to_owned(), a.user_config_files()))
            .collect();
        let of = |n: &str| &files.iter().find(|(name, _)| name == n).unwrap().1;
        if !home.is_empty() {
            assert!(
                of("claude-code").contains(&Utf8PathBuf::from(&home).join(".claude/settings.json"))
            );
            assert!(of("codex").contains(&Utf8PathBuf::from(&home).join(".codex/config.toml")));
        }
        let oc = opencode::OpenCodeAdapter::with_dirs("/g", "/p");
        assert_eq!(
            oc.user_config_files(),
            ["/g/opencode.json", "/g/opencode.jsonc", "/g/config.json"].map(Utf8PathBuf::from)
        );
        // Never a project-scoped file such as `.mcp.json`.
        assert!(files.iter().all(|(_, f)| f.iter().all(|p| p.is_absolute())));
    }

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
    fn http_server_headers_are_read_and_env_references_expanded() {
        std::env::set_var("ENTANGLE_TEST_HDR_TOKEN", "t0k");
        std::env::set_var("ENTANGLE_TEST_HDR_KEY", "k3y");
        let spec = |v: Value| parse_server_entry(&v).unwrap();
        // Claude Code style.
        let McpServerSpec::Http { url, headers } = spec(serde_json::json!({
            "type": "http", "url": "https://x.example/mcp",
            "headers": {
                "Authorization": "Bearer ${ENTANGLE_TEST_HDR_TOKEN}",
                "X-Region": "${ENTANGLE_TEST_HDR_UNSET:-eu}",
                "X-Plain": "a$b{c}"
            }
        })) else {
            panic!("expected http")
        };
        assert_eq!(url, "https://x.example/mcp");
        assert_eq!(headers["Authorization"], "Bearer t0k");
        assert_eq!(headers["X-Region"], "eu");
        assert_eq!(headers["X-Plain"], "a$b{c}");
        // Codex style.
        let McpServerSpec::Http { headers, .. } = spec(serde_json::json!({
            "url": "https://x.example/mcp",
            "http_headers": {"X-A": "1"},
            "env_http_headers": {"X-Key": "ENTANGLE_TEST_HDR_KEY", "X-Gone": "ENTANGLE_TEST_HDR_UNSET"},
            "bearer_token_env_var": "ENTANGLE_TEST_HDR_TOKEN"
        })) else {
            panic!("expected http")
        };
        assert_eq!(headers["X-A"], "1");
        assert_eq!(headers["X-Key"], "k3y");
        assert!(!headers.contains_key("X-Gone"));
        assert_eq!(headers["Authorization"], "Bearer t0k");
        // Debug never prints a credential.
        let dbg = format!(
            "{:?}",
            spec(serde_json::json!({"url": "https://x/m", "headers": {"A": "s3cret"}}))
        );
        assert!(dbg.contains("\"A\"") && !dbg.contains("s3cret"), "{dbg}");
    }

    #[test]
    fn find_adapter_is_case_insensitive() {
        assert!(find_adapter("Claude-Code").is_some());
        assert!(find_adapter("CODEX").is_some());
        assert!(find_adapter("nope-not-an-agent").is_none());
    }
}
