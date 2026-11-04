//! Adapter for Claude Code — reads/writes `.mcp.json` in the project root.

use super::{
    gateway_route_url, parse_server_entry, Adapter, ConfigFormat, LaunchPlan, McpServerSpec,
    Snapshot,
};
use crate::errors::AdapterError;
use camino::{Utf8Path, Utf8PathBuf};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Adapter for the Claude Code AI coding agent.
///
/// Phase 1 targets the project-local `.mcp.json` file. A future iteration
/// will also handle `~/.claude.json` and the platform-specific user config.
pub struct ClaudeCodeAdapter;

impl Adapter for ClaudeCodeAdapter {
    fn name(&self) -> &'static str {
        "claude-code"
    }

    fn config_path(&self) -> Result<Utf8PathBuf, AdapterError> {
        Ok(Utf8PathBuf::from(".mcp.json"))
    }

    fn default_config_is_project_scoped(&self) -> bool {
        true
    }

    /// `~/.claude/settings.json` (spec §8.3): the user's own config, which a
    /// session never touches. Not `~/.claude.json`: that is Claude Code's
    /// mutable app state (start-up counters, per-project history), which it
    /// rewrites on every run — sessions launched by `entangle agent run`
    /// included — so a checksum of it would report a change after any use.
    fn user_config_files(&self) -> Vec<Utf8PathBuf> {
        let Ok(home) = std::env::var("HOME") else {
            return Vec::new();
        };
        vec![Utf8PathBuf::from(home).join(".claude/settings.json")]
    }

    fn snapshot(&self, path: &Utf8PathBuf) -> Result<Snapshot, AdapterError> {
        let bytes = std::fs::read(path).unwrap_or_default();
        Ok(Snapshot {
            original_bytes: bytes,
            format: ConfigFormat::Json,
        })
    }

    fn rewrite(
        &self,
        original: &Snapshot,
        gateway_url: &str,
        server_name: &str,
    ) -> Result<String, AdapterError> {
        let mut json: Value = if original.original_bytes.is_empty() {
            json!({"mcpServers": {}})
        } else {
            serde_json::from_slice(&original.original_bytes)
                .map_err(|e| AdapterError::Parse(e.to_string()))?
        };

        let servers = json
            .as_object_mut()
            .ok_or_else(|| AdapterError::Parse("root not an object".into()))?
            .entry("mcpServers")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| AdapterError::Parse("mcpServers not an object".into()))?;

        servers.insert(
            server_name.to_string(),
            json!({
                "type": "http",
                "url": gateway_url,
                "headers": {
                    "X-Entangle-Session": "managed"
                }
            }),
        );

        serde_json::to_string_pretty(&json).map_err(|e| AdapterError::Parse(e.to_string()))
    }

    fn restore(&self, path: &Utf8PathBuf, snap: &Snapshot) -> Result<(), AdapterError> {
        if snap.original_bytes.is_empty() {
            let _ = std::fs::remove_file(path);
            Ok(())
        } else {
            std::fs::write(path, &snap.original_bytes).map_err(|e| AdapterError::Io(e.to_string()))
        }
    }

    fn binary(&self) -> &'static str {
        "claude"
    }

    fn servers(&self, snap: &Snapshot) -> Result<BTreeMap<String, McpServerSpec>, AdapterError> {
        if snap.original_bytes.is_empty() {
            return Ok(BTreeMap::new());
        }
        let v: Value = serde_json::from_slice(&snap.original_bytes)
            .map_err(|e| AdapterError::Parse(e.to_string()))?;
        Ok(v.get("mcpServers")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, e)| parse_server_entry(e).map(|s| (k.clone(), s)))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn rewrite_for_gateway(
        &self,
        original: &Snapshot,
        gateway_base_url: &str,
        token_env: &str,
    ) -> Result<String, AdapterError> {
        let mut root: Value = if original.original_bytes.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&original.original_bytes)
                .map_err(|e| AdapterError::Parse(e.to_string()))?
        };
        let obj = root
            .as_object_mut()
            .ok_or_else(|| AdapterError::Parse("root not an object".into()))?;
        let names: Vec<String> = obj
            .get("mcpServers")
            .and_then(Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let mut servers = serde_json::Map::new();
        for name in names {
            servers.insert(
                name.clone(),
                json!({
                    "type": "http",
                    "url": gateway_route_url(gateway_base_url, &name),
                    // Claude Code expands ${VAR} in headers: the token never hits disk.
                    "headers": {"Authorization": format!("Bearer ${{{token_env}}}")}
                }),
            );
        }
        obj.insert("mcpServers".into(), Value::Object(servers));
        serde_json::to_string_pretty(&root).map_err(|e| AdapterError::Parse(e.to_string()))
    }

    fn launch_plan(
        &self,
        session_dir: &Utf8Path,
        _source: &Utf8Path,
        config_text: &str,
    ) -> Result<LaunchPlan, AdapterError> {
        let path = session_dir.join("claude-mcp.json");
        std::fs::write(&path, config_text).map_err(|e| AdapterError::Io(e.to_string()))?;
        Ok(LaunchPlan {
            args: vec![
                "--mcp-config".into(),
                path.to_string(),
                // Ignore the user's own MCP config so nothing bypasses the gateway.
                "--strict-mcp-config".into(),
            ],
            config_path: path,
            env: Vec::new(),
        })
    }
}
