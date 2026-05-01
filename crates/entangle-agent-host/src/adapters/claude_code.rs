//! Adapter for Claude Code — reads/writes `.mcp.json` in the project root.

use super::{Adapter, ConfigFormat, Snapshot};
use crate::errors::AdapterError;
use camino::Utf8PathBuf;
use serde_json::{json, Value};

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
}
