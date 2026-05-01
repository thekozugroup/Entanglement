//! Adapter for OpenCode — reads/writes `~/.config/opencode/config.json`.

use super::{Adapter, ConfigFormat, Snapshot};
use crate::errors::AdapterError;
use camino::Utf8PathBuf;
use serde_json::{json, Value};

/// Adapter for the OpenCode AI coding agent.
///
/// Config location: `~/.config/opencode/config.json`
/// MCP server entries live under `mcp.servers.<name>`.
pub struct OpenCodeAdapter;

impl Adapter for OpenCodeAdapter {
    fn name(&self) -> &'static str {
        "opencode"
    }

    fn config_path(&self) -> Result<Utf8PathBuf, AdapterError> {
        let home = std::env::var("HOME").map_err(|_| AdapterError::Io("HOME unset".into()))?;
        Ok(Utf8PathBuf::from(home).join(".config/opencode/config.json"))
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
            json!({"mcp": {"servers": {}}})
        } else {
            serde_json::from_slice(&original.original_bytes)
                .map_err(|e| AdapterError::Parse(e.to_string()))?
        };

        // Ensure mcp.servers exists even if the config had a partial structure.
        if json.get("mcp").is_none() {
            json["mcp"] = json!({"servers": {}});
        }
        if json["mcp"].get("servers").is_none() {
            json["mcp"]["servers"] = json!({});
        }

        let servers = json["mcp"]["servers"]
            .as_object_mut()
            .ok_or_else(|| AdapterError::Parse("mcp.servers missing or not an object".into()))?;

        servers.insert(
            server_name.into(),
            json!({
                "type": "http",
                "url": gateway_url,
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
