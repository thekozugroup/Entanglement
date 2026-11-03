//! Adapter for OpenCode — reads/writes `~/.config/opencode/config.json`.

use super::{
    gateway_route_url, parse_server_entry, Adapter, ConfigFormat, LaunchPlan, McpServerSpec,
    Snapshot,
};
use crate::errors::AdapterError;
use camino::{Utf8Path, Utf8PathBuf};
use serde_json::{json, Value};
use std::collections::BTreeMap;

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

    fn binary(&self) -> &'static str {
        "opencode"
    }

    fn servers(&self, snap: &Snapshot) -> Result<BTreeMap<String, McpServerSpec>, AdapterError> {
        if snap.original_bytes.is_empty() {
            return Ok(BTreeMap::new());
        }
        let v: Value = serde_json::from_slice(&snap.original_bytes)
            .map_err(|e| AdapterError::Parse(e.to_string()))?;
        Ok(v.pointer("/mcp/servers")
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
        let names: Vec<String> = root
            .pointer("/mcp/servers")
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
                    // OpenCode substitutes {env:VAR}: the token never hits disk.
                    "headers": {"Authorization": format!("Bearer {{env:{token_env}}}")}
                }),
            );
        }
        let obj = root
            .as_object_mut()
            .ok_or_else(|| AdapterError::Parse("root not an object".into()))?;
        let mcp = obj.entry("mcp").or_insert_with(|| json!({}));
        let mcp = mcp
            .as_object_mut()
            .ok_or_else(|| AdapterError::Parse("mcp not an object".into()))?;
        mcp.insert("servers".into(), Value::Object(servers));
        serde_json::to_string_pretty(&root).map_err(|e| AdapterError::Parse(e.to_string()))
    }

    fn launch_plan(
        &self,
        session_dir: &Utf8Path,
        _source: &Utf8Path,
        config_text: &str,
    ) -> Result<LaunchPlan, AdapterError> {
        let path = session_dir.join("opencode.json");
        std::fs::write(&path, config_text).map_err(|e| AdapterError::Io(e.to_string()))?;
        Ok(LaunchPlan {
            // OPENCODE_CONFIG names an extra config file merged over the user's.
            env: vec![("OPENCODE_CONFIG".into(), path.to_string())],
            config_path: path,
            args: Vec::new(),
        })
    }
}
