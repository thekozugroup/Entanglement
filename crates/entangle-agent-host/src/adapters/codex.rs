//! Adapter for OpenAI Codex CLI — reads/writes `~/.codex/config.toml`.

use super::{Adapter, ConfigFormat, Snapshot};
use crate::errors::AdapterError;
use camino::Utf8PathBuf;

/// Adapter for the OpenAI Codex CLI agent.
///
/// Config location: `~/.codex/config.toml`
/// MCP server entries live under `[mcp_servers.<name>]`.
pub struct CodexAdapter;

impl Adapter for CodexAdapter {
    fn name(&self) -> &'static str {
        "codex"
    }

    fn config_path(&self) -> Result<Utf8PathBuf, AdapterError> {
        let home = std::env::var("HOME").map_err(|_| AdapterError::Io("HOME unset".into()))?;
        Ok(Utf8PathBuf::from(home).join(".codex/config.toml"))
    }

    fn snapshot(&self, path: &Utf8PathBuf) -> Result<Snapshot, AdapterError> {
        let bytes = std::fs::read(path).unwrap_or_default();
        Ok(Snapshot {
            original_bytes: bytes,
            format: ConfigFormat::Toml,
        })
    }

    fn rewrite(
        &self,
        original: &Snapshot,
        gateway_url: &str,
        server_name: &str,
    ) -> Result<String, AdapterError> {
        let mut doc: toml::Value = if original.original_bytes.is_empty() {
            toml::Value::Table(toml::map::Map::new())
        } else {
            let s = std::str::from_utf8(&original.original_bytes)
                .map_err(|e| AdapterError::Parse(e.to_string()))?;
            toml::from_str(s).map_err(|e| AdapterError::Parse(e.to_string()))?
        };

        let table = doc
            .as_table_mut()
            .ok_or_else(|| AdapterError::Parse("not a table".into()))?;

        let servers = table
            .entry("mcp_servers".to_string())
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));

        let servers_table = servers
            .as_table_mut()
            .ok_or_else(|| AdapterError::Parse("mcp_servers not a table".into()))?;

        let mut entry = toml::map::Map::new();
        entry.insert("url".into(), toml::Value::String(gateway_url.into()));
        entry.insert("transport".into(), toml::Value::String("http".into()));
        servers_table.insert(server_name.into(), toml::Value::Table(entry));

        toml::to_string_pretty(&doc).map_err(|e| AdapterError::Parse(e.to_string()))
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
