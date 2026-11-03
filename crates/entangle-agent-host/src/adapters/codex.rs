//! Adapter for OpenAI Codex CLI — reads/writes `~/.codex/config.toml`.

use super::{
    gateway_route_url, parse_server_entry, Adapter, ConfigFormat, LaunchPlan, McpServerSpec,
    Snapshot,
};
use crate::errors::AdapterError;
use camino::{Utf8Path, Utf8PathBuf};
use std::collections::BTreeMap;

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

    fn binary(&self) -> &'static str {
        "codex"
    }

    fn servers(&self, snap: &Snapshot) -> Result<BTreeMap<String, McpServerSpec>, AdapterError> {
        if snap.original_bytes.is_empty() {
            return Ok(BTreeMap::new());
        }
        let s = std::str::from_utf8(&snap.original_bytes)
            .map_err(|e| AdapterError::Parse(e.to_string()))?;
        let doc: toml::Value = toml::from_str(s).map_err(|e| AdapterError::Parse(e.to_string()))?;
        let Some(table) = doc.get("mcp_servers").and_then(toml::Value::as_table) else {
            return Ok(BTreeMap::new());
        };
        Ok(table
            .iter()
            .filter_map(|(k, e)| {
                let json = serde_json::to_value(e).ok()?;
                parse_server_entry(&json).map(|s| (k.clone(), s))
            })
            .collect())
    }

    fn rewrite_for_gateway(
        &self,
        original: &Snapshot,
        gateway_base_url: &str,
        token_env: &str,
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
        let names: Vec<String> = table
            .get("mcp_servers")
            .and_then(toml::Value::as_table)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let mut servers = toml::map::Map::new();
        for name in names {
            let mut entry = toml::map::Map::new();
            entry.insert(
                "url".into(),
                toml::Value::String(gateway_route_url(gateway_base_url, &name)),
            );
            // Codex reads the bearer token from this env var at connect time.
            entry.insert(
                "bearer_token_env_var".into(),
                toml::Value::String(token_env.into()),
            );
            servers.insert(name, toml::Value::Table(entry));
        }
        table.insert("mcp_servers".into(), toml::Value::Table(servers));
        toml::to_string_pretty(&doc).map_err(|e| AdapterError::Parse(e.to_string()))
    }

    fn launch_plan(
        &self,
        session_dir: &Utf8Path,
        source: &Utf8Path,
        config_text: &str,
    ) -> Result<LaunchPlan, AdapterError> {
        // Codex reads `$CODEX_HOME/config.toml`. Point CODEX_HOME at a session
        // directory and symlink the other files next to the config the
        // session was read from (auth.json, ...) into it so login state
        // survives. Neither the source config nor a `config.toml` next to it
        // is linked: the session's own config.toml replaces them.
        let home = session_dir.join("codex-home");
        std::fs::create_dir_all(&home).map_err(|e| AdapterError::Io(e.to_string()))?;
        #[cfg(unix)]
        link_siblings(source, &home)?;
        #[cfg(not(unix))]
        let _ = source;
        let path = home.join("config.toml");
        std::fs::write(&path, config_text).map_err(|e| AdapterError::Io(e.to_string()))?;
        Ok(LaunchPlan {
            env: vec![("CODEX_HOME".into(), home.to_string())],
            config_path: path,
            args: Vec::new(),
        })
    }
}

/// Symlink every entry of `source`'s directory except `source` itself and
/// any `config.toml` into `home`. A missing directory links nothing; any
/// other failure is an error (an agent started without its login state
/// would fail confusingly later).
#[cfg(unix)]
fn link_siblings(source: &Utf8Path, home: &Utf8Path) -> Result<(), AdapterError> {
    let parent = source
        .parent()
        .filter(|p| !p.as_str().is_empty())
        .unwrap_or(Utf8Path::new("."));
    // Absolute targets: a relative one would resolve against `home`.
    let dir = match std::fs::canonicalize(parent) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(AdapterError::Io(format!("resolving {parent}: {e}"))),
    };
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| AdapterError::Io(format!("reading {}: {e}", dir.display())))?;
    for ent in entries {
        let ent = ent.map_err(|e| AdapterError::Io(format!("reading {}: {e}", dir.display())))?;
        let name = ent.file_name();
        if name == "config.toml" || source.file_name().is_some_and(|f| name == f) {
            continue;
        }
        let target = ent.path();
        std::os::unix::fs::symlink(&target, home.as_std_path().join(&name)).map_err(|e| {
            AdapterError::Io(format!("linking {} into {home}: {e}", target.display()))
        })?;
    }
    Ok(())
}
