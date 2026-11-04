//! Adapter for OpenCode — reads `opencode.json` / `opencode.jsonc`.
//!
//! OpenCode's MCP schema, as documented by OpenCode (no network access was
//! available to re-check it against a live OpenCode; the adapter's tests use
//! fixtures of both entry shapes):
//!
//! ```json
//! { "mcp": {
//!     "fs":  { "type": "local", "command": ["npx", "-y", "server-fs"],
//!              "environment": { "K": "v" }, "enabled": true },
//!     "web": { "type": "remote", "url": "https://example/mcp",
//!              "headers": { "K": "v" }, "enabled": true } } }
//! ```
//!
//! Strings may reference environment variables as `{env:VAR}`.
//!
//! OpenCode does not replace one config with another: it deep-merges every
//! config file it finds. The session config handed over in `OPENCODE_CONFIG`
//! therefore cannot hide the user's own servers. Instead it carries an entry
//! under the **same name** for every server declared in any config OpenCode
//! merges, so each of the user's entries is overridden by a `remote` entry
//! pointing at the gateway (see [`OpenCodeAdapter`] for the files read).

use super::{gateway_route_url, Adapter, ConfigFormat, LaunchPlan, McpServerSpec, Snapshot};
use crate::errors::AdapterError;
use camino::{Utf8Path, Utf8PathBuf};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// Global config files OpenCode reads from its config directory.
const GLOBAL_FILES: [&str; 3] = ["opencode.json", "opencode.jsonc", "config.json"];

/// Project config files OpenCode reads from each directory between the
/// working directory and the repository root.
const PROJECT_FILES: [&str; 4] = [
    "opencode.json",
    "opencode.jsonc",
    ".opencode/opencode.json",
    ".opencode/opencode.jsonc",
];

/// Adapter for the OpenCode AI coding agent.
///
/// Default config (the one whose servers the gateway runs):
/// `opencode.json`, else `opencode.jsonc`, else `config.json` in the global
/// config directory (`$XDG_CONFIG_HOME/opencode`, default
/// `~/.config/opencode`). MCP servers are `mcp.<name>` entries.
///
/// For the session config, server names are also collected from every other
/// file OpenCode merges: the global files above, and `opencode.json(c)` and
/// `.opencode/opencode.json(c)` in the working directory and each parent up
/// to the one holding `.git`. A file that exists but cannot be parsed is an
/// error, so no server can stay outside the gateway unnoticed.
#[derive(Clone, Debug, Default)]
pub struct OpenCodeAdapter {
    global_dir: Option<Utf8PathBuf>,
    project_dir: Option<Utf8PathBuf>,
}

impl OpenCodeAdapter {
    /// Adapter that reads OpenCode's global config from `global_dir` and
    /// starts the project config lookup at `project_dir`, instead of the
    /// global config directory and the current directory.
    pub fn with_dirs(
        global_dir: impl Into<Utf8PathBuf>,
        project_dir: impl Into<Utf8PathBuf>,
    ) -> Self {
        Self {
            global_dir: Some(global_dir.into()),
            project_dir: Some(project_dir.into()),
        }
    }

    fn global_dir(&self) -> Result<Utf8PathBuf, AdapterError> {
        if let Some(d) = &self.global_dir {
            return Ok(d.clone());
        }
        if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|x| !x.is_empty()) {
            return Utf8PathBuf::from_path_buf(x.into())
                .map(|d| d.join("opencode"))
                .map_err(|p| {
                    AdapterError::Io(format!("non-UTF-8 XDG_CONFIG_HOME {}", p.display()))
                });
        }
        let home = std::env::var("HOME").map_err(|_| AdapterError::Io("HOME unset".into()))?;
        Ok(Utf8PathBuf::from(home).join(".config/opencode"))
    }

    fn project_dir(&self) -> Result<Utf8PathBuf, AdapterError> {
        if let Some(d) = &self.project_dir {
            return Ok(d.clone());
        }
        let cwd = std::env::current_dir().map_err(|e| AdapterError::Io(e.to_string()))?;
        Utf8PathBuf::from_path_buf(cwd)
            .map_err(|p| AdapterError::Io(format!("non-UTF-8 current directory {}", p.display())))
    }

    /// Every config file OpenCode merges (other than `OPENCODE_CONFIG`),
    /// whether or not it exists.
    fn merged_config_files(&self) -> Result<Vec<Utf8PathBuf>, AdapterError> {
        let global = self.global_dir()?;
        let mut files: Vec<Utf8PathBuf> = GLOBAL_FILES.iter().map(|f| global.join(f)).collect();
        for dir in self.project_dir()?.ancestors() {
            files.extend(PROJECT_FILES.iter().map(|f| dir.join(f)));
            if dir.join(".git").exists() {
                break;
            }
        }
        Ok(files)
    }

    /// Server names declared in the merged config files, each with the
    /// first file declaring it.
    fn merged_server_names(&self) -> Result<BTreeMap<String, Utf8PathBuf>, AdapterError> {
        let mut names = BTreeMap::new();
        for file in self.merged_config_files()? {
            let bytes = match std::fs::read(&file) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(AdapterError::Io(format!("{file}: {e}"))),
            };
            let entries = parse_jsonc(&bytes)
                .and_then(|root| mcp_entries(&root))
                .map_err(|e| AdapterError::Parse(format!("{file}: {e}")))?;
            for name in entries.keys() {
                names.entry(name.clone()).or_insert_with(|| file.clone());
            }
        }
        Ok(names)
    }
}

impl Adapter for OpenCodeAdapter {
    fn name(&self) -> &'static str {
        "opencode"
    }

    fn config_path(&self) -> Result<Utf8PathBuf, AdapterError> {
        let dir = self.global_dir()?;
        Ok(GLOBAL_FILES
            .iter()
            .map(|f| dir.join(f))
            .find(|p| p.exists())
            .unwrap_or_else(|| dir.join(GLOBAL_FILES[0])))
    }

    fn snapshot(&self, path: &Utf8PathBuf) -> Result<Snapshot, AdapterError> {
        let bytes = std::fs::read(path).unwrap_or_default();
        let format = if path.extension() == Some("jsonc") {
            ConfigFormat::Jsonc
        } else {
            ConfigFormat::Json
        };
        Ok(Snapshot {
            original_bytes: bytes,
            format,
        })
    }

    fn rewrite(
        &self,
        original: &Snapshot,
        gateway_url: &str,
        server_name: &str,
    ) -> Result<String, AdapterError> {
        let mut root = parse_root(original)?;
        let mcp = root
            .as_object_mut()
            .ok_or_else(|| AdapterError::Parse("root not an object".into()))?
            .entry("mcp")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| AdapterError::Parse("mcp not an object".into()))?;
        mcp.insert(
            server_name.into(),
            json!({"type": "remote", "url": gateway_url, "enabled": true}),
        );
        serde_json::to_string_pretty(&root).map_err(|e| AdapterError::Parse(e.to_string()))
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
        let root = parse_root(snap)?;
        Ok(mcp_entries(&root)
            .map_err(AdapterError::Parse)?
            .iter()
            .filter_map(|(k, e)| parse_entry(e).map(|s| (k.clone(), s)))
            .collect())
    }

    fn unmediated_servers(
        &self,
        original: &Snapshot,
    ) -> Result<BTreeMap<String, Utf8PathBuf>, AdapterError> {
        let root = parse_root(original)?;
        let own = mcp_entries(&root).map_err(AdapterError::Parse)?;
        let mut names = self.merged_server_names()?;
        names.retain(|name, _| !own.contains_key(name));
        Ok(names)
    }

    fn rewrite_for_gateway(
        &self,
        original: &Snapshot,
        gateway_base_url: &str,
        token_env: &str,
    ) -> Result<String, AdapterError> {
        let served = self.servers(original)?;
        let mut root = parse_root(original)?;
        let mut names: Vec<String> = mcp_entries(&root)
            .map_err(AdapterError::Parse)?
            .keys()
            .cloned()
            .collect();
        // Re-read the other configs now, as close to the agent's start as
        // possible, so a server added since `prepare` is still overridden.
        names.extend(self.merged_server_names()?.into_keys());
        let mut mcp = Map::new();
        for name in names {
            // Same key as the user's entry, so it overrides it in OpenCode's
            // deep merge. `type: remote` makes OpenCode use `url`; fields
            // this entry does not set (a local entry's `command`,
            // `environment`) may survive the merge but are not used for a
            // remote server. Only servers the gateway runs are enabled; the
            // others (disabled by the user, or declared in a config the
            // gateway does not run) still point at the gateway, which does
            // not serve them.
            let enabled = served.contains_key(&name);
            mcp.insert(
                name.clone(),
                json!({
                    "type": "remote",
                    "url": gateway_route_url(gateway_base_url, &name),
                    // OpenCode substitutes {env:VAR}: the token never hits disk.
                    "headers": {"Authorization": format!("Bearer {{env:{token_env}}}")},
                    "enabled": enabled,
                }),
            );
        }
        root.as_object_mut()
            .ok_or_else(|| AdapterError::Parse("root not an object".into()))?
            .insert("mcp".into(), Value::Object(mcp));
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
        // Assumption (OpenCode's documented load order, not verified here):
        // newer OpenCode versions merge OPENCODE_CONFIG *before* the
        // project's opencode.json and merge the inline OPENCODE_CONFIG_CONTENT
        // last. The overrides are therefore passed in both, the inline copy
        // holding only the `mcp` section so the rest of the user's config
        // (which may hold provider keys) is not put in the environment.
        // Versions that do not know OPENCODE_CONFIG_CONTENT ignore it.
        let session: Value = serde_json::from_str(config_text)
            .map_err(|e| AdapterError::Parse(format!("session config: {e}")))?;
        let inline = json!({"mcp": session.get("mcp").cloned().unwrap_or_else(|| json!({}))});
        Ok(LaunchPlan {
            env: vec![
                ("OPENCODE_CONFIG".into(), path.to_string()),
                ("OPENCODE_CONFIG_CONTENT".into(), inline.to_string()),
            ],
            config_path: path,
            args: Vec::new(),
        })
    }
}

/// Parse a snapshot (empty: an empty config).
fn parse_root(snap: &Snapshot) -> Result<Value, AdapterError> {
    if snap.original_bytes.is_empty() {
        return Ok(json!({}));
    }
    parse_jsonc(&snap.original_bytes).map_err(AdapterError::Parse)
}

/// The `mcp` object of a config (empty when absent).
fn mcp_entries(root: &Value) -> Result<Map<String, Value>, String> {
    let obj = root.as_object().ok_or("root not an object")?;
    match obj.get("mcp") {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(m)) => Ok(m.clone()),
        Some(_) => Err("mcp not an object".into()),
    }
}

/// Parse one `mcp.<name>` entry. `None` for a disabled entry or one that is
/// not a valid local or remote server (OpenCode would not start it either).
fn parse_entry(v: &Value) -> Option<McpServerSpec> {
    let obj = v.as_object()?;
    if obj.get("enabled") == Some(&Value::Bool(false)) {
        return None;
    }
    match obj.get("type")?.as_str()? {
        "local" => {
            let mut parts = obj
                .get("command")?
                .as_array()?
                .iter()
                .map(|x| x.as_str().map(substitute_env))
                .collect::<Option<Vec<_>>>()?
                .into_iter();
            let command = parts.next()?;
            let mut env = BTreeMap::new();
            if let Some(Value::Object(m)) = obj.get("environment") {
                for (k, val) in m {
                    env.insert(k.clone(), substitute_env(val.as_str()?));
                }
            }
            Some(McpServerSpec::Stdio {
                command,
                args: parts.collect(),
                env,
            })
        }
        "remote" => {
            let mut headers = BTreeMap::new();
            if let Some(Value::Object(m)) = obj.get("headers") {
                for (k, val) in m {
                    headers.insert(k.clone(), substitute_env(val.as_str()?));
                }
            }
            Some(McpServerSpec::Http {
                url: substitute_env(obj.get("url")?.as_str()?),
                headers,
            })
        }
        _ => None,
    }
}

/// Replace each `{env:VAR}` with the variable's value (empty when unset), as
/// OpenCode does.
fn substitute_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("{env:") {
        out.push_str(&rest[..i]);
        let after = &rest[i + "{env:".len()..];
        match after.find('}') {
            Some(j) if j > 0 => {
                out.push_str(&std::env::var(&after[..j]).unwrap_or_default());
                rest = &after[j + 1..];
            }
            _ => {
                out.push_str("{env:");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Parse JSON with comments (`//`, `/* */`) and trailing commas, which
/// OpenCode accepts in its config files.
fn parse_jsonc(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    serde_json::from_str(&strip_jsonc(text)).map_err(|e| e.to_string())
}

/// Remove comments and trailing commas outside strings.
fn strip_jsonc(text: &str) -> String {
    // Pass 1: comments become whitespace (newlines kept for error positions).
    let mut plain = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            plain.push(c);
            match c {
                '\\' => {
                    if let Some(n) = chars.next() {
                        plain.push(n);
                    }
                }
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match (c, chars.peek()) {
            ('"', _) => {
                in_string = true;
                plain.push(c);
            }
            ('/', Some('/')) => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        plain.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut prev = ' ';
                for n in chars.by_ref() {
                    if n == '\n' {
                        plain.push('\n');
                    }
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
                plain.push(' ');
            }
            _ => plain.push(c),
        }
    }
    // Pass 2: drop a comma followed only by whitespace and `}` or `]`.
    let mut out = String::with_capacity(plain.len());
    let mut in_string = false;
    let mut escaped = false;
    for (i, c) in plain.char_indices() {
        if in_string {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
        } else if c == '"' {
            in_string = true;
        } else if c == ',' {
            let next = plain[i + 1..].chars().find(|n| !n.is_whitespace());
            if matches!(next, Some('}') | Some(']')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_jsonc_handles_comments_trailing_commas_and_strings() {
        let text = r#"{
  // line comment with "quotes" and a , }
  "a": "x // not a comment, ]", /* block
  comment */ "b": [1, 2,],
  "c": "esc \" , }",
}"#;
        let v: Value = serde_json::from_str(&strip_jsonc(text)).unwrap();
        assert_eq!(
            v,
            json!({"a": "x // not a comment, ]", "b": [1, 2], "c": "esc \" , }"})
        );
    }

    #[test]
    fn substitute_env_replaces_known_and_empties_unknown() {
        let path = std::env::var("PATH").unwrap_or_default();
        assert_eq!(substitute_env("a{env:PATH}b"), format!("a{path}b"));
        assert_eq!(substitute_env("{env:ENTANGLE_SURELY_UNSET_VAR_X}z"), "z");
        assert_eq!(substitute_env("{env:}{env:open"), "{env:}{env:open");
    }
}
