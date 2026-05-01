//! Integration tests for each config adapter.

use entangle_agent_host::adapters::{find_adapter, ConfigFormat};
use std::fs;
use tempfile::TempDir;

const GW: &str = "http://127.0.0.1:9000/mcp";
const SRV: &str = "strata";

// ── claude-code ─────────────────────────────────────────────────────────────

#[test]
fn claude_code_rewrite_empty_creates_minimal_config_with_gateway_url() {
    let adapter = find_adapter("claude-code").unwrap();
    let snap = entangle_agent_host::adapters::Snapshot {
        original_bytes: vec![],
        format: ConfigFormat::Json,
    };
    let out = adapter.rewrite(&snap, GW, SRV).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["mcpServers"][SRV]["url"], GW);
    assert_eq!(v["mcpServers"][SRV]["type"], "http");
}

#[test]
fn claude_code_rewrite_preserves_existing_servers() {
    let existing = serde_json::json!({
        "mcpServers": {
            "my-tool": { "type": "http", "url": "http://localhost:8080" }
        }
    });
    let snap = entangle_agent_host::adapters::Snapshot {
        original_bytes: serde_json::to_vec(&existing).unwrap(),
        format: ConfigFormat::Json,
    };
    let adapter = find_adapter("claude-code").unwrap();
    let out = adapter.rewrite(&snap, GW, SRV).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    // Both old and new entries present
    assert!(v["mcpServers"]["my-tool"].is_object());
    assert_eq!(v["mcpServers"][SRV]["url"], GW);
}

#[test]
fn claude_code_snapshot_then_restore_round_trips() {
    let dir = TempDir::new().unwrap();
    let path = camino::Utf8PathBuf::from_path_buf(dir.path().join(".mcp.json")).unwrap();
    let original = r#"{"mcpServers":{"existing":{"type":"http","url":"http://old"}}}"#;
    fs::write(&path, original).unwrap();

    let adapter = find_adapter("claude-code").unwrap();
    let snap = adapter.snapshot(&path).unwrap();
    assert_eq!(snap.original_bytes, original.as_bytes());

    // Overwrite with something different
    fs::write(&path, b"garbage").unwrap();

    // Restore
    adapter.restore(&path, &snap).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
}

// ── codex ────────────────────────────────────────────────────────────────────

fn codex_home() -> TempDir {
    let dir = TempDir::new().unwrap();
    std::env::set_var("HOME", dir.path().to_str().unwrap());
    dir
}

#[test]
fn codex_rewrite_empty_creates_minimal_config_with_gateway_url() {
    let _dir = codex_home();
    let adapter = find_adapter("codex").unwrap();
    let snap = entangle_agent_host::adapters::Snapshot {
        original_bytes: vec![],
        format: ConfigFormat::Toml,
    };
    let out = adapter.rewrite(&snap, GW, SRV).unwrap();
    let v: toml::Value = toml::from_str(&out).unwrap();
    assert_eq!(v["mcp_servers"][SRV]["url"].as_str().unwrap(), GW);
    assert_eq!(v["mcp_servers"][SRV]["transport"].as_str().unwrap(), "http");
}

#[test]
fn codex_rewrite_preserves_existing_servers() {
    let _dir = codex_home();
    let existing = r#"
[mcp_servers.existing-tool]
url = "http://localhost:7070"
transport = "http"
"#;
    let snap = entangle_agent_host::adapters::Snapshot {
        original_bytes: existing.as_bytes().to_vec(),
        format: ConfigFormat::Toml,
    };
    let adapter = find_adapter("codex").unwrap();
    let out = adapter.rewrite(&snap, GW, SRV).unwrap();
    let v: toml::Value = toml::from_str(&out).unwrap();
    assert!(v["mcp_servers"]["existing-tool"].is_table());
    assert_eq!(v["mcp_servers"][SRV]["url"].as_str().unwrap(), GW);
}

#[test]
fn codex_snapshot_then_restore_round_trips() {
    let dir = codex_home();
    let config_dir = dir.path().join(".codex");
    fs::create_dir_all(&config_dir).unwrap();
    let path_buf = config_dir.join("config.toml");
    let path = camino::Utf8PathBuf::from_path_buf(path_buf.clone()).unwrap();
    let original = "[mcp_servers.old]\nurl = \"http://old\"\ntransport = \"http\"\n";
    fs::write(&path_buf, original).unwrap();

    let adapter = find_adapter("codex").unwrap();
    let snap = adapter.snapshot(&path).unwrap();
    assert_eq!(snap.original_bytes, original.as_bytes());

    fs::write(&path_buf, b"garbage").unwrap();
    adapter.restore(&path, &snap).unwrap();
    assert_eq!(fs::read_to_string(&path_buf).unwrap(), original);
}

// ── opencode ─────────────────────────────────────────────────────────────────

fn opencode_home() -> TempDir {
    let dir = TempDir::new().unwrap();
    std::env::set_var("HOME", dir.path().to_str().unwrap());
    dir
}

#[test]
fn opencode_rewrite_empty_creates_minimal_config_with_gateway_url() {
    let _dir = opencode_home();
    let adapter = find_adapter("opencode").unwrap();
    let snap = entangle_agent_host::adapters::Snapshot {
        original_bytes: vec![],
        format: ConfigFormat::Json,
    };
    let out = adapter.rewrite(&snap, GW, SRV).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["mcp"]["servers"][SRV]["url"], GW);
    assert_eq!(v["mcp"]["servers"][SRV]["type"], "http");
}

#[test]
fn opencode_rewrite_preserves_existing_servers() {
    let _dir = opencode_home();
    let existing = serde_json::json!({
        "mcp": {
            "servers": {
                "existing-tool": { "type": "http", "url": "http://localhost:6060" }
            }
        }
    });
    let snap = entangle_agent_host::adapters::Snapshot {
        original_bytes: serde_json::to_vec(&existing).unwrap(),
        format: ConfigFormat::Json,
    };
    let adapter = find_adapter("opencode").unwrap();
    let out = adapter.rewrite(&snap, GW, SRV).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v["mcp"]["servers"]["existing-tool"].is_object());
    assert_eq!(v["mcp"]["servers"][SRV]["url"], GW);
}

#[test]
fn opencode_snapshot_then_restore_round_trips() {
    let dir = opencode_home();
    let config_dir = dir.path().join(".config/opencode");
    fs::create_dir_all(&config_dir).unwrap();
    let path_buf = config_dir.join("config.json");
    let path = camino::Utf8PathBuf::from_path_buf(path_buf.clone()).unwrap();
    let original = r#"{"mcp":{"servers":{"old":{"type":"http","url":"http://old"}}}}"#;
    fs::write(&path_buf, original).unwrap();

    let adapter = find_adapter("opencode").unwrap();
    let snap = adapter.snapshot(&path).unwrap();
    assert_eq!(snap.original_bytes, original.as_bytes());

    fs::write(&path_buf, b"garbage").unwrap();
    adapter.restore(&path, &snap).unwrap();
    assert_eq!(fs::read_to_string(&path_buf).unwrap(), original);
}
