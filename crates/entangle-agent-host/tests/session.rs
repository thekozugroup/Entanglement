//! `AgentSession`: session-scoped config, original never modified, cleanup.

use camino::Utf8PathBuf;
use entangle_agent_host::{AgentSession, McpServerSpec, SessionError};
use std::fs;
use tempfile::TempDir;

const BASE: &str = "http://127.0.0.1:9000/mcp";

fn utf8(p: &std::path::Path) -> Utf8PathBuf {
    Utf8PathBuf::from_path_buf(p.to_path_buf()).expect("utf8 tempdir")
}

#[test]
fn claude_session_rewrites_every_server_into_session_dir_and_leaves_original_alone() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join(".mcp.json");
    let original = r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","fs"],"env":{"A":"b"}},"remote":{"type":"http","url":"http://x/mcp"}},"other":1}"#;
    fs::write(&src, original).unwrap();
    let sess_dir = utf8(&dir.path().join("sess"));

    let mut s = AgentSession::prepare("claude-code", Some(&utf8(&src))).unwrap();
    assert_eq!(s.servers().len(), 2);
    assert!(matches!(
        s.servers().get("fs"),
        Some(McpServerSpec::Stdio { command, args, env })
            if command == "npx" && args == &["-y", "fs"] && env.get("A").map(String::as_str) == Some("b")
    ));
    assert!(matches!(
        s.servers().get("remote"),
        Some(McpServerSpec::Http { .. })
    ));
    assert!(matches!(s.launch_plan(), Err(SessionError::NotActivated)));

    let plan = s
        .activate(&sess_dir, BASE, "ENTANGLE_SESSION_TOKEN")
        .unwrap()
        .clone();
    assert!(plan.config_path.starts_with(&sess_dir));
    assert_eq!(plan.args[0], "--mcp-config");
    assert!(plan.args.contains(&"--strict-mcp-config".to_string()));

    let text = fs::read_to_string(&plan.config_path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["mcpServers"]["fs"]["url"], format!("{BASE}/fs"));
    assert_eq!(v["mcpServers"]["remote"]["url"], format!("{BASE}/remote"));
    assert_eq!(v["other"], 1, "unrelated keys preserved");
    assert!(
        !text.contains("npx"),
        "original command must not leak into session config"
    );
    assert!(text.contains("${ENTANGLE_SESSION_TOKEN}"));

    assert_eq!(
        fs::read_to_string(&src).unwrap(),
        original,
        "original untouched"
    );
    s.cleanup().unwrap();
    assert!(!sess_dir.exists(), "session dir removed");
    assert_eq!(fs::read_to_string(&src).unwrap(), original);
}

#[test]
fn missing_source_config_yields_empty_session() {
    let dir = TempDir::new().unwrap();
    let src = utf8(&dir.path().join("absent.json"));
    let sess_dir = utf8(&dir.path().join("sess"));
    let mut s = AgentSession::prepare("claude-code", Some(&src)).unwrap();
    assert!(s.servers().is_empty());
    s.activate(&sess_dir, BASE, "T").unwrap();
    s.cleanup().unwrap();
    assert!(!src.exists(), "must not create the user's config");
    assert!(!sess_dir.exists());
}

#[test]
fn cleanup_detects_modified_original() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join(".mcp.json");
    fs::write(&src, r#"{"mcpServers":{}}"#).unwrap();
    let mut s = AgentSession::prepare("claude-code", Some(&utf8(&src))).unwrap();
    s.activate(&utf8(&dir.path().join("sess")), BASE, "T")
        .unwrap();
    fs::write(&src, r#"{"mcpServers":{"x":{"command":"y"}}}"#).unwrap();
    let err = s.cleanup().expect_err("tampering must be reported");
    assert!(matches!(err, SessionError::OriginalModified(_)));
    assert!(err.to_string().contains("ENTANGLE-E0660"));
}

#[test]
fn drop_removes_session_dir() {
    let dir = TempDir::new().unwrap();
    let src = utf8(&dir.path().join("none.json"));
    let sess_dir = utf8(&dir.path().join("sess"));
    {
        let mut s = AgentSession::prepare("claude-code", Some(&src)).unwrap();
        s.activate(&sess_dir, BASE, "T").unwrap();
        assert!(sess_dir.exists());
    }
    assert!(!sess_dir.exists());
}

#[test]
fn codex_session_uses_codex_home_and_env_var_token() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("config.toml");
    fs::write(
        &src,
        "model = \"o3\"\n[mcp_servers.git]\ncommand = \"uvx\"\nargs = [\"mcp-server-git\"]\n",
    )
    .unwrap();
    fs::write(dir.path().join("auth.json"), "{}").unwrap();
    let mut s = AgentSession::prepare("codex", Some(&utf8(&src))).unwrap();
    assert!(matches!(
        s.servers().get("git"),
        Some(McpServerSpec::Stdio { .. })
    ));
    let plan = s
        .activate(&utf8(&dir.path().join("sess")), BASE, "TOK")
        .unwrap()
        .clone();
    assert!(plan
        .env
        .iter()
        .any(|(k, v)| k == "CODEX_HOME" && plan.config_path.starts_with(v)));
    let doc: toml::Value = toml::from_str(&fs::read_to_string(&plan.config_path).unwrap()).unwrap();
    assert_eq!(doc["model"].as_str(), Some("o3"));
    assert_eq!(
        doc["mcp_servers"]["git"]["url"].as_str(),
        Some(format!("{BASE}/git").as_str())
    );
    assert_eq!(
        doc["mcp_servers"]["git"]["bearer_token_env_var"].as_str(),
        Some("TOK")
    );
    s.cleanup().unwrap();
}

#[test]
fn opencode_session_sets_opencode_config_env() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("config.json");
    fs::write(
        &src,
        r#"{"mcp":{"servers":{"a":{"command":["node","a.js"],"environment":{"K":"v"}}}}}"#,
    )
    .unwrap();
    let mut s = AgentSession::prepare("opencode", Some(&utf8(&src))).unwrap();
    assert!(matches!(
        s.servers().get("a"),
        Some(McpServerSpec::Stdio { command, args, env }) if command == "node" && args == &["a.js"] && env.len() == 1
    ));
    let plan = s
        .activate(&utf8(&dir.path().join("sess")), BASE, "TOK")
        .unwrap()
        .clone();
    assert!(plan.env.iter().any(|(k, _)| k == "OPENCODE_CONFIG"));
    let text = fs::read_to_string(&plan.config_path).unwrap();
    assert!(text.contains("{env:TOK}") && text.contains(&format!("{BASE}/a")));
    s.cleanup().unwrap();
}

#[test]
fn unknown_agent_is_an_error() {
    assert!(matches!(
        AgentSession::prepare("nope", None),
        Err(SessionError::UnknownAgent(_))
    ));
}
