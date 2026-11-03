//! `AgentSession`: session-scoped config, original never modified, cleanup.

use camino::{Utf8Path, Utf8PathBuf};
use entangle_agent_host::{
    adapters::claude_code::ClaudeCodeAdapter, Adapter, AdapterError, AgentSession, LaunchPlan,
    McpServerSpec, SessionError, Snapshot,
};
use std::collections::BTreeMap;
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

#[cfg(unix)]
#[test]
fn codex_session_links_the_files_next_to_the_chosen_config() {
    let dir = TempDir::new().unwrap();
    let src_dir = dir.path().join("work-codex");
    fs::create_dir(&src_dir).unwrap();
    let src = src_dir.join("codex.toml");
    let original = "[mcp_servers.git]\ncommand = \"uvx\"\nargs = [\"mcp-server-git\"]\n";
    fs::write(&src, original).unwrap();
    fs::write(src_dir.join("auth.json"), r#"{"who":"work"}"#).unwrap();
    fs::write(src_dir.join("config.toml"), "# another config\n").unwrap();
    let mut s = AgentSession::prepare("codex", Some(&utf8(&src))).unwrap();
    let plan = s
        .activate(&utf8(&dir.path().join("sess")), BASE, "TOK")
        .unwrap()
        .clone();
    let home = plan.config_path.parent().unwrap();
    let auth = home.join("auth.json");
    assert!(
        fs::symlink_metadata(&auth).is_ok_and(|m| m.file_type().is_symlink()),
        "auth.json next to the chosen config is linked into CODEX_HOME"
    );
    assert_eq!(
        fs::canonicalize(fs::read_link(&auth).unwrap()).unwrap(),
        fs::canonicalize(src_dir.join("auth.json")).unwrap()
    );
    let cfg_meta = fs::symlink_metadata(&plan.config_path).unwrap();
    assert!(
        cfg_meta.is_file(),
        "config.toml is the session config, not a link"
    );
    let text = fs::read_to_string(&plan.config_path).unwrap();
    assert!(text.contains(&format!("{BASE}/git")) && !text.contains("uvx"));
    assert!(
        !home.join("codex.toml").exists(),
        "the user's original config is not linked in"
    );
    s.cleanup().unwrap();
    assert_eq!(fs::read_to_string(&src).unwrap(), original);
    assert_eq!(
        fs::read_to_string(src_dir.join("auth.json")).unwrap(),
        r#"{"who":"work"}"#,
        "cleanup does not follow the links"
    );
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

/// Claude Code adapter whose `launch_plan` writes part of the session and
/// then fails, like a full disk would.
struct FailingLaunch;

impl Adapter for FailingLaunch {
    fn name(&self) -> &'static str {
        "failing-launch"
    }
    fn config_path(&self) -> Result<Utf8PathBuf, AdapterError> {
        ClaudeCodeAdapter.config_path()
    }
    fn snapshot(&self, path: &Utf8PathBuf) -> Result<Snapshot, AdapterError> {
        ClaudeCodeAdapter.snapshot(path)
    }
    fn rewrite(&self, o: &Snapshot, url: &str, name: &str) -> Result<String, AdapterError> {
        ClaudeCodeAdapter.rewrite(o, url, name)
    }
    fn restore(&self, path: &Utf8PathBuf, snap: &Snapshot) -> Result<(), AdapterError> {
        ClaudeCodeAdapter.restore(path, snap)
    }
    fn binary(&self) -> &'static str {
        "claude"
    }
    fn servers(&self, snap: &Snapshot) -> Result<BTreeMap<String, McpServerSpec>, AdapterError> {
        ClaudeCodeAdapter.servers(snap)
    }
    fn rewrite_for_gateway(
        &self,
        o: &Snapshot,
        base: &str,
        token_env: &str,
    ) -> Result<String, AdapterError> {
        ClaudeCodeAdapter.rewrite_for_gateway(o, base, token_env)
    }
    fn launch_plan(
        &self,
        session_dir: &Utf8Path,
        _source: &Utf8Path,
        text: &str,
    ) -> Result<LaunchPlan, AdapterError> {
        fs::create_dir_all(session_dir.join("partial")).unwrap();
        fs::write(session_dir.join("partial/credentials-link"), text).unwrap();
        Err(AdapterError::Io("No space left on device".into()))
    }
}

#[test]
fn failed_activate_removes_the_session_dir() {
    let dir = TempDir::new().unwrap();
    let src = utf8(&dir.path().join("none.json"));
    let sess_dir = utf8(&dir.path().join("sess"));
    let mut s = AgentSession::with_adapter(Box::new(FailingLaunch), Some(&src)).unwrap();
    let err = s
        .activate(&sess_dir, BASE, "T")
        .expect_err("launch_plan failure must surface");
    assert!(err.to_string().contains("No space left"), "{err}");
    assert!(
        !sess_dir.exists(),
        "a failed activate must not leave the session dir behind"
    );
    assert!(matches!(s.launch_plan(), Err(SessionError::NotActivated)));
    s.cleanup().unwrap();
    assert!(!sess_dir.exists());
}

#[test]
fn second_activate_removes_the_first_session_dir() {
    let dir = TempDir::new().unwrap();
    let src = utf8(&dir.path().join("none.json"));
    let first = utf8(&dir.path().join("sess-1"));
    let second = utf8(&dir.path().join("sess-2"));
    let mut s = AgentSession::prepare("claude-code", Some(&src)).unwrap();
    s.activate(&first, BASE, "T").unwrap();
    assert!(first.exists());
    let plan = s.activate(&second, BASE, "T").unwrap().clone();
    assert!(plan.config_path.starts_with(&second));
    assert!(!first.exists(), "the replaced activation's dir is removed");
    s.cleanup().unwrap();
    assert!(!second.exists());
}

#[cfg(unix)]
#[test]
fn activate_creates_a_private_session_dir() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let src = utf8(&dir.path().join("none.json"));
    let root = utf8(&dir.path().join("root"));
    let sess_dir = root.join("sess");
    let mut s = AgentSession::prepare("claude-code", Some(&src)).unwrap();
    s.activate(&sess_dir, BASE, "T").unwrap();
    for d in [&root, &sess_dir] {
        let mode = fs::metadata(d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{d} has mode {mode:o}");
    }
    s.cleanup().unwrap();
}

#[test]
fn activate_refuses_an_existing_session_dir() {
    let dir = TempDir::new().unwrap();
    let src = utf8(&dir.path().join("none.json"));
    let sess_dir = utf8(&dir.path().join("sess"));
    fs::create_dir(&sess_dir).unwrap();
    fs::write(sess_dir.join("keep.txt"), "not the session's").unwrap();
    {
        let mut s = AgentSession::prepare("claude-code", Some(&src)).unwrap();
        let err = s
            .activate(&sess_dir, BASE, "T")
            .expect_err("an existing directory must not be taken over");
        assert!(err.to_string().contains("already exists"), "{err}");
        s.cleanup().unwrap();
    }
    assert_eq!(
        fs::read_to_string(sess_dir.join("keep.txt")).unwrap(),
        "not the session's",
        "a directory the session did not create is never deleted"
    );
}

#[test]
fn unknown_agent_is_an_error() {
    assert!(matches!(
        AgentSession::prepare("nope", None),
        Err(SessionError::UnknownAgent(_))
    ));
}
