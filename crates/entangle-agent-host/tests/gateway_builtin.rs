//! A built-in server (`entangle_agent_host::builtin`) is a gateway route
//! like any other: bearer auth, policy, audit, timeout and reply-size cap.
//! Uses a fake plugin backend; the real daemon is exercised by
//! `entangle-cli/tests/agent_tools.rs`.

use std::sync::Arc;
use std::time::Duration;

use camino::Utf8PathBuf;
use entangle_agent_host::builtin::{BoxFuture, PluginBackend, PluginTool};
use entangle_agent_host::{
    generate_bearer_token, AgentSession, AuditDecision, AuditOutcome, EntangleTools, Gateway,
    GatewayConfig, GatewayError, GatewayHandle, McpServerSpec, Policy, ENTANGLE_SERVER_NAME,
};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct Fake;

impl PluginBackend for Fake {
    fn list(&self) -> BoxFuture<'_, Result<Vec<PluginTool>, String>> {
        Box::pin(async {
            Ok(["pub/echo@0.1.0", "pub/slow@0.1.0", "pub/big@0.1.0"]
                .iter()
                .map(|id| PluginTool {
                    plugin_id: (*id).into(),
                    tier: Some(1),
                })
                .collect())
        })
    }
    fn invoke(
        &self,
        plugin_id: &str,
        input: Vec<u8>,
        _timeout: Duration,
    ) -> BoxFuture<'_, Result<Vec<u8>, String>> {
        let id = plugin_id.to_owned();
        Box::pin(async move {
            if id.contains("slow") {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            if id.contains("big") {
                return Ok(vec![b'x'; 64 * 1024]);
            }
            Ok(input)
        })
    }
}

async fn gateway(policy: Policy, timeout: Duration, max_reply: usize) -> (GatewayHandle, String) {
    let token = generate_bearer_token();
    let gw = Gateway::new(GatewayConfig {
        bearer_token: token.clone(),
        ..GatewayConfig::default()
    })
    .with_builtin_server(ENTANGLE_SERVER_NAME, Arc::new(EntangleTools::new(Fake)))
    .with_policy(policy)
    .with_request_timeout(timeout)
    .with_max_downstream_message_bytes(max_reply)
    .start()
    .await
    .unwrap();
    (gw, token)
}

async fn post(gw: &GatewayHandle, token: Option<&str>, msg: &Value) -> (u16, Value) {
    let body = msg.to_string();
    let mut s = tokio::net::TcpStream::connect(gw.addr).await.unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "POST /mcp/entangle HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{auth}\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

fn call(name: &str, input: &str) -> Value {
    json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
           "params":{"name":name,"arguments":{"input":input}}})
}

#[tokio::test]
async fn builtin_route_is_authenticated_policed_and_audited() {
    let policy = Policy {
        allow: vec![],
        deny: vec!["entangle/slow".into()],
    };
    let (gw, token) = gateway(policy, Duration::from_secs(10), 1 << 20).await;

    // No token: nothing is served.
    let (status, _) = post(
        &gw,
        None,
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    assert_eq!(status, 401);

    let (status, list) = post(
        &gw,
        Some(&token),
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    assert_eq!(status, 200);
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["big", "echo", "slow"]);

    let (_, ok) = post(&gw, Some(&token), &call("echo", "hello")).await;
    assert_eq!(ok["id"], 7);
    assert_eq!(ok["result"]["content"][0]["text"], "hello");

    let (_, denied) = post(&gw, Some(&token), &call("slow", "x")).await;
    let msg = denied["error"]["message"].as_str().unwrap();
    assert!(msg.starts_with("ENTANGLE-E0661"), "{msg}");

    let audit = gw.audit_log();
    assert_eq!(audit.len(), 2, "{audit:?}");
    assert_eq!(audit[0].server, "entangle");
    assert_eq!(audit[0].tool, "echo");
    assert_eq!(audit[0].decision, AuditDecision::Allow);
    assert_eq!(audit[0].outcome, AuditOutcome::Ok);
    assert_eq!(audit[1].tool, "slow");
    assert_eq!(audit[1].decision, AuditDecision::Deny);
    gw.shutdown().await;
}

#[tokio::test]
async fn builtin_route_has_the_same_timeout_and_reply_cap() {
    let (gw, token) = gateway(Policy::default(), Duration::from_millis(300), 16 * 1024).await;
    let started = std::time::Instant::now();
    let (_, slow) = post(&gw, Some(&token), &call("slow", "x")).await;
    assert!(started.elapsed() < Duration::from_secs(10));
    let msg = slow["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("ENTANGLE-E0663") && msg.contains("timed out"),
        "{msg}"
    );

    let (_, big) = post(&gw, Some(&token), &call("big", "x")).await;
    let msg = big["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("ENTANGLE-E0663") && msg.contains("cap"),
        "{msg}"
    );

    let audit = gw.audit_log();
    assert!(
        audit
            .iter()
            .all(|r| matches!(r.outcome, AuditOutcome::TransportError { .. })),
        "{audit:?}"
    );
    gw.shutdown().await;
}

#[tokio::test]
async fn builtin_name_must_not_collide_with_a_configured_server() {
    let mut servers = std::collections::BTreeMap::new();
    servers.insert(
        ENTANGLE_SERVER_NAME.to_owned(),
        McpServerSpec::Stdio {
            command: "true".into(),
            args: vec![],
            env: Default::default(),
        },
    );
    let err = Gateway::new(GatewayConfig {
        bearer_token: generate_bearer_token(),
        ..GatewayConfig::default()
    })
    .with_servers(servers)
    .with_builtin_server(ENTANGLE_SERVER_NAME, Arc::new(EntangleTools::new(Fake)))
    .start()
    .await
    .unwrap_err();
    assert!(matches!(err, GatewayError::BuiltinNameTaken { .. }));
    assert!(err.to_string().starts_with("ENTANGLE-E0687"), "{err}");
}

/// Every adapter can add the built-in server to its session config, next
/// to the user's own servers, with the same gateway URL and token
/// reference shape, and without touching the user's file.
#[test]
fn every_adapter_adds_the_builtin_route_to_the_session_config() {
    let dir = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
    let cases = [
        (
            "claude-code",
            "mcp.json",
            r#"{"mcpServers":{"fs":{"command":"npx","args":["fs"]}}}"#,
        ),
        (
            "codex",
            "config.toml",
            "model = \"x\"\n[mcp_servers.fs]\ncommand = \"npx\"\n",
        ),
        (
            "opencode",
            "opencode.json",
            r#"{"mcp":{"fs":{"type":"local","command":["npx","fs"]}}}"#,
        ),
    ];
    for (agent, file, text) in cases {
        let src = root.join(agent).join(file);
        std::fs::create_dir_all(src.parent().unwrap()).unwrap();
        std::fs::write(&src, text).unwrap();
        let mut s = AgentSession::prepare(agent, Some(&src)).unwrap();
        s.add_builtin_server(ENTANGLE_SERVER_NAME).unwrap();
        // The gateway does not run it as a downstream server.
        assert!(!s.servers().contains_key(ENTANGLE_SERVER_NAME), "{agent}");
        assert_eq!(s.builtin_servers(), [ENTANGLE_SERVER_NAME.to_owned()]);
        // Twice is a conflict.
        let err = s.add_builtin_server(ENTANGLE_SERVER_NAME).unwrap_err();
        assert!(err.to_string().starts_with("ENTANGLE-E0687"), "{err}");

        let session_dir = root.join(format!("sess-{agent}"));
        let plan = s
            .activate(&session_dir, "http://127.0.0.1:9/mcp", "TOK")
            .unwrap()
            .clone();
        let written = std::fs::read_to_string(&plan.config_path).unwrap();
        assert!(
            written.contains("http://127.0.0.1:9/mcp/entangle"),
            "{agent}: {written}"
        );
        assert!(
            written.contains("http://127.0.0.1:9/mcp/fs"),
            "{agent}: {written}"
        );
        assert!(!written.contains("npx"), "{agent}: {written}");
        assert_eq!(std::fs::read_to_string(&src).unwrap(), text, "{agent}");
        s.cleanup().unwrap();
    }

    // A user server already called `entangle` is a conflict, not an override.
    let src = root.join("conflict.json");
    std::fs::write(&src, r#"{"mcpServers":{"entangle":{"command":"x"}}}"#).unwrap();
    let mut s = AgentSession::prepare("claude-code", Some(&src)).unwrap();
    let err = s.add_builtin_server(ENTANGLE_SERVER_NAME).unwrap_err();
    assert!(err.to_string().starts_with("ENTANGLE-E0687"), "{err}");
}
