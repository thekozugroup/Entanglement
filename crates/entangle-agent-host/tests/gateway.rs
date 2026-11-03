//! End-to-end gateway tests against a fake stdio MCP server.
//!
//! The fake server lives in this test binary: `fake_mcp_server` below is a
//! no-op unless `ENTANGLE_FAKE_MCP=1`, in which case it speaks
//! newline-delimited JSON-RPC on stdin/stdout. The gateway launches it via
//! `current_exe() --exact fake_mcp_server --nocapture`. (The libtest banner
//! lines on stdout are not JSON and the gateway ignores them.)

use entangle_agent_host::{
    generate_bearer_token, AuditDecision, AuditOutcome, Gateway, GatewayConfig, GatewayHandle,
    McpServerSpec, Policy,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, io::Write, path::PathBuf, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

// ---------------------------------------------------------------- fake server

#[test]
fn fake_mcp_server() {
    if std::env::var("ENTANGLE_FAKE_MCP").as_deref() != Ok("1") {
        return;
    }
    use std::io::BufRead;
    let log_path = std::env::var("FAKE_LOG").unwrap();
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .unwrap();
    if let Ok(p) = std::env::var("FAKE_PID") {
        std::fs::write(p, std::process::id().to_string()).unwrap();
    }
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let method = msg["method"].as_str().unwrap_or("").to_string();
        let tool = msg["params"]["name"].as_str().unwrap_or("").to_string();
        writeln!(log, "{method}:{tool}").unwrap();
        let Some(id) = msg.get("id").cloned() else {
            continue;
        };
        let result = match method.as_str() {
            "initialize" => {
                json!({"protocolVersion": msg["params"]["protocolVersion"], "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}})
            }
            "tools/list" => {
                json!({"tools": [{"name": "echo"}, {"name": "secret"}, {"name": "sleep"}, {"name": "fail"}]})
            }
            "tools/call" => match tool.as_str() {
                "echo" => {
                    json!({"content": [{"type": "text", "text": msg["params"]["arguments"]["text"]}]})
                }
                "sleep" => {
                    std::thread::sleep(Duration::from_millis(
                        msg["params"]["arguments"]["ms"].as_u64().unwrap_or(0),
                    ));
                    json!({"content": []})
                }
                "fail" => json!({"isError": true, "content": [{"type": "text", "text": "nope"}]}),
                _ => json!({"content": [{"type": "text", "text": "SECRET"}]}),
            },
            _ => json!({}),
        };
        writeln!(
            out,
            "{}",
            json!({"jsonrpc": "2.0", "id": id, "result": result})
        )
        .unwrap();
        out.flush().unwrap();
    }
}

// ------------------------------------------------------------------- harness

struct Fixture {
    gw: GatewayHandle,
    token: String,
    log: PathBuf,
    pid: PathBuf,
    _dir: TempDir,
}

fn spec(dir: &TempDir) -> (McpServerSpec, PathBuf, PathBuf) {
    let log = dir.path().join("calls.log");
    let pid = dir.path().join("pid");
    let mut env = BTreeMap::new();
    env.insert("ENTANGLE_FAKE_MCP".into(), "1".into());
    env.insert("FAKE_LOG".into(), log.display().to_string());
    env.insert("FAKE_PID".into(), pid.display().to_string());
    let s = McpServerSpec::Stdio {
        command: std::env::current_exe().unwrap().display().to_string(),
        args: vec![
            "--exact".into(),
            "fake_mcp_server".into(),
            "--nocapture".into(),
        ],
        env,
    };
    (s, log, pid)
}

async fn fixture_with(policy: Policy, max_in_flight: usize) -> Fixture {
    let dir = TempDir::new().unwrap();
    let (s, log, pid) = spec(&dir);
    let token = generate_bearer_token();
    let mut servers = BTreeMap::new();
    servers.insert("fake".to_string(), s);
    servers.insert(
        "remote".to_string(),
        McpServerSpec::Http {
            url: "http://example.invalid/mcp".into(),
        },
    );
    let gw = Gateway::new(GatewayConfig {
        bearer_token: token.clone(),
        max_in_flight,
        ..GatewayConfig::default()
    })
    .with_servers(servers)
    .with_policy(policy)
    .with_request_timeout(Duration::from_secs(20))
    .start()
    .await
    .unwrap();
    Fixture {
        gw,
        token,
        log,
        pid,
        _dir: dir,
    }
}

async fn fixture() -> Fixture {
    fixture_with(Policy::default(), 8).await
}

/// Minimal HTTP/1.1 client. Returns (status, body).
async fn http(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: &str,
) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", body.len());
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

async fn rpc(f: &Fixture, server: &str, msg: Value) -> (u16, Value) {
    let bearer = format!("Bearer {}", f.token);
    let (st, body) = http(
        f.gw.addr,
        "POST",
        &format!("/mcp/{server}"),
        Some(&bearer),
        &msg.to_string(),
    )
    .await;
    (st, serde_json::from_str(&body).unwrap_or(Value::Null))
}

fn calls(f: &Fixture) -> Vec<String> {
    std::fs::read_to_string(&f.log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

// --------------------------------------------------------------------- tests

#[tokio::test]
async fn initialize_list_and_call_round_trip() {
    let f = fixture().await;
    let (st, v) = rpc(&f, "fake", json!({"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}})).await;
    assert_eq!(st, 200);
    assert_eq!(v["id"], "init-1", "client id restored");
    assert_eq!(v["result"]["serverInfo"]["name"], "fake");
    assert_eq!(
        v["result"]["protocolVersion"], "2025-03-26",
        "pass-through of the client's version"
    );

    let (st, _) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    assert_eq!(st, 202);

    let (st, v) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":7,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(v["id"], 7);
    assert_eq!(v["result"]["tools"].as_array().unwrap().len(), 4);

    let (st, v) = rpc(&f, "fake", json!({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}})).await;
    assert_eq!(st, 200);
    assert_eq!(v["result"]["content"][0]["text"], "hi");

    // A second initialize is answered from cache, not forwarded.
    let (_, v) = rpc(&f, "fake", json!({"jsonrpc":"2.0","id":9,"method":"initialize","params":{"protocolVersion":"2025-03-26"}})).await;
    assert_eq!(v["id"], 9);
    assert_eq!(v["result"]["serverInfo"]["name"], "fake");
    let c = calls(&f);
    assert_eq!(
        c.iter().filter(|l| l.starts_with("initialize")).count(),
        1,
        "{c:?}"
    );
    assert_eq!(
        c.iter()
            .filter(|l| l.starts_with("notifications/initialized"))
            .count(),
        1,
        "{c:?}"
    );

    let log = f.gw.audit_log();
    assert_eq!(log.len(), 1);
    assert_eq!(
        (log[0].server.as_str(), log[0].tool.as_str()),
        ("fake", "echo")
    );
    assert_eq!(log[0].decision, AuditDecision::Allow);
    assert_eq!(log[0].outcome, AuditOutcome::Ok);
    f.gw.shutdown().await;
}

#[tokio::test]
async fn gateway_handshakes_itself_when_client_skips_initialize() {
    let f = fixture().await;
    let (st, v) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    assert!(v["result"]["tools"].is_array());
    let c = calls(&f);
    assert_eq!(&c[0][..], "initialize:");
    assert_eq!(&c[1][..], "notifications/initialized:");
    f.gw.shutdown().await;
}

#[tokio::test]
async fn batch_returns_array_and_all_notification_batch_is_202() {
    let f = fixture().await;
    let (st, v) = rpc(&f, "fake", json!([
        {"jsonrpc":"2.0","id":1,"method":"tools/list"},
        {"jsonrpc":"2.0","method":"notifications/cancelled","params":{}},
        {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"b"}}}
    ])).await;
    assert_eq!(st, 200);
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["id"], 1);
    assert_eq!(arr[1]["result"]["content"][0]["text"], "b");
    let (st, _) = rpc(
        &f,
        "fake",
        json!([{"jsonrpc":"2.0","method":"notifications/cancelled"}]),
    )
    .await;
    assert_eq!(st, 202);
    f.gw.shutdown().await;
}

#[tokio::test]
async fn missing_or_wrong_bearer_is_401_and_nothing_spawns() {
    let f = fixture().await;
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string();
    for auth in [
        None,
        Some("Bearer wrong"),
        Some("Basic abc"),
        Some(f.token.as_str()),
        Some("Bearer "),
    ] {
        let (st, _) = http(f.gw.addr, "POST", "/mcp/fake", auth, &body).await;
        assert_eq!(st, 401, "auth={auth:?}");
    }
    assert!(
        calls(&f).is_empty(),
        "downstream must not have been started"
    );
    f.gw.shutdown().await;
}

#[tokio::test]
async fn denied_tool_never_reaches_downstream_and_is_audited() {
    let f = fixture_with(
        Policy {
            allow: vec![],
            deny: vec!["fake/secret".into()],
        },
        8,
    )
    .await;
    let (st, v) = rpc(&f, "fake", json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"secret","arguments":{}}})).await;
    assert_eq!(st, 200);
    assert_eq!(v["id"], 1);
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("ENTANGLE-E0661"));
    assert!(v.get("result").is_none());
    assert!(
        calls(&f).is_empty(),
        "denied call must not even start the downstream: {:?}",
        calls(&f)
    );

    // An allowed tool still works, and fails are classified.
    let (_, v) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fail"}}),
    )
    .await;
    assert_eq!(v["result"]["isError"], true);
    assert!(!calls(&f).iter().any(|l| l == "tools/call:secret"));

    let log = f.gw.audit_log();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].decision, AuditDecision::Deny);
    assert!(matches!(log[0].outcome, AuditOutcome::Denied { .. }));
    assert_eq!(log[0].tool, "secret");
    assert_eq!(log[1].decision, AuditDecision::Allow);
    assert_eq!(log[1].outcome, AuditOutcome::ToolError);
    assert!(log[1].seq > log[0].seq);
    f.gw.shutdown().await;
}

#[tokio::test]
async fn allow_list_blocks_unlisted_tools() {
    let f = fixture_with(
        Policy {
            allow: vec!["fake/echo".into()],
            deny: vec![],
        },
        8,
    )
    .await;
    let (_, v) = rpc(&f, "fake", json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sleep","arguments":{"ms":1}}})).await;
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("allow list"));
    let (_, v) = rpc(&f, "fake", json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}})).await;
    assert!(v["result"].is_object());
    f.gw.shutdown().await;
}

#[tokio::test]
async fn unknown_server_and_bad_routes() {
    let f = fixture().await;
    let bearer = format!("Bearer {}", f.token);
    let body = json!({"jsonrpc":"2.0","id":1,"method":"ping"}).to_string();
    assert_eq!(
        http(f.gw.addr, "POST", "/mcp/nope", Some(&bearer), &body)
            .await
            .0,
        404
    );
    assert_eq!(
        http(f.gw.addr, "POST", "/elsewhere", Some(&bearer), &body)
            .await
            .0,
        404
    );
    assert_eq!(
        http(f.gw.addr, "GET", "/mcp/fake", Some(&bearer), "")
            .await
            .0,
        405
    );
    assert_eq!(
        http(f.gw.addr, "POST", "/mcp/fake", Some(&bearer), "{not json")
            .await
            .0,
        400
    );
    assert_eq!(
        http(f.gw.addr, "POST", "/mcp/fake", Some(&bearer), "[]")
            .await
            .0,
        400
    );
    f.gw.shutdown().await;
}

#[tokio::test]
async fn http_downstream_reports_unsupported() {
    let f = fixture().await;
    let (st, v) = rpc(
        &f,
        "remote",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("ENTANGLE-E0664"));
    f.gw.shutdown().await;
}

#[tokio::test]
async fn oversized_body_is_413() {
    let dir = TempDir::new().unwrap();
    let (s, _, _) = spec(&dir);
    let token = generate_bearer_token();
    let gw = Gateway::new(GatewayConfig {
        bearer_token: token.clone(),
        ..GatewayConfig::default()
    })
    .with_servers(BTreeMap::from([("fake".to_string(), s)]))
    .with_max_body_bytes(64)
    .start()
    .await
    .unwrap();
    let big = json!({"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"x".repeat(500)}})
        .to_string();
    let (st, body) = http(
        gw.addr,
        "POST",
        "/mcp/fake",
        Some(&format!("Bearer {token}")),
        &big,
    )
    .await;
    assert_eq!(st, 413);
    assert!(body.contains("ENTANGLE-E0667"));
    gw.shutdown().await;
}

#[tokio::test]
async fn in_flight_cap_returns_503_when_saturated() {
    let f = fixture_with(Policy::default(), 1).await;
    // Warm up so the slow call is the only thing in flight afterwards.
    rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":0,"method":"tools/list"}),
    )
    .await;
    let addr = f.gw.addr;
    let bearer = format!("Bearer {}", f.token);
    let slow_body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sleep","arguments":{"ms":1500}}}).to_string();
    let b2 = bearer.clone();
    let slow =
        tokio::spawn(async move { http(addr, "POST", "/mcp/fake", Some(&b2), &slow_body).await });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let (st, body) = http(
        addr,
        "POST",
        "/mcp/fake",
        Some(&bearer),
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string(),
    )
    .await;
    assert_eq!(st, 503);
    assert!(body.contains("ENTANGLE-E0665"));
    assert_eq!(
        slow.await.unwrap().0,
        200,
        "the in-flight call still completes"
    );
    // Capacity is released afterwards.
    let (st, _) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    f.gw.shutdown().await;
}

#[tokio::test]
async fn downstream_timeout_is_reported_and_audited() {
    let dir = TempDir::new().unwrap();
    let (s, _, _) = spec(&dir);
    let token = generate_bearer_token();
    let gw = Gateway::new(GatewayConfig {
        bearer_token: token.clone(),
        ..GatewayConfig::default()
    })
    .with_servers(BTreeMap::from([("fake".to_string(), s)]))
    .with_request_timeout(Duration::from_millis(500))
    .start()
    .await
    .unwrap();
    let bearer = format!("Bearer {token}");
    // Handshake (not slow), then a slow call that exceeds the timeout.
    http(
        gw.addr,
        "POST",
        "/mcp/fake",
        Some(&bearer),
        &json!({"jsonrpc":"2.0","id":0,"method":"tools/list"}).to_string(),
    )
    .await;
    let (st, body) = http(gw.addr, "POST", "/mcp/fake", Some(&bearer), &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sleep","arguments":{"ms":1500}}}).to_string()).await;
    assert_eq!(st, 200);
    assert!(
        body.contains("ENTANGLE-E0663") && body.contains("timed out"),
        "{body}"
    );
    assert!(matches!(
        gw.audit_log()[0].outcome,
        AuditOutcome::TransportError { .. }
    ));
    gw.shutdown().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn shutdown_kills_downstream_process() {
    let f = fixture().await;
    rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    let pid: u32 = std::fs::read_to_string(&f.pid)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    assert!(proc_dir.exists(), "downstream should be running");
    let addr = f.gw.addr;
    f.gw.shutdown().await;
    for _ in 0..50 {
        if !proc_dir.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !proc_dir.exists(),
        "downstream pid {pid} still alive after shutdown"
    );
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "listener must be closed"
    );
}

#[tokio::test]
async fn non_loopback_bind_is_still_refused() {
    let err = Gateway::new(GatewayConfig {
        bind: "0.0.0.0:0".parse().unwrap(),
        bearer_token: "t".into(),
        ..GatewayConfig::default()
    })
    .start()
    .await
    .expect_err("must refuse");
    assert!(err.to_string().contains("ENTANGLE-E0622"));
}
