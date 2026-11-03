//! End-to-end gateway tests against a fake stdio MCP server.
//!
//! The fake server lives in this test binary: `fake_mcp_server` below is a
//! no-op unless `ENTANGLE_FAKE_MCP=1`, in which case it speaks
//! newline-delimited JSON-RPC on stdin/stdout. The gateway launches it via
//! `current_exe() --exact fake_mcp_server --nocapture`. (The libtest banner
//! lines on stdout are not JSON and the gateway ignores them.)

use entangle_agent_host::{
    generate_bearer_token, AuditDecision, AuditOutcome, Decision, Gateway, GatewayConfig,
    GatewayHandle, GatewayHooks, McpServerSpec, Policy, ToolCall,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
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
    // Every message received, verbatim, one JSON value per line.
    let mut msgs = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{log_path}.msgs"))
        .unwrap();
    if let Ok(p) = std::env::var("FAKE_PID") {
        std::fs::write(p, std::process::id().to_string()).unwrap();
    }
    let env_ms = |k: &str| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut lines = stdin.lock().lines();
    while let Some(Ok(line)) = lines.next() {
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let method = msg["method"].as_str().unwrap_or("").to_string();
        let tool = msg["params"]["name"].as_str().unwrap_or("").to_string();
        writeln!(log, "{method}:{tool}").unwrap();
        writeln!(msgs, "{msg}").unwrap();
        let Some(id) = msg.get("id").cloned() else {
            continue;
        };
        if tool == "bigerror" {
            let err = json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": "e".repeat(100_000)}});
            writeln!(out, "{err}").unwrap();
            out.flush().unwrap();
            continue;
        }
        let result = match method.as_str() {
            "initialize" => {
                std::thread::sleep(Duration::from_millis(env_ms("FAKE_INIT_DELAY_MS")));
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
                // Die without answering.
                "exit" => std::process::exit(0),
                // Latin-1 (invalid UTF-8) log line on stderr.
                "latin1_stderr" => {
                    std::io::stderr().write_all(b"caf\xe9 log line\n").unwrap();
                    json!({"content": []})
                }
                // Whether stderr can still be written to.
                "stderr_check" => {
                    let r = std::io::stderr().write_all(b"still logging\n");
                    let text = r.map_or_else(|e| format!("err: {e}"), |()| "ok".to_string());
                    json!({"content": [{"type": "text", "text": text}]})
                }
                // An unterminated 3 MiB "reply", then silence.
                "flood" => {
                    write!(out, "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":\"").unwrap();
                    out.write_all(&vec![b'a'; 3 * 1024 * 1024]).unwrap();
                    out.flush().unwrap();
                    std::thread::sleep(Duration::from_secs(30));
                    std::process::exit(0)
                }
                // A non-UTF-8 line on stdout before the real reply.
                "bad_stdout" => {
                    out.write_all(b"\xff\xfe not utf8\n").unwrap();
                    json!({"content": [{"type": "text", "text": "after garbage"}]})
                }
                // Ask the client something and return whatever comes back.
                "elicit" | "server_ping" => {
                    let (sid, req) = if tool == "elicit" {
                        (
                            "srv-1",
                            json!({"jsonrpc":"2.0","id":"srv-1","method":"elicitation/create","params":{"message":"ok?","requestedSchema":{"type":"object","properties":{}}}}),
                        )
                    } else {
                        (
                            "srv-2",
                            json!({"jsonrpc":"2.0","id":"srv-2","method":"ping"}),
                        )
                    };
                    writeln!(out, "{req}").unwrap();
                    out.flush().unwrap();
                    let mut answer = Value::Null;
                    while let Some(Ok(l)) = lines.next() {
                        let Ok(m) = serde_json::from_str::<Value>(&l) else {
                            continue;
                        };
                        writeln!(msgs, "{m}").unwrap();
                        if m["id"] == sid && m.get("method").is_none() {
                            answer = m;
                            break;
                        }
                    }
                    json!({"content": [{"type": "text", "text": answer.to_string()}]})
                }
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
    spec_env(dir, &[])
}

fn spec_env(dir: &TempDir, extra: &[(&str, &str)]) -> (McpServerSpec, PathBuf, PathBuf) {
    let log = dir.path().join("calls.log");
    let pid = dir.path().join("pid");
    let mut env: BTreeMap<String, String> = extra
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
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
    fixture_opts(Arc::new(policy), max_in_flight, Duration::from_secs(20)).await
}

async fn fixture_opts(
    hooks: Arc<dyn GatewayHooks>,
    max_in_flight: usize,
    timeout: Duration,
) -> Fixture {
    fixture_full(hooks, max_in_flight, timeout, &[]).await
}

/// Like [`fixture_opts`], with extra environment for the fake server.
async fn fixture_full(
    hooks: Arc<dyn GatewayHooks>,
    max_in_flight: usize,
    timeout: Duration,
    extra_env: &[(&str, &str)],
) -> Fixture {
    let dir = TempDir::new().unwrap();
    let (s, log, pid) = spec_env(&dir, extra_env);
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
    .with_hooks(hooks)
    .with_request_timeout(timeout)
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

/// Send one request on a raw connection and close the socket after `after`
/// without reading the reply (a client that gives up mid-request).
async fn send_then_drop(f: &Fixture, msg: &Value, after: Duration) {
    let body = msg.to_string();
    let mut s = TcpStream::connect(f.gw.addr).await.unwrap();
    let head = format!(
        "POST /mcp/fake HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAuthorization: Bearer {}\r\n\r\n",
        body.len(),
        f.token
    );
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(body.as_bytes()).await.unwrap();
    tokio::time::sleep(after).await;
    drop(s);
}

/// Hooks that allow everything and count `after_tool` calls.
#[derive(Debug, Default)]
struct CountingHooks {
    after: AtomicUsize,
}

impl GatewayHooks for CountingHooks {
    fn before_tool(&self, _call: &ToolCall) -> Decision {
        Decision::Allow
    }
    fn after_tool(&self, _call: &ToolCall, _outcome: &AuditOutcome) {
        self.after.fetch_add(1, Ordering::SeqCst);
    }
}

/// Poll `cond` every 50 ms for up to `limit`.
async fn wait_until(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    cond()
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

/// [`rpc`] on its own task, for concurrent requests.
fn spawn_rpc(f: &Fixture, msg: Value) -> tokio::task::JoinHandle<(u16, Value)> {
    let addr = f.gw.addr;
    let bearer = format!("Bearer {}", f.token);
    tokio::spawn(async move {
        let (st, body) = http(addr, "POST", "/mcp/fake", Some(&bearer), &msg.to_string()).await;
        (st, serde_json::from_str(&body).unwrap_or(Value::Null))
    })
}

/// Every message the fake server received, in order.
fn received(f: &Fixture) -> Vec<Value> {
    std::fs::read_to_string(format!("{}.msgs", f.log.display()))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
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
async fn requests_racing_a_fresh_handshake_wait_for_it() {
    let f = fixture_full(
        Arc::new(Policy::default()),
        8,
        Duration::from_secs(20),
        &[("FAKE_INIT_DELAY_MS", "600")],
    )
    .await;
    let init = |id: &str| json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}});
    // The first initialize spawns the server and is slow to answer; a
    // second initialize and a tools/list arrive while it is in flight.
    let a = spawn_rpc(&f, init("i1"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let b = spawn_rpc(&f, init("i2"));
    let c = spawn_rpc(&f, json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}));
    let (a, b, c) = (a.await.unwrap(), b.await.unwrap(), c.await.unwrap());
    assert_eq!(a.0, 200);
    assert_eq!(a.1["id"], "i1");
    assert_eq!(a.1["result"]["serverInfo"]["name"], "fake", "{a:?}");
    assert_eq!(b.0, 200);
    assert_eq!(b.1["id"], "i2");
    assert_eq!(b.1["result"]["serverInfo"]["name"], "fake", "{b:?}");
    assert_eq!(c.0, 200);
    assert!(c.1["result"]["tools"].is_array(), "{c:?}");
    // One handshake, completed before anything else reached the server.
    let log = calls(&f);
    assert_eq!(
        log,
        ["initialize:", "notifications/initialized:", "tools/list:"],
        "requests overtook the handshake"
    );
    // The handshake used the first client's own initialize.
    assert_eq!(received(&f)[0]["params"]["clientInfo"]["name"], "t");
    // The client's own notifications/initialized is not sent twice.
    let (st, _) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    assert_eq!(st, 202);
    rpc(&f, "fake", json!({"jsonrpc":"2.0","id":4,"method":"ping"})).await;
    assert_eq!(
        calls(&f)
            .iter()
            .filter(|l| l.starts_with("notifications/initialized"))
            .count(),
        1
    );
    f.gw.shutdown().await;
}

#[tokio::test]
async fn server_initiated_requests_are_answered_not_left_hanging() {
    let f = fixture_opts(Arc::new(Policy::default()), 8, Duration::from_secs(3)).await;
    let (st, _) = rpc(&f, "fake", json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-03-26",
        "capabilities":{"roots":{"listChanged":true},"sampling":{},"elicitation":{},"experimental":{"x":{}}},
        "clientInfo":{"name":"t","version":"0"}}})).await;
    assert_eq!(st, 200);
    // The downstream is not offered client features the gateway cannot relay.
    let caps = &received(&f)[0]["params"]["capabilities"];
    for k in ["roots", "sampling", "elicitation"] {
        assert!(caps.get(k).is_none(), "{k} forwarded: {caps}");
    }
    assert_eq!(caps["experimental"], json!({"x":{}}));

    // A server request gets a JSON-RPC error instead of no answer at all.
    let (st, v) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"elicit"}}),
    )
    .await;
    assert_eq!(st, 200);
    let text = v["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool did not complete: {v}"));
    let answer: Value = serde_json::from_str(text).unwrap();
    assert_eq!(answer["id"], "srv-1", "{answer}");
    assert_eq!(answer["error"]["code"], -32601, "{answer}");
    // ...and ping is answered with an empty result.
    let (_, v) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"server_ping"}}),
    )
    .await;
    let text = v["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool did not complete: {v}"));
    let answer: Value = serde_json::from_str(text).unwrap();
    assert_eq!(answer, json!({"jsonrpc":"2.0","id":"srv-2","result":{}}));
    f.gw.shutdown().await;
}

/// Downstream id the fake server saw for the `tools/call` of `tool`.
fn downstream_id_of(f: &Fixture, tool: &str) -> Value {
    received(f)
        .into_iter()
        .find(|m| m["method"] == "tools/call" && m["params"]["name"] == tool)
        .map(|m| m["id"].clone())
        .unwrap_or_else(|| panic!("no tools/call {tool} reached the server"))
}

fn cancellations(f: &Fixture) -> Vec<Value> {
    received(f)
        .into_iter()
        .filter(|m| m["method"] == "notifications/cancelled")
        .collect()
}

#[tokio::test]
async fn cancellation_is_remapped_to_the_downstream_id() {
    let f = fixture().await;
    // Handshake and tools/list take downstream ids 1 and 2.
    let (st, _) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":0,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    // The client's id 2 is another request's downstream id.
    let slow = spawn_rpc(
        &f,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sleep","arguments":{"ms":800}}}),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (st, _) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2,"reason":"user"}}),
    )
    .await;
    assert_eq!(st, 202);
    assert_eq!(slow.await.unwrap().0, 200);
    // A cancellation for nothing in flight is dropped, not forwarded as-is.
    rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99}}),
    )
    .await;
    rpc(&f, "fake", json!({"jsonrpc":"2.0","id":5,"method":"ping"})).await;

    let sleep_id = downstream_id_of(&f, "sleep");
    assert_ne!(sleep_id, json!(2));
    let c = cancellations(&f);
    assert_eq!(c.len(), 1, "{c:?}");
    assert_eq!(
        c[0]["params"]["requestId"], sleep_id,
        "cancellation hit the wrong downstream request: {c:?}"
    );
    assert_eq!(c[0]["params"]["reason"], "user");
    f.gw.shutdown().await;
}

#[tokio::test]
async fn timed_out_request_is_cancelled_downstream() {
    let f = fixture_opts(Arc::new(Policy::default()), 8, Duration::from_millis(1000)).await;
    let (st, _) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":0,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    let (_, v) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sleep","arguments":{"ms":1800}}}),
    )
    .await;
    assert!(
        v["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("timed out")),
        "{v}"
    );
    let sleep_id = downstream_id_of(&f, "sleep");
    assert!(
        wait_until(Duration::from_secs(5), || cancellations(&f)
            .iter()
            .any(|c| c["params"]["requestId"] == sleep_id))
        .await,
        "no notifications/cancelled for the timed-out request: {:?}",
        cancellations(&f)
    );
    f.gw.shutdown().await;
}

#[tokio::test]
async fn respawned_server_is_handshaken_with_the_clients_protocol_version() {
    let f = fixture().await;
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}});
    let (_, v) = rpc(&f, "fake", init.clone()).await;
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    // The server dies; the next request starts a new one, and the gateway
    // has to do the handshake on the client's behalf.
    let (_, v) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exit"}}),
    )
    .await;
    assert!(v.get("error").is_some(), "{v}");
    let (st, _) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    let inits: Vec<Value> = received(&f)
        .into_iter()
        .filter(|m| m["method"] == "initialize")
        .collect();
    assert_eq!(inits.len(), 2, "{inits:?}");
    assert_eq!(
        inits[1]["params"]["protocolVersion"], "2025-06-18",
        "respawn handshake ignored the version the client negotiated"
    );
    // A client that re-initializes gets the version it asked for.
    let (_, v) = rpc(&f, "fake", init).await;
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18", "{v}");
    f.gw.shutdown().await;
}

#[tokio::test]
async fn non_utf8_output_does_not_break_the_downstream() {
    let f = fixture().await;
    let call = |id: u64, name: &str| json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name}});
    // Garbage on stdout is skipped; the reply after it still arrives.
    let (st, v) = rpc(&f, "fake", call(1, "bad_stdout")).await;
    assert_eq!(st, 200);
    assert_eq!(v["result"]["content"][0]["text"], "after garbage", "{v}");
    let pid = std::fs::read_to_string(&f.pid).unwrap();
    // A Latin-1 log line on stderr must not close the stderr pipe.
    let (_, v) = rpc(&f, "fake", call(2, "latin1_stderr")).await;
    assert!(v.get("result").is_some(), "{v}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (_, v) = rpc(&f, "fake", call(3, "stderr_check")).await;
    assert_eq!(v["result"]["content"][0]["text"], "ok", "{v}");
    assert_eq!(
        std::fs::read_to_string(&f.pid).unwrap(),
        pid,
        "the downstream was restarted"
    );
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
async fn tools_call_without_id_is_audited_as_denied_and_never_forwarded() {
    let f = fixture_with(
        Policy {
            allow: vec![],
            deny: vec!["fake/secret".into()],
        },
        8,
    )
    .await;
    // Start the downstream so notifications would be deliverable.
    let (st, _) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    // tools/call sent as a notification: plain, inside a batch, with an
    // `ID` key (not `id`), and for a tool the policy would allow.
    for msg in [
        json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret","arguments":{}}}),
        json!([{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret","arguments":{}}}]),
        json!({"jsonrpc":"2.0","ID":5,"method":"tools/call","params":{"name":"secret"}}),
        json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}),
    ] {
        let (st, _) = rpc(&f, "fake", msg.clone()).await;
        assert_eq!(st, 202, "{msg}");
    }
    // Any other id-less method that is not `notifications/*` is dropped too;
    // real notifications are still forwarded.
    rpc(&f, "fake", json!({"jsonrpc":"2.0","method":"tools/list"})).await;
    rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","method":"notifications/roots/list_changed"}),
    )
    .await;
    // A request afterwards: everything before it has reached the downstream.
    let (st, _) = rpc(&f, "fake", json!({"jsonrpc":"2.0","id":2,"method":"ping"})).await;
    assert_eq!(st, 200);
    let c = calls(&f);
    assert!(
        !c.iter().any(|l| l.starts_with("tools/call")),
        "a tools/call notification reached the downstream: {c:?}"
    );
    assert_eq!(
        c.iter().filter(|l| l.starts_with("tools/list")).count(),
        1,
        "id-less tools/list must be dropped: {c:?}"
    );
    assert!(
        c.iter().any(|l| l == "notifications/roots/list_changed:"),
        "{c:?}"
    );

    let log = f.gw.audit_log();
    let tools: Vec<&str> = log.iter().map(|r| r.tool.as_str()).collect();
    assert_eq!(tools, ["secret", "secret", "secret", "echo"], "{log:?}");
    for r in &log {
        assert_eq!(r.server, "fake");
        assert_eq!(r.decision, AuditDecision::Deny, "{r:?}");
        assert_eq!(
            r.outcome,
            AuditOutcome::Denied {
                reason: "tools/call sent as notification".into()
            }
        );
    }
    f.gw.shutdown().await;
}

#[tokio::test]
async fn invalid_jsonrpc_objects_get_invalid_request_errors() {
    let f = fixture().await;
    // (message, id expected in the error reply)
    let cases = [
        (json!({"jsonrpc":"2.0","id":14,"method":5}), json!(14)),
        (json!({"jsonrpc":"2.0","id":13}), json!(13)),
        (json!({"jsonrpc":"2.0","method":7}), Value::Null),
        (
            json!({"jsonrpc":"2.0","id":{"a":1},"method":"tools/list"}),
            Value::Null,
        ),
        (
            json!({"jsonrpc":"2.0","id":[1],"method":"tools/list"}),
            Value::Null,
        ),
        (json!({"id":3,"method":"tools/list"}), json!(3)),
        (
            json!({"jsonrpc":"1.0","id":4,"method":"tools/list"}),
            json!(4),
        ),
        (
            json!({"jsonrpc":"2.0","id":6,"method":"tools/list","params":5}),
            json!(6),
        ),
        (
            json!({"jsonrpc":"2.0","id":8,"result":{},"error":{"code":1,"message":"x"}}),
            json!(8),
        ),
    ];
    for (msg, want_id) in cases {
        let (st, v) = rpc(&f, "fake", msg.clone()).await;
        assert_eq!(st, 200, "{msg} -> {v}");
        assert_eq!(v["error"]["code"], -32600, "{msg} -> {v}");
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("ENTANGLE-E0666"),
            "{msg} -> {v}"
        );
        assert_eq!(v["id"], want_id, "{msg} -> {v}");
        assert!(v.get("result").is_none());
    }
    // An invalid element inside a batch gets its own error in the array.
    let (st, v) = rpc(
        &f,
        "fake",
        json!([{"jsonrpc":"2.0","id":1,"method":"ping"}, {"jsonrpc":"2.0","id":2,"method":true}]),
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(v[0]["id"], 1);
    assert!(v[0].get("result").is_some(), "{v}");
    assert_eq!(v[1]["id"], 2);
    assert_eq!(v[1]["error"]["code"], -32600, "{v}");
    // A well-formed client response is still accepted (202) and dropped.
    let (st, _) = rpc(&f, "fake", json!({"jsonrpc":"2.0","id":"s1","result":{}})).await;
    assert_eq!(st, 202);
    // None of the invalid messages reached the downstream.
    let c = calls(&f);
    assert!(!c.iter().any(|l| l.starts_with("tools/list")), "{c:?}");
    f.gw.shutdown().await;
}

#[tokio::test]
async fn audit_records_do_not_keep_unbounded_strings() {
    let f = fixture_with(
        Policy {
            allow: vec!["fake/bigerror".into()],
            deny: vec![],
        },
        8,
    )
    .await;
    let long = "t".repeat(100_000);
    // Denied: the tool name is agent-controlled, and so is the reason text.
    let (st, _) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":long}}),
    )
    .await;
    assert_eq!(st, 200);
    // Also as a notification.
    rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":long}}),
    )
    .await;
    // Allowed, and the downstream answers with a huge JSON-RPC error.
    let (_, v) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bigerror"}}),
    )
    .await;
    assert_eq!(
        v["error"]["message"].as_str().map(str::len),
        Some(100_000),
        "the reply itself is passed through unchanged"
    );
    let log = f.gw.audit_log();
    assert_eq!(log.len(), 3, "{}", log.len());
    for r in &log {
        assert!(r.tool.len() <= 300, "tool kept {} bytes", r.tool.len());
        let text = match &r.outcome {
            AuditOutcome::Denied { reason } => reason,
            AuditOutcome::RpcError { message, .. } => message,
            AuditOutcome::TransportError { message } => message,
            AuditOutcome::Ok | AuditOutcome::ToolError => continue,
        };
        assert!(text.len() <= 1100, "outcome kept {} bytes", text.len());
    }
    assert!(log[0].tool.starts_with("tttt"), "prefix kept");
    assert!(
        log[0].tool.contains("100000"),
        "original length noted: {}",
        log[0].tool
    );
    assert!(matches!(
        &log[2].outcome,
        AuditOutcome::RpcError { code: -32000, message } if message.starts_with("eeee")
    ));
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
async fn oversized_downstream_message_fails_fast_instead_of_buffering() {
    let dir = TempDir::new().unwrap();
    let (s, _, pid_file) = spec(&dir);
    let token = generate_bearer_token();
    let gw = Gateway::new(GatewayConfig {
        bearer_token: token.clone(),
        ..GatewayConfig::default()
    })
    .with_servers(BTreeMap::from([("fake".to_string(), s)]))
    .with_request_timeout(Duration::from_secs(20))
    .with_max_downstream_message_bytes(1024 * 1024)
    .start()
    .await
    .unwrap();
    let bearer = format!("Bearer {token}");
    let post = |body: Value| {
        let bearer = bearer.clone();
        let addr = gw.addr;
        async move {
            tokio::time::timeout(
                Duration::from_secs(8),
                http(addr, "POST", "/mcp/fake", Some(&bearer), &body.to_string()),
            )
            .await
            .expect("request hung")
        }
    };
    let (st, _) = post(json!({"jsonrpc":"2.0","id":0,"method":"tools/list"})).await;
    assert_eq!(st, 200);
    let old_pid = std::fs::read_to_string(&pid_file).unwrap();
    // 3 MiB without a newline: the gateway gives up at 1 MiB.
    let (st, body) =
        post(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"flood"}})).await;
    assert_eq!(st, 200);
    assert!(body.contains("ENTANGLE-E0663"), "{body}");
    assert!(!body.contains("timed out"), "{body}");
    // The offending process was dropped; the next request gets a new one.
    let (st, body) = post(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).await;
    assert_eq!(st, 200);
    assert!(body.contains("\"tools\""), "{body}");
    assert_ne!(std::fs::read_to_string(&pid_file).unwrap(), old_pid);
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
async fn client_disconnect_mid_call_still_audits_and_holds_the_permit() {
    let hooks = Arc::new(CountingHooks::default());
    let f = fixture_opts(hooks.clone(), 1, Duration::from_secs(20)).await;
    let (st, _) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":0,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    // The agent sends an allowed call and closes the socket while it runs.
    send_then_drop(
        &f,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sleep","arguments":{"ms":1200}}}),
        Duration::from_millis(300),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The tool is still running downstream, so it still counts against
    // max_in_flight.
    let (st, body) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":4,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 503, "permit released while the call still runs: {body}");
    assert!(calls(&f).iter().any(|l| l == "tools/call:sleep"));
    // The call finishes and is audited, and after_tool runs.
    assert!(
        wait_until(Duration::from_secs(5), || f.gw.audit_log().len() == 1).await,
        "no audit record for the abandoned call: {:?}",
        f.gw.audit_log()
    );
    let log = f.gw.audit_log();
    assert_eq!(log[0].tool, "sleep");
    assert_eq!(log[0].decision, AuditDecision::Allow);
    assert_eq!(log[0].outcome, AuditOutcome::Ok);
    assert_eq!(hooks.after.load(Ordering::SeqCst), 1);
    // Capacity comes back once it is done.
    let (st, _) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":5,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    f.gw.shutdown().await;
}

#[tokio::test]
async fn client_disconnect_mid_write_does_not_corrupt_the_next_message() {
    let f = fixture().await;
    rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":0,"method":"tools/list"}),
    )
    .await;
    // A: keeps the single-threaded downstream from reading stdin.
    let addr = f.gw.addr;
    let bearer = format!("Bearer {}", f.token);
    let b2 = bearer.clone();
    let slow = tokio::spawn(async move {
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sleep","arguments":{"ms":1500}}}).to_string();
        http(addr, "POST", "/mcp/fake", Some(&b2), &body).await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    // B: larger than the pipe buffer, so its write blocks; the client gives up.
    let big = "x".repeat(1024 * 1024);
    send_then_drop(
        &f,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":big}}}),
        Duration::from_millis(300),
    )
    .await;
    assert_eq!(slow.await.unwrap().0, 200);
    // C: must get its answer, not be glued onto a partial line from B.
    let c = tokio::time::timeout(
        Duration::from_secs(8),
        http(
            addr,
            "POST",
            "/mcp/fake",
            Some(&bearer),
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}).to_string(),
        ),
    )
    .await
    .expect("request after an abandoned large write hung");
    assert_eq!(c.0, 200);
    let v: Value = serde_json::from_str(&c.1).unwrap();
    assert!(v["result"]["tools"].is_array(), "{v}");
    f.gw.shutdown().await;
}

#[tokio::test]
async fn request_timeout_covers_a_blocked_stdin_write() {
    let f = fixture_opts(Arc::new(Policy::default()), 8, Duration::from_millis(1500)).await;
    let (st, _) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":0,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    let old_pid = std::fs::read_to_string(&f.pid).unwrap();
    // A keeps the downstream from reading stdin for 4 s.
    let addr = f.gw.addr;
    let bearer = format!("Bearer {}", f.token);
    let b2 = bearer.clone();
    let slow = tokio::spawn(async move {
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sleep","arguments":{"ms":4000}}}).to_string();
        http(addr, "POST", "/mcp/fake", Some(&b2), &body).await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    // B cannot be written (pipe full): it must time out like any request.
    let big = "x".repeat(1024 * 1024);
    let started = Instant::now();
    let (st, body) = http(
        addr,
        "POST",
        "/mcp/fake",
        Some(&bearer),
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":big}}}).to_string(),
    )
    .await;
    let took = started.elapsed();
    assert_eq!(st, 200);
    assert!(
        body.contains("ENTANGLE-E0663") && body.contains("timed out"),
        "{}",
        &body[..body.len().min(300)]
    );
    assert!(
        took < Duration::from_millis(3000),
        "blocked write was not bounded by the 1.5 s timeout: {took:?}"
    );
    let _ = slow.await;
    // The half-written process was killed; the next request gets a fresh one.
    #[cfg(target_os = "linux")]
    {
        let proc_dir = PathBuf::from(format!("/proc/{}", old_pid.trim()));
        assert!(
            wait_until(Duration::from_secs(5), || !proc_dir.exists()).await,
            "downstream with a half-written line still alive"
        );
    }
    let (st, v) = rpc(
        &f,
        "fake",
        json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    assert!(v["result"]["tools"].is_array(), "{v}");
    assert_ne!(std::fs::read_to_string(&f.pid).unwrap(), old_pid);
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
