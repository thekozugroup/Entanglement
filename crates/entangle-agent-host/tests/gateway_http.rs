//! The gateway proxying HTTP (`url`) downstream MCP servers, against an
//! in-process hyper server standing in for the remote one.

use std::{
    collections::BTreeMap,
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use entangle_agent_host::{
    generate_bearer_token, AuditOutcome, Gateway, GatewayConfig, GatewayHandle, McpServerSpec,
    Policy,
};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Frame, Incoming},
    server::conn::http1,
    service::service_fn,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

// ------------------------------------------------------------ mock downstream

/// How `tools/call` is answered.
#[derive(Clone, Debug)]
enum Mode {
    /// `application/json`.
    Json,
    /// `text/event-stream` carrying a notification, a server `ping`
    /// request, an unrelated response and finally the answer; the body is
    /// delivered in tiny pieces.
    Sse,
    /// A JSON batch containing the answer.
    Batch,
    /// Sleep this long before answering.
    Slow(Duration),
    /// A result of this many bytes.
    Big(usize),
    /// 404, as a server that dropped the session does.
    Gone,
    /// 302 to another host.
    Redirect,
    /// 500.
    Broken,
    /// A stream that ends without the answer.
    SseNoAnswer,
    /// `initialize` is accepted but never answered.
    HangInit,
}

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

struct Mock {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    mode: Arc<Mutex<Mode>>,
}

/// A response body fed from a channel, so chunks reach the client one by one.
struct ChannelBody(tokio::sync::mpsc::Receiver<Bytes>);

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|o| o.map(|b| Ok(Frame::data(b))))
    }
}

type Resp = Response<http_body_util::Either<Full<Bytes>, ChannelBody>>;

fn full(status: u16, ctype: Option<&str>, session: Option<&str>, body: impl Into<Bytes>) -> Resp {
    let mut r = Response::builder().status(status);
    if let Some(c) = ctype {
        r = r.header("content-type", c);
    }
    if let Some(s) = session {
        r = r.header("mcp-session-id", s);
    }
    r.body(http_body_util::Either::Left(Full::new(body.into())))
        .unwrap()
}

fn json_resp(v: &Value, session: Option<&str>) -> Resp {
    full(200, Some("application/json"), session, v.to_string())
}

impl Mock {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mode = Arc::new(Mutex::new(Mode::Json));
        let (s2, m2) = (seen.clone(), mode.clone());
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (s, m) = (s2.clone(), m2.clone());
                tokio::spawn(async move {
                    let svc = service_fn(move |req| handle(req, s.clone(), m.clone()));
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), svc)
                        .await;
                });
            }
        });
        Self { addr, seen, mode }
    }

    fn url(&self) -> String {
        format!("http://{}/mcp", self.addr)
    }

    fn set(&self, m: Mode) {
        *self.mode.lock() = m;
    }

    fn posts(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .iter()
            .filter(|s| s.method == "POST")
            .cloned()
            .collect()
    }
}

async fn handle(
    req: Request<Incoming>,
    seen: Arc<Mutex<Vec<Seen>>>,
    mode: Arc<Mutex<Mode>>,
) -> Result<Resp, Infallible> {
    let method = req.method().to_string();
    // A header sent twice shows as its values joined with ", ".
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in req.headers() {
        let v = v.to_str().unwrap_or("");
        headers
            .entry(k.to_string())
            .and_modify(|e| {
                e.push_str(", ");
                e.push_str(v);
            })
            .or_insert_with(|| v.to_string());
    }
    let bytes = req.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    seen.lock().push(Seen {
        method: method.clone(),
        headers: headers.clone(),
        body: body.clone(),
    });
    if method != "POST" {
        return Ok(full(200, None, None, ""));
    }
    let rpc_method = body["method"].as_str().unwrap_or("");
    let id = body.get("id").cloned();
    // Everything after the handshake must carry the session.
    let has_session = headers.get("mcp-session-id").map(String::as_str) == Some("sess-1");
    if rpc_method != "initialize" && id.is_some() && !has_session && body.get("method").is_some() {
        return Ok(full(400, None, None, "missing session"));
    }
    let Some(id) = id else {
        return Ok(full(202, None, None, "")); // notification / response
    };
    if body.get("method").is_none() {
        return Ok(full(202, None, None, ""));
    }
    let ok = |result: Value| json!({"jsonrpc": "2.0", "id": id, "result": result});
    let hang_init = matches!(*mode.lock(), Mode::HangInit);
    if rpc_method == "initialize" && hang_init {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
    Ok(match rpc_method {
        "initialize" => json_resp(
            &ok(
                json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                       "serverInfo": {"name": "mock", "version": "1"}}),
            ),
            Some("sess-1"),
        ),
        "tools/list" => json_resp(&ok(json!({"tools": [{"name": "echo"}]})), None),
        "tools/call" => {
            let answer = ok(json!({"content": [{"type": "text",
                "text": body["params"]["arguments"]["text"]}]}));
            let m = mode.lock().clone();
            match m {
                Mode::Json | Mode::HangInit => json_resp(&answer, None),
                Mode::Batch => json_resp(&json!([{"jsonrpc":"2.0","method":"x"}, answer]), None),
                Mode::Slow(d) => {
                    tokio::time::sleep(d).await;
                    json_resp(&answer, None)
                }
                Mode::Big(n) => json_resp(&ok(json!({"blob": "x".repeat(n)})), None),
                Mode::Gone => full(404, None, None, "no such session"),
                Mode::Redirect => Response::builder()
                    .status(302)
                    .header("location", "http://169.254.169.254/steal")
                    .body(http_body_util::Either::Left(Full::new(Bytes::new())))
                    .unwrap(),
                Mode::Broken => full(500, None, None, "boom"),
                Mode::Sse | Mode::SseNoAnswer => {
                    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(16);
                    let events = [
                        ": keep-alive comment\n\n".to_string(),
                        format!(
                            "event: message\ndata: {}\n\n",
                            json!({"jsonrpc":"2.0","method":"notifications/progress","params":{}})
                        ),
                        format!(
                            "data: {}\n\n",
                            json!({"jsonrpc":"2.0","id":"srv-1","method":"ping"})
                        ),
                        format!(
                            "data: {}\r\n\r\n",
                            json!({"jsonrpc":"2.0","id":"someone-else","result":{}})
                        ),
                        if matches!(m, Mode::Sse) {
                            format!("data: {answer}\n\n")
                        } else {
                            String::new()
                        },
                    ];
                    tokio::spawn(async move {
                        for e in events {
                            for chunk in e.as_bytes().chunks(7) {
                                if tx.send(Bytes::copy_from_slice(chunk)).await.is_err() {
                                    return;
                                }
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                        }
                    });
                    Response::builder()
                        .status(200)
                        .header("content-type", "text/event-stream")
                        .body(http_body_util::Either::Right(ChannelBody(rx)))
                        .unwrap()
                }
            }
        }
        _ => json_resp(&ok(json!({})), None),
    })
}

// -------------------------------------------------------------------- fixture

struct Fixture {
    gw: GatewayHandle,
    token: String,
    mock: Mock,
}

async fn fixture_with(
    headers: &[(&str, &str)],
    timeout: Duration,
    max_msg: usize,
    policy: Policy,
) -> Fixture {
    let mock = Mock::start().await;
    let token = generate_bearer_token();
    let mut servers = BTreeMap::new();
    servers.insert(
        "remote".to_string(),
        McpServerSpec::Http {
            url: mock.url(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        },
    );
    let gw = Gateway::new(GatewayConfig {
        bearer_token: token.clone(),
        ..GatewayConfig::default()
    })
    .with_servers(servers)
    .with_policy(policy)
    .with_request_timeout(timeout)
    .with_max_downstream_message_bytes(max_msg)
    .start()
    .await
    .unwrap();
    Fixture { gw, token, mock }
}

async fn fixture() -> Fixture {
    fixture_with(
        &[
            ("Authorization", "Bearer downstream-secret"),
            ("X-Api-Key", "k1"),
        ],
        Duration::from_secs(10),
        1 << 20,
        Policy::default(),
    )
    .await
}

struct Reply {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Value,
}

async fn post(f: &Fixture, msg: &Value) -> Reply {
    post_to(f.gw.addr, &f.token, msg).await
}

async fn post_to(addr: SocketAddr, token: &str, msg: &Value) -> Reply {
    let body = msg.to_string();
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST /mcp/remote HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nAuthorization: Bearer {token}\r\n\r\n{body}",
        body.len(),
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Reply {
        status,
        headers,
        body: serde_json::from_str(body).unwrap_or(Value::Null),
    }
}

fn init() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize",
           "params":{"protocolVersion":"2025-06-18","capabilities":{"sampling":{}},
                     "clientInfo":{"name":"t","version":"1"}}})
}

fn call(id: u64, text: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
           "params":{"name":"echo","arguments":{"text":text}}})
}

fn text_of(r: &Reply) -> &str {
    r.body["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("")
}

// ---------------------------------------------------------------------- tests

#[tokio::test]
async fn json_round_trip_with_session_and_headers() {
    let f = fixture().await;
    let r = post(&f, &init()).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    assert_eq!(r.body["id"], 1);
    assert_eq!(r.body["result"]["protocolVersion"], "2025-06-18");
    // The downstream's session id is returned to the client.
    assert_eq!(
        r.headers.get("mcp-session-id").map(String::as_str),
        Some("sess-1")
    );

    let r = post(&f, &call(2, "hello")).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    assert_eq!(text_of(&r), "hello");
    assert_eq!(r.body["id"], 2);
    assert_eq!(
        r.headers.get("mcp-session-id").map(String::as_str),
        Some("sess-1")
    );

    let posts = f.mock.posts();
    let methods: Vec<_> = posts
        .iter()
        .map(|p| p.body["method"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        methods,
        ["initialize", "notifications/initialized", "tools/call"]
    );
    // The gateway's own handshake notification carries the session.
    assert_eq!(posts[1].headers["mcp-session-id"], "sess-1");
    assert_eq!(posts[1].headers["mcp-protocol-version"], "2025-06-18");
    // initialize carries none; later requests carry both.
    assert!(!posts[0].headers.contains_key("mcp-session-id"));
    assert_eq!(posts[2].headers["mcp-session-id"], "sess-1");
    assert_eq!(posts[2].headers["mcp-protocol-version"], "2025-06-18");
    // The user's configured headers are sent on every request, the gateway's
    // bearer token on none of them.
    for p in &posts {
        assert_eq!(
            p.headers["authorization"], "Bearer downstream-secret",
            "{p:?}"
        );
        assert_eq!(p.headers["x-api-key"], "k1");
        assert!(
            !p.headers.values().any(|v| v.contains(&f.token)),
            "gateway token leaked downstream: {p:?}"
        );
        assert!(p.headers["accept"].contains("text/event-stream"));
        assert_eq!(p.headers["content-type"], "application/json");
    }
    // Unrelayable client capabilities are stripped from initialize.
    assert!(posts[0].body["params"]["capabilities"]
        .get("sampling")
        .is_none());
    f.gw.shutdown().await;
}

#[tokio::test]
async fn first_message_without_initialize_gets_a_gateway_handshake() {
    let f = fixture().await;
    let r = post(&f, &json!({"jsonrpc":"2.0","id":7,"method":"tools/list"})).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body["result"]["tools"][0]["name"], "echo");
    let methods: Vec<_> = f
        .mock
        .posts()
        .iter()
        .map(|p| p.body["method"].as_str().unwrap_or("").to_string())
        .collect();
    assert_eq!(
        methods,
        ["initialize", "notifications/initialized", "tools/list"]
    );
    // A later client `initialize` is answered from the cache.
    let r = post(&f, &init()).await;
    assert_eq!(r.body["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(r.body["id"], 1);
    assert_eq!(f.mock.posts().len(), 3, "no second initialize downstream");
    // The client's own notifications/initialized is not forwarded again.
    let r = post(
        &f,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    assert_eq!(r.status, 202);
    assert_eq!(f.mock.posts().len(), 3);
    f.gw.shutdown().await;
}

#[tokio::test]
async fn sse_reply_is_collected_until_the_matching_response() {
    let f = fixture().await;
    post(&f, &init()).await;
    f.mock.set(Mode::Sse);
    let r = post(&f, &call(5, "streamed")).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    assert_eq!(r.body["id"], 5);
    assert_eq!(text_of(&r), "streamed");
    // The server's `ping` request was answered with a separate POST.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let answered = f
        .mock
        .posts()
        .iter()
        .any(|p| p.body["id"] == "srv-1" && p.body["result"] == json!({}));
    assert!(answered, "{:?}", f.mock.posts());
    f.gw.shutdown().await;
}

#[tokio::test]
async fn sse_stream_without_an_answer_is_an_error() {
    let f = fixture().await;
    post(&f, &init()).await;
    f.mock.set(Mode::SseNoAnswer);
    let r = post(&f, &call(5, "x")).await;
    assert_eq!(r.status, 200);
    let msg = r.body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("ENTANGLE-E0671") && msg.contains("without a response"),
        "{msg}"
    );
    f.gw.shutdown().await;
}

#[tokio::test]
async fn json_batch_reply_is_searched_for_the_answer() {
    let f = fixture().await;
    post(&f, &init()).await;
    f.mock.set(Mode::Batch);
    let r = post(&f, &call(9, "batched")).await;
    assert_eq!(text_of(&r), "batched");
    f.gw.shutdown().await;
}

#[tokio::test]
async fn slow_downstream_times_out_with_e0663() {
    let f = fixture_with(&[], Duration::from_millis(300), 1 << 20, Policy::default()).await;
    post(&f, &init()).await;
    f.mock.set(Mode::Slow(Duration::from_secs(5)));
    let t = std::time::Instant::now();
    let r = post(&f, &call(3, "x")).await;
    assert!(t.elapsed() < Duration::from_secs(3));
    let msg = r.body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("ENTANGLE-E0663") && msg.contains("timed out"),
        "{msg}"
    );
    // The audit log records the transport error for the tool call.
    let audit = f.gw.audit_log();
    assert!(
        matches!(&audit.last().unwrap().outcome, AuditOutcome::TransportError { message } if message.contains("E0663")),
        "{audit:?}"
    );
    f.gw.shutdown().await;
}

/// A dropped connection is not a cancellation in MCP Streamable HTTP: a
/// request that times out is cancelled explicitly, under its downstream id
/// and in the session, as the stdio path does.
#[tokio::test]
async fn a_timed_out_request_is_cancelled_downstream() {
    let f = fixture_with(&[], Duration::from_millis(300), 1 << 20, Policy::default()).await;
    post(&f, &init()).await;
    f.mock.set(Mode::Slow(Duration::from_secs(5)));
    let r = post(&f, &call(3, "x")).await;
    assert!(
        r.body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("ENTANGLE-E0663"),
        "{:?}",
        r.body
    );
    let posts = f.mock.posts();
    let sent = posts
        .iter()
        .find(|p| p.body["method"] == "tools/call")
        .expect("the call reached the server");
    let cancel = posts
        .iter()
        .find(|p| p.body["method"] == "notifications/cancelled")
        .unwrap_or_else(|| panic!("no notifications/cancelled sent: {posts:?}"));
    assert_eq!(cancel.body["params"]["requestId"], sent.body["id"]);
    assert!(cancel.body.get("id").is_none(), "a notification");
    assert_eq!(cancel.headers["mcp-session-id"], "sess-1");
    assert_eq!(cancel.headers["mcp-protocol-version"], "2025-06-18");
    f.gw.shutdown().await;
}

#[tokio::test]
async fn oversize_reply_is_refused() {
    let f = fixture_with(&[], Duration::from_secs(10), 4096, Policy::default()).await;
    post(&f, &init()).await;
    f.mock.set(Mode::Big(100_000));
    let r = post(&f, &call(3, "x")).await;
    let msg = r.body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("ENTANGLE-E0663") && msg.contains("4096-byte cap"),
        "{msg}"
    );
    // The route keeps working afterwards.
    f.mock.set(Mode::Json);
    assert_eq!(text_of(&post(&f, &call(4, "ok")).await), "ok");
    f.gw.shutdown().await;
}

#[tokio::test]
async fn policy_and_audit_apply_to_http_routes() {
    let f = fixture_with(
        &[],
        Duration::from_secs(10),
        1 << 20,
        Policy {
            allow: vec![],
            deny: vec!["remote/echo".into()],
        },
    )
    .await;
    post(&f, &init()).await;
    let before = f.mock.posts().len();
    let r = post(&f, &call(2, "nope")).await;
    assert!(
        r.body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("ENTANGLE-E0661"),
        "{:?}",
        r.body
    );
    assert_eq!(
        f.mock.posts().len(),
        before,
        "a denied call never reaches the server"
    );
    assert!(matches!(
        f.gw.audit_log().last().unwrap().outcome,
        AuditOutcome::Denied { .. }
    ));
    f.gw.shutdown().await;

    let f = fixture().await;
    post(&f, &call(2, "yes")).await;
    assert_eq!(f.gw.audit_log().last().unwrap().outcome, AuditOutcome::Ok);
    f.gw.shutdown().await;
}

#[tokio::test]
async fn a_forgotten_session_fails_once_then_recovers() {
    let f = fixture().await;
    post(&f, &init()).await;
    f.mock.set(Mode::Gone);
    let r = post(&f, &call(2, "x")).await;
    let msg = r.body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("ENTANGLE-E0671") && msg.contains("session"),
        "{msg}"
    );
    f.mock.set(Mode::Json);
    // New session transparently established.
    let r = post(&f, &call(3, "again")).await;
    assert_eq!(text_of(&r), "again", "{:?}", r.body);
    let inits = f
        .mock
        .posts()
        .iter()
        .filter(|p| p.body["method"] == "initialize")
        .count();
    assert_eq!(inits, 2);
    f.gw.shutdown().await;
}

#[tokio::test]
async fn errors_and_redirects_are_reported_not_followed() {
    let f = fixture().await;
    post(&f, &init()).await;
    f.mock.set(Mode::Redirect);
    let r = post(&f, &call(2, "x")).await;
    let msg = r.body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("ENTANGLE-E0671") && msg.contains("302"),
        "{msg}"
    );
    f.mock.set(Mode::Broken);
    let r = post(&f, &call(3, "x")).await;
    assert!(r.body["error"]["message"].as_str().unwrap().contains("500"));
    f.gw.shutdown().await;
}

/// A configured `User-Agent` is what the server sees, not a second
/// `User-Agent` next to the gateway's own.
#[tokio::test]
async fn a_configured_user_agent_replaces_the_gateways() {
    let f = fixture_with(
        &[("User-Agent", "my-client/2.0")],
        Duration::from_secs(10),
        1 << 20,
        Policy::default(),
    )
    .await;
    post(&f, &init()).await;
    for p in f.mock.posts() {
        assert_eq!(p.headers["user-agent"], "my-client/2.0", "{p:?}");
    }
    f.gw.shutdown().await;
    let f = fixture().await;
    post(&f, &init()).await;
    assert!(f.mock.posts()[0].headers["user-agent"].starts_with("entangle-gateway/"));
    f.gw.shutdown().await;
}

#[tokio::test]
async fn non_https_non_loopback_and_bad_headers_are_refused_without_contact() {
    let mock = Mock::start().await;
    let token = generate_bearer_token();
    let mut servers = BTreeMap::new();
    for (name, url, headers) in [
        (
            "plain",
            "http://mcp.example.com/mcp".to_string(),
            BTreeMap::new(),
        ),
        (
            "creds",
            "https://u:p@mcp.example.com/mcp".to_string(),
            BTreeMap::new(),
        ),
        (
            "reserved",
            mock.url(),
            [("Mcp-Session-Id".to_string(), "forged".to_string())].into(),
        ),
    ] {
        servers.insert(name.to_string(), McpServerSpec::Http { url, headers });
    }
    let gw = Gateway::new(GatewayConfig {
        bearer_token: token.clone(),
        ..GatewayConfig::default()
    })
    .with_servers(servers)
    .start()
    .await
    .unwrap();
    for name in ["plain", "creds", "reserved"] {
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string();
        let mut s = TcpStream::connect(gw.addr).await.unwrap();
        s.write_all(
            format!(
                "POST /mcp/{name} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {}\r\nAuthorization: Bearer {token}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).await.unwrap();
        assert!(buf.contains("ENTANGLE-E0664"), "{name}: {buf}");
    }
    assert!(
        mock.seen.lock().is_empty(),
        "a refused route must not be contacted"
    );
    gw.shutdown().await;
}

/// The `tools/call` ids the mock received, in arrival order.
fn downstream_call_ids(f: &Fixture) -> Vec<Value> {
    f.mock
        .posts()
        .iter()
        .filter(|p| p.body["method"] == "tools/call")
        .map(|p| p.body["id"].clone())
        .collect()
}

/// Poll until the mock has received `n` `tools/call` requests.
async fn wait_for_calls(f: &Fixture, n: usize) {
    for _ in 0..200 {
        if downstream_call_ids(f).len() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the mock never saw {n} tools/call requests");
}

/// Every client of a route shares one downstream session, so two clients
/// (or a reconnected client reusing ids) can have the same id in flight. The
/// MCP spec forbids reusing a request id within a session: the gateway sends
/// its own unique ids and gives each client back its own id and result.
#[tokio::test]
async fn request_ids_are_unique_within_the_downstream_session() {
    let f = fixture().await;
    post(&f, &init()).await;
    f.mock.set(Mode::Slow(Duration::from_millis(300)));
    let (m1, m2) = (call(3, "first"), call(3, "second"));
    let (a, b) = tokio::join!(post(&f, &m1), post(&f, &m2));
    assert_eq!(
        (a.body["id"].clone(), b.body["id"].clone()),
        (json!(3), json!(3))
    );
    assert_eq!(text_of(&a), "first", "{:?}", a.body);
    assert_eq!(text_of(&b), "second", "{:?}", b.body);
    // A `null` id is the client's business too: it never goes downstream.
    f.mock.set(Mode::Json);
    let r = post(
        &f,
        &json!({"jsonrpc":"2.0","id":null,"method":"tools/call",
                "params":{"name":"echo","arguments":{"text":"n"}}}),
    )
    .await;
    assert_eq!(r.body["id"], Value::Null);
    assert_eq!(text_of(&r), "n");

    let ids: Vec<Value> = f
        .mock
        .posts()
        .iter()
        .filter(|p| p.body.get("method").is_some())
        .filter_map(|p| p.body.get("id").cloned())
        .collect();
    assert_eq!(ids.len(), 4, "initialize + 3 calls: {ids:?}");
    assert!(ids.iter().all(Value::is_u64), "{ids:?}");
    let mut unique = ids.clone();
    unique.sort_by_key(|v| v.as_u64());
    unique.dedup();
    assert_eq!(unique.len(), ids.len(), "an id was reused: {ids:?}");
    f.gw.shutdown().await;
}

/// A client's `notifications/cancelled` names its own id: it is translated
/// to the downstream id of that request, and dropped when that id is in
/// flight for more than one client (it would otherwise cancel both).
#[tokio::test]
async fn cancellation_names_the_downstream_id_and_is_dropped_when_ambiguous() {
    let f = fixture().await;
    post(&f, &init()).await;
    f.mock.set(Mode::Slow(Duration::from_millis(600)));
    let cancel = |id: u64| {
        json!({"jsonrpc":"2.0","method":"notifications/cancelled",
               "params":{"requestId": id, "reason": "user"}})
    };
    let cancels = |f: &Fixture| -> Vec<Value> {
        f.mock
            .posts()
            .iter()
            .filter(|p| p.body["method"] == "notifications/cancelled")
            .map(|p| p.body["params"]["requestId"].clone())
            .collect()
    };

    // Two clients with id 5 in flight: the cancellation is ambiguous.
    let (m1, m2, c5) = (call(5, "a"), call(5, "b"), cancel(5));
    let both = async {
        tokio::join!(post(&f, &m1), post(&f, &m2));
    };
    let cancel_ambiguous = async {
        wait_for_calls(&f, 2).await;
        let r = post(&f, &c5).await;
        assert_eq!(r.status, 202);
    };
    tokio::join!(both, cancel_ambiguous);
    assert!(cancels(&f).is_empty(), "{:?}", cancels(&f));

    // One request with id 7 in flight: translated to its downstream id.
    let (m3, c7) = (call(7, "c"), cancel(7));
    let one = post(&f, &m3);
    let cancel_one = async {
        wait_for_calls(&f, 3).await;
        post(&f, &c7).await;
    };
    tokio::join!(one, cancel_one);
    let downstream = downstream_call_ids(&f)[2].clone();
    assert_eq!(cancels(&f), vec![downstream]);
    f.gw.shutdown().await;
}

#[tokio::test]
async fn shutdown_ends_the_session_with_a_delete() {
    let f = fixture().await;
    post(&f, &init()).await;
    let seen = f.mock.seen.clone();
    f.gw.shutdown().await;
    let deleted = seen.lock().iter().any(|s| {
        s.method == "DELETE"
            && s.headers.get("mcp-session-id").map(String::as_str) == Some("sess-1")
    });
    assert!(deleted);
}

/// Shutdown does not wait out the request timeout of a handshake that is
/// stuck (the server accepted `initialize` but never answers): in-flight
/// HTTP exchanges are abandoned, as killing a stdio server ends its
/// requests, so `GatewayHandle::shutdown` returns promptly.
#[tokio::test]
async fn shutdown_does_not_wait_for_a_stuck_handshake() {
    let f = fixture_with(&[], Duration::from_secs(60), 1 << 20, Policy::default()).await;
    f.mock.set(Mode::HangInit);
    let (addr, token) = (f.gw.addr, f.token.clone());
    // A client whose first request starts the handshake (its connection is
    // dropped by the shutdown, so its reply is not looked at).
    let client = tokio::spawn(async move {
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string();
        let mut s = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST /mcp/remote HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
             Content-Length: {}\r\nAuthorization: Bearer {token}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
    });
    for _ in 0..200 {
        if !f.mock.posts().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(f.mock.posts().len(), 1, "the handshake has started");
    let t = std::time::Instant::now();
    f.gw.shutdown().await;
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "shutdown took {:?}",
        t.elapsed()
    );
    client.abort();
}

/// The `DELETE` is a request after initialization like any other, so it
/// carries the negotiated `MCP-Protocol-Version` (required since
/// 2025-06-18; a server enforcing it answers 400 and keeps the session).
#[tokio::test]
async fn the_session_delete_carries_the_protocol_version() {
    let f = fixture().await;
    post(&f, &init()).await;
    let seen = f.mock.seen.clone();
    f.gw.shutdown().await;
    let seen = seen.lock();
    let delete = seen
        .iter()
        .find(|s| s.method == "DELETE")
        .expect("a DELETE");
    assert_eq!(
        delete
            .headers
            .get("mcp-protocol-version")
            .map(String::as_str),
        Some("2025-06-18"),
        "{delete:?}"
    );
    // Configured headers go with it, the gateway token does not.
    assert_eq!(delete.headers["authorization"], "Bearer downstream-secret");
}
