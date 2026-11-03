//! MCP gateway HTTP server (spec §8.3).
//!
//! A per-session HTTP/1.1 server on loopback. The agent's MCP client is
//! pointed (by the rewritten session config, see [`crate::adapters`]) at
//! `http://127.0.0.1:<port>/mcp/<server>`. Each `POST` carries one MCP
//! JSON-RPC 2.0 message or a batch (MCP "Streamable HTTP" transport, JSON
//! response mode). The gateway authenticates the bearer token, applies the
//! `before_tool` / `after_tool` hooks to `tools/call`, records an audit entry,
//! and forwards to the real downstream MCP server.
//!
//! # Behaviour contract
//!
//! * **Auth**: `Authorization: Bearer <token>` on every request, compared in
//!   constant time; otherwise `401`.
//! * **Routing**: `POST /mcp/<server>`; unknown server `404`; other methods
//!   `405` (no SSE stream is offered, so `GET` is `405` as the spec allows).
//! * **Replies**: a request gets `200 application/json`; notifications and
//!   client responses get `202` with an empty body; a batch gets a JSON array
//!   of the replies (sequentially processed), or `202` if it had none.
//! * **Notifications**: only `notifications/*` methods are forwarded. Any
//!   other id-less message is dropped; a `tools/call` without an id is shown
//!   to `before_tool` and audited as denied ("tools/call sent as
//!   notification") before it is dropped, so it can never bypass policy.
//! * **Downstream**: stdio servers (newline-delimited JSON-RPC) launched
//!   lazily, one process per server per gateway. Request ids are remapped to
//!   gateway-unique ids so concurrent clients can never collide, and restored
//!   on the reply. `initialize` is passed through on first use and cached;
//!   later `initialize` calls get the cached result; if the first message is
//!   not `initialize` the gateway performs the handshake itself. A dead
//!   process is respawned on the next request. Server-initiated requests
//!   and notifications cannot be relayed over this JSON-only transport and
//!   are dropped (logged at debug).
//! * **HTTP downstream servers** (`url` entries) are *not* proxied: requests
//!   to them fail with JSON-RPC error `ENTANGLE-E0664`.
//! * **Limits**: `max_in_flight` concurrent HTTP requests; the next one is
//!   answered `503` (`ENTANGLE-E0665`). Bodies over the cap get `413`
//!   (`ENTANGLE-E0667`). Each downstream request has a timeout
//!   (`ENTANGLE-E0663`).
//! * **Policy/audit**: see [`Policy`], [`GatewayHooks`], [`AuditRecord`].
//!
//! Stable codes used in HTTP/JSON-RPC bodies: E0661 policy denial, E0662
//! downstream failed to start, E0663 downstream closed/timed out, E0664 HTTP
//! downstream unsupported, E0665 too many requests in flight, E0666 malformed
//! JSON-RPC, E0667 body too large, E0668 unknown server/route, E0670 missing
//! or invalid bearer token. (E0669 is `SessionError::NotActivated`.)

use crate::adapters::McpServerSpec;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::{
    body::Incoming,
    header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    convert::Infallible,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    process::{Child, ChildStdin, Command},
    sync::{oneshot, watch, Semaphore},
    task::{JoinHandle, JoinSet},
};

/// Maximum audit records kept in memory (oldest dropped first).
const AUDIT_CAPACITY: usize = 10_000;

/// Configuration for the MCP gateway HTTP server.
#[derive(Clone, Debug)]
pub struct GatewayConfig {
    /// Address to bind. Default is loopback on an ephemeral port.
    pub bind: SocketAddr,
    /// Opaque bearer token the agent's MCP client must present.
    ///
    /// Each session generates a fresh token (spec §8.3). Must be non-empty.
    pub bearer_token: String,
    /// Hard cap on concurrent in-flight requests per session.
    pub max_in_flight: usize,
    /// Permit binding to a non-loopback address.
    ///
    /// Default is `false` — the gateway is local-only and the bearer token
    /// is a powerful credential. Setting this to `true` is an explicit
    /// opt-in for advanced deployments (e.g. binding to a Tailscale
    /// interface address with additional access control on top).
    pub allow_non_loopback: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            bearer_token: String::new(),
            max_in_flight: 16,
            allow_non_loopback: false,
        }
    }
}

impl GatewayConfig {
    /// Validate the bind-address policy.
    ///
    /// Returns [`GatewayError::NonLoopbackBindRefused`] when `bind` is not
    /// loopback and `allow_non_loopback` is `false`.
    pub fn validate(&self) -> Result<(), GatewayError> {
        if !self.bind.ip().is_loopback() && !self.allow_non_loopback {
            return Err(GatewayError::NonLoopbackBindRefused { addr: self.bind });
        }
        Ok(())
    }
}

/// Errors emitted by the gateway.
///
/// `ENTANGLE-E0620` (the former `NotImplemented` scaffold error) is retired
/// and reserved; it is no longer emitted.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// Bind / listen failure.
    #[error("ENTANGLE-E0621: bind {addr}: {source}")]
    Bind {
        /// The address the gateway tried to bind to.
        addr: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The configured bind address is unsafe for the local-only MCP gateway.
    ///
    /// Spec §8.3 requires the gateway to bind loopback (`127.0.0.1` or `::1`).
    /// Binding a wildcard / public address would expose the bearer token to
    /// the entire network. Caller may opt out via [`GatewayConfig::allow_non_loopback`].
    #[error(
        "ENTANGLE-E0622: refusing non-loopback bind {addr} — set allow_non_loopback to override"
    )]
    NonLoopbackBindRefused {
        /// The address the gateway was asked to bind to.
        addr: SocketAddr,
    },
    /// The bearer token is empty, which would authenticate anyone.
    #[error("ENTANGLE-E0623: bearer_token must not be empty (use generate_bearer_token())")]
    EmptyBearerToken,
    /// `max_in_flight` is zero, so no request could ever be served.
    #[error("ENTANGLE-E0624: max_in_flight must be at least 1")]
    ZeroMaxInFlight,
}

/// Generate a fresh, opaque bearer token suitable for one MCP gateway session.
///
/// The token is 256 bits drawn from the operating system's CSPRNG
/// ([`rand_core::OsRng`], backed by `getrandom`), rendered as 64 lowercase
/// hex characters. Callers may also use any other unguessable value.
pub fn generate_bearer_token() -> String {
    use rand_core::{OsRng, RngCore};

    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    hex_encode(&b)
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// Policy, hooks, audit
// ---------------------------------------------------------------------------

/// A `tools/call` about to be (or just) forwarded.
#[derive(Clone, Debug)]
pub struct ToolCall {
    /// Gateway route (downstream server) name.
    pub server: String,
    /// Tool name from `params.name`.
    pub tool: String,
    /// `params.arguments`, or `null`.
    pub arguments: Value,
}

/// Outcome of a policy check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Forward the call.
    Allow,
    /// Refuse the call; it never reaches the downstream server.
    Deny {
        /// Human-readable reason, returned to the agent.
        reason: String,
    },
}

/// How a `tools/call` ended, as recorded in the audit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditOutcome {
    /// The downstream returned a normal result.
    Ok,
    /// The downstream returned `result.isError == true`.
    ToolError,
    /// The downstream returned a JSON-RPC error.
    RpcError {
        /// JSON-RPC error code.
        code: i64,
        /// JSON-RPC error message.
        message: String,
    },
    /// Refused by the policy hook.
    Denied {
        /// Policy reason.
        reason: String,
    },
    /// The gateway could not complete the call (spawn failure, closed, timeout).
    TransportError {
        /// Description (starts with a stable `ENTANGLE-E…` code).
        message: String,
    },
}

/// Policy decision recorded in the audit log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    /// Allowed by `before_tool`.
    Allow,
    /// Denied by `before_tool`.
    Deny,
}

/// One structured audit entry per `tools/call`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    /// Monotonic sequence number within the gateway.
    pub seq: u64,
    /// Wall-clock time (ms since the Unix epoch) at which the call finished.
    pub timestamp_ms: u64,
    /// Downstream server name.
    pub server: String,
    /// Tool name.
    pub tool: String,
    /// Policy decision.
    pub decision: AuditDecision,
    /// Time from receipt to reply, in milliseconds.
    pub duration_ms: u64,
    /// What happened.
    pub outcome: AuditOutcome,
}

/// Extension point run around every `tools/call` (spec §8.3
/// `before_tool` / `after_tool`).
pub trait GatewayHooks: Send + Sync + std::fmt::Debug {
    /// Decide whether the call may proceed. Runs before the downstream is
    /// contacted (or even started).
    fn before_tool(&self, call: &ToolCall) -> Decision;
    /// Observe the finished call. Not run for denied calls.
    fn after_tool(&self, _call: &ToolCall, _outcome: &AuditOutcome) {}
}

/// Simple per-session allow/deny policy over `server/tool` names.
///
/// Patterns: `server/tool` (exact), `server/*` (any tool of a server), `*`
/// (everything). A call is denied if any `deny` pattern matches; otherwise,
/// if `allow` is non-empty it must match one of them; an empty `allow` list
/// allows everything not denied.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// Allow patterns (empty = allow all).
    pub allow: Vec<String>,
    /// Deny patterns; take precedence over `allow`.
    pub deny: Vec<String>,
}

impl Policy {
    fn matches(pat: &str, server: &str, tool: &str) -> bool {
        if pat == "*" {
            return true;
        }
        match pat.split_once('/') {
            Some((s, "*")) => s == server,
            Some((s, t)) => s == server && t == tool,
            None => false,
        }
    }

    /// Evaluate the policy for `server/tool`.
    pub fn evaluate(&self, server: &str, tool: &str) -> Decision {
        if self.deny.iter().any(|p| Self::matches(p, server, tool)) {
            return Decision::Deny {
                reason: format!("{server}/{tool} matches a deny rule"),
            };
        }
        if !self.allow.is_empty() && !self.allow.iter().any(|p| Self::matches(p, server, tool)) {
            return Decision::Deny {
                reason: format!("{server}/{tool} is not in the allow list"),
            };
        }
        Decision::Allow
    }
}

impl GatewayHooks for Policy {
    fn before_tool(&self, call: &ToolCall) -> Decision {
        self.evaluate(&call.server, &call.tool)
    }
}

// ---------------------------------------------------------------------------
// Downstream stdio servers
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum DsError {
    Unsupported(String),
    Spawn(String),
    Closed,
    Timeout,
}

impl DsError {
    /// `(jsonrpc code, message)`.
    fn rpc(&self, server: &str) -> (i64, String) {
        match self {
            Self::Unsupported(url) => (
                -32004,
                format!(
                    "ENTANGLE-E0664: downstream '{server}' is an HTTP MCP server ({url}); \
                     the gateway only proxies stdio servers"
                ),
            ),
            Self::Spawn(e) => (
                -32002,
                format!("ENTANGLE-E0662: failed to start downstream '{server}': {e}"),
            ),
            Self::Closed => (
                -32003,
                format!("ENTANGLE-E0663: downstream '{server}' closed the connection"),
            ),
            Self::Timeout => (
                -32005,
                format!("ENTANGLE-E0663: downstream '{server}' timed out"),
            ),
        }
    }
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>;

struct StdioProc {
    stdin: tokio::sync::Mutex<ChildStdin>,
    child: tokio::sync::Mutex<Child>,
    pending: Pending,
    next_id: AtomicU64,
    alive: Arc<AtomicBool>,
    init_result: Mutex<Option<Value>>,
    initialized_sent: AtomicBool,
}

impl StdioProc {
    fn spawn(
        name: &str,
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
    ) -> Result<Arc<Self>, DsError> {
        let mut child = Command::new(command)
            .args(args)
            .envs(env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| DsError::Spawn(format!("{command}: {e}")))?;
        let (Some(stdin), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            return Err(DsError::Spawn("child stdio unavailable".into()));
        };
        let pending: Pending = Arc::default();
        let alive = Arc::new(AtomicBool::new(true));

        // stdout reader: route responses to waiters.
        {
            let pending = pending.clone();
            let alive = alive.clone();
            let name = name.to_string();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let Ok(v) = serde_json::from_str::<Value>(&line) else {
                        tracing::debug!(server = %name, "non-JSON line on downstream stdout ignored");
                        continue;
                    };
                    let is_response = v.get("method").is_none()
                        && (v.get("result").is_some() || v.get("error").is_some());
                    match (is_response, v.get("id").and_then(Value::as_u64)) {
                        (true, Some(id)) => {
                            if let Some(tx) = pending.lock().remove(&id) {
                                let _ = tx.send(v);
                            }
                        }
                        _ => tracing::debug!(
                            server = %name,
                            "server-initiated message dropped (not relayable over JSON-only transport)"
                        ),
                    }
                }
                alive.store(false, Ordering::Release);
                // Dropping the senders wakes every waiter with "closed".
                pending.lock().clear();
            });
        }
        // stderr reader: surface as debug logs.
        {
            let name = name.to_string();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!(server = %name, "downstream stderr: {line}");
                }
            });
        }

        Ok(Arc::new(Self {
            stdin: tokio::sync::Mutex::new(stdin),
            child: tokio::sync::Mutex::new(child),
            pending,
            next_id: AtomicU64::new(1),
            alive,
            init_result: Mutex::new(None),
            initialized_sent: AtomicBool::new(false),
        }))
    }

    async fn write_line(&self, msg: &Value) -> Result<(), DsError> {
        let mut line = serde_json::to_vec(msg).map_err(|_| DsError::Closed)?;
        line.push(b'\n');
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(&line).await.map_err(|_| DsError::Closed)?;
        stdin.flush().await.map_err(|_| DsError::Closed)
    }

    async fn request(&self, mut msg: Value, timeout: Duration) -> Result<Value, DsError> {
        let orig_id = msg.get("id").cloned().unwrap_or(Value::Null);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        msg["id"] = json!(id);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(id, tx);
        if !self.alive.load(Ordering::Acquire) {
            self.pending.lock().remove(&id);
            return Err(DsError::Closed);
        }
        if let Err(e) = self.write_line(&msg).await {
            self.pending.lock().remove(&id);
            return Err(e);
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(mut resp)) => {
                resp["id"] = orig_id;
                Ok(resp)
            }
            Ok(Err(_)) => Err(DsError::Closed),
            Err(_) => {
                self.pending.lock().remove(&id);
                Err(DsError::Timeout)
            }
        }
    }

    async fn kill(&self) {
        let mut child = self.child.lock().await;
        let _ = child.kill().await;
    }
}

struct Downstream {
    name: String,
    spec: McpServerSpec,
    timeout: Duration,
    proc: tokio::sync::Mutex<Option<Arc<StdioProc>>>,
}

impl Downstream {
    async fn ensure(&self, first_is_initialize: bool) -> Result<Arc<StdioProc>, DsError> {
        let McpServerSpec::Stdio { command, args, env } = &self.spec else {
            let McpServerSpec::Http { url } = &self.spec else {
                return Err(DsError::Closed);
            };
            return Err(DsError::Unsupported(url.clone()));
        };
        let mut guard = self.proc.lock().await;
        if let Some(p) = &*guard {
            if p.alive.load(Ordering::Acquire) {
                return Ok(p.clone());
            }
        }
        tracing::info!(server = %self.name, command = %command, "starting downstream MCP server");
        let p = StdioProc::spawn(&self.name, command, args, env)?;
        if !first_is_initialize {
            // The client skipped (or already completed, against a previous
            // process) the handshake: do it ourselves.
            let init = json!({
                "jsonrpc": "2.0", "id": 0, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "entangle-gateway", "version": env!("CARGO_PKG_VERSION")}
                }
            });
            let resp = match p.request(init, self.timeout).await {
                Ok(r) => r,
                Err(e) => {
                    p.kill().await;
                    return Err(e);
                }
            };
            if let Some(r) = resp.get("result") {
                *p.init_result.lock() = Some(r.clone());
            }
            let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
            if let Err(e) = p.write_line(&note).await {
                p.kill().await;
                return Err(e);
            }
            p.initialized_sent.store(true, Ordering::Release);
        }
        *guard = Some(p.clone());
        Ok(p)
    }

    async fn call(&self, msg: Value) -> Result<Value, DsError> {
        let is_init = msg.get("method").and_then(Value::as_str) == Some("initialize");
        let p = self.ensure(is_init).await?;
        if is_init {
            if let Some(cached) = p.init_result.lock().clone() {
                return Ok(json!({"jsonrpc": "2.0", "id": msg.get("id"), "result": cached}));
            }
        }
        let resp = p.request(msg, self.timeout).await?;
        if is_init {
            if let Some(r) = resp.get("result") {
                *p.init_result.lock() = Some(r.clone());
            }
        }
        Ok(resp)
    }

    async fn notify(&self, msg: &Value) {
        let p = {
            let guard = self.proc.lock().await;
            match &*guard {
                Some(p) if p.alive.load(Ordering::Acquire) => p.clone(),
                _ => {
                    tracing::debug!(server = %self.name, "notification dropped: downstream not running");
                    return;
                }
            }
        };
        if msg.get("method").and_then(Value::as_str) == Some("notifications/initialized")
            && p.initialized_sent.swap(true, Ordering::AcqRel)
        {
            return;
        }
        if let Err(e) = p.write_line(msg).await {
            tracing::debug!(server = %self.name, error = ?e, "notification write failed");
        }
    }

    async fn shutdown(&self) {
        if let Some(p) = self.proc.lock().await.take() {
            p.kill().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Shared state + request handling
// ---------------------------------------------------------------------------

struct Shared {
    token: Vec<u8>,
    servers: BTreeMap<String, Arc<Downstream>>,
    hooks: Arc<dyn GatewayHooks>,
    audit: Mutex<VecDeque<AuditRecord>>,
    seq: AtomicU64,
    permits: Arc<Semaphore>,
    max_body: usize,
}

impl Shared {
    fn record(&self, mut rec: AuditRecord) {
        rec.seq = self.seq.fetch_add(1, Ordering::Relaxed);
        rec.timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        tracing::info!(
            target: "entangle::audit",
            seq = rec.seq,
            server = %rec.server,
            tool = %rec.tool,
            decision = ?rec.decision,
            duration_ms = rec.duration_ms,
            outcome = ?rec.outcome,
            "tools/call"
        );
        let mut log = self.audit.lock();
        if log.len() >= AUDIT_CAPACITY {
            log.pop_front();
        }
        log.push_back(rec);
    }
}

/// Constant-time byte comparison (length is folded into the result rather
/// than short-circuiting).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(x ^ y);
    }
    std::hint::black_box(diff) == 0
}

fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    let mut r = Response::new(Full::new(Bytes::from(bytes)));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r
}

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message.into()}})
}

fn http_error(status: StatusCode, code: &str, msg: &str) -> Response<Full<Bytes>> {
    json_response(
        status,
        &rpc_error(Value::Null, -32000, format!("{code}: {msg}")),
    )
}

fn accepted() -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::new()));
    *r.status_mut() = StatusCode::ACCEPTED;
    r
}

fn authorized(sh: &Shared, req: &Request<Incoming>) -> bool {
    let Some(h) = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some((scheme, tok)) = h.split_once(' ') else {
        return false;
    };
    scheme.eq_ignore_ascii_case("bearer") && ct_eq(tok.trim().as_bytes(), &sh.token)
}

async fn handle(
    sh: Arc<Shared>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(handle_inner(sh, req).await)
}

async fn handle_inner(sh: Arc<Shared>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    if !authorized(&sh, &req) {
        let mut r = http_error(
            StatusCode::UNAUTHORIZED,
            "ENTANGLE-E0670",
            "missing or invalid bearer token",
        );
        r.headers_mut()
            .insert("www-authenticate", HeaderValue::from_static("Bearer"));
        return r;
    }
    let Some(seg) = req.uri().path().strip_prefix("/mcp/") else {
        return http_error(StatusCode::NOT_FOUND, "ENTANGLE-E0668", "no such route");
    };
    let ds = crate::adapters::decode_server_name(seg.trim_end_matches('/'))
        .and_then(|n| sh.servers.get(&n).cloned().map(|d| (n, d)));
    let Some((name, ds)) = ds else {
        return http_error(
            StatusCode::NOT_FOUND,
            "ENTANGLE-E0668",
            "unknown MCP server",
        );
    };
    if req.method() != Method::POST {
        let mut r = http_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "ENTANGLE-E0666",
            "only POST is supported",
        );
        r.headers_mut()
            .insert("allow", HeaderValue::from_static("POST"));
        return r;
    }
    let Ok(_permit) = sh.permits.clone().try_acquire_owned() else {
        let mut r = http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ENTANGLE-E0665",
            "too many requests in flight",
        );
        r.headers_mut()
            .insert("retry-after", HeaderValue::from_static("1"));
        return r;
    };

    let body = match Limited::new(req.into_body(), sh.max_body).collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return http_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "ENTANGLE-E0667",
                "request body too large",
            )
        }
        Err(_) => return http_error(StatusCode::BAD_REQUEST, "ENTANGLE-E0666", "unreadable body"),
    };
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &rpc_error(
                    Value::Null,
                    -32700,
                    format!("ENTANGLE-E0666: parse error: {e}"),
                ),
            )
        }
    };

    match parsed {
        Value::Array(items) => {
            if items.is_empty() {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &rpc_error(Value::Null, -32600, "ENTANGLE-E0666: empty batch"),
                );
            }
            let mut replies = Vec::new();
            for m in items {
                if let Some(r) = handle_message(&sh, &name, &ds, m).await {
                    replies.push(r);
                }
            }
            if replies.is_empty() {
                accepted()
            } else {
                json_response(StatusCode::OK, &Value::Array(replies))
            }
        }
        other => match handle_message(&sh, &name, &ds, other).await {
            Some(r) => json_response(StatusCode::OK, &r),
            None => accepted(),
        },
    }
}

fn classify(resp: &Value) -> AuditOutcome {
    if let Some(err) = resp.get("error") {
        return AuditOutcome::RpcError {
            code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
            message: err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        };
    }
    if resp.pointer("/result/isError").and_then(Value::as_bool) == Some(true) {
        return AuditOutcome::ToolError;
    }
    AuditOutcome::Ok
}

/// Audit reason for a `tools/call` that arrived without an `id`.
const NOTIFICATION_CALL_REASON: &str = "tools/call sent as notification";

/// An id-less message with a `method`. Only `notifications/*` methods are
/// forwarded: anything else would be a request the downstream might act on
/// (JSON-RPC servers process notifications, they just do not reply) without
/// passing policy or audit. A `tools/call` is still shown to `before_tool`
/// and recorded as denied, so the attempt is visible in the audit log.
async fn handle_notification(
    sh: &Shared,
    server: &str,
    ds: &Downstream,
    method: &str,
    msg: &Value,
) {
    if method.starts_with("notifications/") {
        ds.notify(msg).await;
        return;
    }
    if method == "tools/call" {
        let call = ToolCall {
            server: server.to_string(),
            tool: msg
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            arguments: msg
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or(Value::Null),
        };
        // The policy still sees the attempt (hooks may count or alert on
        // it), but the message is dropped whatever it decides.
        let policy = sh.hooks.before_tool(&call);
        tracing::warn!(
            server = %call.server,
            tool = %call.tool,
            policy = ?policy,
            "tools/call without an id dropped"
        );
        sh.record(AuditRecord {
            seq: 0,
            timestamp_ms: 0,
            server: call.server,
            tool: call.tool,
            decision: AuditDecision::Deny,
            duration_ms: 0,
            outcome: AuditOutcome::Denied {
                reason: NOTIFICATION_CALL_REASON.to_string(),
            },
        });
        return;
    }
    tracing::debug!(server = %server, method = %method, "id-less non-notification dropped");
}

/// Process one JSON-RPC message. `None` means "no reply" (HTTP 202).
async fn handle_message(sh: &Shared, server: &str, ds: &Downstream, msg: Value) -> Option<Value> {
    let Some(obj) = msg.as_object() else {
        return Some(rpc_error(
            Value::Null,
            -32600,
            "ENTANGLE-E0666: message is not a JSON object",
        ));
    };
    let method = obj.get("method").and_then(Value::as_str).map(str::to_owned);
    let id = obj.get("id").cloned();
    let (Some(method), Some(id)) = (method.clone(), id) else {
        // Notification (method, no id) or a client response (no method).
        if let Some(method) = method {
            handle_notification(sh, server, ds, &method, &msg).await;
        }
        return None;
    };

    if method != "tools/call" {
        return Some(match ds.call(msg).await {
            Ok(r) => r,
            Err(e) => {
                let (code, text) = e.rpc(server);
                rpc_error(id, code, text)
            }
        });
    }

    let Some(tool) = msg.pointer("/params/name").and_then(Value::as_str) else {
        return Some(rpc_error(
            id,
            -32602,
            "ENTANGLE-E0666: tools/call requires params.name",
        ));
    };
    let call = ToolCall {
        server: server.to_string(),
        tool: tool.to_string(),
        arguments: msg
            .pointer("/params/arguments")
            .cloned()
            .unwrap_or(Value::Null),
    };
    let started = Instant::now();
    let elapsed = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mk = |decision, outcome| AuditRecord {
        seq: 0,
        timestamp_ms: 0,
        server: call.server.clone(),
        tool: call.tool.clone(),
        decision,
        duration_ms: elapsed(),
        outcome,
    };

    if let Decision::Deny { reason } = sh.hooks.before_tool(&call) {
        let text = format!(
            "ENTANGLE-E0661: tool call {}/{} denied by policy: {reason}",
            call.server, call.tool
        );
        sh.record(mk(AuditDecision::Deny, AuditOutcome::Denied { reason }));
        return Some(rpc_error(id, -32001, text));
    }

    let (reply, outcome) = match ds.call(msg).await {
        Ok(resp) => {
            let outcome = classify(&resp);
            (resp, outcome)
        }
        Err(e) => {
            let (code, text) = e.rpc(server);
            (
                rpc_error(id, code, text.clone()),
                AuditOutcome::TransportError { message: text },
            )
        }
    };
    sh.hooks.after_tool(&call, &outcome);
    sh.record(mk(AuditDecision::Allow, outcome));
    Some(reply)
}

// ---------------------------------------------------------------------------
// Public gateway API
// ---------------------------------------------------------------------------

/// Handle returned from [`Gateway::start`].
///
/// Carries the bound socket address so the caller can splice it into the
/// agent's MCP config. Dropping the handle signals the server to stop;
/// call [`GatewayHandle::shutdown`] to also wait and terminate downstream
/// processes deterministically.
pub struct GatewayHandle {
    /// The address the gateway is bound to (resolved after `0`-port binding).
    pub addr: SocketAddr,
    shared: Arc<Shared>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for GatewayHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayHandle")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl GatewayHandle {
    /// Base URL for gateway routes: `http://<addr>/mcp`.
    pub fn base_url(&self) -> String {
        format!("http://{}/mcp", self.addr)
    }

    /// Snapshot of the in-memory audit log (oldest first, capped at 10 000).
    pub fn audit_log(&self) -> Vec<AuditRecord> {
        self.shared.audit.lock().iter().cloned().collect()
    }

    /// Stop accepting, drop open connections, and kill every downstream
    /// process (waiting for it to exit).
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
        for ds in self.shared.servers.values() {
            ds.shutdown().await;
        }
    }
}

impl Drop for GatewayHandle {
    fn drop(&mut self) {
        // Best effort when `shutdown()` was not awaited: the accept loop
        // exits and downstream children are `kill_on_drop`.
        let _ = self.stop.send(true);
    }
}

/// Local MCP gateway.
#[derive(Debug)]
pub struct Gateway {
    config: GatewayConfig,
    servers: BTreeMap<String, McpServerSpec>,
    hooks: Arc<dyn GatewayHooks>,
    request_timeout: Duration,
    max_body_bytes: usize,
}

impl Gateway {
    /// Construct a new gateway with the given config, no downstream servers,
    /// an allow-all policy, a 60 s downstream timeout and a 4 MiB body cap.
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            servers: BTreeMap::new(),
            hooks: Arc::new(Policy::default()),
            request_timeout: Duration::from_secs(60),
            max_body_bytes: 4 * 1024 * 1024,
        }
    }

    /// Set the downstream servers, keyed by route name.
    #[must_use]
    pub fn with_servers(mut self, servers: BTreeMap<String, McpServerSpec>) -> Self {
        self.servers = servers;
        self
    }

    /// Use a [`Policy`] for `before_tool`.
    #[must_use]
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.hooks = Arc::new(policy);
        self
    }

    /// Use custom hooks.
    #[must_use]
    pub fn with_hooks(mut self, hooks: Arc<dyn GatewayHooks>) -> Self {
        self.hooks = hooks;
        self
    }

    /// Per-request timeout towards downstream servers.
    #[must_use]
    pub const fn with_request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }

    /// Maximum accepted request body size in bytes.
    #[must_use]
    pub const fn with_max_body_bytes(mut self, n: usize) -> Self {
        self.max_body_bytes = n;
        self
    }

    /// Borrow the active config.
    pub const fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Bind and start serving. Downstream servers are launched lazily on
    /// their first request.
    pub async fn start(&self) -> Result<GatewayHandle, GatewayError> {
        self.config.validate()?;
        if self.config.bearer_token.is_empty() {
            return Err(GatewayError::EmptyBearerToken);
        }
        if self.config.max_in_flight == 0 {
            return Err(GatewayError::ZeroMaxInFlight);
        }
        let bind = self.config.bind;
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|source| GatewayError::Bind { addr: bind, source })?;
        let addr = listener
            .local_addr()
            .map_err(|source| GatewayError::Bind { addr: bind, source })?;

        let servers = self
            .servers
            .iter()
            .map(|(name, spec)| {
                (
                    name.clone(),
                    Arc::new(Downstream {
                        name: name.clone(),
                        spec: spec.clone(),
                        timeout: self.request_timeout,
                        proc: tokio::sync::Mutex::new(None),
                    }),
                )
            })
            .collect();
        let shared = Arc::new(Shared {
            token: self.config.bearer_token.clone().into_bytes(),
            servers,
            hooks: self.hooks.clone(),
            audit: Mutex::new(VecDeque::new()),
            seq: AtomicU64::new(0),
            permits: Arc::new(Semaphore::new(self.config.max_in_flight)),
            max_body: self.max_body_bytes,
        });

        let (stop, mut stop_rx) = watch::channel(false);
        let sh = shared.clone();
        let task = tokio::spawn(async move {
            let mut conns: JoinSet<()> = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    acc = listener.accept() => match acc {
                        Ok((stream, _)) => {
                            let sh = sh.clone();
                            conns.spawn(async move {
                                let svc = service_fn(move |req| handle(sh.clone(), req));
                                let _ = http1::Builder::new()
                                    .serve_connection(TokioIo::new(stream), svc)
                                    .await;
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "gateway accept failed");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    },
                    Some(_) = conns.join_next(), if !conns.is_empty() => {}
                }
            }
            // Dropping the JoinSet aborts every open connection.
            drop(conns);
        });

        tracing::info!(%addr, servers = shared.servers.len(), "MCP gateway listening");
        Ok(GatewayHandle {
            addr,
            shared,
            stop,
            task: Some(task),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_is_loopback_ephemeral() {
        let c = GatewayConfig::default();
        assert!(c.bind.ip().is_loopback(), "default bind must be loopback");
        assert_eq!(c.bind.port(), 0, "default port is 0 (ephemeral)");
        assert!(c.max_in_flight >= 1);
    }

    #[tokio::test]
    async fn start_binds_ephemeral_loopback_and_shuts_down() {
        let gw = Gateway::new(GatewayConfig {
            bearer_token: generate_bearer_token(),
            ..GatewayConfig::default()
        });
        let h = gw.start().await.expect("start");
        assert!(h.addr.ip().is_loopback());
        assert_ne!(h.addr.port(), 0);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn start_rejects_empty_token_and_zero_cap() {
        let err = Gateway::new(GatewayConfig::default())
            .start()
            .await
            .expect_err("empty token must be refused");
        assert!(matches!(err, GatewayError::EmptyBearerToken));
        assert!(err.to_string().contains("ENTANGLE-E0623"));
        let err = Gateway::new(GatewayConfig {
            bearer_token: "t".into(),
            max_in_flight: 0,
            ..GatewayConfig::default()
        })
        .start()
        .await
        .expect_err("zero cap must be refused");
        assert!(matches!(err, GatewayError::ZeroMaxInFlight));
    }

    #[test]
    fn gateway_holds_its_config() {
        let cfg = GatewayConfig {
            bind: "127.0.0.1:8765".parse().unwrap(),
            bearer_token: "abc".into(),
            max_in_flight: 4,
            allow_non_loopback: false,
        };
        let gw = Gateway::new(cfg.clone());
        assert_eq!(gw.config().bind, cfg.bind);
        assert_eq!(gw.config().bearer_token, "abc");
        assert_eq!(gw.config().max_in_flight, 4);
    }

    #[test]
    fn generate_bearer_token_is_64_hex_chars() {
        let t = generate_bearer_token();
        assert_eq!(t.len(), 64, "expected 64 hex chars; got {t:?}");
        assert!(
            t.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "token must be lowercase hex; got {t:?}"
        );
    }

    #[test]
    fn generate_bearer_token_is_not_repeating() {
        let a = generate_bearer_token();
        let b = generate_bearer_token();
        assert_ne!(a, b, "bearer tokens must differ across calls");
    }

    #[test]
    fn validate_accepts_loopback() {
        let cfg = GatewayConfig::default();
        cfg.validate().expect("loopback default must validate");
    }

    #[test]
    fn validate_rejects_wildcard_bind_by_default() {
        let cfg = GatewayConfig {
            bind: "0.0.0.0:8080".parse().unwrap(),
            ..GatewayConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("wildcard bind must be refused unless explicitly allowed");
        assert!(matches!(err, GatewayError::NonLoopbackBindRefused { .. }));
        assert!(err.to_string().contains("ENTANGLE-E0622"));
    }

    #[test]
    fn validate_allows_wildcard_when_opted_in() {
        let cfg = GatewayConfig {
            bind: "0.0.0.0:8080".parse().unwrap(),
            allow_non_loopback: true,
            ..GatewayConfig::default()
        };
        cfg.validate().expect("opt-in must validate");
    }

    #[tokio::test]
    async fn start_refuses_non_loopback_bind() {
        let cfg = GatewayConfig {
            bind: "0.0.0.0:0".parse().unwrap(),
            bearer_token: "t".into(),
            ..GatewayConfig::default()
        };
        let err = Gateway::new(cfg)
            .start()
            .await
            .expect_err("non-loopback must error");
        assert!(matches!(err, GatewayError::NonLoopbackBindRefused { .. }));
    }

    #[test]
    fn ct_eq_behaves() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"", b"a"));
    }

    #[test]
    fn policy_matching() {
        let p = Policy {
            allow: vec!["fs/*".into(), "git/status".into()],
            deny: vec!["fs/rm".into()],
        };
        assert_eq!(p.evaluate("fs", "read"), Decision::Allow);
        assert_eq!(p.evaluate("git", "status"), Decision::Allow);
        assert!(matches!(p.evaluate("fs", "rm"), Decision::Deny { .. }));
        assert!(matches!(p.evaluate("git", "push"), Decision::Deny { .. }));
        assert_eq!(Policy::default().evaluate("x", "y"), Decision::Allow);
        let deny_all = Policy {
            allow: vec![],
            deny: vec!["*".into()],
        };
        assert!(matches!(deny_all.evaluate("x", "y"), Decision::Deny { .. }));
    }
}
