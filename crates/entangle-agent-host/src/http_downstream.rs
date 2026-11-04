//! Client side of the MCP "Streamable HTTP" transport, for the gateway's
//! `url` (HTTP) downstream servers.
//!
//! One TCP (and TLS) connection per request (`Connection: close`): MCP
//! servers are not latency-critical here and it keeps timeout, size-cap and
//! credential reasoning simple. What this module guarantees:
//!
//! * **Scheme policy**: `https` only, except a loopback host (`localhost`, or
//!   an address in 127.0.0.0/8 or `::1`) where plain `http` is allowed. A
//!   `localhost` name is checked again against the connected peer address.
//! * **Credentials**: only the headers configured for that server in the
//!   user's agent config are sent (plus the protocol headers below). The
//!   gateway's own bearer token is never forwarded, and redirects are not
//!   followed, so those headers cannot be handed to another host.
//! * **Replies**: `application/json` (one message, or a batch) and
//!   `text/event-stream` (events are read until the response to the request
//!   id arrives; other server messages are dropped, server requests are
//!   answered `ping` -> `{}` and anything else -> `-32601` by a separate
//!   POST, as the stdio proxy does).
//! * **Session**: the `Mcp-Session-Id` of a reply is returned to the caller;
//!   the caller passes it (and the negotiated `MCP-Protocol-Version`) back on
//!   later requests.
//! * **Bounds**: one overall timeout for connect, TLS, send and reading the
//!   reply; JSON bodies, SSE events and header blocks over the size cap fail.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use url::{Host, Url};

/// Header names the gateway sets itself; a user header with one of these
/// names is refused rather than silently overridden.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "accept",
    "connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
    "mcp-session-id",
    "mcp-protocol-version",
];

/// Why a request to an HTTP downstream failed.
#[derive(Debug)]
pub(crate) enum HttpError {
    /// The URL or a configured header is not acceptable (never contacted).
    Refused(String),
    /// Transport, status or protocol failure.
    Failed(String),
    /// 404 for a request that carried a session id: the session is gone.
    SessionExpired,
    /// The overall deadline passed.
    Timeout,
    /// A body, event or line exceeded the size cap.
    TooLarge(usize),
    /// The reply ended without a response to the request.
    Closed,
}

/// A successful exchange.
#[derive(Debug)]
pub(crate) struct Reply {
    /// `Mcp-Session-Id` of the reply, if any.
    pub session_id: Option<String>,
    /// The response message; `None` for `202 Accepted` / an empty body.
    pub message: Option<Value>,
}

/// A validated HTTP downstream endpoint plus its configured headers.
pub(crate) struct HttpTarget {
    url: Url,
    plain: bool,
    headers: Vec<(HeaderName, HeaderValue)>,
    tls: std::sync::OnceLock<Result<Arc<rustls::ClientConfig>, String>>,
}

impl std::fmt::Debug for HttpTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Header values are credentials: names only.
        f.debug_struct("HttpTarget")
            .field("url", &redact_url(&self.url))
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(k, _)| k.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// `url` without credentials, query or fragment, for messages and logs.
pub(crate) fn redact_url(url: &Url) -> String {
    let mut u = url.clone();
    let _ = u.set_username("");
    let _ = u.set_password(None);
    u.set_query(None);
    u.set_fragment(None);
    u.to_string()
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(a)) => a.is_loopback(),
        Some(Host::Ipv6(a)) => a.is_loopback(),
        None => false,
    }
}

/// Check `url` against the scheme policy without building a target.
pub(crate) fn check_url(url: &str) -> Result<(), String> {
    parse_url(url).map(|_| ())
}

fn parse_url(raw: &str) -> Result<(Url, bool), String> {
    let url = Url::parse(raw).map_err(|e| format!("not a valid URL: {e}"))?;
    if url.host().is_none() {
        return Err("the URL has no host".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("the URL must not contain credentials; use a configured header".into());
    }
    match url.scheme() {
        "https" => Ok((url, false)),
        "http" if is_loopback(&url) => Ok((url, true)),
        "http" => Err(format!(
            "plain http is only allowed for a loopback host; {} must use https",
            redact_url(&url)
        )),
        other => Err(format!(
            "unsupported URL scheme {other:?} (https is required)"
        )),
    }
}

impl HttpTarget {
    /// Validate `url` and the user's headers.
    pub(crate) fn new<'a>(
        url: &str,
        headers: impl IntoIterator<Item = (&'a String, &'a String)>,
    ) -> Result<Self, HttpError> {
        let (url, plain) = parse_url(url).map_err(HttpError::Refused)?;
        let mut out = Vec::new();
        for (k, v) in headers {
            let name = HeaderName::from_bytes(k.as_bytes())
                .map_err(|_| HttpError::Refused(format!("invalid header name {k:?}")))?;
            if RESERVED_HEADERS.contains(&name.as_str()) {
                return Err(HttpError::Refused(format!(
                    "header {k:?} is set by the gateway and cannot be configured"
                )));
            }
            // Never echo the value: it is a credential.
            let mut value = HeaderValue::from_str(v)
                .map_err(|_| HttpError::Refused(format!("header {k:?} has an invalid value")))?;
            value.set_sensitive(true);
            out.push((name, value));
        }
        Ok(Self {
            url,
            plain,
            headers: out,
            tls: std::sync::OnceLock::new(),
        })
    }

    /// POST one JSON-RPC message and read the reply.
    pub(crate) async fn post(
        self: &Arc<Self>,
        msg: &Value,
        session: Option<&str>,
        protocol: Option<&str>,
        timeout: Duration,
        max: usize,
    ) -> Result<Reply, HttpError> {
        let body =
            Bytes::from(serde_json::to_vec(msg).map_err(|e| HttpError::Failed(e.to_string()))?);
        let want_id = (msg.get("method").is_some())
            .then(|| msg.get("id").cloned())
            .flatten();
        let fut = async {
            let resp = self
                .send(Method::POST, Some(body), session, protocol, timeout)
                .await?;
            self.read_reply(resp, want_id, session, protocol, timeout, max)
                .await
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| HttpError::Timeout)?
    }

    /// Best-effort `DELETE` ending `session` (MCP spec: clients SHOULD),
    /// with the negotiated `MCP-Protocol-Version` like every request after
    /// initialization.
    pub(crate) async fn terminate(
        self: &Arc<Self>,
        session: &str,
        protocol: Option<&str>,
        timeout: Duration,
    ) {
        let fut = self.send(Method::DELETE, None, Some(session), protocol, timeout);
        let _ = tokio::time::timeout(timeout, fut).await;
    }

    async fn send(
        &self,
        method: Method,
        body: Option<Bytes>,
        session: Option<&str>,
        protocol: Option<&str>,
        timeout: Duration,
    ) -> Result<hyper::Response<hyper::body::Incoming>, HttpError> {
        let url = &self.url;
        let host = url
            .host()
            .ok_or_else(|| HttpError::Refused("no host".into()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| HttpError::Refused("no port".into()))?;
        let fail =
            |what: &str, e: &dyn std::fmt::Display| HttpError::Failed(format!("{what}: {e}"));
        // IP literals are dialled as addresses (an IPv6 host_str keeps its brackets).
        let tcp = match &host {
            Host::Ipv4(a) => TcpStream::connect(SocketAddr::new(IpAddr::V4(*a), port)).await,
            Host::Ipv6(a) => TcpStream::connect(SocketAddr::new(IpAddr::V6(*a), port)).await,
            Host::Domain(d) => TcpStream::connect((*d, port)).await,
        }
        .map_err(|e| fail("connect", &e))?;
        if self.plain
            && !tcp
                .peer_addr()
                .map(|a| a.ip().is_loopback())
                .unwrap_or(false)
        {
            // "localhost" must really be loopback, whatever DNS says.
            return Err(HttpError::Refused(
                "plain http host does not resolve to a loopback address".into(),
            ));
        }
        let host_hdr = match (&host, url.port()) {
            (Host::Ipv6(a), Some(p)) => format!("[{a}]:{p}"),
            (Host::Ipv6(a), None) => format!("[{a}]"),
            (h, Some(p)) => format!("{h}:{p}"),
            (h, None) => h.to_string(),
        };
        let mut req = Request::builder()
            .method(method.clone())
            .uri(match url.query() {
                Some(q) => format!("{}?{q}", url.path()),
                None => url.path().to_owned(),
            })
            .header("host", host_hdr)
            .header("connection", "close")
            .header(
                "user-agent",
                concat!("entangle-gateway/", env!("CARGO_PKG_VERSION")),
            );
        if method == Method::POST {
            req = req
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream");
        }
        if let Some(s) = session {
            req = req.header(
                "mcp-session-id",
                HeaderValue::from_str(s).map_err(|_| HttpError::Failed("bad session id".into()))?,
            );
        }
        if let Some(p) = protocol {
            req = req.header(
                "mcp-protocol-version",
                HeaderValue::from_str(p)
                    .map_err(|_| HttpError::Failed("bad protocol version".into()))?,
            );
        }
        for (k, v) in &self.headers {
            req = req.header(k, v);
        }
        let req = req
            .body(Full::new(body.unwrap_or_default()))
            .map_err(|e| fail("building request", &e))?;

        if self.plain {
            roundtrip(TokioIo::new(tcp), req).await
        } else {
            let name = match &host {
                Host::Ipv4(a) => rustls::pki_types::ServerName::IpAddress(IpAddr::V4(*a).into()),
                Host::Ipv6(a) => rustls::pki_types::ServerName::IpAddress(IpAddr::V6(*a).into()),
                Host::Domain(d) => rustls::pki_types::ServerName::try_from((*d).to_owned())
                    .map_err(|e| fail("TLS server name", &e))?,
            };
            let cfg = self
                .tls
                .get_or_init(|| tls_config().map(Arc::new))
                .clone()
                .map_err(|e| HttpError::Failed(format!("TLS configuration: {e}")))?;
            let tls = tokio::time::timeout(
                timeout,
                tokio_rustls::TlsConnector::from(cfg).connect(name, tcp),
            )
            .await
            .map_err(|_| HttpError::Timeout)?
            .map_err(|e| fail("TLS", &e))?;
            roundtrip(TokioIo::new(tls), req).await
        }
    }

    async fn read_reply(
        self: &Arc<Self>,
        resp: hyper::Response<hyper::body::Incoming>,
        want_id: Option<Value>,
        session: Option<&str>,
        protocol: Option<&str>,
        timeout: Duration,
        max: usize,
    ) -> Result<Reply, HttpError> {
        let status = resp.status();
        let session_id = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if status == StatusCode::NOT_FOUND && session.is_some() {
            return Err(HttpError::SessionExpired);
        }
        if !status.is_success() {
            // Redirects land here too: they are never followed.
            return Err(HttpError::Failed(format!("HTTP status {status}")));
        }
        let ctype = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let body = resp.into_body();
        let message = if ctype.starts_with("text/event-stream") {
            match want_id {
                Some(id) => Some(
                    self.read_sse(
                        body,
                        &id,
                        session_id.as_deref().or(session),
                        protocol,
                        timeout,
                        max,
                    )
                    .await?,
                ),
                // A stream answering a notification: nothing to wait for.
                None => None,
            }
        } else {
            let bytes = Limited::new(body, max)
                .collect()
                .await
                .map_err(|e| {
                    if e.downcast_ref::<LengthLimitError>().is_some() {
                        HttpError::TooLarge(max)
                    } else {
                        HttpError::Failed(format!("reading body: {e}"))
                    }
                })?
                .to_bytes();
            if bytes.iter().all(u8::is_ascii_whitespace) {
                if want_id.is_some() && status != StatusCode::ACCEPTED {
                    return Err(HttpError::Failed("empty reply to a request".into()));
                }
                None
            } else if !ctype.starts_with("application/json") {
                return Err(HttpError::Failed(format!(
                    "unexpected content-type {ctype:?} (expected application/json or text/event-stream)"
                )));
            } else {
                let v: Value = serde_json::from_slice(&bytes)
                    .map_err(|e| HttpError::Failed(format!("reply is not JSON: {e}")))?;
                match &want_id {
                    Some(id) => Some(find_response(&v, id).ok_or_else(|| {
                        HttpError::Failed("reply has no response for the request id".into())
                    })?),
                    None => None,
                }
            }
        };
        Ok(Reply {
            session_id,
            message,
        })
    }

    async fn read_sse(
        self: &Arc<Self>,
        mut body: hyper::body::Incoming,
        want: &Value,
        session: Option<&str>,
        protocol: Option<&str>,
        timeout: Duration,
        max: usize,
    ) -> Result<Value, HttpError> {
        let mut buf: Vec<u8> = Vec::new();
        let mut data = String::new();
        loop {
            // Drain complete lines.
            while let Some(nl) = buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buf.drain(..=nl).collect();
                let line = String::from_utf8_lossy(&line);
                let line = line.trim_end_matches(['\n', '\r']);
                if line.is_empty() {
                    if !data.is_empty() {
                        let ev = std::mem::take(&mut data);
                        if let Some(r) = self.sse_event(&ev, want, session, protocol, timeout, max)
                        {
                            return Ok(r);
                        }
                    }
                } else if let Some(rest) = line.strip_prefix("data:") {
                    if !data.is_empty() {
                        data.push('\n');
                    }
                    data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
                    if data.len() > max {
                        return Err(HttpError::TooLarge(max));
                    }
                }
                // `event:`, `id:`, `retry:` and comments carry nothing we use.
            }
            if buf.len() > max {
                return Err(HttpError::TooLarge(max));
            }
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(d) = frame.into_data() {
                        buf.extend_from_slice(&d);
                    }
                }
                Some(Err(e)) => {
                    return Err(HttpError::Failed(format!("reading event stream: {e}")))
                }
                None => {
                    // A final event without its blank line still counts.
                    if !buf.is_empty() {
                        let tail = String::from_utf8_lossy(&buf).into_owned();
                        if let Some(rest) =
                            tail.trim_end_matches(['\n', '\r']).strip_prefix("data:")
                        {
                            if !data.is_empty() {
                                data.push('\n');
                            }
                            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
                        }
                    }
                    if !data.is_empty() {
                        if let Some(r) =
                            self.sse_event(&data, want, session, protocol, timeout, max)
                        {
                            return Ok(r);
                        }
                    }
                    return Err(HttpError::Closed);
                }
            }
        }
    }

    /// Handle one SSE event's data; `Some` when it holds the awaited response.
    fn sse_event(
        self: &Arc<Self>,
        data: &str,
        want: &Value,
        session: Option<&str>,
        protocol: Option<&str>,
        timeout: Duration,
        max: usize,
    ) -> Option<Value> {
        let Ok(v) = serde_json::from_str::<Value>(data) else {
            tracing::debug!("non-JSON SSE event from HTTP downstream dropped");
            return None;
        };
        if let Some(r) = find_response(&v, want) {
            return Some(r);
        }
        let items = match &v {
            Value::Array(a) => a.clone(),
            other => vec![other.clone()],
        };
        for m in items {
            // A server request: answer it (the gateway relays no client features).
            if let (Some(method), Some(id)) = (m.get("method").and_then(Value::as_str), m.get("id"))
            {
                let reply = if method == "ping" {
                    json!({"jsonrpc": "2.0", "id": id, "result": {}})
                } else {
                    json!({"jsonrpc": "2.0", "id": id, "error": {
                        "code": -32601, "message": "method not available through the gateway"}})
                };
                let (this, session, protocol) = (
                    self.clone(),
                    session.map(str::to_owned),
                    protocol.map(str::to_owned),
                );
                tokio::spawn(async move {
                    let _ = this
                        .post(
                            &reply,
                            session.as_deref(),
                            protocol.as_deref(),
                            timeout,
                            max,
                        )
                        .await;
                });
            }
        }
        None
    }
}

/// The message answering `id` in `v` (a message or a batch).
fn find_response(v: &Value, id: &Value) -> Option<Value> {
    let is_answer = |m: &Value| {
        m.get("method").is_none()
            && m.get("id") == Some(id)
            && (m.get("result").is_some() || m.get("error").is_some())
    };
    match v {
        Value::Array(items) => items.iter().find(|m| is_answer(m)).cloned(),
        m if is_answer(m) => Some(m.clone()),
        _ => None,
    }
}

async fn roundtrip<T>(
    io: TokioIo<T>,
    req: Request<Full<Bytes>>,
) -> Result<hyper::Response<hyper::body::Incoming>, HttpError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| HttpError::Failed(format!("HTTP handshake: {e}")))?;
    tokio::spawn(async move {
        // Ends when the response body is consumed or dropped.
        let _ = conn.await;
    });
    sender
        .send_request(req)
        .await
        .map_err(|e| HttpError::Failed(format!("request: {e}")))
}

fn tls_config() -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // System roots too (corporate CAs; honours SSL_CERT_FILE).
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?;
    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_policy() {
        for ok in [
            "https://mcp.example.com/mcp",
            "https://203.0.113.5:8443/mcp?x=1",
            "http://127.0.0.1:8080/mcp",
            "http://localhost/mcp",
            "http://[::1]:9/mcp",
            "https://127.0.0.1/mcp",
        ] {
            assert!(check_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://mcp.example.com/mcp",
            "http://10.0.0.5/mcp",
            "http://localhost.evil.example/mcp",
            "ftp://x/y",
            "https://user:pw@mcp.example.com/mcp",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn headers_are_validated_and_never_echoed() {
        let mut h = std::collections::BTreeMap::new();
        h.insert("Authorization".to_string(), "Bearer s3cret".to_string());
        let t = HttpTarget::new("https://x.example/mcp", &h).unwrap();
        assert!(!format!("{t:?}").contains("s3cret"));
        for reserved in ["Host", "content-type", "Mcp-Session-Id", "accept"] {
            let mut h = std::collections::BTreeMap::new();
            h.insert(reserved.to_string(), "x".to_string());
            assert!(matches!(
                HttpTarget::new("https://x.example/mcp", &h),
                Err(HttpError::Refused(_))
            ));
        }
        let mut h = std::collections::BTreeMap::new();
        h.insert("X-A".to_string(), "bad\r\nvalue: 1".to_string());
        let e = HttpTarget::new("https://x.example/mcp", &h).unwrap_err();
        assert!(
            matches!(&e, HttpError::Refused(m) if !m.contains("bad")),
            "{e:?}"
        );
    }
}
