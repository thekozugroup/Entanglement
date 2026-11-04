//! Minimal HTTP/1.1 transport over hyper with rustls.
//!
//! One connection per request (`Connection: close`): registries are not
//! latency-critical here and this keeps redirect/auth reasoning trivial. The
//! scheme policy lives here so no code path can reach the network around it.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;
use url::{Host, Url};

use crate::error::{OciError, Result};

/// `host:port` (with the scheme's default port filled in) for `url`.
pub(crate) fn authority(url: &Url) -> String {
    let host = match url.host() {
        Some(Host::Ipv6(a)) => format!("[{a}]"),
        Some(h) => h.to_string(),
        None => String::new(),
    };
    match url.port_or_known_default() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    }
}

/// Is `host` (a bare host or `host:port`, IPv6 bracketed) a loopback name?
pub(crate) fn is_loopback_host(host_port: &str) -> bool {
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|a| a.is_loopback())
        .unwrap_or(false)
}

fn url_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(a)) => a.is_loopback(),
        Some(Host::Ipv6(a)) => a.is_loopback(),
        None => false,
    }
}

/// Sends requests; enforces HTTPS-by-default.
pub(crate) struct Transport {
    tls: std::sync::OnceLock<std::result::Result<Arc<rustls::ClientConfig>, String>>,
    allow_plain_http: bool,
    timeout: Duration,
}

impl Transport {
    pub(crate) fn new(allow_plain_http: bool, timeout: Duration) -> Self {
        Self {
            tls: std::sync::OnceLock::new(),
            allow_plain_http,
            timeout,
        }
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Send one request (no redirects, auth or retries — see `client`).
    pub(crate) async fn send(
        &self,
        method: &Method,
        url: &Url,
        headers: &[(String, String)],
        body: Bytes,
    ) -> Result<Response<Incoming>> {
        let auth = authority(url);
        let transport_err = |detail: String| OciError::Transport {
            host: auth.clone(),
            detail,
        };
        let plain = match url.scheme() {
            "https" => false,
            "http" => true,
            other => return Err(transport_err(format!("unsupported URL scheme {other:?}"))),
        };
        if plain && !self.allow_plain_http && !url_is_loopback(url) {
            return Err(OciError::InsecureTransport { host: auth });
        }
        let host = url
            .host()
            .ok_or_else(|| transport_err("URL has no host".into()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| transport_err("URL has no port".into()))?;

        // IP literals are dialled as addresses: `host_str()` keeps an IPv6
        // literal's brackets ("[::1]"), which no resolver accepts.
        let connect = async {
            match &host {
                Host::Ipv4(a) => TcpStream::connect(SocketAddr::new(IpAddr::V4(*a), port)).await,
                Host::Ipv6(a) => TcpStream::connect(SocketAddr::new(IpAddr::V6(*a), port)).await,
                Host::Domain(d) => TcpStream::connect((*d, port)).await,
            }
        };
        let tcp = tokio::time::timeout(self.timeout, connect)
            .await
            .map_err(|_| OciError::Timeout(format!("connecting to {auth}")))?
            .map_err(|e| transport_err(format!("connect: {e}")))?;
        if plain && !self.allow_plain_http {
            // "localhost" must really be loopback, whatever DNS says.
            let peer_ok = tcp
                .peer_addr()
                .map(|a| a.ip().is_loopback())
                .unwrap_or(false);
            if !peer_ok {
                return Err(OciError::InsecureTransport { host: auth });
            }
        }
        let progress = Arc::new(Progress::new());
        let tcp = Counted {
            inner: tcp,
            progress: progress.clone(),
        };

        let mut req = Request::builder()
            .method(method.clone())
            .uri(match url.query() {
                Some(q) => format!("{}?{q}", url.path()),
                None => url.path().to_owned(),
            });
        let default_port = if plain { 80 } else { 443 };
        let host_hdr = if port == default_port {
            match &host {
                Host::Ipv6(a) => format!("[{a}]"),
                h => h.to_string(),
            }
        } else {
            auth.clone()
        };
        req = req
            .header("host", host_hdr)
            .header("connection", "close")
            .header(
                "user-agent",
                concat!("entangle-oci/", env!("CARGO_PKG_VERSION")),
            );
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        // hyper sends an empty body with neither Content-Length nor
        // Transfer-Encoding. Front ends such as Google's answer 411 to a
        // POST/PUT without a length (the upload-session POST and the chunked
        // finalize PUT are empty), so state the zero explicitly, as Go's
        // net/http (Docker, containerd, ORAS) does; hyper keeps a length the
        // caller set.
        if body.is_empty()
            && matches!(*method, Method::POST | Method::PUT | Method::PATCH)
            && !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        {
            req = req.header("content-length", "0");
        }
        let req = req
            .body(Full::new(body))
            .map_err(|e| transport_err(format!("building request: {e}")))?;

        if plain {
            self.roundtrip(TokioIo::new(tcp), req, &auth, &progress)
                .await
        } else {
            let name = tls_server_name(url)
                .map_err(|e| transport_err(format!("bad TLS server name: {e}")))?;
            let cfg = self
                .tls
                .get_or_init(|| tls_config().map(Arc::new))
                .clone()
                .map_err(|e| transport_err(format!("TLS configuration: {e}")))?;
            let connector = tokio_rustls::TlsConnector::from(cfg);
            let tls = tokio::time::timeout(self.timeout, connector.connect(name, tcp))
                .await
                .map_err(|_| OciError::Timeout(format!("TLS handshake with {auth}")))?
                .map_err(|e| transport_err(format!("TLS: {e}")))?;
            self.roundtrip(TokioIo::new(tls), req, &auth, &progress)
                .await
        }
    }

    /// Send `req` and wait for the response head.
    ///
    /// The timeout is an idle timeout: it fires only when the connection has
    /// accepted no bytes for `self.timeout` and no response has arrived. A
    /// fixed deadline would also bound the upload of the request body, so a
    /// multi-MiB PUT/PATCH over a slow link could never finish; once the body
    /// is written, the registry still gets `self.timeout` to answer. (Bytes the
    /// kernel still queues after our last write must drain in that time too;
    /// Linux sizes that queue to about twice the congestion window, i.e. a
    /// few round trips' worth on a real link.)
    async fn roundtrip<T>(
        &self,
        io: TokioIo<T>,
        req: Request<Full<Bytes>>,
        auth: &str,
        progress: &Progress,
    ) -> Result<Response<Incoming>>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let transport_err = |detail: String| OciError::Transport {
            host: auth.to_owned(),
            detail,
        };
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| transport_err(format!("HTTP handshake: {e}")))?;
        tokio::spawn(async move {
            // Ends when the response body is consumed or dropped.
            let _ = conn.await;
        });
        let mut response = std::pin::pin!(sender.send_request(req));
        let mut deadline = progress.last_write() + self.timeout;
        loop {
            match tokio::time::timeout_at(deadline, response.as_mut()).await {
                Ok(r) => return r.map_err(|e| transport_err(format!("request: {e}"))),
                Err(_) => {
                    let next = progress.last_write() + self.timeout;
                    if next <= deadline {
                        return Err(OciError::Timeout(format!("waiting for {auth} to answer")));
                    }
                    deadline = next;
                }
            }
        }
    }
}

/// When a connection last accepted bytes from us.
struct Progress {
    start: Instant,
    /// Microseconds after `start` of the last successful write.
    last_write_us: AtomicU64,
}

impl Progress {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_write_us: AtomicU64::new(0),
        }
    }

    fn wrote(&self, n: usize) {
        if n > 0 {
            let us = u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX);
            self.last_write_us.fetch_max(us, Ordering::Relaxed);
        }
    }

    fn last_write(&self) -> Instant {
        self.start + Duration::from_micros(self.last_write_us.load(Ordering::Relaxed))
    }
}

/// A connection that records when it last accepted bytes (see `roundtrip`).
struct Counted<T> {
    inner: T,
    progress: Arc<Progress>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Counted<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            this.progress.wrote(*n);
        }
        r
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &r {
            this.progress.wrote(*n);
        }
        r
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The name the server's certificate is verified against: the address for
/// an IP literal (an IP SAN), else the DNS name.
fn tls_server_name(
    url: &Url,
) -> std::result::Result<rustls::pki_types::ServerName<'static>, String> {
    use rustls::pki_types::ServerName;
    match url.host().ok_or("URL has no host")? {
        Host::Ipv4(a) => Ok(ServerName::IpAddress(IpAddr::V4(a).into())),
        Host::Ipv6(a) => Ok(ServerName::IpAddress(IpAddr::V6(a).into())),
        Host::Domain(d) => ServerName::try_from(d.to_owned()).map_err(|e| e.to_string()),
    }
}

fn tls_config() -> std::result::Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // System roots too (corporate CAs; honours SSL_CERT_FILE). Failures to
    // load are not fatal: the bundled roots still apply.
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

    #[tokio::test]
    async fn plain_http_to_a_non_loopback_host_is_refused_before_connecting() {
        let t = Transport::new(false, Duration::from_millis(50));
        // TEST-NET-3: would hang/timeout if we tried to connect.
        let url = Url::parse("http://203.0.113.9:5000/v2/").unwrap();
        let e = t
            .send(&Method::GET, &url, &[], Bytes::new())
            .await
            .unwrap_err();
        assert!(matches!(e, OciError::InsecureTransport { .. }), "{e}");
        assert!(e.to_string().starts_with("ENTANGLE-E0801"));
    }

    #[test]
    fn tls_server_name_of_an_ip_literal_is_the_address() {
        use rustls::pki_types::ServerName;
        for (url, ip) in [
            ("https://[::1]:5000/v2/", "::1"),
            ("https://[2001:db8::10]/v2/", "2001:db8::10"),
            ("https://192.0.2.7:5000/v2/", "192.0.2.7"),
        ] {
            let name =
                tls_server_name(&Url::parse(url).unwrap()).unwrap_or_else(|e| panic!("{url}: {e}"));
            let want: IpAddr = ip.parse().unwrap();
            assert_eq!(name, ServerName::IpAddress(want.into()), "{url}");
        }
        assert_eq!(
            tls_server_name(&Url::parse("https://ghcr.io/v2/").unwrap()).unwrap(),
            ServerName::try_from("ghcr.io").unwrap()
        );
    }

    #[tokio::test]
    async fn ipv6_literal_is_dialled_as_an_address_not_looked_up_as_a_name() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let t = Transport::new(false, Duration::from_secs(5));
        match tokio::net::TcpListener::bind("[::1]:0").await {
            Ok(listener) => {
                // IPv6 loopback exists here: a full round trip must work.
                let port = listener.local_addr().unwrap().port();
                tokio::spawn(async move {
                    let (mut s, _) = listener.accept().await.unwrap();
                    let mut buf = vec![0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    s.write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                });
                let url = Url::parse(&format!("http://[::1]:{port}/v2/")).unwrap();
                let resp = t.send(&Method::GET, &url, &[], Bytes::new()).await.unwrap();
                assert_eq!(resp.status(), 200);
            }
            Err(_) => {
                // No IPv6 in this sandbox (EAFNOSUPPORT): the dial must still be
                // an IPv6 connect that fails at the socket, never a DNS lookup
                // of the bracketed text "[::1]".
                let url = Url::parse("http://[::1]:9/v2/").unwrap();
                let e = t
                    .send(&Method::GET, &url, &[], Bytes::new())
                    .await
                    .unwrap_err();
                assert!(matches!(e, OciError::Transport { .. }), "{e}");
                assert!(!e.to_string().contains("lookup"), "{e}");
            }
        }
    }

    #[tokio::test]
    async fn a_slow_but_steady_upload_is_not_cut_off_by_the_request_timeout() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        const BODY: usize = 32 * 1024 * 1024;
        const TIMEOUT: Duration = Duration::from_secs(2);
        // A receiver that reads 128 KiB every 15 ms (~8 MB/s): the upload
        // takes about 4 s, twice the timeout, but the connection keeps
        // accepting bytes all along. Its receive buffer is capped so the
        // kernel cannot swallow the body at once. (Loopback lets the sender's
        // kernel queue ~4 MB, which it then takes ~0.5 s to drain after the
        // last write, still well inside the timeout.)
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.set_recv_buffer_size(256 * 1024).unwrap();
        sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = sock.listen(1).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 128 * 1024];
            let mut head = Vec::new();
            let mut body = None::<usize>;
            loop {
                tokio::time::sleep(Duration::from_millis(15)).await;
                let n = s.read(&mut buf).await.unwrap();
                assert!(n > 0, "client gave up after {body:?} body bytes");
                match body.as_mut() {
                    Some(b) => *b += n,
                    None => {
                        head.extend_from_slice(&buf[..n]);
                        if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                            body = Some(head.len() - (i + 4));
                        }
                    }
                }
                if body.is_some_and(|b| b >= BODY) {
                    break;
                }
            }
            s.write_all(b"HTTP/1.1 201 Created\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await
                .unwrap();
            body.unwrap()
        });
        let t = Transport::new(false, TIMEOUT);
        let url = Url::parse(&format!("http://127.0.0.1:{port}/v2/r/blobs/uploads/x")).unwrap();
        let started = std::time::Instant::now();
        let resp = t
            .send(&Method::PUT, &url, &[], Bytes::from(vec![0x5a; BODY]))
            .await
            .unwrap_or_else(|e| panic!("after {:?}: {e}", started.elapsed()));
        assert_eq!(resp.status(), 201);
        assert_eq!(server.await.unwrap(), BODY);
        assert!(
            started.elapsed() > TIMEOUT,
            "the upload was meant to outlast the timeout ({:?})",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_server_that_reads_nothing_still_times_out() {
        // Accepts, then never reads or answers: the idle timeout must fire.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(s);
        });
        let t = Transport::new(false, Duration::from_millis(300));
        let url = Url::parse(&format!("http://127.0.0.1:{port}/v2/")).unwrap();
        let started = std::time::Instant::now();
        let e = t
            .send(
                &Method::PUT,
                &url,
                &[],
                Bytes::from(vec![1u8; 32 * 1024 * 1024]),
            )
            .await
            .unwrap_err();
        assert!(matches!(e, OciError::Timeout(_)), "{e}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn loopback_detection() {
        for h in [
            "localhost",
            "localhost:5000",
            "127.0.0.1:1",
            "[::1]:5000",
            "127.9.9.9",
        ] {
            assert!(is_loopback_host(h), "{h}");
        }
        for h in [
            "ghcr.io",
            "10.0.0.1:5000",
            "[2001:db8::1]:443",
            "localhost.evil.com",
        ] {
            assert!(!is_loopback_host(h), "{h}");
        }
    }
}
