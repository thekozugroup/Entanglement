//! Minimal HTTP/1.1 transport over hyper with rustls.
//!
//! One connection per request (`Connection: close`): registries are not
//! latency-critical here and this keeps redirect/auth reasoning trivial. The
//! scheme policy lives here so no code path can reach the network around it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
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
            self.roundtrip(TokioIo::new(tcp), req, &auth).await
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
            self.roundtrip(TokioIo::new(tls), req, &auth).await
        }
    }

    async fn roundtrip<T>(
        &self,
        io: TokioIo<T>,
        req: Request<Full<Bytes>>,
        auth: &str,
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
        tokio::time::timeout(self.timeout, sender.send_request(req))
            .await
            .map_err(|_| OciError::Timeout(format!("waiting for {auth} to answer")))?
            .map_err(|e| transport_err(format!("request: {e}")))
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
