//! The Prometheus scrape endpoint (spec §9.6).
//!
//! `GET /metrics` serves [`Registry::render`] in the Prometheus text format
//! 0.0.4. Everything else is `404` (`405` for a wrong method on `/metrics`).
//!
//! # Hardening
//!
//! The endpoint is unauthenticated, so it is meant for loopback:
//! [`resolve_listen`] refuses a non-loopback address unless the operator set
//! `allow_non_loopback = true` (`ENTANGLE-E0656`). Independent of that:
//!
//! - one request per connection (`Connection: close`), so an idle client
//!   cannot hold a slot;
//! - request headers must arrive within [`HEADER_TIMEOUT`] and the whole
//!   exchange within [`CONNECTION_TIMEOUT`];
//! - at most [`MAX_CONNECTIONS`] connections are served at once; further ones
//!   are closed immediately instead of queueing;
//! - request bodies are never read.

use crate::config::MetricsSection;
use bytes::Bytes;
use entangle_observability::Registry;
use http_body_util::Full;
use hyper::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};

/// Default `[metrics] listen` (the OpenTelemetry-registered Prometheus
/// exporter port).
pub const DEFAULT_LISTEN: &str = "127.0.0.1:9464";

/// `Content-Type` of a Prometheus text-format 0.0.4 response.
pub const CONTENT_TYPE_PROMETHEUS: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Connections served at once; extras are closed.
pub const MAX_CONNECTIONS: usize = 32;

/// How long a client may take to send its request head.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on one connection's whole lifetime.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);

/// Failures starting the metrics endpoint.
#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    /// `[metrics] listen` is not an `ip:port`.
    #[error("ENTANGLE-E0655: [metrics] listen {listen:?} is not a valid ip:port: {reason}")]
    InvalidListen {
        /// The configured value.
        listen: String,
        /// Parser message.
        reason: String,
    },
    /// A non-loopback `listen` without `allow_non_loopback = true`.
    #[error(
        "ENTANGLE-E0656: [metrics] listen {addr} is not a loopback address and the endpoint is \
         unauthenticated; bind 127.0.0.1 or set allow_non_loopback = true to expose it on purpose"
    )]
    NonLoopbackRefused {
        /// The refused address.
        addr: SocketAddr,
    },
    /// The socket could not be bound.
    #[error("ENTANGLE-E0657: cannot bind the metrics endpoint to {addr}: {source}")]
    Bind {
        /// The address that failed.
        addr: SocketAddr,
        /// Underlying error.
        source: std::io::Error,
    },
}

/// Parse and vet `[metrics] listen`.
pub fn resolve_listen(cfg: &MetricsSection) -> Result<SocketAddr, MetricsError> {
    let addr: SocketAddr =
        cfg.listen
            .parse()
            .map_err(|e: std::net::AddrParseError| MetricsError::InvalidListen {
                listen: cfg.listen.clone(),
                reason: e.to_string(),
            })?;
    if !addr.ip().is_loopback() {
        if !cfg.allow_non_loopback {
            return Err(MetricsError::NonLoopbackRefused { addr });
        }
        tracing::warn!(
            %addr,
            "[metrics] is listening on a non-loopback address (allow_non_loopback = true); \
             the endpoint has no authentication — restrict it with a firewall"
        );
    }
    Ok(addr)
}

/// A running scrape endpoint.
pub struct MetricsServer {
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl MetricsServer {
    /// Validate `cfg` and start serving `registry`.
    ///
    /// Returns `Ok(None)` when `[metrics] enabled = false`; a disabled
    /// section is not validated, so a stale `listen` cannot block startup.
    /// Otherwise the address is vetted by [`resolve_listen`] (`E0655`,
    /// `E0656`) and bound (`E0657`).
    pub async fn start(
        cfg: &MetricsSection,
        registry: Registry,
    ) -> Result<Option<Self>, MetricsError> {
        Self::start_with_timeouts(cfg, registry, HEADER_TIMEOUT, CONNECTION_TIMEOUT).await
    }

    /// [`MetricsServer::start`] with explicit per-connection timeouts, so
    /// tests need not wait for the production values.
    pub async fn start_with_timeouts(
        cfg: &MetricsSection,
        registry: Registry,
        header_timeout: Duration,
        connection_timeout: Duration,
    ) -> Result<Option<Self>, MetricsError> {
        if !cfg.enabled {
            return Ok(None);
        }
        let addr = resolve_listen(cfg)?;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| MetricsError::Bind { addr, source })?;
        let addr = listener
            .local_addr()
            .map_err(|source| MetricsError::Bind { addr, source })?;
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(accept_loop(
            listener,
            registry,
            stopped,
            header_timeout,
            connection_timeout,
        ));
        tracing::info!(%addr, "metrics endpoint listening (GET /metrics)");
        Ok(Some(Self { addr, stop, task }))
    }

    /// The address actually bound (useful with port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop accepting and wait for the accept loop to end.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

async fn accept_loop(
    listener: TcpListener,
    registry: Registry,
    mut stopped: watch::Receiver<bool>,
    header_timeout: Duration,
    connection_timeout: Duration,
) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let stream = tokio::select! {
            _ = stopped.changed() => return,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(e) => {
                    tracing::debug!(error = %e, "metrics accept failed");
                    // Avoid a hot loop on EMFILE and friends.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            // Over the cap: close instead of queueing.
            drop(stream);
            continue;
        };
        let registry = registry.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |req| {
                let registry = registry.clone();
                async move { Ok::<_, Infallible>(handle(&req, &registry)) }
            });
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout)
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service);
            // Both errors and the overall timeout just end this connection.
            let _ = tokio::time::timeout(connection_timeout, conn).await;
        });
    }
}

/// Route one request. Pure of I/O so it is directly testable.
pub fn handle<B>(req: &Request<B>, registry: &Registry) -> Response<Full<Bytes>> {
    let reply = |status: StatusCode, content_type: &str, body: String| {
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, content_type)
            .header(CACHE_CONTROL, "no-store")
            .body(Full::new(Bytes::from(body)))
            // The builder only fails on invalid header values; ours are static.
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
    };
    if req.uri().path() != "/metrics" {
        return reply(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found\n".into(),
        );
    }
    match *req.method() {
        Method::GET => reply(StatusCode::OK, CONTENT_TYPE_PROMETHEUS, registry.render()),
        Method::HEAD => {
            // Same headers as GET (including Content-Length) with no body.
            let body = registry.render();
            let mut resp = reply(StatusCode::OK, CONTENT_TYPE_PROMETHEUS, String::new());
            if let Ok(len) = body.len().to_string().parse() {
                resp.headers_mut()
                    .insert(hyper::header::CONTENT_LENGTH, len);
            }
            resp
        }
        _ => {
            let mut resp = reply(
                StatusCode::METHOD_NOT_ALLOWED,
                "text/plain; charset=utf-8",
                "method not allowed\n".into(),
            );
            resp.headers_mut()
                .insert(ALLOW, hyper::header::HeaderValue::from_static("GET, HEAD"));
            resp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(listen: &str, allow: bool) -> MetricsSection {
        MetricsSection {
            enabled: true,
            listen: listen.into(),
            allow_non_loopback: allow,
        }
    }

    #[test]
    fn loopback_is_accepted_and_others_need_the_opt_in() {
        assert!(resolve_listen(&section("127.0.0.1:9464", false)).is_ok());
        assert!(resolve_listen(&section("[::1]:9464", false)).is_ok());
        for bad in ["0.0.0.0:9464", "192.0.2.7:9464", "[::]:9464"] {
            let err = resolve_listen(&section(bad, false)).unwrap_err();
            assert!(
                matches!(err, MetricsError::NonLoopbackRefused { .. }),
                "{bad}"
            );
            assert!(err.to_string().contains("ENTANGLE-E0656"));
            assert!(
                resolve_listen(&section(bad, true)).is_ok(),
                "{bad} with opt-in"
            );
        }
    }

    #[test]
    fn unparsable_listen_is_e0655() {
        for bad in ["localhost:9464", "9464", "127.0.0.1", ""] {
            let err = resolve_listen(&section(bad, false)).unwrap_err();
            assert!(err.to_string().contains("ENTANGLE-E0655"), "{bad}: {err}");
        }
    }
}
