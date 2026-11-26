//! Optional loopback Prometheus endpoint. The owner-only RPC socket also serves metrics.

use anyhow::Context;
use entangle_bin::state::DaemonState;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, ALLOW, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

pub async fn bind(addr: Option<SocketAddr>) -> anyhow::Result<Option<TcpListener>> {
    let Some(addr) = addr else { return Ok(None) };
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "runtime.metrics_bind requires a loopback address"
    );
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding metrics endpoint {addr}"))?;
    tracing::info!(address = %listener.local_addr()?, "Prometheus endpoint listening");
    Ok(Some(listener))
}

fn respond(req: Request<Incoming>, state: &DaemonState) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::default());
    if req.uri().path() != "/metrics" {
        *response.status_mut() = StatusCode::NOT_FOUND;
    } else if req.method() != Method::GET {
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET"));
    } else {
        *response.body_mut() = Full::new(Bytes::from(state.render_metrics()));
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        );
    }
    response
}

pub async fn serve(listener: Option<TcpListener>, state: Arc<DaemonState>) -> anyhow::Result<()> {
    let Some(listener) = listener else {
        return std::future::pending().await;
    };
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            Some(_) = clients.join_next(), if !clients.is_empty() => {}
            accepted = listener.accept(), if clients.len() < 16 => {
                let (stream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::warn!(%error, "accepting metrics scrape");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let state = state.clone();
                clients.spawn(async move {
                    let service = service_fn(move |req| std::future::ready(Ok::<_, Infallible>(respond(req, &state))));
                    let _ = tokio::time::timeout(Duration::from_secs(5),
                        http1::Builder::new().keep_alive(false).serve_connection(TokioIo::new(stream), service)).await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_peers::PeerStore;
    use entangle_runtime::{Kernel, KernelConfig};
    use entangle_scheduler::{Dispatcher, WorkerPool};
    use entangle_signing::{IdentityKeyPair, Keyring};
    use entangle_types::peer_id::PeerId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn scraper_and_rpc_render_the_same_snapshot() {
        assert!(bind(None).await.unwrap().is_none());
        assert!(bind(Some("0.0.0.0:0".parse().unwrap())).await.is_err());
        let listener = bind(Some("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap()
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let kernel = Arc::new(Kernel::new(KernelConfig::default(), Keyring::new()).unwrap());
        let workers = WorkerPool::new();
        let identity = IdentityKeyPair::generate();
        let peer = PeerId::from_public_key_bytes(identity.public().as_bytes());
        let dispatcher = Arc::new(Dispatcher::new(workers.clone(), kernel.clone(), peer));
        let state = Arc::new(DaemonState::new(
            kernel,
            dispatcher,
            workers,
            PeerStore::new(),
            identity,
            "worker".into(),
        ));
        let snapshot = state.render_metrics();
        let task = tokio::spawn(serve(Some(listener), state));
        for (request, status) in [
            ("GET /metrics", "200 OK"),
            ("POST /metrics", "405 Method Not Allowed"),
            ("GET /", "404 Not Found"),
        ] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(format!("{request} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = String::new();
            tokio::time::timeout(Duration::from_secs(3), stream.read_to_string(&mut response))
                .await
                .unwrap()
                .unwrap();
            let (headers, body) = response.split_once("\r\n\r\n").unwrap();
            assert!(headers.starts_with(&format!("HTTP/1.1 {status}")));
            if status == "200 OK" {
                assert!(headers.contains("text/plain; version=0.0.4"));
                assert_eq!(body, snapshot);
            } else {
                assert!(body.is_empty());
            }
        }
        task.abort();
    }
}
