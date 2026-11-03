//! Connection-level limits of the MCP gateway: header-read timeout,
//! idle keep-alive timeout, and the cap on concurrent connections.
//!
//! This is its own test binary, with a single test, because it counts the
//! process's open file descriptors: other tests running in parallel in the
//! same process would open sockets and pipes and disturb the count.

use entangle_agent_host::{generate_bearer_token, Gateway, GatewayConfig};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Wait until the server closes `s` (EOF or reset), up to `limit`.
/// Returns how long it took, or `None` if it was still open.
async fn closed_within(s: &mut TcpStream, limit: Duration) -> Option<Duration> {
    let start = Instant::now();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(limit.saturating_sub(start.elapsed()), s.read(&mut buf)).await {
            Err(_) => return None,
            Ok(Ok(0) | Err(_)) => return Some(start.elapsed()),
            // A 408 (or any bytes) before the close is fine; keep reading.
            Ok(Ok(_)) => {}
        }
    }
}

/// One complete keep-alive request; returns once the full response is read.
async fn keep_alive_request(s: &mut TcpStream, token: &str) -> String {
    let req = format!(
        "POST /mcp/nope HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("response timed out")
            .unwrap();
        assert!(n > 0, "connection closed before the response");
        got.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&got).to_string();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let len: usize = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            if body.len() >= len {
                return text;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

async fn connect(addr: SocketAddr) -> TcpStream {
    TcpStream::connect(addr).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_open_and_idle_connections_are_bounded() {
    const CAP: usize = 8;
    let token = generate_bearer_token();
    let gw = Gateway::new(GatewayConfig {
        bearer_token: token.clone(),
        ..GatewayConfig::default()
    })
    .with_header_read_timeout(Duration::from_millis(500))
    .with_max_connections(CAP)
    .start()
    .await
    .unwrap();
    let addr = gw.addr;

    // 1. Headers that never finish: the server hangs up.
    let mut s = connect(addr).await;
    s.write_all(b"POST /mcp/nope HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let t = closed_within(&mut s, Duration::from_secs(3)).await;
    assert!(t.is_some(), "half-open request still open after 3 s");
    drop(s);

    // 2. An idle keep-alive connection is closed too.
    let mut s = connect(addr).await;
    let resp = keep_alive_request(&mut s, &token).await;
    assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
    let t = closed_within(&mut s, Duration::from_secs(3)).await;
    assert!(
        t.is_some(),
        "idle keep-alive connection still open after 3 s"
    );
    drop(s);

    // 3. Many silent connections: the gateway holds at most CAP of them.
    #[cfg(target_os = "linux")]
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let before = open_fds();
        let mut idle = Vec::new();
        for _ in 0..40 {
            idle.push(connect(addr).await);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let grown = open_fds().saturating_sub(before);
        // 40 client sockets plus at most CAP accepted ones (+ slack for
        // runtime internals).
        assert!(
            grown <= 40 + CAP + 4,
            "gateway accepted {} connections beyond the cap of {CAP}",
            grown.saturating_sub(40 + CAP)
        );
        // Legitimate requests are delayed, not refused: once the silent
        // connections time out, a real request is served.
        let mut s = connect(addr).await;
        let resp =
            tokio::time::timeout(Duration::from_secs(15), keep_alive_request(&mut s, &token))
                .await
                .expect("request behind the silent connections was never served");
        assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
        drop(idle);
    }
    gw.shutdown().await;
}
