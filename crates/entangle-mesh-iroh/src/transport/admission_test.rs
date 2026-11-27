//! One paused loopback client and a normally admitted request use a tiny admission budget.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn idle_and_incomplete_openings_expire_without_limiting_an_admitted_request() {
    timeout(Duration::from_secs(30), exercise())
        .await
        .expect("loopback admission test timed out");
}

async fn exercise() {
    let opening_time = Duration::from_secs(1);
    let server = Arc::new(
        MeshIroh::start(
            MeshIrohConfig {
                request_timeout: opening_time,
                ..MeshIrohConfig::loopback()
            },
            &IdentityKeyPair::generate(),
        )
        .await
        .unwrap(),
    );
    let client = MeshIroh::start(MeshIrohConfig::loopback(), &IdentityKeyPair::generate())
        .await
        .unwrap();
    let address = crate::parse_node_addr(&server.node_addrs()[0]).unwrap();
    let peer = client.local_peer_id();
    let live = Arc::new(Semaphore::new(1));
    let reads = Arc::new(Semaphore::new(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let listener = tokio::spawn(serve_bounded(
        server.clone(),
        move |req| {
            let count = observed.clone();
            async move {
                assert_eq!(req.peer_id(), peer);
                assert_eq!(req.payload(), b"ordinary job");
                count.fetch_add(1, Ordering::Relaxed);
                // The opening deadline ends when the complete request enters its handler.
                tokio::time::sleep(opening_time + Duration::from_millis(100)).await;
                req.respond(b"job complete").await
            }
        },
        live.clone(),
        reads.clone(),
    ));
    let idle = client.connect(&address).await.unwrap();
    while live.available_permits() != 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(reads.available_permits(), 1);
    idle.closed().await;
    let paused = client.connect(&address).await.unwrap();
    let (mut sender, _receiver) = paused.inner.open_bi().await.unwrap();
    // Ordinary pause part way through the four-byte frame header.
    sender.write_all(&[0, 0]).await.unwrap();
    while reads.available_permits() != 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(live.available_permits(), 0);
    paused.closed().await;
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        client.request(&address, b"ordinary job").await.unwrap(),
        b"job complete"
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    client.shutdown().await;
    server.shutdown().await;
    listener.await.unwrap();
    assert_eq!(live.available_permits(), 1);
    assert_eq!(reads.available_permits(), 1);
}
