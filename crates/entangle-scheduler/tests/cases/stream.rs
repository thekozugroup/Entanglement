//! §16.5 positive and negative contracts over real, mutually authenticated QUIC.
use super::*;
use entangle_scheduler::stream::{StreamError, StreamEvent, StreamExecutor, StreamOutput};
use entangle_types::task::{ChannelSpec, PartialResultPolicy, StreamingTask};

fn streaming(plugin: PluginId) -> StreamingTask {
    StreamingTask {
        id: uuid::Uuid::new_v4(),
        plugin,
        resources: ResourceSpec::default(),
        integrity: IntegrityPolicy::None,
        timeout_ms: 5000,
        partial_result: PartialResultPolicy::KeepSigned,
        channel: ChannelSpec {
            max_chunk_bytes: 8,
            max_total_bytes: 16,
            credit_window: 1,
            ..Default::default()
        },
    }
}
struct Producer;
#[async_trait::async_trait]
impl StreamExecutor for Producer {
    async fn produce(
        &self,
        _task: StreamingTask,
        input: Vec<u8>,
        output: StreamOutput,
    ) -> Result<(), String> {
        if input == b"slow" {
            drop(output);
            tokio::time::sleep(Duration::from_secs(20)).await;
            return Ok(());
        }
        output.send_chunk(input).await?;
        output.send_chunk(b"second".to_vec()).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credit_exhaustion_stalls_at_timeout_and_verified_credit_resumes() {
    deadline("signed credit stream", async {
        let publisher = IdentityKeyPair::generate();
        let a = Node::start(&publisher).await;
        let mut b = Node::start(&publisher).await;
        let plugin = b.load_hello_pong(&publisher).await;
        b.serve_with(
            RemoteTaskServer::new(
                b.kernel.clone(),
                Arc::new([a.peer_id].into_iter().collect::<StaticAllowlist>()),
                b.peer_id,
            )
            .with_max_timeout_ms(1000)
            .with_stream_executor(b.identity.clone(), Arc::new(Producer)),
        );
        let d = dispatcher_for(&a, &b);
        let task = streaming(plugin);
        let (peer, mut stream) = d.dispatch_stream(task.clone(), b"first").await.unwrap();
        assert_eq!(peer, b.peer_id);
        let StreamEvent::Chunk(first) = stream.next().await.unwrap() else {
            panic!("expected first chunk")
        };
        assert_eq!(first.bytes, b"first");
        first.verify(&b.identity.public(), task.id, 0).unwrap();
        let before = std::time::Instant::now();
        assert!(matches!(
            stream.next().await.unwrap(),
            StreamEvent::Stalled {
                chunks: 1,
                bytes: 5
            }
        ));
        assert!(
            (Duration::from_millis(4500)..=Duration::from_millis(5500)).contains(&before.elapsed())
        );
        assert!(b
            .kernel
            .metrics()
            .render()
            .contains("entangle_scheduler_streams_stalled_total"));
        stream.credit(1).await.unwrap();
        let StreamEvent::Chunk(second) = stream.next().await.unwrap() else {
            panic!("expected second chunk")
        };
        assert_eq!(second.bytes, b"second");
        second.verify(&b.identity.public(), task.id, 1).unwrap();
        assert!(matches!(
            stream.next().await.unwrap(),
            StreamEvent::Finished
        ));

        // The same worker must cancel backend/compute work that does not yield.
        let (_, mut slow) = d
            .dispatch_stream(streaming(task.plugin), b"slow")
            .await
            .unwrap();
        let err = tokio::time::timeout(Duration::from_secs(4), slow.next())
            .await
            .expect("lower configured server cap must terminate execution")
            .unwrap_err();
        assert!(
            err.to_string().contains("worker active-time limit"),
            "{err}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_missed_pings_close_channel() {
    deadline("unresponsive executor", async {
        let publisher = IdentityKeyPair::generate();
        let a = Node::start(&publisher).await;
        let b = Node::start(&publisher).await;
        let worker = b.transport.clone();
        let dropped = tokio::spawn(async move {
            let conn = worker.accept().await.unwrap().unwrap();
            let req = conn.accept_request().await.unwrap().unwrap();
            let (mut wr, mut rd) = req.into_stream().split();
            wr.send(&[1]).await.unwrap();
            let mut count = 0;
            while let Ok(frame) = rd.receive(64).await {
                assert_eq!(frame.len(), 16);
                assert_eq!(frame[0], 4);
                count += 1;
                // Explicitly withhold all three Pong responses.
            }
            count
        });
        let d = dispatcher_for(&a, &b);
        let (_peer, mut stream) = d
            .dispatch_stream(
                streaming(
                    "00112233445566778899aabbccddeeff/stream-lines@0.1.0"
                        .parse()
                        .unwrap(),
                ),
                b"",
            )
            .await
            .unwrap();
        let before = std::time::Instant::now();
        assert!(matches!(stream.next().await, Err(StreamError::PeerLost)));
        assert!((Duration::from_secs(13)..=Duration::from_secs(17)).contains(&before.elapsed()));
        assert_eq!(dropped.await.unwrap(), 3);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_authenticated_worker_signatures_deliver_chunks() {
    deadline("signed chunk identity", async {
        let publisher = IdentityKeyPair::generate();
        let a = Node::start(&publisher).await;
        let b = Node::start(&publisher).await;
        let worker = b.transport.clone();
        let unrelated = IdentityKeyPair::generate();
        let task = streaming(
            "00112233445566778899aabbccddeeff/stream-lines@0.1.0"
                .parse()
                .unwrap(),
        );
        let task_id = task.id;
        tokio::spawn(async move {
            use sha2::{Digest, Sha256};
            let conn = worker.accept().await.unwrap().unwrap();
            let req = conn.accept_request().await.unwrap().unwrap();
            let (mut wr, _rd) = req.into_stream().split();
            wr.send(&[1]).await.unwrap();
            let msg = b"fixture";
            let seq = 0u64;
            let ts = 1000u64;
            let mut signed = b"entangle/stream/chunk/1\0".to_vec();
            signed.extend_from_slice(task_id.as_bytes());
            signed.extend_from_slice(&seq.to_be_bytes());
            signed.extend_from_slice(&ts.to_be_bytes());
            signed.extend_from_slice(&Sha256::digest(msg));
            let signature = unrelated.sign(&signed);
            let mut packet = vec![2];
            packet.extend_from_slice(&seq.to_be_bytes());
            packet.extend_from_slice(&ts.to_be_bytes());
            packet.extend_from_slice(signature.as_bytes());
            packet.extend_from_slice(msg);
            wr.send(&packet).await.unwrap();
            wr.finish().unwrap();
            conn.closed().await;
        });
        let d = dispatcher_for(&a, &b);
        let (_, mut stream) = d.dispatch_stream(task, b"").await.unwrap();
        assert!(matches!(
            stream.next().await,
            Err(StreamError::BadChunkSignature)
        ));
    })
    .await;
}

#[tokio::test]
async fn replicated_stream_integrity_fails_before_route_lookup() {
    let publisher = IdentityKeyPair::generate();
    let a = Node::start(&publisher).await;
    let d = Dispatcher::new(WorkerPool::new(), a.kernel.clone(), a.peer_id);
    let mut task = streaming(
        "00112233445566778899aabbccddeeff/stream-lines@0.1.0"
            .parse()
            .unwrap(),
    );
    for policy in [
        IntegrityPolicy::Deterministic { replicas: 2 },
        IntegrityPolicy::SemanticEquivalent {
            metric: "sim".into(),
            threshold: 0.5,
        },
    ] {
        task.integrity = policy;
        assert!(matches!(
            d.dispatch_stream(task.clone(), b"").await,
            Err(StreamError::InvalidIntegrityForStreaming)
        ));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_wasm_guest_lines_cross_quic_under_credit() {
    deadline("progressive native WIT stream", async {
        let publisher = IdentityKeyPair::generate();
        let a = Node::start(&publisher).await;
        let b = Node::start(&publisher).await;
        let package = tempfile::tempdir().unwrap();
        let manifest = include_str!("../../../../examples/stream-lines/entangle.toml")
            .replace("PUBLISHER_PLACEHOLDER", &publisher.fingerprint_hex());
        let wasm = include_bytes!("../../../entangle-host/tests/fixtures/stream-lines.wasm");
        std::fs::write(package.path().join("entangle.toml"), &manifest).unwrap();
        std::fs::write(package.path().join("plugin.wasm"), wasm).unwrap();
        let bundle = sign_artifact(wasm, manifest.as_bytes(), &publisher);
        std::fs::write(
            package.path().join("plugin.wasm.sig"),
            toml::to_string(&bundle).unwrap(),
        )
        .unwrap();
        let plugin = b.kernel.load_plugin_from_dir(package.path()).await.unwrap();
        assert!(b.kernel.is_stream_plugin(&plugin));
        assert!(!a.kernel.has_plugin(&plugin));
        b.serve_with(
            RemoteTaskServer::new(
                b.kernel.clone(),
                Arc::new([a.peer_id].into_iter().collect::<StaticAllowlist>()),
                b.peer_id,
            )
            .with_max_timeout_ms(1000)
            .with_stream_executor(b.identity.clone(), b.kernel.clone()),
        );
        let d = dispatcher_for(&a, &b);
        let task = streaming(plugin.clone());
        let (_, mut stream) = d
            .dispatch_stream(task.clone(), b"one\ntwo\nthree\n")
            .await
            .unwrap();
        for (n, expected) in [b"one\n".as_slice(), b"two\n", b"three\n"]
            .into_iter()
            .enumerate()
        {
            let StreamEvent::Chunk(c) = stream.next().await.unwrap() else {
                panic!("expected guest yield")
            };
            assert_eq!(c.bytes, expected);
            c.verify(&b.identity.public(), task.id, n as u64).unwrap();
            if n == 0 {
                // An authentic WIT guest remains suspended past the active execution cap.
                tokio::time::sleep(Duration::from_millis(1300)).await;
            }
            if n < 2 {
                stream.credit(1).await.unwrap();
            }
        }
        assert!(matches!(
            stream.next().await.unwrap(),
            StreamEvent::Finished
        ));

        let mut bounded = streaming(plugin);
        bounded.channel.max_total_bytes = 4;
        let (_, mut stream) = d.dispatch_stream(bounded, b"one\ntwo\n").await.unwrap();
        assert!(matches!(
            stream.next().await.unwrap(),
            StreamEvent::Chunk(_)
        ));
        stream.credit(1).await.unwrap_or(());
        assert!(matches!(
            stream.next().await,
            Err(StreamError::TotalBytesExceeded)
        ));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reduced_active_cap_interrupts_compute_wasm_adapted_to_a_stream() {
    deadline("bounded adapted guest", async {
        let publisher = IdentityKeyPair::generate();
        let a = Node::start(&publisher).await;
        let b = Node::start(&publisher).await;
        let package = tempfile::tempdir().unwrap();
        let wasm = include_bytes!("../../../entangle-host/tests/fixtures/stress.wasm");
        let plugin = write_plugin_package(package.path(), &publisher, wasm);
        b.kernel.load_plugin_from_dir(package.path()).await.unwrap();
        b.serve_with(
            RemoteTaskServer::new(
                b.kernel.clone(),
                Arc::new([a.peer_id].into_iter().collect::<StaticAllowlist>()),
                b.peer_id,
            )
            .with_max_timeout_ms(250)
            .with_stream_executor(b.identity.clone(), b.kernel.clone()),
        );
        let d = dispatcher_for(&a, &b);
        let (_, mut stream) = d
            .dispatch_stream(streaming(plugin), b"spin:5000")
            .await
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect(
                "worker must interrupt the guest well before its five-second computation finishes",
            )
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("active-time limit")
                || error.contains("timed out")
                || error.contains("timeout"),
            "{error}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_stream_drains_receipt_when_peer_stops_receiving_credit() {
    deadline("half-closed control channel", async {
        let publisher = IdentityKeyPair::generate();
        let a = Node::start(&publisher).await;
        let b = Node::start(&publisher).await;
        let worker = b.transport.clone();
        tokio::spawn(async move {
            let conn = worker.accept().await.unwrap().unwrap();
            let req = conn.accept_request().await.unwrap().unwrap();
            let (mut wr, rd) = req.into_stream().split();
            wr.send(&[1]).await.unwrap();
            drop(rd);
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut end = [0u8; 17];
            end[0] = 7;
            wr.send(&end).await.unwrap();
            wr.finish().unwrap();
            conn.closed().await;
        });
        let d = dispatcher_for(&a, &b);
        let (_, mut stream) = d
            .dispatch_stream(
                streaming(
                    "00112233445566778899aabbccddeeff/stream-lines@0.1.0"
                        .parse()
                        .unwrap(),
                ),
                b"",
            )
            .await
            .unwrap();
        assert!(matches!(
            stream.next().await.unwrap(),
            StreamEvent::Finished
        ));
    })
    .await;
}
