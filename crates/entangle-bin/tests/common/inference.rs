use super::{plugin, request, Node};
use entangle_rpc::{
    Client, RpcError, StreamOpenParams, StreamRead, TierPolicyAction, TierPolicyParams,
};
use entangle_scheduler::stream::SignedChunk;
use entangle_signing::IdentityKeyPair;
use entangle_types::task::{
    ChannelSpec, IntegrityPolicy, PartialResultPolicy, StreamingTask, TaskId,
};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::UdpSocket,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Notify,
    time::{sleep, timeout},
};

#[derive(Default)]
struct Backend {
    ready: AtomicBool,
    posts: AtomicUsize,
    finish: Notify,
}

impl Backend {
    async fn serve(&self, socket: TcpStream, chat: bool) {
        let mut socket = BufReader::new(socket);
        let mut request = String::new();
        socket.read_line(&mut request).await.unwrap();
        let mut length = 0;
        loop {
            let mut line = String::new();
            if socket.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" {
                break;
            }
            if let Some(value) = line.strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
        }
        let mut body = vec![0; length];
        socket.read_exact(&mut body).await.unwrap();
        let tcp = socket.get_mut();
        if request.starts_with("GET /v1/models ") {
            let data = if self.ready.load(Ordering::SeqCst) {
                r#"{"data":[{"id":"test-model"}]}"#
            } else {
                r#"{"data":[{"id":"another-model"}]}"#
            };
            tcp.write_all(
                format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{data}", data.len()).as_bytes(),
            ).await.unwrap();
            return;
        }
        self.posts.fetch_add(1, Ordering::SeqCst);
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["model"], "test-model");
        assert_eq!(body["max_tokens"], 12);
        assert_eq!(body["temperature"], 0.5);
        assert_eq!(body["stream"], true);
        if chat {
            assert!(request.starts_with("POST /v1/chat/completions "));
            assert_eq!(
                body["messages"],
                json!([{"role":"user","content":"test question"}])
            );
        } else {
            assert!(request.starts_with("POST /v1/completions "));
            assert_eq!(body["prompt"], "test question");
        }
        tcp.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream; charset=utf-8\r\nconnection: close\r\n\r\n: ready\r\n\r\n")
            .await.unwrap();
        let delta = if chat {
            json!({"delta":{"content":"70°"},"index":0})
        } else {
            json!({"text":"70°","index":0})
        };
        let event = format!("data: {}\r\n\r\n", json!({"choices":[delta]}));
        let split = event.find('°').unwrap() + 1;
        tcp.write_all(&event.as_bytes()[..split]).await.unwrap();
        tokio::task::yield_now().await;
        tcp.write_all(&event.as_bytes()[split..]).await.unwrap();
        self.finish.notified().await;
        let delta = if chat {
            json!({"delta":{"content":" F"},"index":0,"finish_reason":"stop"})
        } else {
            json!({"text":" F","index":0,"finish_reason":"stop"})
        };
        let event = format!("data: {}\n\ndata: [DONE]\n\n", json!({"choices":[delta]}));
        tcp.write_all(event.as_bytes()).await.unwrap();
    }
}

#[tokio::test]
async fn configured_inference_streams_incremental_signed_chunks() {
    for chat in [true, false] {
        timeout(Duration::from_secs(35), exercise(chat))
            .await
            .unwrap();
    }
}

async fn exercise(chat: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let backend = Arc::new(Backend::default());
    backend.ready.store(true, Ordering::SeqCst);
    let serve = tokio::spawn({
        let backend = backend.clone();
        async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let backend = backend.clone();
                tokio::spawn(async move { backend.serve(socket, chat).await });
            }
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let worker = Node::new(dir.path().join("worker"));
    let coordinator = Node::new(dir.path().join("coordinator"));
    let publisher = IdentityKeyPair::generate();
    plugin::keyring_for(&publisher)
        .save(&worker.home.join(".entangle/keyring.toml"))
        .unwrap();
    let package = dir.path().join("fallback");
    fs::create_dir(&package).unwrap();
    let fallback = plugin::write_plugin_package(&package, &publisher, &plugin::hello_pong_wasm());
    let port = UdpSocket::bind("127.0.0.1:0").unwrap();
    let worker_addr = port.local_addr().unwrap();
    let transports = &["iroh"];
    worker.configure(&coordinator, worker_addr, None, transports);
    coordinator.configure(
        &worker,
        "127.0.0.1:0".parse().unwrap(),
        Some(worker_addr),
        transports,
    );
    let path = if chat {
        "chat/completions"
    } else {
        "completions"
    };
    writeln!(
        OpenOptions::new()
            .append(true)
            .open(worker.home.join(".entangle/config.toml"))
            .unwrap(),
        "\n[runtime.inference]\nendpoint=\"http://{backend_addr}/v1/{path}\"\nmodel=\"test-model\"",
    )
    .unwrap();
    drop(port);
    let binary = Path::new(env!("CARGO_BIN_EXE_entangled"));
    let executor = worker.start(binary, transports).await;
    assert_eq!(
        executor
            .client
            .plugins_load(&package)
            .await
            .unwrap()
            .plugin_id,
        fallback
    );
    let submitter = coordinator.start(binary, transports).await;
    let plugin_id = format!(
        "{}/openai-inference@0.1.0",
        worker.identity.public().fingerprint_hex()
    );
    let mut input = StreamOpenParams {
        task: StreamingTask {
            id: TaskId::new_v4(),
            plugin: plugin_id.parse().unwrap(),
            channel: ChannelSpec {
                credit_window: 1,
                ..Default::default()
            },
            resources: Default::default(),
            integrity: IntegrityPolicy::TrustedExecutor {
                allowlist: vec![worker.peer_id()],
            },
            timeout_ms: 10_000,
            partial_result: PartialResultPolicy::KeepSigned,
        },
        input: br#"{"prompt":"test question","max_tokens":12,"temperature":0.5}"#.to_vec(),
    };

    let handle = loop {
        match submitter.client.stream_open(&input).await {
            Ok(handle) => break handle,
            Err(RpcError::Rpc { message, .. }) if message.contains("no live workers") => {
                sleep(Duration::from_millis(30)).await
            }
            Err(error) => panic!("inference stream placement failed: {error}"),
        }
    };
    assert_eq!(handle.executor, worker.peer_id());
    for (expected, text) in ["70°", " F"].into_iter().enumerate() {
        let StreamRead::Chunk {
            seq,
            timestamp_ms,
            signature,
            bytes,
        } = next(&submitter.client, &handle.session).await.unwrap()
        else {
            panic!("worker must return a token while the upstream connection is still open")
        };
        assert_eq!(bytes, text.as_bytes());
        let chunk = SignedChunk {
            seq,
            timestamp_ms,
            signature,
            bytes,
        };
        chunk
            .verify(&worker.identity.public(), input.task.id, expected as u64)
            .unwrap();
        if expected == 0 {
            backend.finish.notify_one();
        }
    }
    assert!(matches!(
        next(&submitter.client, &handle.session).await.unwrap(),
        StreamRead::Finished
    ));
    assert!(submitter
        .client
        .compute_dispatch(request(&plugin_id))
        .await
        .unwrap_err()
        .to_string()
        .contains("no live workers"));
    assert_eq!(backend.posts.load(Ordering::SeqCst), 1);

    // Paired transport access alone is insufficient to invoke this adapter.
    input.task.id = TaskId::new_v4();
    let integrity = std::mem::replace(&mut input.task.integrity, IntegrityPolicy::None);
    let handle = submitter.client.stream_open(&input).await.unwrap();
    assert!(next(&submitter.client, &handle.session)
        .await
        .unwrap_err()
        .to_string()
        .contains("requires a TrustedExecutor"));
    input.task.integrity = integrity;

    // A previously advertised worker refuses new generation once the model is absent.
    backend.ready.store(false, Ordering::SeqCst);
    input.task.id = TaskId::new_v4();
    let handle = submitter.client.stream_open(&input).await.unwrap();
    let error = next(&submitter.client, &handle.session).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("configured local inference model is not ready"),
        "{error}"
    );
    assert_eq!(backend.posts.load(Ordering::SeqCst), 1);

    // A genuine live tier decrease wins even if the model recovers.
    backend.ready.store(true, Ordering::SeqCst);
    let proposed = TierPolicyParams {
        target: Some(2),
        action: TierPolicyAction::Review,
        approved: None,
    };
    let review = executor.client.tier_policy(proposed.clone()).await.unwrap();
    executor
        .client
        .tier_policy(TierPolicyParams {
            action: TierPolicyAction::Apply,
            approved: Some(review),
            ..proposed
        })
        .await
        .unwrap();
    input.task.id = TaskId::new_v4();
    match submitter.client.stream_open(&input).await {
        // Placement may still hold the previously advertised capability.
        Ok(handle) => assert!(next(&submitter.client, &handle.session)
            .await
            .unwrap_err()
            .to_string()
            .contains("E0043")),
        Err(error) => assert!(error.to_string().contains("no live workers"), "{error}"),
    }
    assert_eq!(backend.posts.load(Ordering::SeqCst), 1);
    serve.abort();

    // A signed WASI component still streams on the same worker after disabling the provider.
    input.task.id = TaskId::new_v4();
    input.task.plugin = fallback.parse().unwrap();
    input.input = b"fallback".to_vec();
    let handle = submitter.client.stream_open(&input).await.unwrap();
    let StreamRead::Chunk { bytes, .. } = next(&submitter.client, &handle.session).await.unwrap()
    else {
        panic!("signed WASI fallback did not stream")
    };
    assert_eq!(bytes, b"Hello, fallback!");
    assert!(matches!(
        next(&submitter.client, &handle.session).await.unwrap(),
        StreamRead::Finished
    ));
}

async fn next(client: &Client, session: &str) -> Result<StreamRead, RpcError> {
    loop {
        match client.stream_read(session).await? {
            StreamRead::Waiting => continue,
            event => return Ok(event),
        }
    }
}
