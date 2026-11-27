use super::*;

fn metric_package(publisher: &IdentityKeyPair) -> (PluginId, tempfile::TempDir) {
    let path = tempfile::tempdir().unwrap();
    let metric_id: PluginId = format!("{}/metric@1.0.0", publisher.fingerprint_hex())
        .parse()
        .unwrap();
    let manifest = format!("[plugin]\nid='{metric_id}'\nversion='1.0.0'\ntier=2\nruntime='wasm'\n[build]\nwit_world='entangle:integrity/comparator@0.1.0'\ntarget='wasm32-wasip2'\n");
    let wasm = wat::parse_str(include_str!(
        "../../../entangle-host/tests/fixtures/byte-distance.wat"
    ))
    .unwrap();
    let sig = sign_artifact(&wasm, manifest.as_bytes(), publisher);
    std::fs::write(path.path().join("entangle.toml"), &manifest).unwrap();
    std::fs::write(path.path().join("plugin.wasm"), &wasm).unwrap();
    std::fs::write(
        path.path().join("plugin.wasm.sig"),
        toml::to_string(&sig).unwrap(),
    )
    .unwrap();
    (metric_id, path)
}

/// Real comparator instances and real signed tasks on three independent QUIC workers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn atc_int_1_2_3_5_submitter_only_signed_metric_and_output_guard() {
    use entangle_runtime::RuntimeError;
    use entangle_scheduler::wire::{encode_response, RemoteTaskResponse};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tracing::instrument::WithSubscriber;
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let mut workers = vec![
        Node::start(&publisher).await,
        Node::start(&publisher).await,
        Node::start(&publisher).await,
    ];
    let (metric_id, path) = metric_package(&publisher);
    let pool = WorkerPool::new();
    let directory = Arc::new(PeerDirectory::new());
    let oversized = Arc::new(AtomicBool::new(false));
    let legacy = Arc::new(AtomicBool::new(false));
    let mut worker_metrics = vec![];
    let job_package = tempfile::tempdir().unwrap();
    let job = write_plugin_package(
        job_package.path(),
        &publisher,
        include_bytes!("../../../entangle-host/tests/fixtures/stress.wasm"),
    );
    let receipts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let first = workers[0].peer_id;
    for node in &mut workers {
        node.kernel
            .load_plugin_from_dir(job_package.path())
            .await
            .unwrap();
        node.kernel.load_plugin_from_dir(path.path()).await.unwrap();
        worker_metrics.push(node.kernel.prepare_metric(&metric_id).unwrap());
        pool.upsert(worker_for(node.peer_id));
        directory.insert(node.address());
        let server = Arc::new(RemoteTaskServer::new(
            node.kernel.clone(),
            Arc::new(StaticAllowlist::new().allow(submitter.peer_id)),
            node.peer_id,
        ));
        let oversize = oversized.clone();
        let legacy_peer = legacy.clone();
        let worker = node.peer_id;
        let receipts = receipts.clone();
        tokio::spawn(entangle_mesh_iroh::serve(
            node.transport.clone(),
            move |peer, frame| {
                let server = server.clone();
                let oversize = oversize.clone();
                let legacy_peer = legacy_peer.clone();
                let receipts = receipts.clone();
                async move {
                    if worker == first
                        && legacy_peer.load(Ordering::SeqCst)
                        && frame == b"\0entangle/signed-semantic/1?"
                    {
                        return encode_response(&RemoteTaskResponse::err(
                            RemoteErrorCode::UnsupportedVersion,
                            "v1 only",
                        ))
                        .unwrap();
                    }
                    let signed = frame.starts_with(b"\0entangle/signed-semantic/1!");
                    let raw = server.handle(peer, frame).await;
                    if signed {
                        if let RemoteOutcome::Ok { output } =
                            decode_response(&raw, 8192).unwrap().outcome
                        {
                            receipts
                                .lock()
                                .unwrap()
                                .push((worker, output[..48].to_vec()));
                        }
                    }
                    // Inject a recorded bad result after the authorized worker completes a real job.
                    if worker == first && oversize.load(Ordering::SeqCst) {
                        if let RemoteOutcome::Ok { mut output } =
                            decode_response(&raw, 8192).unwrap().outcome
                        {
                            if output.len() >= 48 {
                                output.resize(48 + 2048, b'x');
                                return encode_response(&RemoteTaskResponse::ok(output)).unwrap();
                            }
                        }
                    }
                    raw
                }
            },
        ));
    }
    let client = RemoteDispatch::new(submitter.transport.clone(), directory)
        .with_signer(submitter.identity.clone());
    let dispatcher = Dispatcher::new(pool.clone(), submitter.kernel.clone(), submitter.peer_id)
        .with_remote(Arc::new(client));
    let mut task = task_for(job.clone(), b"spin:800");
    task.max_output_bytes = 1024;
    task.integrity = IntegrityPolicy::SemanticEquivalent {
        metric: metric_id.to_string(),
        threshold: 0.5,
    };
    // An otherwise correct signed metric whose publisher is absent from *this*
    // submitter's keyring is rejected both at load and scheduler submission.
    let ring = submitter.kernel.keyring();
    let trusted = ring.write().remove(&publisher.fingerprint()).unwrap();
    assert!(matches!(
        submitter.kernel.load_plugin_from_dir(path.path()).await,
        Err(RuntimeError::Signing(_))
    ));
    assert!(matches!(
        dispatcher.dispatch_one_shot(task.clone()).await,
        Err(DispatchError::Runtime(RuntimeError::MetricNotInKeyring(_)))
    ));
    ring.write().add(trusted);
    submitter
        .kernel
        .load_plugin_from_dir(path.path())
        .await
        .unwrap();
    let metric = submitter.kernel.prepare_metric(&metric_id).unwrap();
    assert_eq!(metric.instantiations(), 0);
    // Independently construct the canonical policy fields from the submitted
    // metric and threshold, without consulting the scheduler or worker receipt.
    let canonical = postcard::to_allocvec(&(
        metric_id.to_string(),
        metric.cid,
        metric.publisher,
        0.5_f32.to_bits(),
        3_u8,
        2_u8,
    ))
    .unwrap();
    let expected_hash: [u8; 32] = Sha256::digest(canonical).into();
    let mut events = workers[0].kernel.bus().subscribe();
    let submission = tokio::spawn({
        let dispatcher = dispatcher.clone();
        let task = task.clone();
        async move { dispatcher.dispatch_one_shot(task).await }
    });
    deadline("running replica", async {
        loop {
            let event = events.recv().await.unwrap();
            if event.payload.plugin == job && event.payload.phase == LifecyclePhase::Activated {
                break;
            }
        }
    })
    .await;
    assert!(
        !submission.is_finished(),
        "the control must arrive while replicas are running"
    );
    let mut mutation = b"\0entangle/signed-semantic/1/mutate".to_vec();
    mutation.extend_from_slice(task.id.as_bytes());
    mutation.extend_from_slice(&0.75_f32.to_le_bytes());
    let rejected = deadline(
        "authenticated policy mutation",
        submitter
            .transport
            .request(&workers[0].address(), &mutation),
    )
    .await
    .unwrap();
    assert!(matches!(
        decode_response(&rejected, 0).unwrap().outcome,
        RemoteOutcome::Err {
            code: RemoteErrorCode::PolicyMutation,
            ..
        }
    ));
    let result = deadline("semantic replicas", submission)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.output, b"spun");
    {
        let receipts = receipts.lock().unwrap();
        assert_eq!(receipts.len(), 3);
        assert_eq!(
            receipts
                .iter()
                .map(|(peer, _)| peer)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3
        );
        assert!(receipts
            .iter()
            .all(|(_, r)| r[..16] == task.id.as_bytes()[..] && r[16..48] == expected_hash));
    }
    assert_eq!(metric.instantiations(), 3);
    assert!(worker_metrics.iter().all(|m| m.instantiations() == 0));
    let before = pool.semantic_reputation(&first);
    task.input = b"short response".to_vec();
    task.id = uuid::Uuid::new_v4();
    oversized.store(true, Ordering::SeqCst);
    let log = tempfile::NamedTempFile::new().unwrap();
    let writer = log.reopen().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.try_clone().unwrap())
        .finish();
    let error = deadline(
        "oversized replica",
        dispatcher
            .dispatch_one_shot(task.clone())
            .with_subscriber(subscriber),
    )
    .await
    .unwrap_err();
    let records = std::fs::read_to_string(log.path()).unwrap();
    assert!(records
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .any(|entry| {
            let fields = &entry["fields"];
            fields["message"] == "OutputSizeExceededWarning"
                && fields["peer_id"] == first.to_hex()
                && fields["declared"] == 1024
                && fields["actual"] == 2048
        }));
    assert!(matches!(
        error,
        DispatchError::OutputSizeExceeded(
            entangle_types::errors::EntangleError::OutputSizeExceeded {
                declared: 1024,
                actual: 2048,
                ..
            }
        )
    ));
    assert_eq!(metric.instantiations(), 3);
    assert!(pool.semantic_reputation(&first) < before);
    assert!(submitter
        .kernel
        .metrics()
        .render()
        .contains("entangle_semantic_oversized_results_total 1"));
    assert!(worker_metrics.iter().all(|m| m.instantiations() == 0));
    // A legacy worker must fail negotiation before *any* replica executes.
    let executed = receipts.lock().unwrap().len();
    oversized.store(false, Ordering::SeqCst);
    legacy.store(true, Ordering::SeqCst);
    task.id = uuid::Uuid::new_v4();
    assert!(matches!(
        dispatcher.dispatch_one_shot(task).await,
        Err(DispatchError::RemoteRejected {
            code: RemoteErrorCode::UnsupportedVersion,
            ..
        })
    ));
    assert_eq!(receipts.lock().unwrap().len(), executed);
    assert_eq!(metric.instantiations(), 3);
}

/// Admin package listings include all worlds; scheduler inventories describe executable jobs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_inventory_distinguishes_metric_one_shot_and_progressive_worlds() {
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let mut worker = Node::start(&publisher).await;
    let one_shot = worker.load_hello_pong(&publisher).await;
    let (metric, metric_dir) = metric_package(&publisher);
    worker
        .kernel
        .load_plugin_from_dir(metric_dir.path())
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let manifest = include_str!("../../../../examples/stream-lines/entangle.toml")
        .replace("PUBLISHER_PLACEHOLDER", &publisher.fingerprint_hex());
    let bytes = include_bytes!("../../../entangle-host/tests/fixtures/stream-lines.wasm");
    std::fs::write(dir.path().join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.path().join("plugin.wasm"), bytes).unwrap();
    std::fs::write(
        dir.path().join("plugin.wasm.sig"),
        toml::to_string(&sign_artifact(bytes, manifest.as_bytes(), &publisher)).unwrap(),
    )
    .unwrap();
    let stream = worker
        .kernel
        .load_plugin_from_dir(dir.path())
        .await
        .unwrap();
    assert!(worker.kernel.has_compute_plugin(&one_shot));
    assert!(!worker.kernel.has_compute_plugin(&metric));
    assert!(!worker.kernel.has_compute_plugin(&stream));
    assert_eq!(worker.kernel.list_plugins().len(), 3);
    let directory = Arc::new(PeerDirectory::new());
    directory.insert(worker.address());
    let client = RemoteDispatch::new(submitter.transport.clone(), directory);
    let descriptor = worker_for(worker.peer_id);
    worker.serve_with(
        RemoteTaskServer::new(
            worker.kernel.clone(),
            Arc::new(StaticAllowlist::new().allow(submitter.peer_id)),
            worker.peer_id,
        )
        .with_capabilities(descriptor.clone())
        .with_stream_executor(worker.identity.clone(), worker.kernel.clone()),
    );
    let report = deadline("ABI inventory", client.capabilities(worker.peer_id))
        .await
        .unwrap();
    assert_eq!(report.plugins, [one_shot].into());
    assert_eq!(report.streaming_plugins, [stream.clone()].into());
    let dispatcher = Dispatcher::new(WorkerPool::new(), worker.kernel.clone(), worker.peer_id)
        .with_local_worker(descriptor);
    for id in [stream, metric] {
        let task = task_for(id, b"not a one-shot job");
        assert!(matches!(
            dispatcher.dispatch_one_shot(task).await,
            Err(DispatchError::Placement(_))
        ));
    }
}
