//! The real WIT guest yields rows as the host acknowledges each write.
use entangle_runtime::{Kernel, KernelConfig};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::plugin_id::PluginId;

async fn loaded() -> (Kernel, PluginId) {
    loaded_at_tier(1).await
}

async fn loaded_at_tier(tier: u8) -> (Kernel, PluginId) {
    let temp = tempfile::tempdir().unwrap();
    let key = IdentityKeyPair::generate();
    let wasm = include_bytes!("../../entangle-host/tests/fixtures/stream-lines.wasm");
    let manifest = include_str!("../../../examples/stream-lines/entangle.toml")
        .replace("PUBLISHER_PLACEHOLDER", &key.fingerprint_hex())
        .replace("tier = 1", &format!("tier = {tier}"));
    let sig = sign_artifact(wasm, manifest.as_bytes(), &key);
    std::fs::write(temp.path().join("entangle.toml"), manifest).unwrap();
    std::fs::write(temp.path().join("plugin.wasm"), wasm).unwrap();
    std::fs::write(
        temp.path().join("plugin.wasm.sig"),
        toml::to_string(&sig).unwrap(),
    )
    .unwrap();
    let mut ring = Keyring::new();
    ring.add(TrustEntry {
        fingerprint: key.fingerprint(),
        public_key: *key.public().as_bytes(),
        added_at: 0,
        publisher_name: "fixture".into(),
        note: String::new(),
    });
    let kernel = Kernel::new(KernelConfig::default(), ring).unwrap();
    let id = kernel.load_plugin_from_dir(temp.path()).await.unwrap();
    assert!(kernel.is_stream_plugin(&id));
    (kernel, id)
}

#[tokio::test]
async fn wasm_emits_progressive_rows_and_waits_for_each_acknowledgement() {
    let (kernel, id) = loaded().await;
    let (tx, mut rx) = tokio::sync::mpsc::channel(3);
    let worker = tokio::spawn(async move {
        kernel
            .invoke_stream(&id, b"one\ntwo\n", 5000, 8, 8, move |bytes| {
                let tx = tx.clone();
                async move {
                    let (ack, wait) = tokio::sync::oneshot::channel();
                    tx.send((bytes, ack))
                        .await
                        .map_err(|_| "closed".to_owned())?;
                    wait.await.map_err(|_| "closed".to_owned())
                }
            })
            .await
    });
    let (first, ack) = rx.recv().await.unwrap();
    assert_eq!(first, b"one\n");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .is_err()
    );
    ack.send(()).unwrap();
    let (second, ack) = rx.recv().await.unwrap();
    assert_eq!(second, b"two\n");
    ack.send(()).unwrap();
    worker.await.unwrap().unwrap();
}

#[tokio::test]
async fn negotiated_limits_and_closed_receiver_fail_the_wasm_guest() {
    let (kernel, id) = loaded().await;
    for (chunk, total) in [(2, 100), (100, 5)] {
        assert!(kernel
            .invoke_stream(&id, b"one\ntwo\n", 1000, chunk, total, |_| async { Ok(()) })
            .await
            .is_err());
    }
    assert!(kernel
        .invoke_stream(&id, b"row", 1000, 16, 16, |_| async {
            Err("receiver closed".into())
        })
        .await
        .is_err());
}

#[tokio::test]
async fn withholding_credit_pauses_compute_time_only_until_the_acknowledgement() {
    use std::time::Duration;
    let (kernel, id) = loaded().await;
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = count.clone();
    kernel
        .invoke_stream(&id, b"one\ntwo\n", 150, 8, 8, move |_| {
            let observed = observed.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(225)).await;
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .unwrap();
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn withholding_stream_credit_cannot_stall_unload_or_tier_lowering() {
    use entangle_runtime::RuntimeError;
    use entangle_types::tier::Tier;
    use std::sync::Arc;
    use tokio::{
        sync::Notify,
        time::{timeout, Duration},
    };

    let (kernel, id) = loaded_at_tier(3).await;
    let kernel = Arc::new(kernel);
    let writing = Arc::new(Notify::new());
    let credit = Arc::new(Notify::new());
    let worker = {
        let kernel = kernel.clone();
        let id = id.clone();
        let writing = writing.clone();
        let credit = credit.clone();
        tokio::spawn(async move {
            kernel
                .invoke_stream(&id, b"row", 500, 16, 16, move |_| {
                    writing.notify_one();
                    let credit = credit.clone();
                    async move {
                        credit.notified().await;
                        Ok(())
                    }
                })
                .await
        })
    };
    timeout(Duration::from_secs(10), writing.notified())
        .await
        .unwrap();
    let before = kernel.broker().audit_log().len();
    assert!(matches!(
        timeout(Duration::from_secs(10), kernel.unload(&id))
            .await
            .unwrap(),
        Err(RuntimeError::DrainTimeout(_))
    ));
    let change = kernel.reserve_tier_change(Tier::Pure).await.unwrap();
    assert_eq!(change.affected().len(), 1);
    let err = timeout(
        Duration::from_secs(10),
        change.apply(Default::default(), || panic!("persist called before drain")),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(matches!(
        err.downcast_ref::<RuntimeError>(),
        Some(RuntimeError::DrainTimeout(_))
    ));
    assert!(kernel.has_plugin(&id));
    assert_eq!(kernel.broker().policy().max_tier_allowed, Tier::Native);
    assert_eq!(kernel.broker().audit_log().len(), before);
    credit.notify_one();
    timeout(Duration::from_secs(5), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    kernel
        .reserve_tier_change(Tier::Pure)
        .await
        .unwrap()
        .apply(Default::default(), || Ok(()))
        .await
        .unwrap();
    assert!(!kernel.has_plugin(&id));
}
