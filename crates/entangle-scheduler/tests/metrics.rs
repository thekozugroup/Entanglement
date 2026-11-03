//! The scheduler's metrics: dispatch verdicts, oversized replica outputs,
//! reputation tier counts and the in-flight / worker gauges.

use std::sync::Arc;

use entangle_observability::catalog::names;
use entangle_observability::Registry;
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::integrity::{ReplicaBytes, ReplicaResult};
use entangle_scheduler::{
    DispatchError, Dispatcher, PolicyEnvelope, ReputationReason, WorkerInfo, WorkerPool,
};
use entangle_signing::Keyring;
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::task::{IntegrityPolicy, OneShotTask, PolicyKind};

fn peer(b: u8) -> PeerId {
    PeerId::from_public_key_bytes(&[b; 32])
}

fn dispatcher(registry: &Registry, pool: WorkerPool) -> Dispatcher {
    let kernel = Arc::new(Kernel::new(KernelConfig::default(), Keyring::new()).unwrap());
    Dispatcher::new(pool, kernel, peer(1)).with_metrics(registry.clone())
}

fn task(policy: IntegrityPolicy) -> OneShotTask {
    let plugin: PluginId = "0123456789abcdef0123456789abcdef/absent@1.0.0"
        .parse()
        .unwrap();
    let mut t = OneShotTask::with_defaults(plugin, b"x".to_vec());
    t.integrity = policy;
    t
}

#[tokio::test]
async fn dispatch_verdicts_are_counted_by_policy_kind_and_outcome() {
    let registry = Registry::new();
    let d = dispatcher(&registry, WorkerPool::new());

    // Nothing is loaded, so a local dispatch fails: a "failed" verdict, not a
    // rejection by the integrity pipeline.
    d.dispatch_one_shot(task(IntegrityPolicy::None))
        .await
        .unwrap_err();
    // A refused policy (Attested is unsupported) is "rejected".
    let err = d
        .dispatch_one_shot(task(IntegrityPolicy::Attested {
            tee: "sgx".into(),
        }))
        .await
        .unwrap_err();
    assert!(matches!(err, DispatchError::Integrity(_)), "{err}");

    let v = |policy, outcome| {
        registry.value(
            names::INTEGRITY_VERDICTS,
            &[("policy", policy), ("outcome", outcome)],
        )
    };
    assert_eq!(v("none", "failed"), Some(1.0));
    assert_eq!(v("attested", "rejected"), Some(1.0));
    assert_eq!(d.inflight(), 0);
    let _ = registry.render(); // collectors publish the gauges at scrape time
    assert_eq!(
        registry.value(names::SCHEDULER_INFLIGHT, &[]),
        Some(0.0),
        "in-flight returns to zero after every dispatch"
    );
}

#[tokio::test]
async fn oversized_outputs_and_reputation_tiers_are_exposed() {
    let registry = Registry::new();
    let pool = WorkerPool::new();
    pool.upsert(WorkerInfo {
        peer_id: peer(7),
        display_name: "w".into(),
        cpu_cores: 4.0,
        memory_bytes: 1 << 30,
        gpu: None,
        npu: None,
        network_bandwidth_bps: 1,
        rtt_ms: 1,
        load: 0.0,
        cost: 1.0,
    });
    let d = dispatcher(&registry, pool);

    // INV-INT-2: a replica larger than the task's max_output_bytes.
    let mut t = task(IntegrityPolicy::None);
    t.max_output_bytes = 4;
    let envelope = PolicyEnvelope::seal(&t.integrity).unwrap();
    let replica = ReplicaResult {
        peer: peer(7),
        remote: true,
        outcome: Ok(ReplicaBytes {
            bytes: vec![0; 64],
            observed_policy_hash: envelope.hash(),
        }),
    };
    let err = d
        .verifier()
        .accept(&t, &envelope, vec![replica])
        .await
        .unwrap_err();
    assert!(matches!(err, DispatchError::OutputSizeExceeded(_)), "{err}");
    assert_eq!(registry.value(names::OUTPUT_SIZE_EXCEEDED, &[]), Some(1.0));

    // The oversized remote replica cost the peer reputation, which the
    // scrape-time collector reports as tier counts (never per peer).
    for _ in 0..8 {
        d.verifier().reputation().penalize(
            &peer(9),
            PolicyKind::Deterministic,
            ReputationReason::DisagreedWithQuorum,
        );
    }
    let text = registry.render();
    assert!(
        text.contains("entangle_reputation_peers{policy=\"none\",tier=\"good\"} 1")
            || text.contains("entangle_reputation_peers{policy=\"none\",tier=\"probation\"} 1")
            || text.contains("entangle_reputation_peers{policy=\"none\",tier=\"excluded\"} 1"),
        "{text}"
    );
    assert!(
        text.contains("entangle_reputation_peers{policy=\"deterministic\",tier=\"excluded\"} 1"),
        "{text}"
    );
    assert!(text.contains("entangle_scheduler_workers 1"), "{text}");
    assert!(!text.contains(&peer(9).to_hex()), "no peer id in any label");
}
