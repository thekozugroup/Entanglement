//! IPC hot-path benchmarks: topic glob matching, bus publish, and fan-out.
//!
//! These cover the three costs a busy daemon pays per message:
//!   1. `Topic::matches` — run once per *filtered* subscriber per envelope,
//!      so it is the most-executed function on the bus.
//!   2. `Bus::publish` — envelope construction plus the broadcast send.
//!   3. fan-out — publish plus one `recv` per subscriber (tokio's broadcast
//!      channel stores one copy and clones per receiver, so the payload clone
//!      cost lands on the receive side).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use entangle_ipc::{Bus, Envelope, Topic};
use std::hint::black_box;

// ---------------------------------------------------------------------------
// Topic glob matching
// ---------------------------------------------------------------------------

fn bench_topic_matches(c: &mut Criterion) {
    // Representative of the topics actually published by the runtime
    // (`runtime.plugin.lifecycle`, `broker.audit`, …).
    let deep = Topic::new("runtime.plugin.lifecycle").expect("valid topic");
    let shallow = Topic::new("broker.audit").expect("valid topic");

    let cases: &[(&str, &Topic, &str)] = &[
        // literal hit — every segment compared
        ("literal_hit", &deep, "runtime.plugin.lifecycle"),
        // single-segment wildcard
        ("wildcard_hit", &deep, "runtime.*.lifecycle"),
        // trailing ** prefix match
        ("doublestar_hit", &deep, "runtime.**"),
        // whole-pattern ** (early out)
        ("match_all", &deep, "**"),
        // miss on segment count — the common case for a subscriber that
        // filters a topic it does not care about
        ("miss_arity", &deep, "broker.*"),
        // miss on a literal segment, same arity
        ("miss_literal", &shallow, "policy.audit"),
    ];

    let mut group = c.benchmark_group("ipc");
    for (name, topic, pattern) in cases {
        group.bench_function(BenchmarkId::new("topic_matches", name), |b| {
            b.iter(|| black_box(topic.matches(black_box(pattern))));
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Publish
// ---------------------------------------------------------------------------

/// A payload size representative of a small plugin message.
fn payload() -> Vec<u8> {
    vec![0xABu8; 256]
}

fn bench_publish(c: &mut Criterion) {
    let topic = Topic::new("runtime.plugin.lifecycle").expect("valid topic");
    let mut group = c.benchmark_group("ipc");

    // No subscribers: measures envelope construction + the failed send.
    // This is the path the kernel takes for lifecycle events when nothing
    // has subscribed, so it is worth knowing in isolation.
    group.bench_function(BenchmarkId::new("publish", "no_subscribers"), |b| {
        let bus: Bus<Vec<u8>> = Bus::new(1024);
        let p = payload();
        b.iter(|| {
            let env = Envelope::new(topic.clone(), p.clone());
            black_box(bus.publish(env).is_err())
        });
    });

    // One subscriber, drained every iteration.
    group.bench_function(BenchmarkId::new("publish", "1_subscriber"), |b| {
        let bus: Bus<Vec<u8>> = Bus::new(1024);
        let mut sub = bus.subscribe();
        let p = payload();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        b.iter(|| {
            bus.publish(Envelope::new(topic.clone(), p.clone()))
                .expect("publish");
            rt.block_on(async { black_box(sub.recv().await.expect("recv")) })
        });
    });

    group.finish();
}

/// Where does `publish` actually spend its time?
///
/// `Envelope::new` mints a v4 UUID and reads the wall clock; `Envelope::clone`
/// does neither (it copies the already-minted id). Benchmarking both against
/// the same payload attributes the publish cost between envelope *identity*
/// and everything else, which is what tells you whether tuning the bus itself
/// could pay off at all.
fn bench_envelope(c: &mut Criterion) {
    let topic = Topic::new("runtime.plugin.lifecycle").expect("valid topic");
    let p = payload();
    let template = Envelope::new(topic.clone(), p.clone());

    let mut group = c.benchmark_group("ipc");
    group.bench_function(BenchmarkId::new("envelope", "new"), |b| {
        b.iter(|| black_box(Envelope::new(topic.clone(), p.clone())));
    });
    group.bench_function(BenchmarkId::new("envelope", "clone"), |b| {
        b.iter(|| black_box(template.clone()));
    });
    group.finish();
}

fn bench_fanout(c: &mut Criterion) {
    let topic = Topic::new("runtime.plugin.lifecycle").expect("valid topic");
    let mut group = c.benchmark_group("ipc");

    for n in [4usize, 16] {
        group.bench_function(BenchmarkId::new("fanout", n), |b| {
            let bus: Bus<Vec<u8>> = Bus::new(1024);
            let mut subs: Vec<_> = (0..n).map(|_| bus.subscribe()).collect();
            let p = payload();
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime");
            b.iter(|| {
                bus.publish(Envelope::new(topic.clone(), p.clone()))
                    .expect("publish");
                rt.block_on(async {
                    for s in subs.iter_mut() {
                        black_box(s.recv().await.expect("recv"));
                    }
                })
            });
        });
    }

    group.finish();
}

/// Filtered fan-out: every subscriber runs `Topic::matches` against every
/// envelope, and most envelopes are rejected. This is the shape of a real
/// daemon where several components each watch one topic prefix.
fn bench_filtered_recv(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc");
    group.bench_function(BenchmarkId::new("filtered_recv", "1_of_8"), |b| {
        let bus: Bus<Vec<u8>> = Bus::new(1024);
        let mut sub = bus.subscribe_topic("runtime.plugin.*");
        let wanted = Topic::new("runtime.plugin.lifecycle").expect("valid topic");
        let noise = Topic::new("broker.audit").expect("valid topic");
        let p = payload();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        b.iter(|| {
            // 7 envelopes the filter rejects, then 1 it accepts.
            for _ in 0..7 {
                bus.publish(Envelope::new(noise.clone(), p.clone()))
                    .expect("publish");
            }
            bus.publish(Envelope::new(wanted.clone(), p.clone()))
                .expect("publish");
            rt.block_on(async { black_box(sub.recv().await.expect("recv")) })
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_topic_matches,
    bench_publish,
    bench_envelope,
    bench_fanout,
    bench_filtered_recv
);
criterion_main!(benches);
