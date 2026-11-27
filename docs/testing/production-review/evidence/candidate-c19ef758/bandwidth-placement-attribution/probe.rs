//! Controlled component replay with the frozen worker pool and scoring modules.
#![allow(dead_code)]
mod placement;
mod worker;

use entangle_types::{peer_id::PeerId, plugin_id::PluginId, resource::ResourceSpec};
use std::{collections::HashSet, time::Duration};
use worker::{WorkerCapabilities, WorkerInfo, WorkerPool};

const BYTES: usize = 786_515;
const FAST_BPS: u64 = 52_689_170;
const SLOW_BPS: u64 = 3_178_372;

fn main() {
    let fast = PeerId::from_hex("302f7252cdfcb0350dd5ab28abf43516").unwrap();
    let slow = PeerId::from_hex("7d95a82c2494003d04b316f8faf60b15").unwrap();
    let plugin: PluginId = "aabbccddeeff00112233445566778899/fixture@1.0.0".parse().unwrap();
    let spec = ResourceSpec {cpu_cores: 0.01, ..ResourceSpec::default()};
    let ttl = Duration::from_secs(60);
    for (fast_rtt, expected) in [(57, fast), (131, slow)] {
        let pool = WorkerPool::new();
        for (id, rtt_ms, bps) in [(fast, fast_rtt, FAST_BPS), (slow, 57, SLOW_BPS)] {
            let info = WorkerInfo {peer_id: id, display_name: id.to_string(), cpu_cores: 4.0, memory_bytes: 1 << 30, gpu: None, npu: None, network_bandwidth_bps: 0, rtt_ms, load: 0.0, cost: 1.0};
            assert!(pool.upsert_authenticated(WorkerCapabilities {worker: info, plugins: HashSet::from([plugin.clone()]), streaming_plugins: HashSet::new()}));
            let (_, reservation) = pool.choose(ttl, &spec, &plugin, 0, None, |peer| *peer == id).unwrap();
            pool.record_upload(&id, &reservation, bps);
        }
        let scores = [fast, slow].map(|id| pool.choose(ttl, &spec, &plugin, BYTES, None, |peer| *peer == id).unwrap().0.score);
        let (winner, _) = pool.choose(ttl, &spec, &plugin, BYTES, None, |peer| [fast, slow].contains(peer)).unwrap();
        assert_eq!(winner.peer_id, expected);
        println!("fast_rtt_ms={fast_rtt} slow_rtt_ms=57 fast_score={:.8} slow_score={:.8} expected={expected} chosen={} reason={}",scores[0],scores[1],winner.peer_id,winner.reason);
    }
}
