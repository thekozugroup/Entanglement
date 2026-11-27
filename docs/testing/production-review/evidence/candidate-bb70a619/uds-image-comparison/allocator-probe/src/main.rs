
#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
// ── compute/dispatch types ───────────────────────────────────────────────────

/// Integrity mode for a compute dispatch request.
///
/// Serialised as a tagged union with `kind` discriminant (kebab-case).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ComputeIntegrity {
    /// No integrity checking; accept the first response.
    None,
    /// Run N identical replicas; require byte-for-byte identical outputs.
    Deterministic {
        /// Number of independent execution replicas.
        replicas: u8,
    },
    /// Run three distinct remote replicas and compare each output pair on the submitter.
    SemanticEquivalent {
        /// Fully qualified ID of a signed local comparator package.
        metric: String,
        /// Accept pairwise distances strictly below this value.
        threshold: f32,
        /// Per-replica byte ceiling, enforced before any comparison.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_output_bytes: Option<u64>,
    },
    /// Accept output only from explicitly allow-listed peers (hex peer ids).
    TrustedExecutor {
        /// Hex-encoded peer ids whose outputs are trusted without further verification.
        allowlist: Vec<String>,
    },
}

/// Parameters for the `compute/dispatch` RPC method.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComputeDispatchParams {
    /// Id of the plugin to invoke.
    pub plugin_id: String,
    /// Raw input bytes; serialised as a JSON array of numbers.
    pub input: Vec<u8>,
    /// Maximum wall-clock time for the invocation in milliseconds.
    pub timeout_ms: u64,
    /// Required CPU cores (fractional; 0.0 = no requirement).
    pub cpu_cores: f32,
    /// Required host memory in bytes (0 = no requirement).
    pub memory_bytes: u64,
    /// Whether a GPU is required (simplified for Phase 1).
    pub gpu_required: bool,
    /// Minimum GPU VRAM required in bytes (0 = no requirement).
    pub gpu_vram_min_bytes: u64,
    /// Integrity policy to enforce.
    pub integrity: ComputeIntegrity,
}

/// Result of the `compute/dispatch` RPC method.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComputeDispatchResult {
    /// Hex peer id of the worker that executed the task.
    pub chosen_peer: String,
    /// Placement score assigned to the chosen worker.
    pub score: f32,
    /// Human-readable explanation of the placement decision.
    pub reason: String,
    /// Raw output bytes returned by the plugin.
    pub output: Vec<u8>,
}

#[derive(Deserialize)]
struct Req<'a> {
    jsonrpc: String,
    id: serde_json::Value,
    method: String,
    #[serde(default, borrow)]
    params: Option<&'a RawValue>,
}


#[derive(Deserialize)]
struct LegacyReq {
    jsonrpc: String,
    id: serde_json::Value,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Probe;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(size: usize) {
    PEAK.fetch_max(LIVE.fetch_add(size, Relaxed) + size, Relaxed);
}

unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc(layout);
        if !pointer.is_null() { grow(layout.size()) }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout);
        LIVE.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let pointer = System.realloc(pointer, layout, size);
        if !pointer.is_null() {
            if size >= layout.size() {
                grow(size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - size, Relaxed);
            }
        }
        pointer
    }
}

#[global_allocator]
static ALLOCATOR: Probe = Probe;

fn measure(line: &str, typed: bool) -> usize {
    let before = LIVE.load(Relaxed);
    PEAK.store(before, Relaxed);
    let p: ComputeDispatchParams = if typed {
        let req: Req<'_> = serde_json::from_str(line).unwrap();
        assert_eq!(req.method, "compute/dispatch");
        serde_json::from_str::<ComputeDispatchParams>(req.params.unwrap().get()).unwrap()
    } else {
        let req: LegacyReq = serde_json::from_str(line).unwrap();
        assert_eq!(req.method, "compute/dispatch");
        serde_json::from_value(req.params).unwrap()
    };
    assert_eq!(p.input.len(), 8 * 1024 * 1024);
    assert!(p.input.iter().all(|&e| e == 120));
    PEAK.load(Relaxed) - before
}

fn main() {
    let mut data = String::with_capacity(32*1024*1024 + 512);
    data.push_str(r#"{"jsonrpc":"2.0","method":"compute/dispatch","id":3,"params":{"plugin_id":"fixture","timeout_ms":6000,"memory_bytes":0,"cpu_cores":0,"gpu_required":false,"gpu_vram_min_bytes":0,"integrity":{"kind":"none"},"input":["#);
    for _ in 0..(8*1024*1024 - 1) { data.push_str("120,"); }
    data.push_str("120]}}");
    let old = measure(&data, false);
    let new = measure(&data, true);
    println!("request_json={} input={} value_size={} legacy_peak_above_input={} typed_peak_above_input={}",
        data.len(), 8*1024*1024, std::mem::size_of::<serde_json::Value>(), old, new);
    assert!(old >= 8 * 1024 * 1024 * std::mem::size_of::<serde_json::Value>());
    assert!(new < 9 * 1024 * 1024);
}
