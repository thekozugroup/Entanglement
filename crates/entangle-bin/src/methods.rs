//! JSON-RPC 2.0 method dispatch for the `entangled` daemon.
//!
//! Supported Phase-1 methods:
//! - `version`         → `{ "entangled": "0.1.0", "runtime": "0.1.0", "types": "0.1.0" }`
//! - `plugins/list`    → `["<plugin_id>", …]`
//! - `plugins/load`    → params `{ "dir": "<path>" }` → plugin id string
//! - `plugins/unload`  → params `{ "id": "<plugin_id>" }` → null
//! - `plugins/invoke`  → params `{ "plugin_id": "<id>", "input": […], "timeout_ms": N }` → `{ "output": […] }`
//! - `compute/dispatch` → params `ComputeDispatchParams` → `ComputeDispatchResult`
//!
//! Iter 9 stub methods (Discovery not yet wired into Kernel — see TODO below):
//! - `mesh/peers`   → `{ "peers": [] }` stub
//! - `mesh/status`  → `{ "local_peer_id": "", … }` stub

use entangle_rpc::methods::{
    method, ComputeDispatchParams, ComputeDispatchResult, ComputeIntegrity, MeshPeersResult,
    MeshStatusResult, PluginsInvokeParams, PluginsInvokeResult,
};
use entangle_runtime::Kernel;
use entangle_scheduler::{Dispatcher, WorkerPool};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ── JSON-RPC envelope types ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct Req {
    #[allow(dead_code)]
    jsonrpc: String,
    id: serde_json::Value,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Serialize)]
struct Resp<T: Serialize> {
    jsonrpc: &'static str,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

// ── error helpers ────────────────────────────────────────────────────────────

fn error_resp(id: serde_json::Value, code: i32, message: impl Into<String>) -> String {
    let resp: Resp<serde_json::Value> = Resp {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcError {
            code,
            message: message.into(),
        }),
    };
    serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"internal serialization error"}}"#.to_owned())
}

fn ok_resp<T: Serialize>(id: serde_json::Value, result: T) -> String {
    let resp = Resp {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    };
    serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"internal serialization error"}}"#.to_owned())
}

// ── dispatch ─────────────────────────────────────────────────────────────────

/// Parse `line` as a JSON-RPC 2.0 request, dispatch to the appropriate handler,
/// and return a serialized JSON-RPC 2.0 response string.
pub async fn dispatch(line: &str, kernel: &Arc<Kernel>) -> String {
    // -32700: Parse error
    let req: Req = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "JSON parse error");
            return error_resp(serde_json::Value::Null, -32700, format!("parse error: {e}"));
        }
    };

    // -32600: Invalid Request (jsonrpc field must be "2.0")
    if req.jsonrpc != "2.0" {
        return error_resp(req.id, -32600, "invalid request: jsonrpc must be \"2.0\"");
    }

    tracing::debug!(method = %req.method, "RPC dispatch");

    match req.method.as_str() {
        m if m == method::VERSION => handle_version(req.id),
        m if m == method::PLUGINS_LIST => handle_plugins_list(req.id, kernel),
        m if m == method::PLUGINS_LOAD => handle_plugins_load(req.id, req.params, kernel).await,
        m if m == method::PLUGINS_UNLOAD => handle_plugins_unload(req.id, req.params, kernel).await,
        m if m == method::PLUGINS_INVOKE => handle_plugins_invoke(req.id, req.params, kernel).await,
        m if m == method::MESH_PEERS => handle_mesh_peers(req.id),
        m if m == method::MESH_STATUS => handle_mesh_status(req.id),
        m if m == method::COMPUTE_DISPATCH => {
            handle_compute_dispatch(req.id, req.params, kernel).await
        }
        _ => error_resp(req.id, -32601, format!("method not found: {}", req.method)),
    }
}

// ── method handlers ───────────────────────────────────────────────────────────

fn handle_version(id: serde_json::Value) -> String {
    #[derive(Serialize)]
    struct VersionResult {
        entangled: &'static str,
        runtime: &'static str,
        types: &'static str,
    }
    ok_resp(
        id,
        VersionResult {
            entangled: env!("CARGO_PKG_VERSION"),
            runtime: env!("CARGO_PKG_VERSION"),
            types: env!("CARGO_PKG_VERSION"),
        },
    )
}

fn handle_plugins_list(id: serde_json::Value, kernel: &Arc<Kernel>) -> String {
    let ids: Vec<String> = kernel
        .list_plugins()
        .iter()
        .map(|p| p.to_string())
        .collect();
    ok_resp(id, ids)
}

async fn handle_plugins_load(
    id: serde_json::Value,
    params: serde_json::Value,
    kernel: &Arc<Kernel>,
) -> String {
    #[derive(Deserialize)]
    struct LoadParams {
        dir: String,
    }
    let p: LoadParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
    };
    let dir = std::path::PathBuf::from(&p.dir);
    match kernel.load_plugin_from_dir(&dir).await {
        Ok(plugin_id) => ok_resp(id, plugin_id.to_string()),
        Err(e) => error_resp(id, -32000, format!("server error: {e}")),
    }
}

async fn handle_plugins_unload(
    id: serde_json::Value,
    params: serde_json::Value,
    kernel: &Arc<Kernel>,
) -> String {
    #[derive(Deserialize)]
    struct UnloadParams {
        id: String,
    }
    let p: UnloadParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
    };
    let plugin_id: entangle_types::plugin_id::PluginId = match p.id.parse() {
        Ok(pid) => pid,
        Err(e) => return error_resp(id, -32602, format!("invalid plugin id: {e}")),
    };
    match kernel.unload(&plugin_id).await {
        Ok(()) => ok_resp(id, serde_json::Value::Null),
        Err(e) => error_resp(id, -32000, format!("server error: {e}")),
    }
}

async fn handle_plugins_invoke(
    id: serde_json::Value,
    params: serde_json::Value,
    kernel: &Arc<Kernel>,
) -> String {
    let p: PluginsInvokeParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
    };
    let plugin_id: entangle_types::plugin_id::PluginId = match p.plugin_id.parse() {
        Ok(pid) => pid,
        Err(e) => return error_resp(id, -32602, format!("invalid plugin id: {e}")),
    };
    match kernel.invoke(&plugin_id, &p.input, p.timeout_ms).await {
        Ok(output) => ok_resp(id, PluginsInvokeResult { output }),
        Err(e) => error_resp(id, -32000, format!("server error: {e}")),
    }
}

// ── compute/dispatch ──────────────────────────────────────────────────────────

/// Handle `compute/dispatch`.
///
/// Phase 1: builds an ephemeral `Dispatcher` with an empty `WorkerPool` per
/// call. The empty pool causes placement to fall back to local kernel execution
/// for tasks with zero resource requirements. Tasks that specify non-zero
/// resources will fail with a placement error until iter 26 wires the real
/// shared dispatcher populated by mesh-local advertisement.
async fn handle_compute_dispatch(
    id: serde_json::Value,
    params: serde_json::Value,
    kernel: &Arc<Kernel>,
) -> String {
    use entangle_types::{
        peer_id::PeerId,
        plugin_id::PluginId,
        resource::{GpuBackend, GpuRequirement, ResourceSpec},
        task::{IntegrityPolicy, OneShotTask},
    };

    let p: ComputeDispatchParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
    };

    // Parse plugin id.
    let plugin_id: PluginId = match p.plugin_id.parse() {
        Ok(pid) => pid,
        Err(e) => return error_resp(id, -32602, format!("invalid plugin id: {e}")),
    };

    // Verify the plugin is loaded before dispatching.
    if !kernel.list_plugins().contains(&plugin_id) {
        return error_resp(id, -32000, "plugin not loaded");
    }

    // Build ResourceSpec from flat params.
    let gpu = if p.gpu_required || p.gpu_vram_min_bytes > 0 {
        Some(GpuRequirement {
            vram_min_bytes: p.gpu_vram_min_bytes,
            backend: GpuBackend::Any,
        })
    } else {
        None
    };
    let resources = ResourceSpec {
        cpu_cores: p.cpu_cores,
        memory_bytes: p.memory_bytes,
        gpu,
        ..ResourceSpec::default()
    };

    // Map ComputeIntegrity → IntegrityPolicy.
    let integrity = match p.integrity {
        ComputeIntegrity::None => IntegrityPolicy::None,
        ComputeIntegrity::Deterministic { replicas } => IntegrityPolicy::Deterministic { replicas },
        ComputeIntegrity::TrustedExecutor { ref allowlist } => {
            let peers: Vec<PeerId> = allowlist
                .iter()
                .map(|h| PeerId::from_hex(h))
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_default();
            IntegrityPolicy::TrustedExecutor { allowlist: peers }
        }
    };

    // Ephemeral local peer id (placeholder — iter 26 plumbs the real one from
    // the daemon's identity).
    let local_peer_id = PeerId::from_public_key_bytes(&[0u8; 32]);

    // Build the OneShotTask.
    let mut task = OneShotTask::with_defaults(plugin_id, p.input);
    task.resources = resources;
    task.integrity = integrity;
    task.timeout_ms = p.timeout_ms;

    // Build an ephemeral Dispatcher (empty WorkerPool for Phase 1).
    let dispatcher = Dispatcher::new(WorkerPool::new(), kernel.clone(), local_peer_id);

    match dispatcher.dispatch_one_shot(task).await {
        Ok(result) => {
            let out = ComputeDispatchResult {
                chosen_peer: result.chosen.peer_id.to_hex(),
                score: result.chosen.score,
                reason: result.chosen.reason,
                output: result.output,
            };
            ok_resp(id, out)
        }
        Err(e) => error_resp(id, -32000, format!("dispatch error: {e}")),
    }
}

// TODO(iter 7): wire entangle-mesh-local::Discovery into Kernel so these
// handlers can return real peer data. Until Discovery is integrated, both
// methods return empty/zero stubs.

fn handle_mesh_peers(id: serde_json::Value) -> String {
    ok_resp(id, MeshPeersResult { peers: vec![] })
}

fn handle_mesh_status(id: serde_json::Value) -> String {
    ok_resp(
        id,
        MeshStatusResult {
            local_peer_id: String::new(),
            local_display_name: String::new(),
            transports_active: vec![],
            seen_peer_count: 0,
            trusted_peer_count: 0,
        },
    )
}
