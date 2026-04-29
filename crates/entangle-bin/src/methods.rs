//! JSON-RPC 2.0 method dispatch for the `entangled` daemon.
//!
//! Supported Phase-1 methods:
//! - `version`        → `{ "entangled": "0.1.0", "runtime": "0.1.0", "types": "0.1.0" }`
//! - `plugins/list`   → `["<plugin_id>", …]`
//! - `plugins/load`   → params `{ "dir": "<path>" }` → plugin id string
//! - `plugins/unload` → params `{ "id": "<plugin_id>" }` → null

use entangle_runtime::Kernel;
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
        "version" => handle_version(req.id),
        "plugins/list" => handle_plugins_list(req.id, kernel),
        "plugins/load" => handle_plugins_load(req.id, req.params, kernel).await,
        "plugins/unload" => handle_plugins_unload(req.id, req.params, kernel).await,
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
