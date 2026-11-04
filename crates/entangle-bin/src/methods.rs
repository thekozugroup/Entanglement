//! JSON-RPC 2.0 method dispatch for the `entangled` daemon.
//!
//! Every handler speaks the shared wire types from [`entangle_rpc::methods`]
//! so the typed [`entangle_rpc::Client`] can decode each response — the result
//! and param shapes below are contract, not internal detail.
//!
//! Supported Phase-1 methods:
//! - `version`         → `{ "entangled": "0.1.0", "runtime": "0.1.0", "types": "0.1.0" }`
//! - `plugins/list`    → `{ "plugins": ["<plugin_id>", …] }`  (`PluginsListResult`)
//! - `plugins/load`    → params `{ "dir": "<path>" }` → `{ "plugin_id": "<id>" }`  (`PluginsLoadResult`)
//! - `plugins/unload`  → params `{ "plugin_id": "<plugin_id>" }` → null  (`PluginsUnloadParams`)
//! - `plugins/invoke`  → params `{ "plugin_id": "<id>", "input": […], "timeout_ms": N }` → `{ "output": […] }`
//! - `compute/dispatch` → params `ComputeDispatchParams` → `ComputeDispatchResult`
//! - `mesh/peers`   → sighted peers overlaid with the PeerStore (`trusted` comes
//!   only from the store, never from an unauthenticated sighting)
//! - `mesh/status`  → local_peer_id (identity-derived), display_name, real transport list, counts
//! - `metrics/export` → `{ "text": "<Prometheus exposition>" }` (what `GET /metrics` serves)
//! - `diag/mesh`    → mesh triage report, optionally with per-peer round-trip probes
//! - `security/plan-max-tier` → params `MaxTierParams` → `MaxTierPlan` (dry run)
//! - `security/apply-max-tier` → params `MaxTierApplyParams` → `MaxTierApplied`
//! - `security/cancel-max-tier` → params `MaxTierParams` → null
//! - `perms/list`   → params `{ "plugin_id"?: "<id>" }` → `PermsListResult`: each
//!   plugin's declared capabilities and their grant state (granted / denied /
//!   revoked / not-granted)
//! - `perms/revoke` → params `{ "plugin_id", "capability" }` → `{ "withdrawn": [ids], "plugin_id" }`
//!
//! Every request is counted in `entangle_rpc_requests_total{method,outcome}`
//! and timed in `entangle_rpc_request_duration_seconds{method}`; the `method`
//! label is normalised to the implemented set, so clients cannot mint labels.

use crate::state::DaemonState;
use entangle_rpc::methods::{
    method, AffectedPlugin, ComputeDispatchParams, ComputeDispatchResult, ComputeIntegrity,
    DiagMeshParams, MaxTierApplied, MaxTierApplyParams, MaxTierParams, MaxTierPlan,
    MeshStatusResult, MetricsExportResult, PermsListParams, PermsRevokeParams, PermsRevokeResult,
    PluginsInvokeParams, PluginsInvokeResult, PluginsListResult, PluginsLoadParams,
    PluginsLoadResult, PluginsUnloadParams,
};
use entangle_runtime::MaxTierRefusal;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::Instrument as _;

/// Upper bound (5 minutes) applied to any client-supplied `timeout_ms` before
/// it reaches the kernel. Client input is untrusted: without a clamp a caller
/// could pin a worker on a single invocation indefinitely. Values above this
/// are clamped down; applies to both `plugins/invoke` and `compute/dispatch`.
const MAX_INVOKE_TIMEOUT_MS: u64 = 5 * 60 * 1_000;

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
pub async fn dispatch(line: &str, state: &Arc<DaemonState>) -> String {
    let started = std::time::Instant::now();
    let record = |method: &str, resp: &str, id_json: &str| {
        entangle_observability::catalog::rpc_request(
            &state.metrics,
            method,
            !is_error_response(resp, id_json),
            started.elapsed().as_secs_f64(),
        );
    };

    // -32700: Parse error
    let req: Req = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "JSON parse error");
            let resp = error_resp(serde_json::Value::Null, -32700, format!("parse error: {e}"));
            record("unknown", &resp, "null");
            return resp;
        }
    };
    let id_json = serde_json::to_string(&req.id).unwrap_or_default();

    // -32600: Invalid Request (jsonrpc field must be "2.0")
    if req.jsonrpc != "2.0" {
        let resp = error_resp(req.id, -32600, "invalid request: jsonrpc must be \"2.0\"");
        record("unknown", &resp, &id_json);
        return resp;
    }

    tracing::debug!(method = %req.method, "RPC dispatch");
    let method_name = req.method.clone();
    // The span's `method` is normalised like the metric label, so a client
    // cannot inject arbitrary text into traces either.
    let known = entangle_observability::catalog::RPC_METHODS.contains(&method_name.as_str());
    let span = tracing::info_span!(
        "rpc.request",
        otel.kind = "server",
        method = if known {
            method_name.as_str()
        } else {
            "unknown"
        },
    );
    let resp = route(req, state).instrument(span).await;
    record(&method_name, &resp, &id_json);
    resp
}

/// `true` when `resp` (a response this module built for a request whose id
/// serialises to `id_json`) is a JSON-RPC error.
///
/// Responses are serialised as `{"jsonrpc":"2.0","id":<id>,` followed by
/// `"result"` or `"error"`, so the discriminating key sits right after the id
/// prefix we know exactly; nothing inside a result can be mistaken for it.
fn is_error_response(resp: &str, id_json: &str) -> bool {
    let prefix = format!(r#"{{"jsonrpc":"2.0","id":{id_json},"#);
    resp.strip_prefix(&prefix)
        .is_some_and(|rest| rest.starts_with(r#""error":"#))
        // A response that does not have our shape (serialisation fallback).
        || !resp.starts_with(&prefix)
}

async fn route(req: Req, state: &Arc<DaemonState>) -> String {
    // Debug-build fault point: a panic in the RPC server (spec §2.1).
    entangle_core::fault::inject("rpc");
    match req.method.as_str() {
        m if m == method::VERSION => handle_version(req.id),
        m if m == method::TIME => handle_time(req.id),
        m if m == method::PLUGINS_LIST => handle_plugins_list(req.id, state),
        m if m == method::PLUGINS_LOAD => handle_plugins_load(req.id, req.params, state).await,
        m if m == method::PLUGINS_UNLOAD => handle_plugins_unload(req.id, req.params, state).await,
        m if m == method::PLUGINS_INVOKE => handle_plugins_invoke(req.id, req.params, state).await,
        m if m == method::MESH_PEERS => handle_mesh_peers(req.id, state).await,
        m if m == method::MESH_STATUS => handle_mesh_status(req.id, state).await,
        m if m == method::COMPUTE_DISPATCH => {
            handle_compute_dispatch(req.id, req.params, state).await
        }
        m if m == method::SECURITY_PLAN_MAX_TIER => handle_security_plan(req.id, req.params, state),
        m if m == method::SECURITY_APPLY_MAX_TIER => {
            handle_security_apply(req.id, req.params, state).await
        }
        m if m == method::SECURITY_CANCEL_MAX_TIER => {
            handle_security_cancel(req.id, req.params, state)
        }
        m if m == method::METRICS_EXPORT => ok_resp(
            req.id,
            MetricsExportResult {
                text: state.metrics.render(),
            },
        ),
        m if m == method::DIAG_MESH => handle_diag_mesh(req.id, req.params, state).await,
        m if m == method::PERMS_LIST => handle_perms_list(req.id, req.params, state),
        m if m == method::PERMS_REVOKE => handle_perms_revoke(req.id, req.params, state),
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

fn handle_time(id: serde_json::Value) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let unix_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    ok_resp(id, entangle_rpc::TimeResult { unix_millis })
}

fn handle_plugins_list(id: serde_json::Value, state: &Arc<DaemonState>) -> String {
    let plugins: Vec<String> = state
        .kernel
        .list_plugins()
        .iter()
        .map(|p| p.to_string())
        .collect();
    // Wire contract: a JSON object `{ "plugins": [...] }`, not a bare array —
    // the typed client decodes `PluginsListResult`.
    ok_resp(id, PluginsListResult { plugins })
}

async fn handle_plugins_load(
    id: serde_json::Value,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> String {
    let p: PluginsLoadParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
    };
    let dir = std::path::PathBuf::from(&p.dir);
    state.refresh_disabled_plugins();
    let opts = entangle_runtime::LoadOptions {
        accept_new_capabilities: p.accept_new_capabilities,
        allow_downgrade: p.allow_downgrade,
    };
    match state.kernel.load_plugin(&dir, opts).await {
        // Wire contract: `{ "plugin_id": "<id>" }`, not a bare string; a hot
        // reload adds `replaced` (and `migrated`).
        Ok(outcome) => {
            state.persist_plugins();
            ok_resp(
                id,
                PluginsLoadResult {
                    plugin_id: outcome.plugin_id.to_string(),
                    migrated: outcome.replaced.as_ref().is_some_and(|r| r.migrated),
                    replaced: outcome.replaced.map(|r| r.previous.to_string()),
                },
            )
        }
        Err(e) => error_resp(id, -32000, format!("server error: {e}")),
    }
}

async fn handle_plugins_unload(
    id: serde_json::Value,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> String {
    // Wire contract: params are `{ "plugin_id": "<id>" }` (`PluginsUnloadParams`);
    // the former local `{ "id": ... }` shape the typed client never sent.
    let p: PluginsUnloadParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
    };
    let plugin_id: entangle_types::plugin_id::PluginId = match p.plugin_id.parse() {
        Ok(pid) => pid,
        Err(e) => return error_resp(id, -32602, format!("invalid plugin id: {e}")),
    };
    match state.kernel.unload(&plugin_id).await {
        Ok(()) => {
            state.persist_plugins();
            ok_resp(id, serde_json::Value::Null)
        }
        // An entry that failed to restore at startup is not loaded; unloading
        // its id forgets it (see `plugin_state`).
        Err(entangle_runtime::RuntimeError::NotLoaded(_))
            if state
                .plugin_state
                .as_ref()
                .is_some_and(|s| s.has_failed_entry(&plugin_id)) =>
        {
            if let Some(store) = &state.plugin_state {
                store.record(&state.kernel, Some(&plugin_id));
            }
            ok_resp(id, serde_json::Value::Null)
        }
        Err(e) => error_resp(id, -32000, format!("server error: {e}")),
    }
}

async fn handle_plugins_invoke(
    id: serde_json::Value,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> String {
    let p: PluginsInvokeParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
    };
    let plugin_id: entangle_types::plugin_id::PluginId = match p.plugin_id.parse() {
        Ok(pid) => pid,
        Err(e) => return error_resp(id, -32602, format!("invalid plugin id: {e}")),
    };
    // Clamp the client-supplied timeout before it reaches the kernel.
    let timeout_ms = p.timeout_ms.min(MAX_INVOKE_TIMEOUT_MS);
    match state.kernel.invoke(&plugin_id, &p.input, timeout_ms).await {
        Ok(output) => ok_resp(id, PluginsInvokeResult { output }),
        Err(e) => error_resp(id, -32000, format!("server error: {e}")),
    }
}

// ── security/*-max-tier ───────────────────────────────────────────────────────

fn parse_tier(id: &serde_json::Value, n: u8) -> Result<entangle_types::tier::Tier, String> {
    entangle_types::tier::Tier::try_from(n)
        .map_err(|e| error_resp(id.clone(), -32602, format!("invalid max_tier {n}: {e}")))
}

fn affected_wire(infos: &[entangle_runtime::LoadedPluginInfo]) -> Vec<AffectedPlugin> {
    infos
        .iter()
        .map(|i| AffectedPlugin {
            plugin_id: i.plugin.to_string(),
            tier: i.tier as u8,
            native: i.native,
            uptime_secs: i.uptime.as_secs(),
        })
        .collect()
}

/// `security/plan-max-tier`: read-only delta set (spec §9.4.1 step 1).
fn handle_security_plan(
    id: serde_json::Value,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> String {
    let p: MaxTierParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
    };
    let requested = match parse_tier(&id, p.max_tier) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let current = state.kernel.max_tier_allowed();
    let affected = if requested < current {
        affected_wire(&state.kernel.plugins_above(requested))
    } else {
        Vec::new()
    };
    ok_resp(
        id,
        MaxTierPlan {
            current: current as u8,
            requested: requested as u8,
            affected,
        },
    )
}

/// `security/apply-max-tier`: change the ceiling at runtime. Never unloads
/// unless `unload` is set; the CLI sets it only after the operator chose
/// unload-and-disable or passed `--force-unload`.
async fn handle_security_apply(
    id: serde_json::Value,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> String {
    let p: MaxTierApplyParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
    };
    let new = match parse_tier(&id, p.max_tier) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let confirmed: Option<Vec<entangle_types::plugin_id::PluginId>> = match p
        .confirmed
        .map(|ids| ids.iter().map(|s| s.parse()).collect::<Result<Vec<_>, _>>())
        .transpose()
    {
        Ok(c) => c,
        Err(e) => return error_resp(id, -32602, format!("invalid confirmed plugin id: {e}")),
    };
    let ids = |v: &[entangle_runtime::LoadedPluginInfo]| {
        v.iter()
            .map(|a| a.plugin.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    match state
        .kernel
        .apply_max_tier(new, p.unload, confirmed.as_deref())
        .await
    {
        Ok(o) => {
            if !o.unloaded.is_empty() {
                state.persist_plugins();
            }
            ok_resp(
                id,
                MaxTierApplied {
                    old: o.old as u8,
                    new: o.new as u8,
                    unloaded: o.unloaded.iter().map(|p| p.to_string()).collect(),
                },
            )
        }
        Err(MaxTierRefusal::NeedsUnload(affected)) => error_resp(
            id,
            -32001,
            format!(
                "ENTANGLE-E0750: lowering max_tier_allowed to {} would unload {} plugin(s): {}",
                p.max_tier,
                affected.len(),
                ids(&affected)
            ),
        ),
        Err(MaxTierRefusal::Unconfirmed(unseen)) => error_resp(
            id,
            -32001,
            format!(
                "ENTANGLE-E0758: lowering max_tier_allowed to {} would also unload {} plugin(s) \
                 that were not on the confirmed list (loaded since it was shown): {}; nothing \
                 was changed",
                p.max_tier,
                unseen.len(),
                ids(&unseen)
            ),
        ),
    }
}

/// `security/cancel-max-tier`: audit a cancelled lowering (`ENTANGLE-I0216`).
fn handle_security_cancel(
    id: serde_json::Value,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> String {
    let p: MaxTierParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
    };
    let requested = match parse_tier(&id, p.max_tier) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    state.kernel.record_lowering_cancelled(requested);
    ok_resp(id, serde_json::Value::Null)
}

// ── perms/* ───────────────────────────────────────────────────────────────────

fn perms_error(id: serde_json::Value, e: crate::perms::PermsError) -> String {
    let code = match e {
        crate::perms::PermsError::InvalidId(_) => -32602,
        _ => -32000,
    };
    error_resp(id, code, e.to_string())
}

fn handle_perms_list(
    id: serde_json::Value,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> String {
    // `params` may be omitted entirely (`null`): list every plugin.
    let p: PermsListParams = if params.is_null() {
        PermsListParams::default()
    } else {
        match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
        }
    };
    match crate::perms::list(&state.kernel, p.plugin_id.as_deref()) {
        Ok(r) => ok_resp(id, r),
        Err(e) => perms_error(id, e),
    }
}

fn handle_perms_revoke(
    id: serde_json::Value,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> String {
    let p: PermsRevokeParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
    };
    match crate::perms::revoke(&state.kernel, &p.plugin_id, &p.capability) {
        Ok(revoked) => {
            // A revocation survives a restart (`plugin_state`).
            state.persist_plugins();
            ok_resp(
                id,
                PermsRevokeResult {
                    withdrawn: revoked.withdrawn,
                    plugin_id: Some(revoked.plugin.to_string()),
                },
            )
        }
        Err(e) => perms_error(id, e),
    }
}

// ── compute/dispatch ──────────────────────────────────────────────────────────

/// Handle `compute/dispatch`.
///
/// Uses the shared `Dispatcher` from `DaemonState` rather than building an
/// ephemeral instance per call. The real `local_peer_id` comes from the
/// identity keypair loaded at startup.
async fn handle_compute_dispatch(
    id: serde_json::Value,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
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

    // Verify the plugin is loaded before dispatching (an id replaced by a
    // hot reload counts: its calls run on the version that replaced it).
    if state.kernel.resolve(&plugin_id).is_none() {
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
    //
    // A malformed peer hex in a TrustedExecutor allowlist is a hard error, not
    // a silently-dropped entry: swallowing it (the old `.unwrap_or_default()`)
    // could collapse the allowlist to empty and admit an unintended executor.
    let integrity = match p.integrity {
        ComputeIntegrity::None => IntegrityPolicy::None,
        ComputeIntegrity::Deterministic { replicas } => IntegrityPolicy::Deterministic { replicas },
        ComputeIntegrity::TrustedExecutor { ref allowlist } => {
            let mut peers: Vec<PeerId> = Vec::with_capacity(allowlist.len());
            for h in allowlist {
                match PeerId::from_hex(h) {
                    Ok(pid) => peers.push(pid),
                    Err(e) => {
                        return error_resp(
                            id,
                            -32602,
                            format!("invalid trusted-executor peer id {h:?}: {e}"),
                        )
                    }
                }
            }
            IntegrityPolicy::TrustedExecutor { allowlist: peers }
        }
        ComputeIntegrity::SemanticEquivalent {
            replicas,
            quorum,
            ref metric,
            ref metric_dir,
            threshold,
        } => match resolve_metric(state, metric, metric_dir.as_deref()).await {
            Ok(metric) => IntegrityPolicy::SemanticEquivalent {
                replicas,
                quorum,
                metric,
                threshold,
            },
            Err((code, msg)) => return error_resp(id, code, msg),
        },
    };

    // Build the OneShotTask using the identity-derived local_peer_id.
    let mut task = OneShotTask::with_defaults(plugin_id, p.input);
    task.resources = resources;
    task.integrity = integrity;
    // Clamp the client-supplied timeout before it flows into the kernel.
    task.timeout_ms = p.timeout_ms.min(MAX_INVOKE_TIMEOUT_MS);

    // Use the shared Dispatcher — no ephemeral construction per call.
    let dispatcher = state.dispatcher.clone();

    match dispatcher.dispatch_one_shot(task).await {
        Ok(result) => ok_resp(id, compute_result(result)),
        Err(e) => error_resp(id, -32000, format!("dispatch error: {e}")),
    }
}

/// Resolve a `semantic-equivalent` metric to a pinned, verified reference on
/// this daemon (the submitter). Loads the signed package from `metric_dir`
/// when given (idempotent), otherwise requires it to be loaded already.
async fn resolve_metric(
    state: &Arc<DaemonState>,
    metric: &str,
    metric_dir: Option<&str>,
) -> Result<entangle_types::task::MetricRef, (i32, String)> {
    let wanted: entangle_types::plugin_id::PluginId = metric
        .parse()
        .map_err(|e| (-32602, format!("invalid metric plugin id: {e}")))?;
    let registry = Arc::clone(state.dispatcher.verifier().metrics());
    let reference = match metric_dir {
        Some(dir) => {
            // `[plugins] disabled` applies to metric packages too; pick up an
            // `entangle plugins disable/enable` made since the last load.
            state.refresh_disabled_plugins();
            let dir = std::path::PathBuf::from(dir);
            tokio::task::spawn_blocking(move || registry.load_from_dir(&dir))
                .await
                .map_err(|e| (-32000, format!("loading metric: {e}")))?
                .map_err(|e| (-32000, format!("dispatch error: {e}")))?
        }
        None => registry.find_by_plugin(&wanted).ok_or_else(|| {
            (
                -32000,
                format!(
                    "metric {wanted} is not loaded on the daemon; pass its signed package \
                     directory (--metric-dir)"
                ),
            )
        })?,
    };
    if reference.plugin != wanted {
        return Err((
            -32602,
            format!(
                "the metric package holds {}, not the requested {wanted}",
                reference.plugin
            ),
        ));
    }
    Ok(reference)
}

/// Render a dispatch result for the wire, including the integrity audit.
pub(crate) fn compute_result(result: entangle_scheduler::DispatchResult) -> ComputeDispatchResult {
    ComputeDispatchResult {
        chosen_peer: result.chosen.peer_id.to_hex(),
        score: result.chosen.score,
        reason: result.chosen.reason,
        output: result.output,
        policy_hash: Some(result.policy_hash.to_hex()),
        replicas: result
            .replicas
            .iter()
            .map(|r| entangle_rpc::methods::ComputeReplica {
                peer: r.peer.to_hex(),
                remote: r.remote,
                status: r.status.label().to_owned(),
                error: r.status.error().map(str::to_owned),
                observed_policy_hash: r.observed_policy_hash.map(|h| h.to_hex()),
                output_bytes: r.output_bytes,
            })
            .collect(),
        pair_agreement: result.pair_agreement,
        spot_check: Some(result.spot_check.label().to_owned()),
    }
}

// ── diag/mesh ─────────────────────────────────────────────────────────────────

async fn handle_diag_mesh(
    id: serde_json::Value,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> String {
    // `null` (no params) means "no probe".
    let p: DiagMeshParams = if params.is_null() {
        DiagMeshParams::default()
    } else {
        match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return error_resp(id, -32602, format!("invalid params: {e}")),
        }
    };
    let report = crate::diag::mesh_report(
        state,
        p.probe,
        std::time::Duration::from_millis(p.probe_timeout_ms),
    )
    .await;
    ok_resp(id, report)
}

// ── mesh/peers ────────────────────────────────────────────────────────────────

/// A single peer entry on the `mesh/peers` wire.
///
/// This is a strict superset of [`entangle_rpc::methods::MeshPeer`]: it adds
/// `addresses_verified` (which that shared type does not yet carry) while
/// keeping every existing field, so the typed client still decodes it — serde
/// ignores the extra field. When `entangle-rpc` grows the field this local
/// struct collapses back into the shared type.
#[derive(Serialize)]
struct MeshPeerView {
    peer_id: String,
    display_name: String,
    addresses: Vec<String>,
    port: u16,
    version: String,
    last_seen_secs_ago: u64,
    /// Present (and not revoked) in the local PeerStore. Never inferred from a
    /// sighting.
    trusted: bool,
    /// Whether the peer's advertised addresses have been cryptographically
    /// proven to belong to it. Always `false` in Phase 1 — mDNS sightings are
    /// unauthenticated, so no address ownership is verified.
    addresses_verified: bool,
}

/// Result envelope for `mesh/peers` — superset of `MeshPeersResult`.
#[derive(Serialize)]
struct MeshPeersView {
    peers: Vec<MeshPeerView>,
}

/// Return the merged view of sighted (mDNS) and trusted (PeerStore) peers.
///
/// Trust is authoritative from the PeerStore, never from a sighting: an
/// unauthenticated mDNS record can claim any `peer_id`, so being sighted alone
/// never sets `trusted`. `addresses_verified` is always `false` in Phase 1.
///
/// Merge rules:
/// - Sighted peers seed the list with `trusted=false` and their live
///   addresses/version.
/// - Each non-revoked PeerStore entry is overlaid: it sets `trusted=true` and
///   supplies the authoritative display name; a matching sighting keeps its
///   live (still-unverified) addresses.
/// - Trusted-but-not-sighted peers appear with empty `addresses` and
///   `last_seen_secs_ago` derived from `last_seen_at`.
async fn handle_mesh_peers(id: serde_json::Value, state: &Arc<DaemonState>) -> String {
    use entangle_peers::TrustLevel;
    use entangle_types::peer_id::PeerId;
    use std::collections::HashMap;
    use std::time::SystemTime;

    // ── 1. Collect trusted peers from PeerStore ───────────────────────────
    let trusted_map: HashMap<PeerId, _> = state
        .peer_store
        .list()
        .into_iter()
        .filter(|p| p.trust != TrustLevel::Revoked)
        .map(|p| (p.peer_id, p))
        .collect();

    // ── 2. Collect sighted peers from Discovery snapshot ──────────────────
    let sighted: Vec<entangle_mesh_local::PeerSeen> = if let Some(d) = &state.discovery {
        d.snapshot_peers().await
    } else {
        vec![]
    };

    // ── 3. Build merged peer list ─────────────────────────────────────────
    let now = SystemTime::now();
    let mut result: HashMap<PeerId, MeshPeerView> = HashMap::new();

    // Insert sighted peers first — trusted stays false here; it is set only by
    // the PeerStore overlay below.
    for p in &sighted {
        let last_seen_secs_ago = p.last_seen.elapsed().map(|d| d.as_secs()).unwrap_or(0);
        result.insert(
            p.peer_id,
            MeshPeerView {
                peer_id: p.peer_id.to_hex(),
                display_name: p.display_name.clone(),
                addresses: p.addresses.iter().map(|a| a.to_string()).collect(),
                port: p.port,
                version: p.version.clone(),
                last_seen_secs_ago,
                trusted: false,
                addresses_verified: false,
            },
        );
    }

    // Overlay PeerStore records — the sole source of `trusted=true`.
    for (peer_id, tp) in &trusted_map {
        match result.get_mut(peer_id) {
            Some(view) => {
                // Both sighted and trusted: keep the live (unverified) addresses
                // but take trust + authoritative display name from the store.
                view.trusted = true;
                view.display_name = tp.display_name.clone();
            }
            None => {
                let last_seen_secs_ago = tp
                    .last_seen_at
                    .map(|unix_secs| {
                        let then =
                            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(unix_secs);
                        now.duration_since(then).map(|d| d.as_secs()).unwrap_or(0)
                    })
                    .unwrap_or(0);
                result.insert(
                    *peer_id,
                    MeshPeerView {
                        peer_id: peer_id.to_hex(),
                        display_name: tp.display_name.clone(),
                        addresses: vec![],
                        port: 0,
                        version: String::new(),
                        last_seen_secs_ago,
                        trusted: true,
                        addresses_verified: false,
                    },
                );
            }
        }
    }

    let peers: Vec<MeshPeerView> = result.into_values().collect();
    ok_resp(id, MeshPeersView { peers })
}

// ── mesh/status ───────────────────────────────────────────────────────────────

/// Return this node's mesh status.
///
/// `local_peer_id` is the real identity-derived hex. `trusted_peer_count` is
/// the live non-revoked count from the PeerStore, while `seen_peer_count` is
/// the live count of discovery sightings (which may include untrusted peers) —
/// the two are distinct and must not be conflated. `transports_active`
/// reflects what is actually running: `["local"]` when mDNS discovery is up,
/// `[]` when no transport is configured.
async fn handle_mesh_status(id: serde_json::Value, state: &Arc<DaemonState>) -> String {
    use entangle_peers::TrustLevel;

    let trusted_peer_count = state
        .peer_store
        .list()
        .into_iter()
        .filter(|p| p.trust != TrustLevel::Revoked)
        .count();

    // Derive both the seen count and the transport list from the live
    // discovery handle rather than hardcoding either.
    let (seen_peer_count, transports_active) = match &state.discovery {
        Some(d) => (d.snapshot_peers().await.len(), vec!["local".to_owned()]),
        None => (0, vec![]),
    };

    ok_resp(
        id,
        MeshStatusResult {
            local_peer_id: state.local_peer_id.to_hex(),
            local_display_name: state.local_display_name.clone(),
            transports_active,
            seen_peer_count,
            trusted_peer_count,
        },
    )
}
