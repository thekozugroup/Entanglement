//! `entangle compute` subcommands — dispatch a one-shot task via the scheduler.
//!
//! Attempt RPC to the running `entangled` daemon first.
//! Falls back to a local in-process kernel + ephemeral dispatcher ONLY when:
//!   - The daemon is not running (`RpcError::DaemonNotRunning`), AND
//!   - The user passed `--allow-local` (or `ENTANGLE_ALLOW_LOCAL=1`).
//!
//! The daemon matches local hardware and discovered workers against task requirements.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Args, Subcommand};
use entangle_rpc::{
    methods::{ComputeDispatchParams, ComputeDispatchResult, ComputeIntegrity},
    Client as RpcClient, RpcError,
};
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_types::{
    peer_id::PeerId,
    plugin_id::PluginId,
    resource::{GpuBackend, GpuRequirement, ResourceSpec},
    task::{IntegrityPolicy, OneShotTask},
};
use std::str::FromStr;

use crate::cmd::plugins::OutputSink;
use crate::config;
use crate::daemon_not_running_error;

// ---------------------------------------------------------------------------
// Clap types
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct ComputeArgs {
    #[command(subcommand)]
    pub cmd: ComputeCmd,
}

#[derive(Subcommand)]
pub enum ComputeCmd {
    /// Dispatch a one-shot plugin invocation via the scheduler.
    Dispatch(DispatchArgs),
}

#[derive(Args)]
pub struct DispatchArgs {
    /// Plugin ID in `<publisher>/<name>@<version>` format.
    plugin_id: String,

    /// Inline input string (UTF-8). Mutually exclusive with --input-file.
    #[arg(long, conflicts_with = "input_file")]
    input: Option<String>,

    /// Path to a file whose contents are used as input bytes.
    #[arg(long, conflicts_with = "input")]
    input_file: Option<String>,

    /// Write the exact result bytes to stdout. Placement details go to stderr.
    #[arg(long, conflicts_with = "output_file")]
    raw: bool,

    /// Save the exact result bytes to a file.
    #[arg(long, value_name = "PATH")]
    output_file: Option<String>,

    /// Maximum wall-clock time for the invocation in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    timeout_ms: u64,

    /// Required CPU cores (fractional; 0 = no requirement).
    #[arg(long, default_value_t = 0.0)]
    cpu_cores: f32,

    /// Required host memory in bytes (0 = no requirement).
    #[arg(long, default_value_t = 0)]
    memory_bytes: u64,

    /// Require a GPU (any backend).
    #[arg(long)]
    gpu: bool,

    /// Minimum GPU VRAM required in mebibytes (0 = no requirement).
    #[arg(long, default_value_t = 0)]
    gpu_vram_min_mib: u64,

    /// Integrity policy: none | deterministic | trusted-executor.
    #[arg(long, default_value = "none")]
    integrity: String,

    /// Number of replicas for --integrity deterministic.
    #[arg(long, default_value_t = 2)]
    replicas: u8,

    /// Allow-listed peer hex ids for --integrity trusted-executor.
    /// May be repeated.
    #[arg(long = "allow")]
    allow: Vec<String>,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub async fn run(args: ComputeArgs) -> anyhow::Result<()> {
    match args.cmd {
        ComputeCmd::Dispatch(args) => dispatch(args).await,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rpc_client() -> RpcClient {
    RpcClient::new(RpcClient::default_socket())
}

fn allow_local() -> bool {
    std::env::var("ENTANGLE_ALLOW_LOCAL")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false)
}

fn parse_integrity(
    integrity: &str,
    replicas: u8,
    allow: &[String],
) -> anyhow::Result<ComputeIntegrity> {
    match integrity {
        "none" => Ok(ComputeIntegrity::None),
        "deterministic" => Ok(ComputeIntegrity::Deterministic { replicas }),
        "trusted-executor" => {
            // Reject any malformed allowlist entry up front rather than
            // silently dropping it; the daemon receives only valid hex ids.
            for h in allow {
                PeerId::from_hex(h)
                    .map_err(|e| anyhow::anyhow!("invalid --allow peer id '{h}': {e}"))?;
            }
            Ok(ComputeIntegrity::TrustedExecutor {
                allowlist: allow.to_vec(),
            })
        }
        other => Err(anyhow::anyhow!(
            "unknown integrity mode '{other}'; expected one of: none, deterministic, trusted-executor"
        )),
    }
}

fn write_dispatch_output(result: ComputeDispatchResult, sink: OutputSink) -> anyhow::Result<()> {
    let placement = format!(
        "Chosen: {} (score={:.2})\nReason: {}",
        result.chosen_peer, result.score, result.reason
    );
    if sink != OutputSink::Pretty {
        eprintln!("{placement}");
        return sink.write(&result.output);
    }

    println!("{placement}");
    match std::str::from_utf8(&result.output) {
        Ok(text) if !text.contains('\0') => println!("Output: {text}"),
        _ => println!("Output: {}", BASE64.encode(&result.output)),
    }
    Ok(())
}

async fn dispatch(args: DispatchArgs) -> anyhow::Result<()> {
    let DispatchArgs {
        plugin_id,
        input,
        input_file,
        timeout_ms,
        cpu_cores,
        memory_bytes,
        gpu,
        gpu_vram_min_mib,
        integrity,
        replicas,
        allow,
        raw,
        output_file,
    } = args;
    anyhow::ensure!(
        cpu_cores.is_finite() && cpu_cores >= 0.0,
        "--cpu-cores must be finite and nonnegative"
    );
    let input_bytes: Vec<u8> = match (input.as_deref(), input_file.as_deref()) {
        (Some(s), _) => s.as_bytes().to_vec(),
        (_, Some(path)) => tokio::fs::read(path)
            .await
            .map_err(|e| anyhow::anyhow!("reading --input-file {path}: {e}"))?,
        (None, None) => Vec::new(),
    };

    let integrity_rpc = parse_integrity(&integrity, replicas, &allow)?;
    let gpu_vram_min_bytes = gpu_vram_min_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("--gpu-vram-min-mib exceeds the supported byte range"))?;
    let params = ComputeDispatchParams {
        plugin_id,
        input: input_bytes,
        timeout_ms,
        cpu_cores,
        memory_bytes,
        gpu_required: gpu,
        gpu_vram_min_bytes,
        integrity: integrity_rpc,
    };

    let client = rpc_client();
    let result = match client.compute_dispatch(&params).await {
        Ok(result) => result,
        Err(RpcError::DaemonNotRunning(_)) if allow_local() => dispatch_local(params).await?,
        Err(RpcError::DaemonNotRunning(_)) => return Err(daemon_not_running_error()),
        Err(error) => return Err(error.into()),
    };
    write_dispatch_output(result, OutputSink::from_flags(output_file, raw))
}

async fn dispatch_local(params: ComputeDispatchParams) -> anyhow::Result<ComputeDispatchResult> {
    use std::sync::Arc;
    let kernel = Arc::new(config::local_kernel()?);
    let ComputeDispatchParams {
        plugin_id,
        input,
        timeout_ms,
        cpu_cores,
        memory_bytes,
        gpu_required,
        gpu_vram_min_bytes,
        integrity,
    } = params;

    // Parse plugin id.
    let pid =
        PluginId::from_str(&plugin_id).map_err(|e| anyhow::anyhow!("invalid plugin id: {e}"))?;

    // Build ResourceSpec.
    let gpu_req = if gpu_required || gpu_vram_min_bytes > 0 {
        Some(GpuRequirement {
            vram_min_bytes: gpu_vram_min_bytes,
            backend: GpuBackend::Any,
        })
    } else {
        None
    };
    let resources = ResourceSpec {
        cpu_cores,
        memory_bytes,
        gpu: gpu_req,
        ..ResourceSpec::default()
    };

    // Map integrity.
    let integrity_policy = match integrity {
        ComputeIntegrity::None => IntegrityPolicy::None,
        ComputeIntegrity::Deterministic { replicas } => IntegrityPolicy::Deterministic { replicas },
        ComputeIntegrity::TrustedExecutor { allowlist: allow } => {
            // Hard-error on any malformed entry instead of silently dropping it.
            let peers: Vec<PeerId> = allow
                .iter()
                .map(|h| {
                    PeerId::from_hex(h)
                        .map_err(|e| anyhow::anyhow!("invalid --allow peer id '{h}': {e}"))
                })
                .collect::<anyhow::Result<_>>()?;
            IntegrityPolicy::TrustedExecutor { allowlist: peers }
        }
    };

    let local_peer_id = PeerId::from_public_key_bytes(&[0u8; 32]);
    let mut task = OneShotTask::with_defaults(pid, input);
    task.resources = resources;
    task.integrity = integrity_policy;
    task.timeout_ms = timeout_ms;

    let dispatcher = Dispatcher::new(WorkerPool::new(), kernel, local_peer_id);
    let result = dispatcher
        .dispatch_one_shot(task)
        .await
        .map_err(|e| anyhow::anyhow!("dispatch error: {e}"))?;

    Ok(ComputeDispatchResult {
        chosen_peer: result.chosen.peer_id.to_hex(),
        score: result.chosen.score,
        reason: result.chosen.reason,
        output: result.output,
    })
}
