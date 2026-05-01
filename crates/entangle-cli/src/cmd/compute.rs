//! `entangle compute` subcommands — dispatch a one-shot task via the scheduler.
//!
//! Iter 24: attempt RPC to the running `entangled` daemon first.
//! Falls back to a local in-process kernel + ephemeral dispatcher ONLY when:
//!   - The daemon is not running (`RpcError::DaemonNotRunning`), AND
//!   - The user passed `--allow-local` (or `ENTANGLE_ALLOW_LOCAL=1`).
//!
//! Phase 1 note: the daemon's WorkerPool is empty — dispatches with zero
//! resource requirements fall back to local kernel execution. Tasks that
//! specify non-zero resources will fail until iter 26 populates the pool via
//! mesh-local advertisement.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Args, Subcommand};
use entangle_rpc::{
    methods::{ComputeDispatchParams, ComputeIntegrity},
    Client as RpcClient, RpcError,
};
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::Keyring;
use entangle_types::{
    peer_id::PeerId,
    plugin_id::PluginId,
    resource::{GpuBackend, GpuRequirement, ResourceSpec},
    task::{IntegrityPolicy, OneShotTask},
};
use std::str::FromStr;

use crate::config;

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
    Dispatch {
        /// Plugin ID in `<publisher>/<name>@<version>` format.
        plugin_id: String,

        /// Inline input string (UTF-8). Mutually exclusive with --input-file.
        #[arg(long, conflicts_with = "input_file")]
        input: Option<String>,

        /// Path to a file whose contents are used as input bytes.
        #[arg(long, conflicts_with = "input")]
        input_file: Option<String>,

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
    },
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub async fn run(args: ComputeArgs) -> anyhow::Result<()> {
    match args.cmd {
        ComputeCmd::Dispatch {
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
        } => {
            dispatch(
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
            )
            .await
        }
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
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

fn daemon_not_running_error() -> anyhow::Error {
    anyhow::anyhow!(
        "error: daemon not running at ~/.entangle/sock.\n\
         Start it with 'entangled run' or pass --allow-local to use a \
         local in-process kernel (no persistent state)."
    )
}

fn build_kernel() -> anyhow::Result<Kernel> {
    let kr_path = config::keyring_path();
    let keyring = Keyring::load(&kr_path)?;
    Kernel::new(KernelConfig::default(), keyring)
        .map_err(|e| anyhow::anyhow!("failed to build kernel: {e}"))
}

fn parse_integrity(
    integrity: &str,
    replicas: u8,
    allow: &[String],
) -> anyhow::Result<ComputeIntegrity> {
    match integrity {
        "none" => Ok(ComputeIntegrity::None),
        "deterministic" => Ok(ComputeIntegrity::Deterministic { replicas }),
        "trusted-executor" => Ok(ComputeIntegrity::TrustedExecutor {
            allowlist: allow.to_vec(),
        }),
        other => Err(anyhow::anyhow!(
            "unknown integrity mode '{other}'; expected one of: none, deterministic, trusted-executor"
        )),
    }
}

fn print_dispatch_output(chosen_peer: &str, score: f32, reason: &str, output: &[u8]) {
    println!("Chosen: {chosen_peer} (score={score:.2})");
    println!("Reason: {reason}");
    match std::str::from_utf8(output) {
        Ok(s) if !s.contains('\x00') => println!("Output: {s}"),
        _ => println!("Output: {}", BASE64.encode(output)),
    }
}

// ---------------------------------------------------------------------------
// dispatch implementation
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    plugin_id: String,
    input: Option<String>,
    input_file: Option<String>,
    timeout_ms: u64,
    cpu_cores: f32,
    memory_bytes: u64,
    gpu: bool,
    gpu_vram_min_mib: u64,
    integrity: String,
    replicas: u8,
    allow: Vec<String>,
) -> anyhow::Result<()> {
    let input_bytes: Vec<u8> = match (input.as_deref(), input_file.as_deref()) {
        (Some(s), _) => s.as_bytes().to_vec(),
        (_, Some(path)) => tokio::fs::read(path)
            .await
            .map_err(|e| anyhow::anyhow!("reading --input-file {path}: {e}"))?,
        (None, None) => Vec::new(),
    };

    let integrity_rpc = parse_integrity(&integrity, replicas, &allow)?;
    let gpu_vram_min_bytes = gpu_vram_min_mib * 1024 * 1024;

    let params = ComputeDispatchParams {
        plugin_id: plugin_id.clone(),
        input: input_bytes.clone(),
        timeout_ms,
        cpu_cores,
        memory_bytes,
        gpu_required: gpu,
        gpu_vram_min_bytes,
        integrity: integrity_rpc,
    };

    let client = rpc_client();
    match client.compute_dispatch(params).await {
        Ok(r) => {
            print_dispatch_output(&r.chosen_peer, r.score, &r.reason, &r.output);
            Ok(())
        }
        Err(RpcError::DaemonNotRunning(_)) => {
            if allow_local() {
                dispatch_local(
                    plugin_id,
                    input_bytes,
                    timeout_ms,
                    cpu_cores,
                    memory_bytes,
                    gpu,
                    gpu_vram_min_bytes,
                    &integrity,
                    replicas,
                    &allow,
                )
                .await
            } else {
                Err(daemon_not_running_error())
            }
        }
        Err(e) => Err(e.into()),
    }
}

// ---------------------------------------------------------------------------
// Local-kernel fallback (--allow-local)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn dispatch_local(
    plugin_id: String,
    input_bytes: Vec<u8>,
    timeout_ms: u64,
    cpu_cores: f32,
    memory_bytes: u64,
    gpu: bool,
    gpu_vram_min_bytes: u64,
    integrity: &str,
    replicas: u8,
    allow: &[String],
) -> anyhow::Result<()> {
    use std::sync::Arc;

    let kernel = Arc::new(build_kernel()?);

    // Parse plugin id.
    let pid =
        PluginId::from_str(&plugin_id).map_err(|e| anyhow::anyhow!("invalid plugin id: {e}"))?;

    // Build ResourceSpec.
    let gpu_req = if gpu || gpu_vram_min_bytes > 0 {
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
        "none" => IntegrityPolicy::None,
        "deterministic" => IntegrityPolicy::Deterministic { replicas },
        "trusted-executor" => {
            let peers: Vec<PeerId> = allow
                .iter()
                .filter_map(|h| PeerId::from_hex(h).ok())
                .collect();
            IntegrityPolicy::TrustedExecutor { allowlist: peers }
        }
        other => return Err(anyhow::anyhow!("unknown integrity mode '{other}'")),
    };

    let local_peer_id = PeerId::from_public_key_bytes(&[0u8; 32]);
    let mut task = OneShotTask::with_defaults(pid, input_bytes);
    task.resources = resources;
    task.integrity = integrity_policy;
    task.timeout_ms = timeout_ms;

    let dispatcher = Dispatcher::new(WorkerPool::new(), kernel, local_peer_id);
    let result = dispatcher
        .dispatch_one_shot(task)
        .await
        .map_err(|e| anyhow::anyhow!("dispatch error: {e}"))?;

    print_dispatch_output(
        &result.chosen.peer_id.to_hex(),
        result.chosen.score,
        &result.chosen.reason,
        &result.output,
    );
    Ok(())
}
