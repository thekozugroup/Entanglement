//! `entangle compute` subcommands — dispatch a one-shot task via the scheduler.
//!
//! Attempt RPC to the running `entangled` daemon first.
//! Falls back to a local in-process kernel + ephemeral dispatcher ONLY when:
//!   - The daemon is not running (`RpcError::DaemonNotRunning`), AND
//!   - The user passed `--allow-local` (or `ENTANGLE_ALLOW_LOCAL=1`).
//!
//! The local kernel starts empty, so the task plugin is loaded first from its
//! signed package (`--plugin-dir`, default `~/.entangle/plugins/<name>`).
//!
//! Phase 1 note: the daemon's WorkerPool is empty — dispatches with zero
//! resource requirements fall back to local kernel execution. Tasks that
//! specify non-zero resources will fail until the pool is populated via
//! mesh-local advertisement.
//!
//! `--integrity semantic-equivalent` replicates the task and compares the
//! outputs pairwise with a signed metric component (spec §7.5). The metric
//! runs on the submitter — the daemon, or this process with `--allow-local`
//! — and is identified by `--metric <plugin-id>`; its signed package is read
//! from `--metric-dir` (default `~/.entangle/plugins/<name>`, where
//! `entangle plugins install <metric> --no-load` puts it).

use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Args, Subcommand};
use entangle_rpc::{
    methods::{ComputeDispatchParams, ComputeDispatchResult, ComputeIntegrity, ComputeReplica},
    Client as RpcClient, RpcError,
};
use entangle_runtime::Kernel;
use entangle_scheduler::{DispatchResult, Dispatcher, WorkerPool, Workload};
use entangle_signing::Keyring;
use entangle_types::{
    peer_id::PeerId,
    plugin_id::PluginId,
    resource::{GpuBackend, GpuRequirement, ResourceSpec},
    task::{IntegrityPolicy, OneShotTask},
};
use std::path::{Path, PathBuf};
use std::str::FromStr;

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
    /// Run a streaming task on a trusted peer (or, with --allow-local, in
    /// this process) and write its chunks to stdout as they arrive.
    Stream(super::compute_stream::StreamArgs),
}

/// `entangle compute dispatch` flags.
#[derive(Args)]
pub struct DispatchArgs {
    /// Plugin ID in `<publisher>/<name>@<version>` format.
    pub plugin_id: String,

    /// Inline input string (UTF-8). Mutually exclusive with --input-file.
    #[arg(long, conflicts_with = "input_file")]
    pub input: Option<String>,

    /// Path to a file whose contents are used as input bytes.
    #[arg(long, conflicts_with = "input")]
    pub input_file: Option<String>,

    /// Maximum wall-clock time for the invocation in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    pub timeout_ms: u64,

    /// Required CPU cores (fractional; 0 = no requirement).
    #[arg(long, default_value_t = 0.0)]
    pub cpu_cores: f32,

    /// Required host memory in bytes (0 = no requirement).
    #[arg(long, default_value_t = 0)]
    pub memory_bytes: u64,

    /// Require a GPU (any backend).
    #[arg(long)]
    pub gpu: bool,

    /// Minimum GPU VRAM required in mebibytes (0 = no requirement).
    #[arg(long, default_value_t = 0)]
    pub gpu_vram_min_mib: u64,

    /// Integrity policy: none | deterministic | semantic-equivalent | trusted-executor.
    /// Default: the --workload preset's, else none.
    #[arg(long)]
    pub integrity: Option<String>,

    /// Reference-workload preset (spec §7.0): `a` (LLM offload to your own
    /// machine: trusted-executor over the --allow ids, 1 MiB output cap),
    /// `b` (batch on a trusted mesh: deterministic, 1 replica),
    /// `b-federated` (deterministic, 3 replicas) or `c` (test runs:
    /// deterministic, 1 replica, 3 attempts). Explicit flags override it.
    #[arg(long)]
    pub workload: Option<String>,

    /// The task's max_output_bytes (default 16 MiB; workload a: 1 MiB).
    #[arg(long)]
    pub max_output_bytes: Option<u64>,

    /// Attempts in all when a worker crashes or is lost mid-task, the first
    /// included (default 3; 1 never retries). Plugin errors, refusals and
    /// timeouts are never retried.
    #[arg(long)]
    pub max_attempts: Option<u8>,

    /// Number of replicas for --integrity deterministic or semantic-equivalent
    /// (default 2; with --workload b, b-federated or c and no --integrity,
    /// overrides the preset's count). Replicas go to distinct trusted peers;
    /// any remainder runs locally.
    #[arg(long)]
    pub replicas: Option<u8>,

    /// Allow-listed peer hex ids for --integrity trusted-executor.
    /// May be repeated.
    #[arg(long = "allow")]
    pub allow: Vec<String>,

    /// semantic-equivalent: metric plugin id, `<publisher>/<name>@<version>`
    /// (e.g. a build of plugins/metric-bleu-4). Its publisher must be in your
    /// keyring; it runs only on this machine, never on the workers.
    #[arg(long)]
    pub metric: Option<String>,

    /// semantic-equivalent: the metric's signed package directory.
    /// Defaults to `~/.entangle/plugins/<metric-name>` when that exists.
    #[arg(long)]
    pub metric_dir: Option<PathBuf>,

    /// semantic-equivalent: pairwise metric distance strictly below which two
    /// replica outputs agree (e.g. 0.15 for metric-bleu-4).
    #[arg(long)]
    pub threshold: Option<f64>,

    /// semantic-equivalent: minimum number of agreeing replica pairs.
    /// Default: a strict majority of the replicas*(replicas-1)/2 pairs.
    #[arg(long)]
    pub quorum: Option<u8>,

    /// `--allow-local` only: the task plugin's signed package directory.
    /// Defaults to `~/.entangle/plugins/<plugin-name>` when that exists. The
    /// daemon path ignores it (the daemon has its own loaded plugins).
    #[arg(long)]
    pub plugin_dir: Option<PathBuf>,

    /// Print the result as one JSON object.
    #[arg(long)]
    pub json: bool,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub async fn run(args: ComputeArgs) -> anyhow::Result<()> {
    match args.cmd {
        ComputeCmd::Dispatch(a) => dispatch(a).await,
        ComputeCmd::Stream(a) => super::compute_stream::run(a).await,
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

fn build_kernel() -> anyhow::Result<Kernel> {
    let kr_path = config::keyring_path();
    let keyring = Keyring::load(&kr_path)?;
    Kernel::new(config::kernel_config()?, keyring)
        .map_err(|e| anyhow::anyhow!("failed to build kernel: {e}"))
}

/// `--replicas` when no preset decides: 2.
const DEFAULT_REPLICAS: u8 = 2;

/// Strict majority of the `replicas * (replicas - 1) / 2` replica pairs.
fn default_quorum(replicas: u8) -> u8 {
    let r = usize::from(replicas);
    let pairs = r * r.saturating_sub(1) / 2;
    u8::try_from(pairs / 2 + 1).unwrap_or(u8::MAX)
}

/// The metric package directory to send: `--metric-dir`, else
/// `~/.entangle/plugins/<name>` if it exists, as an absolute path (the daemon
/// does not share this process's working directory).
fn resolve_metric_dir(flag: Option<&Path>, name: &str) -> anyhow::Result<Option<String>> {
    let dir = match flag {
        Some(d) => d.to_path_buf(),
        None => {
            let d = config::entangle_dir().join("plugins").join(name);
            if !d.is_dir() {
                return Ok(None);
            }
            d
        }
    };
    let abs = std::fs::canonicalize(&dir)
        .with_context(|| format!("metric package directory {}", dir.display()))?;
    Ok(Some(abs.to_string_lossy().into_owned()))
}

/// The semantic-equivalent-only flags that were passed, by name.
fn stray_semantic_flags(a: &DispatchArgs) -> Vec<&'static str> {
    [
        (a.metric.is_some(), "--metric"),
        (a.metric_dir.is_some(), "--metric-dir"),
        (a.threshold.is_some(), "--threshold"),
        (a.quorum.is_some(), "--quorum"),
    ]
    .into_iter()
    .filter_map(|(set, name)| set.then_some(name))
    .collect()
}

/// The `--workload` preset, if one was asked for.
fn parse_workload(a: &DispatchArgs) -> anyhow::Result<Option<Workload>> {
    a.workload
        .as_deref()
        .map(|w| w.parse::<Workload>().map_err(anyhow::Error::from))
        .transpose()
}

/// The integrity policy to send: `--integrity` when given (explicit flags
/// override the preset), else the `--workload` preset's, else `none`.
fn resolve_integrity(
    a: &DispatchArgs,
    workload: Option<Workload>,
) -> anyhow::Result<ComputeIntegrity> {
    match (a.integrity.as_deref(), workload) {
        (None, Some(w)) => {
            if !stray_semantic_flags(a).is_empty() {
                return parse_integrity(a);
            }
            let executors = a
                .allow
                .iter()
                .map(|h| {
                    PeerId::from_hex(h)
                        .map_err(|e| anyhow::anyhow!("invalid --allow peer id '{h}': {e}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(match w.integrity(&executors)? {
                IntegrityPolicy::TrustedExecutor { allowlist } => {
                    ComputeIntegrity::TrustedExecutor {
                        allowlist: allowlist.iter().map(PeerId::to_hex).collect(),
                    }
                }
                // An explicit --replicas wins over the preset's count.
                IntegrityPolicy::Deterministic { replicas } => ComputeIntegrity::Deterministic {
                    replicas: a.replicas.unwrap_or(replicas),
                },
                _ => ComputeIntegrity::None,
            })
        }
        _ => parse_integrity(a),
    }
}

/// `--max-output-bytes`, else the preset's, else the default (`None`).
fn resolve_max_output_bytes(a: &DispatchArgs, workload: Option<Workload>) -> Option<u64> {
    a.max_output_bytes.or(match workload {
        Some(Workload::A) => Some(Workload::A_MAX_OUTPUT_BYTES),
        _ => None,
    })
}

/// `--max-attempts`, else the preset's, else the default (`None`).
fn resolve_max_attempts(a: &DispatchArgs, workload: Option<Workload>) -> Option<u8> {
    a.max_attempts.or(match workload {
        Some(Workload::C) => Some(3),
        _ => None,
    })
}

fn parse_integrity(a: &DispatchArgs) -> anyhow::Result<ComputeIntegrity> {
    let integrity = a.integrity.as_deref().unwrap_or("none");
    let replicas = a.replicas.unwrap_or(DEFAULT_REPLICAS);
    // These flags configure verification only under semantic-equivalent.
    // Dropping them silently would run the task once, unverified, while the
    // operator believes it was checked.
    if integrity != "semantic-equivalent" {
        let stray = stray_semantic_flags(a);
        if !stray.is_empty() {
            anyhow::bail!(
                "{} only apply with --integrity semantic-equivalent (got --integrity {}); \
                 add --integrity semantic-equivalent or drop the flag",
                stray.join(", "),
                integrity
            );
        }
    }
    match integrity {
        "none" => Ok(ComputeIntegrity::None),
        "deterministic" => Ok(ComputeIntegrity::Deterministic { replicas }),
        "trusted-executor" => {
            // Reject any malformed allowlist entry up front rather than
            // silently dropping it; the daemon receives only valid hex ids.
            for h in &a.allow {
                PeerId::from_hex(h)
                    .map_err(|e| anyhow::anyhow!("invalid --allow peer id '{h}': {e}"))?;
            }
            Ok(ComputeIntegrity::TrustedExecutor {
                allowlist: a.allow.clone(),
            })
        }
        "semantic-equivalent" => {
            let metric = a.metric.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "--integrity semantic-equivalent needs --metric <PLUGIN_ID> \
                     (e.g. <your-fingerprint>/metric-bleu-4@0.1.0)"
                )
            })?;
            let id = PluginId::from_str(&metric)
                .map_err(|e| anyhow::anyhow!("invalid --metric plugin id: {e}"))?;
            let threshold = a.threshold.ok_or_else(|| {
                anyhow::anyhow!(
                    "--integrity semantic-equivalent needs --threshold <DISTANCE> \
                     (e.g. 0.15 for metric-bleu-4)"
                )
            })?;
            if !threshold.is_finite() || threshold <= 0.0 {
                anyhow::bail!("--threshold must be a finite distance > 0, got {threshold}");
            }
            if replicas < 2 {
                anyhow::bail!(
                    "--integrity semantic-equivalent needs --replicas 2 or more \
                     (it compares replica pairs)"
                );
            }
            let pairs = usize::from(replicas) * (usize::from(replicas) - 1) / 2;
            let quorum = a.quorum.unwrap_or_else(|| default_quorum(replicas));
            if quorum == 0 || usize::from(quorum) > pairs {
                anyhow::bail!(
                    "--quorum must be between 1 and {pairs} (the replica pair count for \
                     --replicas {}), got {quorum}",
                    replicas
                );
            }
            Ok(ComputeIntegrity::SemanticEquivalent {
                replicas,
                quorum,
                metric,
                metric_dir: resolve_metric_dir(a.metric_dir.as_deref(), &id.name)?,
                threshold,
            })
        }
        other => Err(anyhow::anyhow!(
            "unknown integrity mode '{other}'; expected one of: none, deterministic, \
             semantic-equivalent, trusted-executor"
        )),
    }
}

/// The scheduler's attempt records in RPC form.
fn rpc_attempts(
    attempts: &[entangle_scheduler::Attempt],
) -> Vec<entangle_rpc::methods::ComputeAttempt> {
    attempts
        .iter()
        .map(|a| entangle_rpc::methods::ComputeAttempt {
            replica: a.replica,
            peer: a.peer.to_hex(),
            remote: a.remote,
            kind: a.kind.label().to_owned(),
            cause: match a.kind {
                entangle_scheduler::AttemptKind::Retry(cause) => Some(cause.label().to_owned()),
                _ => None,
            },
            outcome: a.outcome.label().to_owned(),
            error: match &a.outcome {
                entangle_scheduler::AttemptOutcome::Failed(why) => Some(why.clone()),
                _ => None,
            },
            elapsed_ms: u64::try_from(a.elapsed.as_millis()).unwrap_or(u64::MAX),
        })
        .collect()
}

/// Render a local dispatch result in the same shape the daemon returns.
fn compute_result(result: DispatchResult) -> ComputeDispatchResult {
    ComputeDispatchResult {
        chosen_peer: result.chosen.peer_id.to_hex(),
        score: result.chosen.score,
        reason: result.chosen.reason,
        output: result.output,
        // A local (daemonless) dispatch keeps no trace store to look up.
        task_id: None,
        policy_hash: Some(result.policy_hash.to_hex()),
        replicas: result
            .replicas
            .iter()
            .map(|r| ComputeReplica {
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
        attempts: rpc_attempts(&result.attempts),
        executed_component: result.executed_component.map(hex::encode),
    }
}

fn print_dispatch_output(r: &ComputeDispatchResult, json: bool) -> anyhow::Result<()> {
    if json {
        let body = serde_json::json!({
            "chosen_peer": r.chosen_peer,
            "score": r.score,
            "reason": r.reason,
            // UTF-8 text when the output is text, else null; always base64.
            "output": std::str::from_utf8(&r.output).ok(),
            "output_base64": BASE64.encode(&r.output),
            "task_id": r.task_id,
            "policy_hash": r.policy_hash,
            "replicas": r.replicas,
            "pair_agreement": r.pair_agreement,
            "spot_check": r.spot_check,
            "attempts": r.attempts,
            "executed_component": r.executed_component,
        });
        println!("{}", serde_json::to_string(&body)?);
        return Ok(());
    }
    println!("Chosen: {} (score={:.2})", r.chosen_peer, r.score);
    println!("Reason: {}", r.reason);
    if let Some(t) = &r.task_id {
        println!("Task: {t}  (entangle trace task {t})");
    }
    match std::str::from_utf8(&r.output) {
        Ok(s) if !s.contains('\x00') => println!("Output: {s}"),
        _ => println!("Output: {}", BASE64.encode(&r.output)),
    }
    if let Some(c) = &r.executed_component {
        println!("Component: {c}");
    }
    if r.attempts.len() > r.replicas.len().max(1) {
        for at in &r.attempts {
            let place = if at.remote { "remote" } else { "local" };
            let kind = match &at.cause {
                Some(cause) => format!("{} ({cause})", at.kind),
                None => at.kind.clone(),
            };
            match &at.error {
                Some(e) => println!(
                    "Attempt: replica {} {kind} on {} ({place}) {} after {}ms: {e}",
                    at.replica, at.peer, at.outcome, at.elapsed_ms
                ),
                None => println!(
                    "Attempt: replica {} {kind} on {} ({place}) {} after {}ms",
                    at.replica, at.peer, at.outcome, at.elapsed_ms
                ),
            }
        }
    }
    if r.replicas.len() > 1 {
        if let Some(h) = &r.policy_hash {
            println!("Policy: {h}");
        }
        if let Some((agreeing, pairs)) = r.pair_agreement {
            println!("Agreement: {agreeing} of {pairs} replica pairs");
        }
        for rep in &r.replicas {
            let place = if rep.remote { "remote" } else { "local" };
            match &rep.error {
                Some(e) => println!("Replica: {} ({place}) {}: {e}", rep.peer, rep.status),
                None => println!("Replica: {} ({place}) {}", rep.peer, rep.status),
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// dispatch implementation
// ---------------------------------------------------------------------------

async fn dispatch(a: DispatchArgs) -> anyhow::Result<()> {
    let input_bytes: Vec<u8> = match (a.input.as_deref(), a.input_file.as_deref()) {
        (Some(s), _) => s.as_bytes().to_vec(),
        (_, Some(path)) => tokio::fs::read(path)
            .await
            .map_err(|e| anyhow::anyhow!("reading --input-file {path}: {e}"))?,
        (None, None) => Vec::new(),
    };

    let workload = parse_workload(&a)?;
    let integrity_rpc = resolve_integrity(&a, workload)?;
    let max_output_bytes = resolve_max_output_bytes(&a, workload);
    let max_attempts = resolve_max_attempts(&a, workload);
    let gpu_vram_min_bytes = a.gpu_vram_min_mib * 1024 * 1024;

    let params = ComputeDispatchParams {
        plugin_id: a.plugin_id.clone(),
        input: input_bytes.clone(),
        timeout_ms: a.timeout_ms,
        cpu_cores: a.cpu_cores,
        memory_bytes: a.memory_bytes,
        gpu_required: a.gpu,
        gpu_vram_min_bytes,
        integrity: integrity_rpc.clone(),
        max_output_bytes,
        max_attempts,
    };

    let client = rpc_client();
    match client.compute_dispatch(params).await {
        Ok(r) => print_dispatch_output(&r, a.json),
        Err(RpcError::DaemonNotRunning(_)) => {
            if allow_local() {
                let limits = (max_output_bytes, max_attempts);
                dispatch_local(&a, input_bytes, gpu_vram_min_bytes, integrity_rpc, limits).await
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

async fn dispatch_local(
    a: &DispatchArgs,
    input_bytes: Vec<u8>,
    gpu_vram_min_bytes: u64,
    integrity: ComputeIntegrity,
    (max_output_bytes, max_attempts): (Option<u64>, Option<u8>),
) -> anyhow::Result<()> {
    use std::sync::Arc;

    let kernel = Arc::new(build_kernel()?);

    // Parse plugin id.
    let pid =
        PluginId::from_str(&a.plugin_id).map_err(|e| anyhow::anyhow!("invalid plugin id: {e}"))?;

    // A fresh kernel has nothing loaded: load the task plugin from its signed
    // package first, or every invoke fails "not loaded".
    let plugin_dir = match &a.plugin_dir {
        Some(d) => d.clone(),
        None => {
            let d = config::entangle_dir().join("plugins").join(&pid.name);
            if !d.is_dir() {
                anyhow::bail!(
                    "--allow-local needs the signed package of {pid}: pass --plugin-dir <DIR> \
                     (looked in {})",
                    d.display()
                );
            }
            d
        }
    };
    let loaded = kernel
        .load_plugin_from_dir(&plugin_dir)
        .await
        .map_err(|e| anyhow::anyhow!("loading plugin from {}: {e}", plugin_dir.display()))?;
    if loaded != pid {
        anyhow::bail!(
            "the plugin package in {} holds {loaded}, not {pid}",
            plugin_dir.display()
        );
    }

    // Build ResourceSpec.
    let gpu_req = if a.gpu || gpu_vram_min_bytes > 0 {
        Some(GpuRequirement {
            vram_min_bytes: gpu_vram_min_bytes,
            backend: GpuBackend::Any,
        })
    } else {
        None
    };
    let resources = ResourceSpec {
        cpu_cores: a.cpu_cores,
        memory_bytes: a.memory_bytes,
        gpu: gpu_req,
        ..ResourceSpec::default()
    };

    let local_peer_id = PeerId::from_public_key_bytes(&[0u8; 32]);
    let dispatcher = Dispatcher::new(WorkerPool::new(), kernel, local_peer_id);

    // Map integrity.
    let integrity_policy = match integrity {
        ComputeIntegrity::None => IntegrityPolicy::None,
        ComputeIntegrity::Deterministic { replicas } => IntegrityPolicy::Deterministic { replicas },
        ComputeIntegrity::TrustedExecutor { allowlist } => {
            // Hard-error on any malformed entry instead of silently dropping it.
            let peers: Vec<PeerId> = allowlist
                .iter()
                .map(|h| {
                    PeerId::from_hex(h)
                        .map_err(|e| anyhow::anyhow!("invalid --allow peer id '{h}': {e}"))
                })
                .collect::<anyhow::Result<_>>()?;
            IntegrityPolicy::TrustedExecutor { allowlist: peers }
        }
        ComputeIntegrity::SemanticEquivalent {
            replicas,
            quorum,
            metric,
            metric_dir,
            threshold,
        } => {
            let dir = metric_dir.ok_or_else(|| {
                anyhow::anyhow!(
                    "no signed package found for metric {metric}: pass --metric-dir <DIR> \
                     (looked in ~/.entangle/plugins/<name>)"
                )
            })?;
            let reference = dispatcher
                .verifier()
                .metrics()
                .load_from_dir(Path::new(&dir))
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if reference.plugin.to_string() != metric {
                anyhow::bail!(
                    "the metric package in {dir} holds {}, not {metric}",
                    reference.plugin
                );
            }
            IntegrityPolicy::SemanticEquivalent {
                replicas,
                quorum,
                metric: reference,
                threshold,
            }
        }
    };

    let mut task = OneShotTask::with_defaults(pid, input_bytes);
    task.resources = resources;
    task.integrity = integrity_policy;
    task.timeout_ms = a.timeout_ms;
    if let Some(n) = max_output_bytes {
        task.max_output_bytes = n;
    }
    if let Some(n) = max_attempts {
        task.retry.max_attempts = n;
    }

    let result = dispatcher
        .dispatch_one_shot(task)
        .await
        .map_err(|e| anyhow::anyhow!("dispatch error: {e}"))?;

    print_dispatch_output(&compute_result(result), a.json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(clap::Parser)]
    struct Cli {
        #[command(flatten)]
        a: DispatchArgs,
    }

    fn args(argv: &[&str]) -> DispatchArgs {
        use clap::Parser as _;
        let mut full = vec!["dispatch", "0123456789abcdef0123456789abcdef/demo@0.1.0"];
        full.extend_from_slice(argv);
        Cli::try_parse_from(full).expect("args").a
    }

    #[test]
    fn workload_presets_fill_in_what_flags_leave_unset() {
        let me = PeerId::from_public_key_bytes(&[5; 32]).to_hex();
        // a: trusted-executor over --allow, 1 MiB output cap.
        let a = args(&["--workload", "a", "--allow", &me]);
        let w = parse_workload(&a).unwrap();
        assert_eq!(
            resolve_integrity(&a, w).unwrap(),
            ComputeIntegrity::TrustedExecutor {
                allowlist: vec![me.clone()]
            }
        );
        assert_eq!(resolve_max_output_bytes(&a, w), Some(1024 * 1024));
        assert_eq!(resolve_max_attempts(&a, w), None);
        let err = resolve_integrity(&args(&["--workload", "a"]), w).unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0472"), "{err}");
        // b / b-federated / c: deterministic; c retries.
        for (name, replicas) in [("b", 1), ("b-federated", 3), ("c", 1)] {
            let a = args(&["--workload", name]);
            let w = parse_workload(&a).unwrap();
            assert_eq!(
                resolve_integrity(&a, w).unwrap(),
                ComputeIntegrity::Deterministic { replicas }
            );
            assert_eq!(resolve_max_output_bytes(&a, w), None);
        }
        let c = args(&["--workload", "c"]);
        assert_eq!(
            resolve_max_attempts(&c, parse_workload(&c).unwrap()),
            Some(3)
        );
        let err = parse_workload(&args(&["--workload", "z"])).unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0471"), "{err}");
    }

    #[test]
    fn explicit_flags_override_the_preset() {
        let me = PeerId::from_public_key_bytes(&[5; 32]).to_hex();
        let a = args(&[
            "--workload",
            "a",
            "--allow",
            &me,
            "--integrity",
            "none",
            "--max-output-bytes",
            "77",
            "--max-attempts",
            "1",
        ]);
        let w = parse_workload(&a).unwrap();
        assert_eq!(resolve_integrity(&a, w).unwrap(), ComputeIntegrity::None);
        assert_eq!(resolve_max_output_bytes(&a, w), Some(77));
        assert_eq!(resolve_max_attempts(&a, w), Some(1));
        let b = args(&[
            "--workload",
            "b",
            "--integrity",
            "deterministic",
            "--replicas",
            "5",
        ]);
        assert_eq!(
            resolve_integrity(&b, parse_workload(&b).unwrap()).unwrap(),
            ComputeIntegrity::Deterministic { replicas: 5 }
        );
        // --replicas alone overrides the preset's replica count.
        for (name, replicas) in [("b-federated", 5), ("b", 3), ("c", 2)] {
            let a = args(&["--workload", name, "--replicas", &replicas.to_string()]);
            assert_eq!(
                resolve_integrity(&a, parse_workload(&a).unwrap()).unwrap(),
                ComputeIntegrity::Deterministic { replicas },
                "--workload {name} --replicas {replicas}"
            );
        }
        // No preset, no --integrity: none, as before.
        let plain = args(&[]);
        assert_eq!(
            resolve_integrity(&plain, None).unwrap(),
            ComputeIntegrity::None
        );
    }

    #[test]
    fn default_quorum_is_a_strict_majority_of_pairs() {
        assert_eq!(default_quorum(2), 1); // 1 pair
        assert_eq!(default_quorum(3), 2); // 3 pairs
        assert_eq!(default_quorum(4), 4); // 6 pairs
        assert_eq!(default_quorum(5), 6); // 10 pairs
        assert_eq!(
            default_quorum(255),
            u8::MAX,
            "saturates instead of wrapping"
        );
    }
}
