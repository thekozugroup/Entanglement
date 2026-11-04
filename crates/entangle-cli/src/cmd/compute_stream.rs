//! `entangle compute stream` — run a streaming task and write its chunks to
//! stdout as they arrive (spec §7.1).
//!
//! # Direct, not through the daemon
//!
//! Unlike `compute dispatch`, this command does **not** go through the
//! running `entangled`. It is itself the submitter: it opens its own
//! `mesh.iroh` endpoint with the node identity (`~/.entangle/identity.key`)
//! and dials the executor under `entangle/stream/1`. Why:
//!
//! * **End-to-end backpressure.** Credit is granted as *this process*
//!   consumes chunks — i.e. as fast as stdout drains. Relaying through the
//!   daemon would put a second buffer and a second flow-control layer
//!   between the executor and the terminal: the daemon's RPC
//!   (`entangle-rpc`) is one JSON request / one JSON response, with no
//!   server push, so the daemon would have to buffer the stream or
//!   re-implement credit over polling. Either way the executor would be
//!   paced by the daemon, not by the reader.
//! * **Attribution where it is used.** Each chunk is verified against the
//!   executor's transport-authenticated key in the process that prints it,
//!   and `--json` reports that per chunk.
//! * **Same identity, same trust.** The executor admits peers by `PeerId`;
//!   using the node identity means the executor's allowlist entry for this
//!   node covers the CLI too. The command dispatches only to peers this
//!   node has paired with (`~/.entangle/peers.toml`), like the daemon.
//!
//! The cost is that the CLI needs the identity key (the same file the
//! daemon reads, readable only by its owner) and its own UDP socket while
//! the stream runs.
//!
//! Without `--peer`, `--allow-local` runs the plugin in this process — the
//! same protocol over an in-memory stream, chunks signed by the node
//! identity (or a throwaway key if there is none).

use std::io::Write as _;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::Args;
use entangle_mesh_iroh::{parse_node_addr, IrohPeer, MeshIroh, MeshIrohConfig, ALPN_STREAM};
use entangle_peers::{PeerStore, TrustLevel};
use entangle_runtime::Kernel;
use entangle_scheduler::stream::{
    ChunkPoll, StreamError, StreamHandle, StreamOptions, StreamServer, TRUSTED_EXECUTOR_HINT,
};
use entangle_scheduler::StaticAllowlist;
use entangle_signing::{IdentityKeyPair, Keyring};
use entangle_types::{
    peer_id::PeerId,
    plugin_id::PluginId,
    task::{IntegrityPolicy, PartialResultPolicy, StreamingTask},
};

use crate::config;

/// `entangle compute stream` flags.
#[derive(Args)]
pub struct StreamArgs {
    /// Stream plugin ID in `<publisher>/<name>@<version>` format.
    pub plugin_id: String,

    /// Inline initial input (UTF-8). Mutually exclusive with --input-file.
    #[arg(long, conflicts_with = "input_file")]
    pub input: Option<String>,

    /// Path to a file whose contents are the initial input.
    #[arg(long, conflicts_with = "input")]
    pub input_file: Option<String>,

    /// The executor: a peer id (its address is taken from `[scheduler] peers`
    /// in ~/.entangle/config.toml) or a long address `<pubkey-hex>@host:port`.
    /// The peer must be paired (`entangle mesh trust`). Omit it, with
    /// --allow-local, to run the plugin in this process.
    #[arg(long)]
    pub peer: Option<String>,

    /// Integrity policy: none | trusted-executor. Streams cannot be
    /// replicated, so deterministic and semantic-equivalent are refused.
    #[arg(long, default_value = "none")]
    pub integrity: String,

    /// trusted-executor: peer ids the executor must be one of. May be repeated.
    #[arg(long = "allow")]
    pub allow: Vec<String>,

    /// What an interrupted stream leaves: keep | keep-signed | discard.
    /// `discard` holds all output back until the stream completes.
    #[arg(long, default_value = "keep")]
    pub partial: String,

    /// Wall-clock timeout for the whole stream, in milliseconds.
    #[arg(long, default_value_t = StreamingTask::DEFAULT_TIMEOUT_MS)]
    pub timeout_ms: u64,

    /// Credit window: chunks the executor may send ahead of this reader.
    #[arg(long, default_value_t = 16)]
    pub credit_window: u32,

    /// --allow-local only: the plugin's signed package directory. Defaults to
    /// `~/.entangle/plugins/<plugin-name>`.
    #[arg(long)]
    pub plugin_dir: Option<PathBuf>,

    /// Write one JSON object per chunk (seq, bytes, text/base64, signature
    /// status) and a final status object, instead of the raw bytes.
    #[arg(long)]
    pub json: bool,
}

fn parse_partial(s: &str) -> anyhow::Result<PartialResultPolicy> {
    match s {
        "keep" => Ok(PartialResultPolicy::Keep),
        "keep-signed" => Ok(PartialResultPolicy::KeepSigned),
        "discard" => Ok(PartialResultPolicy::Discard),
        other => {
            anyhow::bail!("unknown --partial '{other}'; expected keep, keep-signed or discard")
        }
    }
}

fn parse_integrity(a: &StreamArgs) -> anyhow::Result<IntegrityPolicy> {
    match a.integrity.as_str() {
        "none" => {
            if !a.allow.is_empty() {
                anyhow::bail!("--allow only applies with --integrity trusted-executor");
            }
            Ok(IntegrityPolicy::None)
        }
        "trusted-executor" => {
            let allowlist = a
                .allow
                .iter()
                .map(|h| {
                    PeerId::from_hex(h)
                        .map_err(|e| anyhow::anyhow!("invalid --allow peer id '{h}': {e}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            if allowlist.is_empty() {
                anyhow::bail!("--integrity trusted-executor needs at least one --allow <peer-id>");
            }
            Ok(IntegrityPolicy::TrustedExecutor { allowlist })
        }
        // Let the scheduler's own submit-time check explain the refusal
        // (ENTANGLE-E0350, ATC-INT-4), so the CLI says exactly what the
        // library would.
        "deterministic" => Ok(IntegrityPolicy::Deterministic { replicas: 3 }),
        other => anyhow::bail!(
            "--integrity {other} cannot be used for a stream; streams accept none or \
             trusted-executor. hint: {TRUSTED_EXECUTOR_HINT}"
        ),
    }
}

fn read_input(a: &StreamArgs) -> anyhow::Result<Vec<u8>> {
    Ok(match (a.input.as_deref(), a.input_file.as_deref()) {
        (Some(s), _) => s.as_bytes().to_vec(),
        (_, Some(path)) => {
            std::fs::read(path).with_context(|| format!("reading --input-file {path}"))?
        }
        (None, None) => Vec::new(),
    })
}

/// The node identity, if this machine has one.
fn node_identity() -> anyhow::Result<Option<IdentityKeyPair>> {
    let path = config::identity_path();
    if !path.exists() {
        return Ok(None);
    }
    let pem =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let key = IdentityKeyPair::from_pem(&pem)
        .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
    Ok(Some(key))
}

/// The raw `~/.entangle/config.toml`, read leniently: this command needs
/// only `[scheduler] peers` / `relay`, which the CLI's own schema does not
/// model (the daemon owns that section).
fn raw_config() -> anyhow::Result<toml::Value> {
    let path = config::config_path();
    if !path.exists() {
        return Ok(toml::Value::Table(Default::default()));
    }
    let text = std::fs::read_to_string(&path)?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Resolve `--peer` to a dialable descriptor.
fn resolve_peer(spec: &str, cfg: &toml::Value) -> anyhow::Result<IrohPeer> {
    if spec.contains('@') {
        return parse_node_addr(spec).map_err(|e| anyhow::anyhow!("--peer {spec}: {e}"));
    }
    let id = PeerId::from_hex(spec).map_err(|e| {
        anyhow::anyhow!("--peer must be a peer id or <pubkey-hex>@host:port, got '{spec}': {e}")
    })?;
    let entries = cfg
        .get("scheduler")
        .and_then(|s| s.get("peers"))
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    entries
        .iter()
        .filter_map(|v| v.as_str())
        .filter_map(|s| parse_node_addr(s).ok())
        .find(|p| p.peer_id == id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no address known for peer {id}: add its long address to [scheduler] peers in \
                 ~/.entangle/config.toml, or pass --peer <pubkey-hex>@host:port"
            )
        })
}

pub async fn run(a: StreamArgs) -> anyhow::Result<()> {
    let plugin =
        PluginId::from_str(&a.plugin_id).map_err(|e| anyhow::anyhow!("invalid plugin id: {e}"))?;
    let mut task = StreamingTask::with_defaults(plugin.clone(), read_input(&a)?);
    task.integrity = parse_integrity(&a)?;
    task.partial_result = parse_partial(&a.partial)?;
    // Text mode prints raw bytes, which carry no signatures: `keep-signed`
    // would keep nothing `keep` does not. The signatures are in `--json`.
    if task.partial_result == PartialResultPolicy::KeepSigned && !a.json {
        anyhow::bail!(
            "--partial keep-signed needs --json: the plain byte output carries no signatures,              so nothing attributable would be kept (use --partial keep for the bytes alone)"
        );
    }
    task.timeout_ms = a.timeout_ms;
    task.channel.credit_window = a.credit_window;
    // ATC-INT-4: refused here, before any socket is opened.
    entangle_scheduler::validate_stream_submit(&task)?;

    match &a.peer {
        Some(spec) => run_remote(&a, &task, spec).await,
        None if allow_local() => run_local(&a, &task, &plugin).await,
        None => anyhow::bail!(
            "entangle compute stream runs directly against an executor (not through the \
             daemon): pass --peer <peer-id|pubkey-hex@host:port>, or --allow-local to run the \
             plugin in this process"
        ),
    }
}

fn allow_local() -> bool {
    std::env::var("ENTANGLE_ALLOW_LOCAL")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

async fn run_remote(a: &StreamArgs, task: &StreamingTask, spec: &str) -> anyhow::Result<()> {
    let identity = node_identity()?.ok_or_else(|| {
        anyhow::anyhow!(
            "no node identity at {}: run `entangle init` first (the executor admits this node \
             by its identity)",
            config::identity_path().display()
        )
    })?;
    let cfg = raw_config()?;
    let peer = resolve_peer(spec, &cfg)?;
    let store = PeerStore::open(config::entangle_dir().join("peers.toml"))?;
    if !matches!(store.get(&peer.peer_id), Some(p) if p.trust != TrustLevel::Revoked) {
        anyhow::bail!(
            "peer {} is not trusted: pair it first (`entangle mesh trust` / `entangle pair`)",
            peer.peer_id
        );
    }
    let relay = cfg
        .get("scheduler")
        .and_then(|s| s.get("relay"))
        .and_then(|r| r.as_bool())
        .unwrap_or(true);
    let transport = MeshIroh::start(
        MeshIrohConfig {
            alpn: ALPN_STREAM.to_vec(),
            allow_derp_relay: relay,
            ..MeshIrohConfig::default()
        },
        &identity,
    )
    .await
    .context("starting the mesh.iroh endpoint")?;
    let handle =
        entangle_scheduler::open_stream(&transport, &peer, task, StreamOptions::default()).await?;
    let result = consume(handle, a.json, task.partial_result).await;
    use entangle_mesh_iroh::MeshTransport as _;
    transport.shutdown().await;
    result
}

async fn run_local(a: &StreamArgs, task: &StreamingTask, plugin: &PluginId) -> anyhow::Result<()> {
    let keyring = Keyring::load(&config::keyring_path())?;
    // The same config-honouring kernel as `compute dispatch --allow-local`:
    // a local stream is never more permissive than the daemon would be.
    let kernel = Arc::new(
        Kernel::new(config::kernel_config()?, keyring)
            .map_err(|e| anyhow::anyhow!("failed to build kernel: {e}"))?,
    );
    let dir = match &a.plugin_dir {
        Some(d) => d.clone(),
        None => config::entangle_dir().join("plugins").join(&plugin.name),
    };
    let loaded = kernel
        .load_plugin_from_dir(&dir)
        .await
        .map_err(|e| anyhow::anyhow!("loading plugin from {}: {e}", dir.display()))?;
    if &loaded != plugin {
        anyhow::bail!(
            "the plugin package in {} holds {loaded}, not {plugin}",
            dir.display()
        );
    }
    // The executor is this node (its identity signs the chunks); the
    // submitter end is a throwaway key the in-process executor admits.
    let executor = node_identity()?.unwrap_or_else(IdentityKeyPair::generate);
    let submitter = IdentityKeyPair::generate();
    let submitter_id = PeerId::from_public_key_bytes(submitter.public().as_bytes());
    let server = StreamServer::new(
        kernel,
        Arc::new(StaticAllowlist::new().allow(submitter_id)),
        executor.clone(),
    );
    let (sub_io, exec_io) = entangle_mesh_iroh::duplex_pair(
        *submitter.public().as_bytes(),
        *executor.public().as_bytes(),
        entangle_mesh_iroh::MAX_FRAME_BYTES,
        entangle_mesh_iroh::DEFAULT_DUPLEX_BUFFER,
    );
    let served = tokio::spawn(async move { server.handle(exec_io).await });
    let handle = StreamHandle::start(sub_io, task, StreamOptions::default())?;
    let result = consume(handle, a.json, task.partial_result).await;
    let _ = served.await;
    result
}

/// Print chunks as they arrive (or, under `discard`, once the stream is
/// complete), then the outcome.
async fn consume(
    mut handle: StreamHandle,
    json: bool,
    partial: PartialResultPolicy,
) -> anyhow::Result<()> {
    // No input beyond the initial one.
    handle.finish_input().await.ok();
    let executor = handle.executor();
    let hold_back = partial == PartialResultPolicy::Discard;
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut out = std::io::stdout();
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let mut cancelled = false;
    let terminal = loop {
        let poll = tokio::select! {
            poll = handle.next() => poll,
            _ = &mut interrupt, if !cancelled => {
                cancelled = true;
                handle.cancel().await;
                continue;
            }
        };
        match poll {
            ChunkPoll::Chunk(chunk) => {
                let line = if json {
                    let mut l = serde_json::to_vec(&serde_json::json!({
                        "seq": chunk.seq,
                        "bytes": chunk.bytes.len(),
                        "text": std::str::from_utf8(&chunk.bytes).ok(),
                        "base64": BASE64.encode(&chunk.bytes),
                        "signature": "verified",
                        "signature_hex": hex::encode(chunk.signature.to_bytes()),
                    }))?;
                    l.push(b'\n');
                    l
                } else {
                    chunk.bytes
                };
                if hold_back {
                    held.push(line);
                } else {
                    out.write_all(&line)?;
                    out.flush()?;
                }
            }
            other => break other,
        }
    };
    let report = handle.finish().await;
    match terminal {
        ChunkPoll::Ended(end) => {
            for line in held {
                out.write_all(&line)?;
            }
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "complete",
                        "executor": executor.to_hex(),
                        "chunks": end.chunks,
                        "bytes": end.bytes,
                        "transcript": hex::encode(end.transcript),
                        "end_signature_hex": hex::encode(end.signature.to_bytes()),
                    })
                );
            }
            out.flush()?;
            Ok(())
        }
        ChunkPoll::Closed(error) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "interrupted",
                        "executor": executor.to_hex(),
                        "reason": error.reason().as_str(),
                        "error": error.to_string(),
                        "chunks": report.context.received_chunks,
                        "bytes": report.context.received_bytes,
                        "partial": partial_label(partial),
                    })
                );
            }
            Err(interrupted(error, partial))
        }
        ChunkPoll::Chunk(_) | ChunkPoll::Pending => {
            Err(anyhow::anyhow!("stream ended unexpectedly"))
        }
    }
}

fn partial_label(p: PartialResultPolicy) -> &'static str {
    match p {
        PartialResultPolicy::Discard => "discarded",
        PartialResultPolicy::Keep => "kept",
        PartialResultPolicy::KeepSigned => "kept-signed",
    }
}

fn interrupted(error: StreamError, partial: PartialResultPolicy) -> anyhow::Error {
    anyhow::anyhow!(
        "stream interrupted ({}); partial output {}",
        error,
        partial_label(partial)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> StreamArgs {
        StreamArgs {
            plugin_id: "0123456789abcdef0123456789abcdef/s@0.1.0".into(),
            input: None,
            input_file: None,
            peer: None,
            integrity: "none".into(),
            allow: vec![],
            partial: "keep".into(),
            timeout_ms: 1,
            credit_window: 1,
            plugin_dir: None,
            json: false,
        }
    }

    #[test]
    fn integrity_flags_map_onto_stream_policies() {
        assert_eq!(parse_integrity(&args()).unwrap(), IntegrityPolicy::None);
        let mut a = args();
        a.integrity = "trusted-executor".into();
        assert!(parse_integrity(&a).is_err(), "needs --allow");
        a.allow = vec![PeerId::from_public_key_bytes(&[1; 32]).to_hex()];
        assert!(matches!(
            parse_integrity(&a).unwrap(),
            IntegrityPolicy::TrustedExecutor { allowlist } if allowlist.len() == 1
        ));
        let mut a = args();
        a.integrity = "semantic-equivalent".into();
        let err = parse_integrity(&a).unwrap_err().to_string();
        assert!(err.contains("TrustedExecutor"), "{err}");
    }

    #[test]
    fn peers_resolve_from_long_addresses_or_the_scheduler_section() {
        let key = [0xaa; 32];
        let long = format!("{}@127.0.0.1:4100", hex::encode(key));
        let cfg: toml::Value =
            toml::from_str(&format!("[scheduler]\npeers = [\"{long}\"]\n")).unwrap();
        let by_addr = resolve_peer(&long, &toml::Value::Table(Default::default())).unwrap();
        let by_id = resolve_peer(&by_addr.peer_id.to_hex(), &cfg).unwrap();
        assert_eq!(by_addr, by_id);
        let other = PeerId::from_public_key_bytes(&[0xbb; 32]).to_hex();
        assert!(resolve_peer(&other, &cfg).is_err());
        assert!(resolve_peer("nonsense", &cfg).is_err());
    }

    #[test]
    fn partial_policies_parse() {
        assert_eq!(parse_partial("keep").unwrap(), PartialResultPolicy::Keep);
        assert_eq!(
            parse_partial("keep-signed").unwrap(),
            PartialResultPolicy::KeepSigned
        );
        assert_eq!(
            parse_partial("discard").unwrap(),
            PartialResultPolicy::Discard
        );
        assert!(parse_partial("maybe").is_err());
    }
}
