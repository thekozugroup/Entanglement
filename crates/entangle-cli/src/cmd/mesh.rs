//! `entangle mesh` subcommands — peers, routes, status, trust, untrust, revoke.
//!
//! `routes` lives in [`crate::cmd::routes`].
//!
//! Iter 9: RPC-backed `peers` and `status`; direct on-disk writes for
//! `trust` / `untrust` / `revoke` (spec §6.3 — these never go through RPC).
//!
//! The daemon picks up `~/.entangle/peers.toml` changes on next start (or,
//! future iter, via file-watch reload).
//!
//! `untrust` and `revoke` also revoke the `mesh.peer` capability token this
//! node issued to the peer while pairing (its revocation ids go into
//! `~/.entangle/revoked-tokens.toml`, which the daemon re-reads on every
//! check), and `trust` on an already-paired peer keeps the peer's token
//! fields — so taking a peer off the allowlist and putting it back by hand
//! never revives a token issued before. See `entangle peers`.

use anyhow::bail;
use clap::{Args, Subcommand};
use entangle_peers::TrustedPeer;
use entangle_rpc::{methods::MeshStatusResult, Client as RpcClient, RpcError};

use crate::cmd::peers::{open_peer_store, open_revocations, parse_peer_id, report_revoked};
use crate::daemon_not_running_error;

// ── Clap types ───────────────────────────────────────────────────────────────

/// Arguments for the `mesh` top-level subcommand.
#[derive(Args)]
pub struct MeshArgs {
    #[command(subcommand)]
    pub cmd: MeshCmd,
}

/// `entangle mesh` subcommands.
#[derive(Subcommand)]
pub enum MeshCmd {
    /// List peers seen on the mesh, indicating which are trusted.
    Peers {
        /// Emit machine-readable JSON instead of the plain-text table.
        #[arg(long)]
        json: bool,
    },
    /// Per trusted peer: which of this node's transports reach it, which one
    /// is picked, and what to change when none can (spec §6.4).
    Routes {
        /// Emit machine-readable JSON instead of the table.
        #[arg(long)]
        json: bool,
        /// Count only paths that answer a probe round trip (through the daemon).
        #[arg(long)]
        probe: bool,
        /// Per-peer probe timeout in milliseconds.
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,
    },
    /// Show local mesh state: own peer id, active transports, peer counts.
    Status {
        /// Emit machine-readable JSON instead of the plain-text summary.
        #[arg(long)]
        json: bool,
    },
    /// Add a peer to the persistent allowlist by pasting their public key hex.
    Trust {
        /// Peer id (hex) to trust.
        peer_id: String,
        /// Ed25519 public key in hex (32 bytes = 64 hex chars).
        #[arg(long)]
        public_key_hex: String,
        /// Human-readable display name for this peer.
        #[arg(long)]
        display_name: String,
        /// Optional human-readable note.
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Remove a peer from the allowlist (and revoke the capability token
    /// this node issued to it; same as `entangle peers remove`).
    Untrust {
        /// Peer id (hex) to remove.
        peer_id: String,
    },
    /// Revoke a peer (keeps audit trail; refuses future connections; revokes
    /// the capability token this node issued to it).
    Revoke {
        /// Peer id (hex) to revoke.
        peer_id: String,
    },
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

pub async fn run(args: MeshArgs) -> anyhow::Result<()> {
    match args.cmd {
        MeshCmd::Peers { json } => peers(json).await,
        MeshCmd::Status { json } => status(json).await,
        MeshCmd::Routes {
            json,
            probe,
            timeout_ms,
        } => crate::cmd::routes::run(json, probe, timeout_ms).await,
        MeshCmd::Trust {
            peer_id,
            public_key_hex,
            display_name,
            note,
        } => trust(peer_id, public_key_hex, display_name, note),
        MeshCmd::Untrust { peer_id } => untrust(peer_id),
        MeshCmd::Revoke { peer_id } => revoke(peer_id),
    }
}

// ── `peers` ──────────────────────────────────────────────────────────────────

async fn peers(json: bool) -> anyhow::Result<()> {
    let client = rpc_client();

    let peers = match client.mesh_peers().await {
        Ok(r) => r.peers,
        Err(RpcError::DaemonNotRunning(_)) => {
            if allow_local() {
                // Stub: no mDNS in-process — return empty list.
                Vec::new()
            } else {
                return Err(daemon_not_running_error());
            }
        }
        Err(e) => return Err(e.into()),
    };

    if json {
        let body = serde_json::json!({ "peers": peers });
        println!("{}", serde_json::to_string(&body)?);
    } else {
        print_peers_table(&peers);
    }
    Ok(())
}

fn print_peers_table(peers: &[entangle_rpc::MeshPeer]) {
    // Plain-ASCII table header — no external table libraries.
    println!("{:<36}  {:<16}  {:<22}  TRUST", "PEER ID", "NAME", "ADDR");
    if peers.is_empty() {
        println!("(no peers)");
        return;
    }
    for p in peers {
        let addr = p.addresses.first().map(|s| s.as_str()).unwrap_or("-");
        let trust = if p.trusted { "trusted" } else { "unpaired" };
        // Truncate peer_id to 36 chars for readability
        let short_id = if p.peer_id.len() > 36 {
            &p.peer_id[..36]
        } else {
            &p.peer_id
        };
        let name = if p.display_name.is_empty() {
            "(unknown)"
        } else {
            &p.display_name
        };
        println!("{:<36}  {:<16}  {:<22}  {}", short_id, name, addr, trust);
    }
}

// ── `status` ─────────────────────────────────────────────────────────────────

async fn status(json: bool) -> anyhow::Result<()> {
    let client = rpc_client();

    let result = match client.mesh_status().await {
        Ok(r) => r,
        Err(RpcError::DaemonNotRunning(_)) => {
            if allow_local() {
                // Stub local status — no daemon means no live mesh state.
                MeshStatusResult {
                    local_peer_id: "(none — daemon not running)".to_owned(),
                    local_display_name: "(none)".to_owned(),
                    transports_active: Vec::new(),
                    seen_peer_count: 0,
                    trusted_peer_count: 0,
                }
            } else {
                return Err(daemon_not_running_error());
            }
        }
        Err(e) => return Err(e.into()),
    };

    if json {
        println!("{}", serde_json::to_string(&result)?);
        return Ok(());
    }

    let transports = if result.transports_active.is_empty() {
        "[]".to_owned()
    } else {
        format!("[{}]", result.transports_active.join(", "))
    };

    println!("local_peer_id:       {}", result.local_peer_id);
    println!("local_display_name:  {}", result.local_display_name);
    println!("transports_active:   {}", transports);
    println!("seen_peer_count:     {}", result.seen_peer_count);
    println!("trusted_peer_count:  {}", result.trusted_peer_count);

    Ok(())
}

// ── `trust` ──────────────────────────────────────────────────────────────────

fn trust(
    peer_id_hex: String,
    public_key_hex: String,
    display_name: String,
    note: String,
) -> anyhow::Result<()> {
    let peer_id = parse_peer_id(&peer_id_hex)?;
    let store = open_peer_store()?;

    // Validate up front: decode + 32-byte length check + derive-and-compare so
    // a forged peer_id/public_key pair is rejected before it hits the store.
    let mut peer = TrustedPeer::new_validated(peer_id, public_key_hex, display_name.clone())
        .map_err(|e| anyhow::anyhow!("cannot trust peer: {e}"))?;
    if !note.is_empty() {
        peer.note = note;
    }

    // An already-paired peer keeps its token fields: the token this node
    // presents to it, and the revocation ids of the one it was issued (so a
    // later `untrust` / `peers remove` can still revoke it).
    store.add_keeping_tokens(peer)?;
    println!("trusted: {} ({})", peer_id_hex, display_name);
    Ok(())
}

// ── `untrust` ────────────────────────────────────────────────────────────────

fn untrust(peer_id_hex: String) -> anyhow::Result<()> {
    let peer_id = parse_peer_id(&peer_id_hex)?;
    let store = open_peer_store()?;
    let revocations = open_revocations()?;

    match store.remove_revoking(&peer_id, &revocations)? {
        Some(peer) => {
            println!("removed: {}", peer_id_hex);
            report_revoked(&peer);
            Ok(())
        }
        // Non-zero exit so scripts can detect a no-op removal.
        None => bail!("peer not found: {}", peer_id_hex),
    }
}

// ── `revoke` ─────────────────────────────────────────────────────────────────

fn revoke(peer_id_hex: String) -> anyhow::Result<()> {
    let peer_id = parse_peer_id(&peer_id_hex)?;
    let store = open_peer_store()?;
    let revocations = open_revocations()?;

    let issued = store.get(&peer_id);
    store.revoke_revoking(&peer_id, &revocations)?;
    println!("revoked: {}", peer_id_hex);
    if let Some(peer) = issued {
        report_revoked(&peer);
    }
    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn rpc_client() -> RpcClient {
    RpcClient::new(RpcClient::default_socket())
}

fn allow_local() -> bool {
    std::env::var("ENTANGLE_ALLOW_LOCAL")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false)
}
