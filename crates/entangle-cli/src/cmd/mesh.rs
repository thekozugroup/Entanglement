//! `entangle mesh` subcommands — peers, status, trust, untrust, revoke.
//!
//! Iter 9: RPC-backed `peers` and `status`; direct on-disk writes for
//! `trust` / `untrust` / `revoke` (spec §6.3 — these never go through RPC).
//!
//! The daemon picks up `~/.entangle/peers.toml` changes on next start (or,
//! future iter, via file-watch reload).

use clap::{Args, Subcommand};
use entangle_peers::{PeerStore, TrustedPeer};
use entangle_rpc::{Client as RpcClient, RpcError};
use entangle_types::peer_id::PeerId;

use crate::config;

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
    Peers,
    /// Show local mesh state: own peer id, active transports, peer counts.
    Status,
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
    /// Remove a peer from the allowlist.
    Untrust {
        /// Peer id (hex) to remove.
        peer_id: String,
    },
    /// Revoke a peer (keeps audit trail; refuses future connections).
    Revoke {
        /// Peer id (hex) to revoke.
        peer_id: String,
    },
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

pub async fn run(args: MeshArgs) -> anyhow::Result<()> {
    match args.cmd {
        MeshCmd::Peers => peers().await,
        MeshCmd::Status => status().await,
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

async fn peers() -> anyhow::Result<()> {
    let client = rpc_client();

    let result = match client.mesh_peers().await {
        Ok(r) => r,
        Err(RpcError::DaemonNotRunning(_)) => {
            if allow_local() {
                // Stub: no mDNS in-process — return empty list.
                print_peers_table(&[]);
                return Ok(());
            }
            return Err(daemon_not_running_error());
        }
        Err(e) => return Err(e.into()),
    };

    print_peers_table(&result.peers);
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

async fn status() -> anyhow::Result<()> {
    let client = rpc_client();

    let result = match client.mesh_status().await {
        Ok(r) => r,
        Err(RpcError::DaemonNotRunning(_)) => {
            if allow_local() {
                // Stub local status.
                println!("local_peer_id:       (none — daemon not running)");
                println!("local_display_name:  (none)");
                println!("transports_active:   []");
                println!("seen_peer_count:     0");
                println!("trusted_peer_count:  0");
                return Ok(());
            }
            return Err(daemon_not_running_error());
        }
        Err(e) => return Err(e.into()),
    };

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

    let mut peer = TrustedPeer::new(peer_id, public_key_hex, display_name.clone());
    if !note.is_empty() {
        peer.note = note;
    }

    store.add(peer)?;
    println!("trusted: {} ({})", peer_id_hex, display_name);
    Ok(())
}

// ── `untrust` ────────────────────────────────────────────────────────────────

fn untrust(peer_id_hex: String) -> anyhow::Result<()> {
    let peer_id = parse_peer_id(&peer_id_hex)?;
    let store = open_peer_store()?;

    match store.remove(&peer_id)? {
        Some(_) => println!("removed: {}", peer_id_hex),
        None => println!("peer not found: {}", peer_id_hex),
    }
    Ok(())
}

// ── `revoke` ─────────────────────────────────────────────────────────────────

fn revoke(peer_id_hex: String) -> anyhow::Result<()> {
    let peer_id = parse_peer_id(&peer_id_hex)?;
    let store = open_peer_store()?;

    store.revoke(&peer_id)?;
    println!("revoked: {}", peer_id_hex);
    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn rpc_client() -> RpcClient {
    RpcClient::new(RpcClient::default_socket())
}

fn open_peer_store() -> anyhow::Result<PeerStore> {
    let path = config::entangle_dir().join("peers.toml");
    let store = PeerStore::open(path)?;
    Ok(store)
}

fn parse_peer_id(hex_str: &str) -> anyhow::Result<PeerId> {
    PeerId::from_hex(hex_str)
        .map_err(|e| anyhow::anyhow!("invalid peer id '{}': {}", hex_str, e))
}

fn allow_local() -> bool {
    std::env::var("ENTANGLE_ALLOW_LOCAL")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false)
}

fn daemon_not_running_error() -> anyhow::Error {
    anyhow::anyhow!(
        "error: daemon not running at ~/.entangle/sock.\n\
         Start it with 'entangled run' or pass --allow-local to use a \
         local in-process kernel (no persistent state)."
    )
}
