//! `entangle peers` — the paired-peer allowlist and its capability tokens.
//!
//! `entangle mesh peers` lists what the *daemon* sees on the mesh; this
//! command works on `~/.entangle/peers.toml` directly (no daemon needed) and
//! shows what remote work depends on: whether this node holds a `mesh.peer`
//! capability token for each peer (spec §6.3 step 4). A peer paired before
//! tokens existed has none, and refuses this node's requests while it
//! requires tokens — re-pair it with `entangle pair`.
//!
//! `entangle peers remove` drops a peer **and** revokes the token this node
//! issued to it while pairing: its revocation ids go into the local
//! revocation set (`~/.entangle/revoked-tokens.toml`, spec §6.5 — revocation
//! is local, there is no gossip), so adding the peer back to the allowlist by
//! hand later does not revive that token. `entangle mesh untrust` and
//! `entangle mesh revoke` revoke the same way.

use anyhow::{bail, Context};
use clap::{Args, Subcommand};
use entangle_peers::{PeerStore, RevocationStore, TrustLevel, TrustedPeer, REVOCATIONS_FILE};
use entangle_types::peer_id::PeerId;

use crate::config;

/// Arguments for the `peers` top-level subcommand.
#[derive(Args)]
pub struct PeersArgs {
    #[command(subcommand)]
    pub cmd: PeersCmd,
}

/// `entangle peers` subcommands.
#[derive(Subcommand)]
pub enum PeersCmd {
    /// List paired peers and whether this node holds a capability token for
    /// each (peers without one must be re-paired with `entangle pair`).
    List {
        /// Emit machine-readable JSON instead of the plain-text table.
        #[arg(long)]
        json: bool,
    },
    /// Remove a peer and revoke the capability token this node issued to it.
    Remove {
        /// Peer id (hex) to remove.
        peer_id: String,
    },
}

/// Run `entangle peers`.
pub async fn run(args: PeersArgs) -> anyhow::Result<()> {
    match args.cmd {
        PeersCmd::List { json } => list(json),
        PeersCmd::Remove { peer_id } => remove(&peer_id),
    }
}

fn list(json: bool) -> anyhow::Result<()> {
    let mut peers = open_peer_store()?.list();
    peers.sort_by(|a, b| {
        a.display_name
            .cmp(&b.display_name)
            .then_with(|| a.peer_id.to_hex().cmp(&b.peer_id.to_hex()))
    });
    if json {
        // Never the token itself: it is a credential for this node.
        let rows: Vec<serde_json::Value> = peers
            .iter()
            .map(|p| {
                serde_json::json!({
                    "peer_id": p.peer_id.to_hex(),
                    "display_name": p.display_name,
                    "trust": trust_label(p.trust),
                    "has_token": p.has_capability_token(),
                    "issued_token": !p.issued_token_revocation_ids.is_empty(),
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "peers": rows }));
        return Ok(());
    }

    println!(
        "{:<32}  {:<20}  {:<8}  {:<7}  ISSUED",
        "PEER ID", "NAME", "TRUST", "TOKEN"
    );
    if peers.is_empty() {
        println!("(no peers — pair one with `entangle pair`)");
        return Ok(());
    }
    for p in &peers {
        println!(
            "{:<32}  {:<20}  {:<8}  {:<7}  {}",
            p.peer_id.to_hex(),
            if p.display_name.is_empty() {
                "(unnamed)"
            } else {
                &p.display_name
            },
            trust_label(p.trust),
            if p.has_capability_token() {
                "yes"
            } else {
                "none"
            },
            if p.issued_token_revocation_ids.is_empty() {
                "no"
            } else {
                "yes"
            },
        );
    }
    let tokenless = peers
        .iter()
        .filter(|p| p.trust != TrustLevel::Revoked && !p.has_capability_token())
        .count();
    if tokenless > 0 {
        println!(
            "\n{tokenless} peer(s) without a capability token: they refuse this node's remote \
             tasks and streams while they require tokens. Re-pair each with `entangle pair`."
        );
    }
    Ok(())
}

fn remove(peer_id_hex: &str) -> anyhow::Result<()> {
    let peer_id = parse_peer_id(peer_id_hex)?;
    let store = open_peer_store()?;
    let revocations = open_revocations()?;
    match store.remove_revoking(&peer_id, &revocations)? {
        Some(peer) => {
            println!("removed: {peer_id_hex}");
            report_revoked(&peer);
            Ok(())
        }
        None => bail!("peer not found: {peer_id_hex}"),
    }
}

/// Tell the operator what the removal revoked (nothing, for a peer paired
/// before tokens existed).
pub(crate) fn report_revoked(peer: &TrustedPeer) {
    let n = peer.issued_token_revocation_ids.len();
    if n > 0 {
        println!(
            "revoked the capability token this node issued to it ({n} revocation id(s) added to \
             {REVOCATIONS_FILE})"
        );
    }
}

fn trust_label(trust: TrustLevel) -> &'static str {
    match trust {
        TrustLevel::Trusted => "trusted",
        TrustLevel::Observer => "observer",
        TrustLevel::Revoked => "revoked",
    }
}

/// `~/.entangle/peers.toml`.
pub(crate) fn open_peer_store() -> anyhow::Result<PeerStore> {
    let path = config::entangle_dir().join("peers.toml");
    PeerStore::open(&path).with_context(|| format!("open {}", path.display()))
}

/// `~/.entangle/revoked-tokens.toml`. A file that exists but cannot be read
/// is an error: a revocation must never be silently dropped.
pub(crate) fn open_revocations() -> anyhow::Result<RevocationStore> {
    revocations_at(&config::entangle_dir().join(REVOCATIONS_FILE))
}

/// The revocation set at `path` (see [`open_revocations`]).
pub(crate) fn revocations_at(path: &std::path::Path) -> anyhow::Result<RevocationStore> {
    RevocationStore::open(path).with_context(|| {
        format!(
            "the capability-token revocation set {} cannot be read; fix or move it aside first",
            path.display()
        )
    })
}

pub(crate) fn parse_peer_id(hex_str: &str) -> anyhow::Result<PeerId> {
    PeerId::from_hex(hex_str).map_err(|e| anyhow::anyhow!("invalid peer id '{hex_str}': {e}"))
}
