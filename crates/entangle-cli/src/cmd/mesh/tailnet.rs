//! Link an already trusted worker to one device visible to the local Tailscale daemon.

use std::fs::{File, Permissions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use clap::Subcommand;
use entangle_mesh_tailscale::{is_tailnet_ip, MeshTailscale, TailnetStatus};
use entangle_peers::{PeerStore, TrustLevel};
use entangle_runtime::config::{lock_config_writer, Config, TailnetPeerConfig};
use entangle_signing::{IdentityKeyPair, IdentityPublicKey};
use entangle_types::peer_id::PeerId;
use rustix::fs::{open, Mode, OFlags};
use serde::Serialize;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table};

use crate::config;

#[derive(Subcommand)]
pub enum TailnetCmd {
    /// Associate an online Tailscale device with a previously trusted Entanglement worker.
    Link {
        /// Stable Tailscale node ID from `entangle mesh tailnet`.
        node_id: String,
        /// Trusted Entanglement peer ID (hex fingerprint).
        #[arg(long)]
        peer: String,
        /// Scheduler UDP port on the worker.
        #[arg(long)]
        port: NonZeroU16,
    },
}

#[derive(Serialize)]
struct Link {
    node_id: String,
    peer_id: String,
    public_key: String,
    port: NonZeroU16,
    changed: bool,
    tailscale_enabled: bool,
}

pub(super) async fn run(cmd: TailnetCmd, json: bool) -> Result<()> {
    let TailnetCmd::Link {
        node_id,
        peer,
        port,
    } = cmd;
    let peer = super::parse_peer_id(&peer)?;
    let status = MeshTailscale::default().status().await?;
    let pem = zeroize::Zeroizing::new(
        std::fs::read_to_string(config::identity_path())
            .context("read local Entanglement identity (run entangle init first)")?,
    );
    let local_key = IdentityKeyPair::from_pem(&pem).context("parse local identity")?;
    let local = PeerId::from_public_key_bytes(local_key.public().as_bytes());
    ensure!(
        peer != local,
        "cannot link this node's own Entanglement identity"
    );
    let link = link_worker(
        &config::config_path(),
        &super::open_peer_store()?,
        &status,
        node_id,
        peer,
        port,
    )?;
    if json {
        println!("{}", serde_json::to_string(&link)?);
    } else {
        let state = if link.changed {
            "Linked"
        } else {
            "Already linked"
        };
        println!(
            "{state} {} to trusted worker {} on UDP {}.",
            link.node_id.escape_default(),
            link.peer_id,
            link.port
        );
        if !link.tailscale_enabled {
            println!(
                "Enable tailscale in [mesh].transports on this node before using this mapping."
            );
        }
        println!("To load changes to scheduler mappings, restart entangled.");
    }
    Ok(())
}

fn link_worker(
    path: &Path,
    store: &PeerStore,
    status: &TailnetStatus,
    node_id: String,
    peer: PeerId,
    port: NonZeroU16,
) -> Result<Link> {
    let writer = lock_config_writer(path)?;
    let (original, permissions) = read_config(path)?;
    let cfg: Config = toml::from_str(&original).context("invalid Entanglement configuration")?;
    let bind: SocketAddr = cfg
        .scheduler
        .bind
        .parse()
        .context("invalid scheduler.bind")?;
    validate_node(status, &node_id, bind)?;
    // PeerStore validates the persisted ID/key binding and reloads on list_current.
    let paired = store
        .list_current()?
        .into_iter()
        .find(|entry| entry.peer_id == peer && entry.trust == TrustLevel::Trusted)
        .context(
            "no currently trusted Entanglement peer with that ID; verify and pair the worker first",
        )?;
    let raw: [u8; 32] = hex::decode(paired.public_key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid length for trusted Entanglement public key"))?;
    IdentityPublicKey::from_bytes(&raw).context("invalid trusted Entanglement public key")?;
    let public_key = hex::encode(raw);
    let changed = needs_mapping(&cfg.scheduler.tailnet_peers, &node_id, &public_key, port)?;
    if changed {
        let next = append_mapping(&original, &node_id, &public_key, port)?;
        let directory = path.parent().context("config.toml has no parent")?;
        let mut temp = tempfile::NamedTempFile::new_in(directory)?;
        temp.write_all(next.as_bytes())?;
        temp.as_file().set_permissions(permissions.clone())?;
        temp.as_file().sync_all()?;
        let (current, current_permissions) = read_config(path)?;
        ensure!(
            current == original && current_permissions == permissions,
            "configuration changed; retry the link"
        );
        ensure!(
            store.is_currently_trusted(&peer),
            "worker trust changed; retry the link"
        );
        temp.persist(path).map_err(|e| e.error)?;
        writer
            .sync_all()
            .context("mapping was committed but could not sync the configuration directory")?;
    }
    Ok(Link {
        node_id,
        peer_id: peer.to_hex(),
        public_key,
        port,
        changed,
        tailscale_enabled: cfg
            .mesh
            .transports
            .iter()
            .any(|transport| transport == "tailscale"),
    })
}

fn validate_node(status: &TailnetStatus, node_id: &str, bind: SocketAddr) -> Result<()> {
    ensure!(
        !node_id.is_empty() && node_id.trim() == node_id && !node_id.chars().any(char::is_control),
        "invalid Tailscale stable node ID"
    );
    ensure!(status.is_running(), "local Tailscale backend is not online");
    ensure!(
        status.local_ips.iter().any(|&ip| is_tailnet_ip(ip)
            && ip.is_ipv4() == bind.is_ipv4()
            && (bind.ip().is_unspecified() || bind.ip() == ip)),
        "local Tailscale node has no address compatible with scheduler.bind"
    );
    let mut matches = status.peers.iter().filter(|p| p.node_id == node_id);
    let node = matches
        .next()
        .context("no visible remote Tailscale device with that stable node ID")?;
    ensure!(
        matches.next().is_none(),
        "ambiguous Tailscale stable node ID"
    );
    ensure!(node.online, "Tailscale worker is offline");
    ensure!(
        node.ips.iter().any(|&ip| is_tailnet_ip(ip)
            && ip.is_ipv4() == bind.is_ipv4()
            && !status.local_ips.contains(&ip)),
        "worker has no remote Tailscale node address in the scheduler bind address family"
    );
    Ok(())
}

fn needs_mapping(
    peers: &[TailnetPeerConfig],
    node_id: &str,
    key: &str,
    port: NonZeroU16,
) -> Result<bool> {
    let mut found = false;
    for entry in peers {
        let same_node = entry.node_id == node_id;
        let same_key = entry.public_key.eq_ignore_ascii_case(key);
        if same_node || same_key {
            ensure!(!found && same_node && same_key && entry.port == port,
                "existing tailnet mapping conflicts with this node, key or port; review scheduler.tailnet_peers");
            found = true;
        }
    }
    Ok(!found)
}

fn append_mapping(original: &str, node_id: &str, key: &str, port: NonZeroU16) -> Result<String> {
    let mut doc: DocumentMut = original.parse()?;
    let mut entry = Table::new();
    entry.insert("node_id", toml_edit::value(node_id));
    entry.insert("public_key", toml_edit::value(key));
    entry.insert("port", toml_edit::value(i64::from(port.get())));
    let scheduler = doc.entry("scheduler").or_insert(Item::Table(Table::new()));
    let inline = scheduler.is_inline_table();
    let scheduler = scheduler
        .as_table_like_mut()
        .context("scheduler must be a table")?;
    if !scheduler.contains_key("tailnet_peers") {
        let empty = if inline {
            toml_edit::value(Array::new())
        } else {
            Item::ArrayOfTables(ArrayOfTables::new())
        };
        scheduler.insert("tailnet_peers", empty);
    }
    let peers = scheduler
        .get_mut("tailnet_peers")
        .context("missing tailnet_peers")?;
    if let Some(tables) = peers.as_array_of_tables_mut() {
        tables.push(entry);
    } else if let Some(array) = peers.as_array_mut() {
        array.push(entry.into_inline_table());
    } else {
        bail!("scheduler.tailnet_peers must be an array of tables");
    }
    let next = doc.to_string();
    toml::from_str::<Config>(&next).context("updated configuration is invalid")?;
    Ok(next)
}

fn read_config(path: &Path) -> Result<(String, Permissions)> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| {
        format!(
            "open regular configuration file {} (run entangle init first)",
            path.display()
        )
    })?;
    let mut file = File::from(fd);
    let meta = file.metadata()?;
    ensure!(meta.is_file(), "configuration must be a regular file");
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok((text, meta.permissions()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_supports_existing_inline_dotted_and_standard_tables() {
        let port = NonZeroU16::new(7443).unwrap();
        for raw in [
            "scheduler = { relay = false } # preserve me\n",
            "scheduler = { relay = false, tailnet_peers = [] } # preserve me\n",
            "scheduler.relay = false # preserve me\n",
            "[scheduler]\nrelay=false # preserve me\ntailnet_peers = []\n",
            "[scheduler]\nrelay=false # preserve me\n[[scheduler.tailnet_peers]]\nnode_id='older'\npublic_key='older-key'\nport=12\n",
            "# preserve me\n",
        ] {
            let updated = append_mapping(raw, "new", "a-key", port).unwrap();
            let config: Config = toml::from_str(&updated).unwrap();
            assert!(updated.contains("# preserve me"), "{updated}");
            let entries = config.scheduler.tailnet_peers;
            let last = entries.last().unwrap();
            assert_eq!((&*last.node_id, &*last.public_key, last.port), ("new", "a-key", port));
            if raw.contains("older") {
                assert_eq!(entries[0].node_id, "older");
                assert_eq!(entries.len(), 2);
            } else {
                assert_eq!(entries.len(), 1);
            }
        }
    }

    #[test]
    fn reusing_mapping_requires_a_single_matching_node_key_and_port() {
        let port = NonZeroU16::new(7443).unwrap();
        let old = TailnetPeerConfig {
            node_id: "n1".into(),
            public_key: "ABCD".into(),
            port,
        };
        let entries = std::slice::from_ref(&old);
        assert!(!needs_mapping(entries, "n1", "abcd", port).unwrap());
        assert!(needs_mapping(entries, "n2", "other", port).unwrap());
        assert!(needs_mapping(entries, "n1", "other", port).is_err());
        assert!(needs_mapping(entries, "n2", "abcd", port).is_err());
        assert!(needs_mapping(entries, "n1", "abcd", NonZeroU16::new(13).unwrap()).is_err());
        assert!(needs_mapping(&[old.clone(), old], "n1", "abcd", port).is_err());
    }
}
