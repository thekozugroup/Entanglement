//! Operator-facing explicit bridge grant, forwarding, and bounded destination inbox.
use super::{parse_peer_id, rpc_client};
use anyhow::{ensure, Context};
use clap::Subcommand;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Subcommand)]
pub enum BridgeCmd {
    /// Provision a fresh durable budget ledger. Never replaces an existing ledger.
    Init {
        /// Absolute ledger file in an existing private directory.
        ledger: PathBuf,
    },
    /// Sign this endpoint's finite delegation to one bridge and one destination.
    Grant {
        /// Paired bridge peer ID.
        #[arg(long)]
        via: String,
        /// Receiving peer ID.
        #[arg(long)]
        destination: String,
        /// Bytes per second, at most 1 MiB/s.
        #[arg(long)]
        rate: u64,
        /// Lifetime payload byte cap, at most 1 GiB.
        #[arg(long)]
        total: u64,
        /// Seconds from now, at most 3600.
        #[arg(long)]
        ttl: u32,
        /// New file for the sealed signed grant.
        #[arg(long)]
        output: PathBuf,
    },
    /// Deliver one signed payload through a paired bridge to a paired recipient.
    Send {
        /// Paired forwarding node.
        #[arg(long)]
        via: String,
        /// Paired receiving node.
        #[arg(long)]
        destination: String,
        /// Sealed origin grant.
        #[arg(long)]
        origin_grant: PathBuf,
        /// Sealed grant obtained from the destination.
        #[arg(long)]
        destination_grant: PathBuf,
        /// Source payload file, 1–65536 bytes.
        #[arg(long)]
        input: PathBuf,
    },
    /// Pop one verified inbox payload to stdout. Print origin and bridge IDs to stderr.
    Read,
}
pub async fn run(cmd: BridgeCmd) -> anyhow::Result<()> {
    match cmd {
        BridgeCmd::Init { ledger } => {
            ensure!(ledger.is_absolute(), "ledger path must be absolute");
            entangle_signing::BridgeReceiver::initialize(&ledger)?;
        }
        BridgeCmd::Grant {
            via,
            destination,
            rate,
            total,
            ttl,
            output,
        } => {
            let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
            let bytes = entangle_signing::mint_relay(
                &std::fs::read_to_string(crate::config::identity_path())?,
                parse_peer_id(&via)?,
                parse_peer_id(&destination)?,
                rate,
                total,
                now.checked_add(i64::from(ttl)).context("expiry overflow")?,
                now,
            )?;
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut dst = opts.open(output)?;
            dst.write_all(&bytes)?;
            dst.sync_all()?;
        }
        BridgeCmd::Send {
            via,
            destination,
            origin_grant,
            destination_grant,
            input,
        } => {
            rpc_client()
                .relay_send(&entangle_rpc::RelaySend {
                    via: parse_peer_id(&via)?,
                    destination: parse_peer_id(&destination)?,
                    origin_grant: read_bounded(&origin_grant)?,
                    destination_grant: read_bounded(&destination_grant)?,
                    bytes: read_bounded(&input)?,
                })
                .await?;
        }
        BridgeCmd::Read => {
            let message = rpc_client()
                .relay_read()
                .await?
                .context("relay inbox is empty")?;
            eprintln!("origin {} via {}", message.origin, message.bridge);
            std::io::stdout().lock().write_all(&message.bytes)?;
        }
    }
    Ok(())
}
fn read_bounded(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    ensure!(
        (1..=65536).contains(&bytes.len()),
        "{} must contain 1..65536 bytes",
        path.display()
    );
    Ok(bytes)
}
