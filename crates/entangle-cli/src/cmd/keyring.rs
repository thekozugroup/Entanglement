//! `entangle keyring` subcommands — list, add, remove trusted publisher keys.

use anyhow::Context;
use clap::{Args, Subcommand};
use entangle_signing::{IdentityPublicKey, Keyring, TrustEntry};

use crate::config;

// ---------------------------------------------------------------------------
// Clap types
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct KeyringArgs {
    #[command(subcommand)]
    pub cmd: KeyringCmd,
}

#[derive(Subcommand)]
pub enum KeyringCmd {
    /// List all trusted publisher keys in the keyring.
    List,
    /// Add a trusted publisher key.
    Add {
        /// 32-byte public key in hex (64 hex chars).
        public_key_hex: String,
        /// Human-readable name for this publisher.
        #[arg(long)]
        name: String,
        /// Optional free-form note (e.g. "vendor X official key").
        #[arg(long)]
        note: Option<String>,
    },
    /// Remove a key by its 16-byte fingerprint (32 hex chars).
    Remove {
        /// Fingerprint hex to remove.
        fingerprint_hex: String,
    },
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub async fn run(args: KeyringArgs) -> anyhow::Result<()> {
    match args.cmd {
        KeyringCmd::List => list().await,
        KeyringCmd::Add {
            public_key_hex,
            name,
            note,
        } => add(public_key_hex, name, note).await,
        KeyringCmd::Remove { fingerprint_hex } => remove(fingerprint_hex).await,
    }
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

async fn list() -> anyhow::Result<()> {
    let path = config::keyring_path();
    let kr = Keyring::load(&path)?;
    let entries: Vec<_> = kr.entries().collect();
    if entries.is_empty() {
        println!("keyring is empty — add a key with `entangle keyring add <PUBLIC_KEY_HEX> --name <NAME>`");
        return Ok(());
    }
    println!(
        "{:<34} {:<20} {:<20} note",
        "fingerprint", "name", "added_at"
    );
    println!("{}", "-".repeat(100));
    for e in entries {
        let fp = hex::encode(e.fingerprint);
        let added = e.added_at;
        println!(
            "{:<34} {:<20} {:<20} {}",
            fp, e.publisher_name, added, e.note
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// add
// ---------------------------------------------------------------------------

async fn add(public_key_hex: String, name: String, note: Option<String>) -> anyhow::Result<()> {
    // Decode hex → 32 bytes.
    let bytes = hex::decode(&public_key_hex).context("public_key_hex must be valid hex")?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "public key must be 32 bytes (64 hex chars), got {} bytes ({} hex chars)",
            bytes.len(),
            public_key_hex.len()
        );
    }
    let key_bytes: [u8; 32] = bytes.try_into().expect("length checked above");

    let pk = IdentityPublicKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("invalid public key: {e}"))?;
    let fingerprint = pk.fingerprint();
    let fp_hex = pk.fingerprint_hex();

    let added_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let entry = TrustEntry {
        fingerprint,
        public_key: key_bytes,
        publisher_name: name.clone(),
        added_at,
        note: note.unwrap_or_default(),
    };

    let path = config::keyring_path();
    let mut kr = Keyring::load(&path)?;
    kr.add(entry);
    kr.save(&path)?;

    println!("added {} \"{}\"", fp_hex, name);
    Ok(())
}

// ---------------------------------------------------------------------------
// remove
// ---------------------------------------------------------------------------

async fn remove(fingerprint_hex: String) -> anyhow::Result<()> {
    let bytes = hex::decode(&fingerprint_hex).context("fingerprint_hex must be valid hex")?;
    if bytes.len() != 16 {
        anyhow::bail!(
            "fingerprint must be 16 bytes (32 hex chars), got {} bytes",
            bytes.len()
        );
    }
    let fp: [u8; 16] = bytes.try_into().expect("length checked above");

    let path = config::keyring_path();
    let mut kr = Keyring::load(&path)?;
    match kr.remove(&fp) {
        Some(e) => {
            kr.save(&path)?;
            println!("removed {} \"{}\"", fingerprint_hex, e.publisher_name);
        }
        None => {
            println!("not found: {}", fingerprint_hex);
        }
    }
    Ok(())
}
