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
    List {
        /// Emit machine-readable JSON instead of the plain-text table.
        #[arg(long)]
        json: bool,
    },
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
        KeyringCmd::List { json } => list(json).await,
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

async fn list(json: bool) -> anyhow::Result<()> {
    let path = config::keyring_path();
    let kr = Keyring::load(&path)?;
    let entries: Vec<_> = kr.entries().collect();
    if json {
        let body = serde_json::json!({ "entries": entries });
        println!("{}", serde_json::to_string(&body)?);
        return Ok(());
    }
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
// add / ensure_trusted
// ---------------------------------------------------------------------------

/// What [`ensure_trusted`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustOutcome {
    /// The key was not in the keyring and has been added.
    Added {
        /// Fingerprint (32 hex chars) of the newly trusted key.
        fp_hex: String,
    },
    /// The key was already trusted; the keyring was left untouched.
    AlreadyTrusted {
        /// Fingerprint (32 hex chars) of the already-trusted key.
        fp_hex: String,
        /// Name it is already recorded under.
        name: String,
    },
}

/// Decode a 32-byte Ed25519 public key from hex, with actionable errors.
fn parse_public_key(public_key_hex: &str) -> anyhow::Result<([u8; 32], IdentityPublicKey)> {
    let bytes = hex::decode(public_key_hex).context(
        "public_key_hex must be valid hex — `entangle plugins build` prints the exact value",
    )?;
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
    Ok((key_bytes, pk))
}

/// Trust `public_key_hex`, doing nothing if it is already trusted.
///
/// This is the shared, **idempotent** trust primitive: `keyring add`,
/// `plugins install`, and `quickstart` all go through it, so trusting a key
/// twice can never error, and can never overwrite the name or note a user
/// already chose for that key.
pub fn ensure_trusted(
    public_key_hex: &str,
    name: &str,
    note: &str,
) -> anyhow::Result<TrustOutcome> {
    let (key_bytes, pk) = parse_public_key(public_key_hex)?;
    let fingerprint = pk.fingerprint();
    let fp_hex = pk.fingerprint_hex();

    let path = config::keyring_path();
    let mut kr =
        Keyring::load(&path).with_context(|| format!("reading keyring at {}", path.display()))?;

    if let Some(existing) = kr.lookup(&fingerprint) {
        return Ok(TrustOutcome::AlreadyTrusted {
            fp_hex,
            name: existing.publisher_name.clone(),
        });
    }

    let added_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    kr.add(TrustEntry {
        fingerprint,
        public_key: key_bytes,
        publisher_name: name.to_owned(),
        added_at,
        note: note.to_owned(),
    });
    kr.save(&path)
        .with_context(|| format!("writing keyring at {}", path.display()))?;

    Ok(TrustOutcome::Added { fp_hex })
}

async fn add(public_key_hex: String, name: String, note: Option<String>) -> anyhow::Result<()> {
    match ensure_trusted(&public_key_hex, &name, note.as_deref().unwrap_or(""))? {
        TrustOutcome::Added { fp_hex } => println!("added {} \"{}\"", fp_hex, name),
        TrustOutcome::AlreadyTrusted {
            fp_hex,
            name: existing,
        } => println!(
            "already trusted: {} \"{}\" (keyring unchanged)",
            fp_hex, existing
        ),
    }
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
            Ok(())
        }
        // Non-zero exit so scripts can detect a no-op removal.
        None => anyhow::bail!("not found: {}", fingerprint_hex),
    }
}
