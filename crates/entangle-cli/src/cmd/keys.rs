//! `entangle keys gen` — publisher keypair generation (spec §9.3 step 2,
//! §12 M2).
//!
//! A publisher key signs plugins; it is a separate key from the node's
//! identity (`~/.entangle/identity.key`), so a plugin author can keep it
//! offline or share one between machines. The key is an ordinary
//! `entangle-signing` Ed25519 keypair in the same PKCS#8 PEM form as the
//! identity key, so every signing command takes it as is (`entangle plugins
//! build --key <file>`).
//!
//! *Deviation (spec §9.3):* keys are written under `~/.entangle/publishers/`
//! (next to the rest of Entanglement's files), not `~/.config/entangle/`.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use clap::{Args, Subcommand};
use entangle_signing::IdentityKeyPair;

use crate::config;

/// `entangle keys` arguments.
#[derive(Args)]
pub struct KeysArgs {
    #[command(subcommand)]
    cmd: KeysCmd,
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Generate an Ed25519 publisher keypair for signing plugins.
    #[command(long_about = "\
Generate an Ed25519 publisher keypair for signing plugins.

Writes ~/.entangle/publishers/<label>.key (the private key, PKCS#8 PEM, mode
0600) and <label>.pub (the public key, hex), and prints the public key and its
fingerprint. An existing key with that label is never overwritten. Sign with
`entangle plugins build --key ~/.entangle/publishers/<label>.key`; with --trust
the public key is also added to this machine's keyring, so plugins it signs
load here.")]
    Gen {
        /// Name for the key: letters, digits, `.`, `_` and `-` (it becomes the file name).
        #[arg(long)]
        label: String,
        /// Also add the public key to the local keyring (`entangle keyring`).
        #[arg(long)]
        trust: bool,
        /// Write the files here instead of ~/.entangle/publishers.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
}

/// Entry point for `entangle keys`.
pub async fn run(a: KeysArgs) -> Result<()> {
    match a.cmd {
        KeysCmd::Gen { label, trust, dir } => gen(&label, trust, dir),
    }
}

/// Where publisher keys go by default.
pub fn publishers_dir() -> PathBuf {
    config::entangle_dir().join("publishers")
}

/// A label usable as a file name: 1–64 of `[A-Za-z0-9._-]`, not starting
/// with `.` or `-`.
fn check_label(label: &str) -> Result<()> {
    let ok = !label.is_empty()
        && label.len() <= 64
        && !label.starts_with(['.', '-'])
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !ok {
        bail!(
            "ENTANGLE-E0885: invalid key label {label:?}: use 1-64 letters, digits, `.`, `_` or \
             `-`, not starting with `.` or `-`"
        );
    }
    Ok(())
}

fn create_private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    let made = {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    };
    #[cfg(not(unix))]
    let made = std::fs::create_dir_all(dir);
    made.with_context(|| format!("creating {}", dir.display()))
}

/// Create `path` (which must not exist) with `bytes` and `mode`, the mode
/// applied at creation so a private key is never readable by others.
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn gen(label: &str, trust: bool, dir: Option<PathBuf>) -> Result<()> {
    check_label(label)?;
    let dir = dir.unwrap_or_else(publishers_dir);
    let key_path = dir.join(format!("{label}.key"));
    let pub_path = dir.join(format!("{label}.pub"));
    for p in [&key_path, &pub_path] {
        if std::fs::symlink_metadata(p).is_ok() {
            bail!(
                "ENTANGLE-E0885: {} already exists; refusing to overwrite a publisher key \
                 (choose another --label, or move the old key away first)",
                p.display()
            );
        }
    }
    create_private_dir(&dir)?;

    let kp = IdentityKeyPair::generate();
    let public_hex = hex::encode(kp.public().as_bytes());
    write_new(&key_path, kp.to_pem().as_bytes(), 0o600)?;
    if let Err(e) = write_new(&pub_path, format!("{public_hex}\n").as_bytes(), 0o644) {
        // Keep the pair together: no private key without its public half.
        let _ = std::fs::remove_file(&key_path);
        return Err(e);
    }

    println!("Generated publisher key {label:?}");
    println!(
        "  private key: {} (mode 0600; keep it secret and back it up)",
        key_path.display()
    );
    println!("  public key:  {}", pub_path.display());
    println!("  ed25519:{public_hex}");
    println!(
        "  fingerprint: {} (as `entangle keyring list` shows it)",
        kp.fingerprint_hex()
    );
    if trust {
        match crate::cmd::keyring::ensure_trusted(&public_hex, label, "entangle keys gen")? {
            crate::cmd::keyring::TrustOutcome::Added { fp_hex } => {
                println!(
                    "  trusted in {} ({fp_hex})",
                    config::keyring_path().display()
                )
            }
            crate::cmd::keyring::TrustOutcome::AlreadyTrusted { fp_hex, name } => {
                println!("  already trusted as {name:?} ({fp_hex})")
            }
        }
    } else {
        println!("Trust it on a machine with: entangle keyring add {public_hex} --name {label}");
    }
    println!(
        "Sign plugins with: entangle plugins build --key {}",
        key_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_safe_file_names() {
        for good in ["alice", "a.b_c-1", "X"] {
            assert!(check_label(good).is_ok(), "{good}");
        }
        for bad in ["", ".hidden", "-x", "a/b", "..", "a b", &"x".repeat(65)] {
            let err = check_label(bad).unwrap_err().to_string();
            assert!(err.contains("ENTANGLE-E0885"), "{bad}: {err}");
        }
    }
}
