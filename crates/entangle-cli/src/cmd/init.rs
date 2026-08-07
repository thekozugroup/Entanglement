//! `entangle init` — initialise the user's entangle directory (spec §9.2).
//!
//! Interactive mode (default): walks the operator through a 4-step wizard using
//! `dialoguer` prompts.  `--non-interactive` skips all prompts and uses defaults,
//! preserving the original silent behaviour for scripted use.

use crate::{
    config::{self, entangle_dir, Config, MeshConfig, SecurityConfig},
    identity::ensure_identity,
};
use anyhow::Context;
use clap::Args;
use entangle_signing::{IdentityKeyPair, Keyring};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Args, Debug, Default)]
pub struct InitArgs {
    /// Skip all prompts; use defaults (display_name=hostname, transports=local,
    /// max_tier=5, action=generate).  Existing files are left in place.
    #[arg(long)]
    pub non_interactive: bool,
}

// ---------------------------------------------------------------------------
// Wizard inputs
// ---------------------------------------------------------------------------

enum IdentityAction {
    Generate,
    Import(String),
}

struct WizardAnswers {
    /// Device display name (gathered for future use in config; stored when
    /// a `display_name` field is added to `Config`).
    #[allow(dead_code)]
    display_name: String,
    transports: Vec<String>,
    max_tier: u8,
    action: IdentityAction,
}

/// Empty peer store.  Trusted peers are persisted as a `[[peer]]`
/// array-of-tables (see the `entangle-peers` crate); a brand-new store is just
/// a header comment, which parses to zero peers.  The previous stub emitted a
/// bogus `[peers]` table that does not match the real schema.
const PEERS_STUB: &str = "# Entanglement peer store — managed by `entangle`.\n\
# Trusted peers are recorded as [[peer]] array-of-tables; this file starts empty.\n";

/// Write the empty peer-store stub at mode 0600.
///
/// `PeerStore::save` creates the file 0600, so a store written by the daemon or
/// by `entangle mesh trust` is owner-only. Writing the stub with a plain
/// `fs::write` would instead leave it at the process umask (0644 in a default
/// container), so a freshly-`init`ed host had a world-readable trust file until
/// its first mutation. This keeps the permission story consistent from the very
/// first write.
fn write_peers_stub(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?
        }
        #[cfg(not(unix))]
        {
            std::fs::File::create(path)?
        }
    };
    f.write_all(PEERS_STUB.as_bytes())?;
    // `mode` only applies at creation; tighten an existing file too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Import-overwrite decision (pure, unit-testable — no stdin, no I/O)
// ---------------------------------------------------------------------------

/// What the Import arm should do about an identity that may already be on disk.
///
/// Computed purely from the existing and incoming fingerprints so the
/// data-loss-relevant logic can be unit-tested without a terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ImportDecision {
    /// No identity.key on disk yet — write the imported key unconditionally.
    Write,
    /// An identity.key already exists whose fingerprint matches the imported
    /// key, so writing would be a no-op.  Leave the file untouched.
    Skip,
    /// An identity.key already exists that *differs* from the imported key (or
    /// could not be parsed).  Overwriting destroys the old Ed25519 key and
    /// breaks every existing pairing (`peer_id` derives from the public key),
    /// so this requires explicit confirmation and a backup first.
    ConfirmReplace {
        /// Fingerprint of the existing on-disk key, or `None` if it could not
        /// be parsed.
        existing_fp: Option<String>,
        /// Fingerprint of the imported key.
        new_fp: String,
    },
}

/// Decide, purely from fingerprints, what the Import arm should do.
///
/// * `None`            → no key on disk                → [`ImportDecision::Write`]
/// * `Some(Ok(fp))`    → parsed key, `fp == new_fp`    → [`ImportDecision::Skip`]
/// * `Some(Ok(fp))`    → parsed key, `fp != new_fp`    → [`ImportDecision::ConfirmReplace`]
/// * `Some(Err(()))`   → present but unparseable       → [`ImportDecision::ConfirmReplace`]
fn decide_import(existing: Option<Result<String, ()>>, new_fp: &str) -> ImportDecision {
    match existing {
        None => ImportDecision::Write,
        Some(Ok(fp)) if fp == new_fp => ImportDecision::Skip,
        Some(Ok(fp)) => ImportDecision::ConfirmReplace {
            existing_fp: Some(fp),
            new_fp: new_fp.to_string(),
        },
        Some(Err(())) => ImportDecision::ConfirmReplace {
            existing_fp: None,
            new_fp: new_fp.to_string(),
        },
    }
}

/// Read the fingerprint of the identity currently at `id_path`, if any.
///
/// Returns `None` when no file exists, `Some(Ok(fp))` when it parses to
/// fingerprint `fp`, and `Some(Err(()))` when a file is present but is not a
/// valid PEM keypair — the latter is treated as "differs" so a corrupt key is
/// never silently overwritten.
fn read_existing_fingerprint(id_path: &Path) -> Option<Result<String, ()>> {
    if !id_path.exists() {
        return None;
    }
    match std::fs::read_to_string(id_path) {
        Ok(pem) => match IdentityKeyPair::from_pem(&pem) {
            Ok(kp) => Some(Ok(kp.fingerprint_hex())),
            Err(_) => Some(Err(())),
        },
        Err(_) => Some(Err(())),
    }
}

/// Convenience: read the on-disk key at `id_path` and [`decide_import`].
fn decide_import_at(id_path: &Path, new_fp: &str) -> ImportDecision {
    decide_import(read_existing_fingerprint(id_path), new_fp)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn system_hostname() -> String {
    // Try /etc/hostname first (Linux), then env vars.
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "my-device".to_string())
}

/// Format a raw fingerprint_hex string as `xxxx-xxxx-xxxx-xxxx` (groups of 4).
fn fmt_fingerprint(raw: &str) -> String {
    raw.chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

/// Create `~/.entangle` at mode 0700 on Unix — it holds the private identity
/// key and must not be group/world accessible.
fn create_entangle_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Write PEM to `id_path`, restricting it to mode 0600 on Unix.
fn write_identity_pem(id_path: &Path, pem: &str) -> anyhow::Result<()> {
    std::fs::write(id_path, pem).with_context(|| format!("write {}", id_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(id_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Back up the existing identity to `identity.key.bak-<unix_ts>` (mode 0600)
/// before it is overwritten, so a mistaken import is at least recoverable.
/// The original file is copied, never moved.
fn backup_identity(id_path: &Path) -> anyhow::Result<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let mut name = id_path.as_os_str().to_owned();
    name.push(format!(".bak-{ts}"));
    let bak = PathBuf::from(name);
    std::fs::copy(id_path, &bak)
        .with_context(|| format!("back up {} to {}", id_path.display(), bak.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(0o600));
    }
    Ok(bak)
}

/// A changed identity invalidates every existing pairing (the peer relationship
/// was authenticated against our *old* public key).  If the store actually
/// holds peers, warn and offer to clear it.  Only reachable from the wizard's
/// confirmed-overwrite branch, so prompting here is safe.
fn warn_and_maybe_clear_stale_peers(peers_path: &Path) -> anyhow::Result<()> {
    let has_peers = std::fs::read_to_string(peers_path)
        .map(|s| s.contains("[[peer]]"))
        .unwrap_or(false);
    if !has_peers {
        return Ok(());
    }
    println!();
    println!(
        "  WARNING: your identity changed, so the pairings in {} are now stale",
        peers_path.display()
    );
    println!("           and will no longer authenticate.");
    let clear = dialoguer::Confirm::new()
        .with_prompt("  Clear peers.toml now (you will need to re-pair)?")
        .default(false)
        .interact()
        .context("clear stale peers confirmation")?;
    if clear {
        write_peers_stub(peers_path).with_context(|| format!("clear {}", peers_path.display()))?;
        println!(
            "  Cleared {}. Re-pair your devices with `entangle pair`.",
            peers_path.display()
        );
    } else {
        println!(
            "  Left {} in place — its entries should be re-paired before use.",
            peers_path.display()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Interactive wizard
// ---------------------------------------------------------------------------

fn run_wizard() -> anyhow::Result<WizardAnswers> {
    use dialoguer::{Input, Select};

    let hostname = system_hostname();

    println!("Welcome to Entanglement.\n");
    println!(
        "This will set up your local Entanglement directory at {}/",
        entangle_dir().display()
    );
    println!("and set up your Ed25519 device identity (generate or import).\n");

    // [1/4] Display name
    println!("[1/4] Choose a display name for this device.");
    println!("      Default: {hostname} (system hostname)");
    let display_name: String = Input::new()
        .with_prompt("     ")
        .default(hostname.clone())
        .interact_text()
        .context("display name prompt")?;

    // [2/4] Transports
    println!();
    println!("[2/4] Choose mesh transports to enable. Multiple separated by commas.");
    println!("      Choices:");
    println!("        local       LAN-only mDNS discovery (Phase 1, recommended)");
    println!("        iroh        QUIC mesh with NAT hole-punching (Phase 2, scaffolded)");
    println!("        tailscale   Use your existing tailnet (Phase 2, scaffolded)");
    println!("      Default: local");
    let transport_input: String = Input::new()
        .with_prompt("     ")
        .default("local".to_string())
        .interact_text()
        .context("transports prompt")?;
    let transports: Vec<String> = transport_input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let transports = if transports.is_empty() {
        vec!["local".to_string()]
    } else {
        transports
    };

    // [3/4] Max tier
    println!();
    println!("[3/4] Set max permission tier (1-5; 5 = native subprocess plugins allowed).");
    println!("      Default: 5 (most permissive — can be tightened later)");
    let tier_input: String = Input::new()
        .with_prompt("     ")
        .default("5".to_string())
        .interact_text()
        .context("max tier prompt")?;
    let max_tier: u8 = tier_input.trim().parse::<u8>().unwrap_or(5).clamp(1, 5);

    // [4/4] Identity action
    println!();
    println!("[4/4] Generate or import an identity key?");
    println!("      [g] Generate fresh Ed25519 key (recommended for new device)");
    println!("      [i] Import existing PEM file (path)");
    println!("      Default: g");
    let action_choices = &[
        "g — Generate fresh Ed25519 key",
        "i — Import existing PEM file",
    ];
    let action_idx = Select::new()
        .with_prompt("     ")
        .default(0)
        .items(action_choices)
        .interact()
        .context("identity action prompt")?;

    let action = if action_idx == 1 {
        let path: String = Input::new()
            .with_prompt("      PEM file path")
            .interact_text()
            .context("PEM path prompt")?;
        IdentityAction::Import(path.trim().to_string())
    } else {
        IdentityAction::Generate
    };

    Ok(WizardAnswers {
        display_name,
        transports,
        max_tier,
        action,
    })
}

// ---------------------------------------------------------------------------
// Core init logic
// ---------------------------------------------------------------------------

pub async fn run(args: InitArgs) -> anyhow::Result<()> {
    ensure_initialised(args, true).await
}

/// The body of `entangle init`, reusable by other commands.
///
/// `entangle quickstart` needs exactly this — create-or-keep the identity,
/// config, peer store, and keyring — but prints its own closing banner, so
/// `print_next_steps` suppresses `init`'s. Nothing about the identity-writing
/// logic is duplicated there: it all lives here.
///
/// Idempotent: with all four files present this returns early without touching
/// anything.
pub(crate) async fn ensure_initialised(
    args: InitArgs,
    print_next_steps: bool,
) -> anyhow::Result<()> {
    let dir = entangle_dir();
    let id_path = config::identity_path();
    let cfg_path = config::config_path();
    let kr_path = config::keyring_path();
    let peers_path = dir.join("peers.toml");

    // Idempotency check: all four files already present → nothing to do.
    if id_path.exists() && cfg_path.exists() && kr_path.exists() && peers_path.exists() {
        println!("Already initialized at {}.", dir.display());
        return Ok(());
    }

    create_entangle_dir(&dir)?;

    // Resolve wizard answers (interactive or default).
    let answers = if args.non_interactive {
        WizardAnswers {
            display_name: system_hostname(),
            transports: vec!["local".to_string()],
            max_tier: 5,
            action: IdentityAction::Generate,
        }
    } else {
        run_wizard()?
    };

    println!();
    match &answers.action {
        IdentityAction::Generate => println!("Setting up identity..."),
        IdentityAction::Import(_) => println!("Importing identity..."),
    }

    // --- identity.key ---
    let kp = match &answers.action {
        IdentityAction::Generate => {
            let kp = ensure_identity(&id_path)?;
            println!("  Identity ready at {} (mode 0600)", id_path.display());
            kp
        }
        IdentityAction::Import(pem_path) => {
            let pem = std::fs::read_to_string(pem_path)
                .with_context(|| format!("read PEM from {pem_path}"))?;
            let kp =
                IdentityKeyPair::from_pem(&pem).map_err(|e| anyhow::anyhow!("invalid PEM: {e}"))?;
            let new_fp = kp.fingerprint_hex();

            match decide_import_at(&id_path, &new_fp) {
                ImportDecision::Write => {
                    write_identity_pem(&id_path, &pem)?;
                    println!("  Wrote {} (mode 0600)", id_path.display());
                }
                ImportDecision::Skip => {
                    println!(
                        "  Imported key already matches {} — left in place.",
                        id_path.display()
                    );
                }
                ImportDecision::ConfirmReplace {
                    existing_fp,
                    new_fp,
                } => {
                    println!();
                    println!("  An identity already exists at {}.", id_path.display());
                    match &existing_fp {
                        Some(fp) => println!("     existing fingerprint: {}", fmt_fingerprint(fp)),
                        None => println!(
                            "     existing key is present but could NOT be parsed (corrupt?)."
                        ),
                    }
                    println!("     imported fingerprint: {}", fmt_fingerprint(&new_fp));
                    println!();
                    println!("  WARNING: overwriting REPLACES this device's Ed25519 identity.");
                    println!("           Every existing pairing breaks (peer_id derives from the");
                    println!("           public key) and the old private key is UNRECOVERABLE.");

                    let proceed = dialoguer::Confirm::new()
                        .with_prompt("  Overwrite the existing identity.key?")
                        .default(false)
                        .interact()
                        .context("identity overwrite confirmation")?;
                    if !proceed {
                        anyhow::bail!(
                            "aborted: kept existing identity.key at {}",
                            id_path.display()
                        );
                    }

                    let bak = backup_identity(&id_path)?;
                    println!("  Backed up existing key to {} (mode 0600)", bak.display());
                    write_identity_pem(&id_path, &pem)?;
                    println!("  Wrote {} (mode 0600)", id_path.display());

                    // Identity changed → any trusted peers are now stale.
                    warn_and_maybe_clear_stale_peers(&peers_path)?;
                }
            }
            kp
        }
    };

    let fingerprint = fmt_fingerprint(&kp.fingerprint_hex());
    println!("  Fingerprint: {fingerprint}");

    // --- config.toml ---
    if !cfg_path.exists() {
        let cfg = Config {
            mesh: MeshConfig {
                transports: answers.transports,
                multi_node: false,
            },
            security: SecurityConfig {
                max_tier_allowed: answers.max_tier,
            },
        };
        config::save(&cfg_path, &cfg)?;
        println!("  Wrote {}", cfg_path.display());
    } else {
        println!("  Kept existing {}", cfg_path.display());
    }

    // --- peers.toml ---
    if !peers_path.exists() {
        write_peers_stub(&peers_path)?;
        println!("  Wrote {} (empty)", peers_path.display());
    } else {
        println!("  Kept existing {}", peers_path.display());
    }

    // --- keyring.toml ---
    if !kr_path.exists() {
        Keyring::new().save(&kr_path)?;
        println!("  Wrote {} (empty)", kr_path.display());
    } else {
        println!("  Kept existing {}", kr_path.display());
    }

    if print_next_steps {
        println!();
        println!("Next steps:");
        println!("  - Install a plugin:        entangle plugins install <NAME>");
        println!("  - See what is available:   entangle plugins available");
        println!("  - Pair another device:     entangle pair");
        println!("  - Start the daemon:        entangled run");
        println!("  - Run diagnostics:         entangle doctor");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_signing::IdentityKeyPair;

    /// Deterministic keypair PEM + fingerprint for a given seed byte.
    fn seed_pem(seed: u8) -> (String, String) {
        let kp = IdentityKeyPair::from_seed(&[seed; 32]);
        (kp.to_pem(), kp.fingerprint_hex())
    }

    #[test]
    fn decide_import_no_existing_writes() {
        let (_, fp) = seed_pem(1);
        assert_eq!(decide_import(None, &fp), ImportDecision::Write);
    }

    #[test]
    fn decide_import_identical_key_is_skip() {
        let (_, fp) = seed_pem(7);
        assert_eq!(
            decide_import(Some(Ok(fp.clone())), &fp),
            ImportDecision::Skip
        );
    }

    #[test]
    fn decide_import_differing_key_requires_confirmation() {
        let (_, existing) = seed_pem(2);
        let (_, incoming) = seed_pem(3);
        assert_ne!(existing, incoming);
        assert_eq!(
            decide_import(Some(Ok(existing.clone())), &incoming),
            ImportDecision::ConfirmReplace {
                existing_fp: Some(existing),
                new_fp: incoming,
            }
        );
    }

    #[test]
    fn decide_import_unparseable_existing_requires_confirmation() {
        let (_, incoming) = seed_pem(4);
        assert_eq!(
            decide_import(Some(Err(())), &incoming),
            ImportDecision::ConfirmReplace {
                existing_fp: None,
                new_fp: incoming,
            }
        );
    }

    /// Pre-seed identity.key with a DIFFERENT key and assert the on-disk
    /// decision does NOT clobber it silently: it must land on the
    /// confirmation path, and taking a backup must preserve the old bytes
    /// (leaving the original intact).
    #[test]
    fn preseeded_differing_identity_is_not_clobbered_without_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let id_path = dir.path().join("identity.key");

        let (existing_pem, existing_fp) = seed_pem(10);
        std::fs::write(&id_path, &existing_pem).unwrap();

        let (_incoming_pem, incoming_fp) = seed_pem(11);
        assert_ne!(existing_fp, incoming_fp);

        // The pure decision must require confirmation — never a silent Write.
        let decision = decide_import_at(&id_path, &incoming_fp);
        assert_eq!(
            decision,
            ImportDecision::ConfirmReplace {
                existing_fp: Some(existing_fp.clone()),
                new_fp: incoming_fp,
            }
        );

        // The write path must back up the old key before any overwrite, and the
        // backup must preserve the original bytes byte-for-byte.
        let bak = backup_identity(&id_path).unwrap();
        assert!(bak.exists(), "backup not created");
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), existing_pem);
        // The original is untouched — backup copies, never moves.
        assert_eq!(std::fs::read_to_string(&id_path).unwrap(), existing_pem);
    }

    /// Importing a byte-identical key over an existing identity is a no-op.
    #[test]
    fn preseeded_identical_identity_is_skip() {
        let dir = tempfile::tempdir().unwrap();
        let id_path = dir.path().join("identity.key");

        let (pem, fp) = seed_pem(21);
        std::fs::write(&id_path, &pem).unwrap();

        assert_eq!(decide_import_at(&id_path, &fp), ImportDecision::Skip);
    }

    #[cfg(unix)]
    #[test]
    fn backup_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let id_path = dir.path().join("identity.key");
        let (pem, _) = seed_pem(30);
        std::fs::write(&id_path, &pem).unwrap();

        let bak = backup_identity(&id_path).unwrap();
        let mode = std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
