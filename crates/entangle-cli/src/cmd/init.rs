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
use entangle_signing::Keyring;

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
    println!("and generate a fresh Ed25519 device identity.\n");

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

    std::fs::create_dir_all(&dir)?;

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
    println!("Generating identity...");

    // --- identity.key ---
    let kp = match &answers.action {
        IdentityAction::Generate => ensure_identity(&id_path)?,
        IdentityAction::Import(pem_path) => {
            let pem = std::fs::read_to_string(pem_path)
                .with_context(|| format!("read PEM from {pem_path}"))?;
            use entangle_signing::IdentityKeyPair;
            let kp =
                IdentityKeyPair::from_pem(&pem).map_err(|e| anyhow::anyhow!("invalid PEM: {e}"))?;
            std::fs::write(&id_path, &pem)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&id_path, std::fs::Permissions::from_mode(0o600));
            }
            kp
        }
    };

    let raw_fp = kp.fingerprint_hex();
    let fingerprint = fmt_fingerprint(&raw_fp);
    println!("  Wrote {} (mode 0600)", id_path.display());
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
        std::fs::write(
            &peers_path,
            "# Entanglement peer store — managed by `entangle`.\n[peers]\n",
        )?;
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

    println!();
    println!("Next steps:");
    println!("  - Pair another device:    entangle pair");
    println!("  - Add a publisher key:     entangle keyring add <hex>");
    println!("  - Start the daemon:        entangled run");
    println!("  - Run diagnostics:         entangle doctor");

    Ok(())
}
