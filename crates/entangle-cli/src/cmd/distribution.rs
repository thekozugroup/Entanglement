//! Install a prebuilt package with publisher authentication and local tier enforcement.
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use entangle_oci::{read_file, registry as oci, PackageFiles, ARCHIVE_LIMIT};
use entangle_signing::{IdentityPublicKey, Keyring};
use std::path::Path;

use crate::config;

#[derive(Args)]
pub struct InstallArgs {
    /// Package directory, entangle.toml, signed local or HTTPS .tar.zst, or OCI reference.
    reference: String,
    /// Require this publisher/name@version before installing a package from any source.
    #[arg(long)]
    expect_id: Option<entangle_types::plugin_id::PluginId>,
    /// Use plain HTTP with an OCI registry at a literal loopback IP.
    #[arg(long)]
    http_loopback: bool,
    /// Install optional shell warning functions without prompting.
    #[arg(long, conflicts_with = "no_wrapper")]
    wrapper: bool,
    /// Disable shell warning functions and remember the opt-out.
    #[arg(long)]
    no_wrapper: bool,
}

pub async fn install(args: InstallArgs) -> Result<()> {
    let cfg = config::load(&config::config_path())?;
    let keys = Keyring::load(&config::keyring_path())?;
    let reference = &args.reference;
    let package = if reference.starts_with("oci://") {
        oci::pull(reference, args.http_loopback, &keys).await?
    } else if reference.starts_with("https://") || reference.starts_with("http://") {
        oci::fetch_archive(reference, args.http_loopback, &keys).await?
    } else {
        let path = Path::new(reference);
        if path.is_dir() || path.file_name().is_some_and(|n| n == "entangle.toml") {
            let dir = if path.is_dir() {
                path
            } else {
                path.parent().unwrap_or(Path::new("."))
            };
            PackageFiles::from_directory_with_tier_check(dir, &keys, |tier| {
                Ok(cfg.check_install_tier(tier)?)
            })?
        } else {
            ensure!(
                reference.ends_with(".tar.zst"),
                "expected a package directory, entangle.toml or .tar.zst"
            );
            let sig = read_file(Path::new(&format!("{reference}.sig")), 64)?;
            PackageFiles::from_signed_archive(&read_file(path, ARCHIVE_LIMIT)?, &sig, &keys)?
        }
    };
    if let Some(expected) = args.expect_id {
        ensure!(
            expected == package.plugin_id,
            "expected plugin {expected}, received {}",
            package.plugin_id
        );
    }
    cfg.check_install_tier(package.effective_tier)?;
    // Compile and link the exact verified bytes in a disposable kernel. A rejected
    // component must never create a persistent plugin entry.
    let staging = tempfile::tempdir()?;
    let candidate = package.cache(staging.path())?;
    config::local_kernel()?
        .load_plugin_from_dir(&candidate)
        .await?;
    let installed = package.cache(&config::entangle_dir().join("plugins/installed"))?;
    println!("Installed {}\n{}", package.plugin_id, installed.display());
    if args.no_wrapper {
        super::wrapper::disable()?;
    } else if args.wrapper {
        super::wrapper::enable(None)?;
    } else if cfg.wrappers.install.is_none() {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            let install = dialoguer::Confirm::new()
                .with_prompt(
                    "Install shell warnings for agents launched outside Entanglement sessions?",
                )
                .default(false)
                .interact()?;
            if install {
                super::wrapper::enable(None)?;
            } else {
                super::wrapper::disable()?;
            }
        }
    }
    Ok(())
}

#[derive(Args)]
pub struct RegistryArgs {
    #[command(subcommand)]
    command: RegistryCommand,
}

#[derive(Subcommand)]
enum RegistryCommand {
    /// Fetch and authenticate the full tag list with the mirror's public key.
    Tags {
        repository: String,
        /// Pinned 32-byte mirror Ed25519 public key, encoded as hex.
        #[arg(long)]
        mirror_key: String,
        /// Use HTTP at a literal loopback registry IP.
        #[arg(long)]
        http_loopback: bool,
    },
}

pub async fn registry(args: RegistryArgs) -> Result<()> {
    let RegistryCommand::Tags {
        repository,
        mirror_key,
        http_loopback,
    } = args.command;
    let raw: [u8; 32] = hex::decode(mirror_key)?
        .try_into()
        .ok()
        .context("expected 32-byte mirror public key")?;
    let listing = oci::list_tags(
        &repository,
        http_loopback,
        &IdentityPublicKey::from_bytes(&raw)?,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&listing)?);
    Ok(())
}
