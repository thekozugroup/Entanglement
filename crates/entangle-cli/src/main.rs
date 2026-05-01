//! `entangle` CLI — entry point.
//!
//! Implements Phase-1 subcommands (spec §9.2 operator UX):
//! init, version, doctor, keyring {list,add,remove}, plugins {list,load,unload,invoke}.
//! Daemon RPC wired in iter 4; falls back to local in-process kernel with --allow-local.

use clap::{Parser, Subcommand};

mod cmd;
mod config;
mod identity;

use cmd::{keyring::KeyringArgs, plugins::PluginsArgs};

#[derive(Parser)]
#[command(
 name = "entangle",
 version,
 about = "Entanglement CLI — manage plugins, identity, and trusted keys",
 long_about = None
)]
struct Cli {
    /// Use local in-process kernel (no daemon, no persistent state). For testing only.
    ///
    /// When the daemon is not running, commands normally fail with an actionable error.
    /// Pass this flag (or set ENTANGLE_ALLOW_LOCAL=1) to fall back to a short-lived
    /// in-process kernel instead.  State is NOT shared with any running daemon.
    #[arg(long, global = true)]
    allow_local: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate identity, write ~/.entangle/identity.key and config.toml.
    Init,
    /// Print detailed version information (CLI, runtime, toolchain, daemon).
    Version,
    /// Run health checks: identity, config, keyring, daemon reachability.
    Doctor,
    /// Manage the trusted publisher keyring.
    #[command(subcommand_required = true)]
    Keyring(KeyringArgs),
    /// Manage loaded plugins.
    #[command(subcommand_required = true)]
    Plugins(PluginsArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // Propagate --allow-local as an env var so subcommand modules can read it
    // without threading the flag through every call frame.
    if cli.allow_local {
        std::env::set_var("ENTANGLE_ALLOW_LOCAL", "1");
    }

    match cli.cmd {
        Cmd::Init => cmd::init::run().await,
        Cmd::Version => cmd::version::run().await,
        Cmd::Doctor => cmd::doctor::run().await,
        Cmd::Keyring(a) => cmd::keyring::run(a).await,
        Cmd::Plugins(a) => cmd::plugins::run(a).await,
    }
}
