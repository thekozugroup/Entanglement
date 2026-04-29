//! `entangle` CLI — entry point.
//!
//! Implements Phase-1 subcommands (spec §9.2 operator UX):
//! init, version, doctor, keyring {list,add,remove}, plugins {list,load,unload}.
//! Daemon RPC arrives in iter 11.

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
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate identity, write ~/.entangle/identity.key and config.toml.
    Init,
    /// Print detailed version information (CLI, runtime, toolchain).
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

    match Cli::parse().cmd {
        Cmd::Init => cmd::init::run().await,
        Cmd::Version => cmd::version::run().await,
        Cmd::Doctor => cmd::doctor::run().await,
        Cmd::Keyring(a) => cmd::keyring::run(a).await,
        Cmd::Plugins(a) => cmd::plugins::run(a).await,
    }
}
