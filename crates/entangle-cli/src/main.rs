//! `entangle` CLI — entry point.
//!
//! Implements Phase-1 subcommands (spec §9.2 operator UX):
//! init, version, doctor, keyring {list,add,remove}, plugins {list,load,unload,invoke},
//! mesh {peers,status,trust,untrust,revoke}, pair (initiator/responder).
//! Daemon RPC wired; falls back to local in-process kernel with --allow-local.
//! Pairing goes directly to peers.toml (no daemon RPC).

use clap::{Parser, Subcommand};

mod cmd;
mod config;
mod identity;

use cmd::{
    compute::ComputeArgs, init::InitArgs, keyring::KeyringArgs, mesh::MeshArgs, pair::PairArgs,
    plugins::PluginsArgs,
};

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
    Init(InitArgs),
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
    /// Manage the local mesh: list peers, trust/untrust/revoke.
    #[command(subcommand_required = true)]
    Mesh(MeshArgs),
    /// Pair this device with another (short-code + fingerprint exchange).
    Pair(PairArgs),
    /// Dispatch compute tasks via the scheduler.
    #[command(subcommand_required = true)]
    Compute(ComputeArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    entangle_observability::init_with_filter("warn,entangle=info");

    let cli = Cli::parse();

    // Propagate --allow-local as an env var so subcommand modules can read it
    // without threading the flag through every call frame.
    if cli.allow_local {
        std::env::set_var("ENTANGLE_ALLOW_LOCAL", "1");
    }

    match cli.cmd {
        Cmd::Init(a) => cmd::init::run(a).await,
        Cmd::Version => cmd::version::run().await,
        Cmd::Doctor => cmd::doctor::run().await,
        Cmd::Keyring(a) => cmd::keyring::run(a).await,
        Cmd::Plugins(a) => cmd::plugins::run(a).await,
        Cmd::Mesh(a) => cmd::mesh::run(a).await,
        Cmd::Pair(a) => cmd::pair::run(a).await,
        Cmd::Compute(a) => cmd::compute::run(a).await,
    }
}
