//! `entangle` CLI — entry point.
//!
//! Implements Phase-1 subcommands (spec §9.2 operator UX):
//! init, version, doctor, keyring {list,add,remove}, plugins {list,load,unload,invoke},
//! mesh {peers,status,trust,untrust,revoke}, pair (initiator/responder).
//! Daemon RPC wired; falls back to local in-process kernel with --allow-local.
//! Pairing goes directly to peers.toml (no daemon RPC).

use clap::{CommandFactory, Parser, Subcommand};

mod cmd;
mod config;
mod identity;

use cmd::{
    compute::ComputeArgs, init::InitArgs, keyring::KeyringArgs, mesh::MeshArgs, pair::PairArgs,
    plugins::PluginsArgs, quickstart::QuickstartArgs,
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
    /// Encrypt this stopped node's identity, trust, installed plugins and data.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Backup(cmd::backup::BackupArgs),
    /// Recover an encrypted snapshot into a fresh node home.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Restore(cmd::backup::RestoreArgs),
    /// Validate or reload the daemon security ceiling.
    Config(cmd::tier::ConfigArgs),
    /// Change live security policy.
    Security(cmd::tier::SecurityArgs),
    /// Zero to a working plugin in one command: identity, install, load, invoke.
    #[command(long_about = "\
Zero to a working plugin in one command.

  1. identity  create ~/.entangle/ and an Ed25519 identity key if absent
  2. trust     add your own publisher key to your keyring
  3. catalog   find a plugin catalog and pick a starter plugin
  4. build     compile it to wasm and sign it with your key
  5. load      into the running daemon, or a temporary in-process kernel
  6. invoke    run it on a sample input and print the output

Safe to run repeatedly: every step is a no-op when it is already done. Nothing
is downloaded — the starter plugin is built from source in a local catalog (see
`entangle plugins install --help` for how that catalog is resolved).")]
    Quickstart(QuickstartArgs),
    /// Generate identity, write ~/.entangle/identity.key and config.toml.
    Init(InitArgs),
    /// Install an authenticated package into the local plugin store.
    Install(cmd::distribution::InstallArgs),
    /// Manage optional shell warnings for agents launched outside a session.
    #[command(subcommand_required = true)]
    Wrapper(cmd::wrapper::WrapperArgs),
    /// Inspect a signed registry mirror listing.
    Registry(cmd::distribution::RegistryArgs),
    /// Print detailed version information (CLI, runtime, toolchain, daemon).
    Version,
    /// Run health checks: identity, config, keyring, daemon reachability.
    Doctor,
    /// Manage the trusted publisher keyring.
    #[command(subcommand_required = true)]
    Keyring(KeyringArgs),
    /// Author plugins (new, build) and manage loaded ones (list, load, unload, invoke).
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
    /// Process photographs with trusted mesh workers.
    #[command(subcommand_required = true)]
    Image(cmd::image::ImageArgs),
    /// Verify an Entanglement release archive.
    Release(cmd::release::ReleaseArgs),
    /// Print the host platform, OS sandbox indicators, and native plugin support.
    PrintPlatform,
    /// Print Prometheus exposition from the running daemon.
    ///
    /// Phase 1: prints the daemon's own counter/gauge/histogram families
    /// (still empty in the CLI process — wired to the daemon's registry in
    /// Phase 2 when the scrape endpoint is exposed).
    Metrics,
    /// Generate shell completion script for the given shell to stdout.
    ///
    /// Example: `entangle completions bash > /etc/bash_completion.d/entangle`.
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, powershell, elvish).
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // `iroh::net_report` probes public relay servers on startup and logs a WARN
    // per unreachable probe. On a LAN-only or offline host that is a dozen
    // alarming-looking lines dumped into the middle of `entangle pair`, none of
    // which the user can act on — relays are a WAN fallback, and LAN pairing
    // works without them. Silenced to `error` so genuine relay failures still
    // surface; `RUST_LOG` overrides this whole string when debugging.
    entangle_observability::init_with_filter("warn,entangle=info,iroh::net_report=error");

    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // Print a clean, single-line error plus its cause chain. We
            // deliberately format with `Display` (not `Debug`) so an ambient
            // `RUST_BACKTRACE=1` never dumps a stack trace on routine errors.
            eprintln!("error: {e}");
            for cause in e.chain().skip(1) {
                eprintln!("  caused by: {cause}");
            }
            std::process::ExitCode::FAILURE
        }
    }
}

/// Parse arguments and dispatch the selected subcommand.
///
/// Kept separate from `main` so the error-formatting boundary lives in exactly
/// one place and never leaks a backtrace.
async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Propagate --allow-local as an env var so subcommand modules can read it
    // without threading the flag through every call frame.
    if cli.allow_local {
        std::env::set_var("ENTANGLE_ALLOW_LOCAL", "1");
    }

    match cli.cmd {
        Cmd::Config(args) => cmd::tier::config(args).await,
        Cmd::Security(args) => cmd::tier::security(args).await,
        Cmd::Quickstart(a) => cmd::quickstart::run(a).await,
        Cmd::Init(a) => cmd::init::run(a).await,
        Cmd::Install(a) => cmd::distribution::install(a).await,
        Cmd::Wrapper(a) => cmd::wrapper::run(a),
        Cmd::Registry(a) => cmd::distribution::registry(a).await,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Cmd::Backup(a) => cmd::backup::backup(a),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Cmd::Restore(a) => cmd::backup::restore(a),
        Cmd::Version => cmd::version::run().await,
        Cmd::Doctor => cmd::doctor::run().await,
        Cmd::Keyring(a) => cmd::keyring::run(a).await,
        Cmd::Plugins(a) => cmd::plugins::run(a).await,
        Cmd::Mesh(a) => cmd::mesh::run(a).await,
        Cmd::Pair(a) => cmd::pair::run(a).await,
        Cmd::Compute(a) => cmd::compute::run(a).await,
        Cmd::Image(a) => cmd::image::run(a).await,
        Cmd::Release(a) => cmd::release::run(a),
        Cmd::PrintPlatform => print_platform(),
        Cmd::Metrics => print_metrics().await,
        Cmd::Completions { shell } => generate_completions(shell),
    }
}

/// Shared "daemon not running" error used by the RPC-backed subcommands
/// (`plugins`, `mesh`, `compute`). Deduplicated here so the wording stays
/// consistent. The leading `error: ` prefix is intentionally omitted — the
/// error boundary in `main` adds it exactly once.
pub(crate) fn daemon_not_running_error() -> anyhow::Error {
    anyhow::anyhow!(
        "daemon not running at ~/.entangle/sock.\n\
         Start it with 'entangled run' or pass --allow-local to use a \
         local in-process kernel (no persistent state)."
    )
}

/// Write a shell completion script for `shell` to stdout.
fn generate_completions(shell: clap_complete::Shell) -> anyhow::Result<()> {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
    Ok(())
}

async fn print_metrics() -> anyhow::Result<()> {
    let client = entangle_rpc::Client::new(entangle_rpc::Client::default_socket());
    let metrics =
        tokio::time::timeout(std::time::Duration::from_secs(3), client.metrics()).await??;
    print!("{metrics}");
    Ok(())
}

fn print_platform() -> anyhow::Result<()> {
    let probe = entangle_runtime::probe_os_sandbox();
    println!(
        "{} {} (sandbox: {}). {}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        probe.description(),
        entangle_runtime::os_sandbox::NATIVE_RUNNER_STATUS
    );
    Ok(())
}
