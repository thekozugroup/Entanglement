//! Cargo subcommand for signed, reproducible Entanglement component archives.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod archive;
mod rustc;
mod source;

#[derive(Parser)]
#[command(name = "cargo entangle", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Actions,
}

#[derive(Subcommand)]
enum Actions {
    /// Build a committed WASI plugin and write a reproducible .tar.zst package.
    Package {
        /// Plugin project directory.
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// Output archive. Defaults to the package name and version under `target/entangle`.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Publisher identity PEM. Defaults to ~/.entangle/identity.key.
        #[arg(long)]
        key: Option<PathBuf>,
        /// HTTPS Git repository to record in place of the origin URL.
        #[arg(long)]
        source_url: Option<String>,
        /// Build timestamp to record in place of the source commit timestamp.
        #[arg(long)]
        source_date_epoch: Option<u64>,
        /// Zstandard compression thread count. The default is one.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=32))]
        threads: u32,
    },
    /// Sign the SHA-256 digest of an archive with its publisher key.
    Sign {
        /// Path to the .tar.zst archive.
        archive: PathBuf,
        /// Publisher identity PEM. Defaults to ~/.entangle/identity.key.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Authenticate an archive and rebuild its recorded source commit.
    Verify {
        /// Rebuild the source and compare its packaged SHA-256 digest.
        #[arg(long = "rebuild", required = true)]
        _rebuild: bool,
        /// Path to the .tar.zst archive.
        archive: PathBuf,
        /// Local Git checkout to use in place of cloning the recorded HTTPS URL.
        #[arg(long)]
        source: Option<PathBuf>,
        /// Trusted publisher keyring. Defaults to ~/.entangle/keyring.toml.
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().collect::<Vec<_>>();
    if let Some(result) = rustc::forward(&args) {
        match result {
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(error) => {
                eprintln!("error: cargo-entangle could not run rustc: {error:#}");
                return ExitCode::FAILURE;
            }
        }
    }
    // Cargo passes its subcommand name as argv[1] when invoking a binary.
    if args.get(1).is_some_and(|arg| arg == "entangle") {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);
    let verify = matches!(cli.command, Actions::Verify { .. });
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let status = if verify { "FAIL" } else { "error" };
            eprintln!("{status}: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Actions) -> Result<()> {
    match command {
        Actions::Package {
            dir,
            out,
            key,
            source_url,
            source_date_epoch,
            threads,
        } => archive::package(
            &dir,
            out.as_deref(),
            key.as_deref(),
            source_url,
            source_date_epoch,
            threads,
        ),
        Actions::Sign { archive, key } => archive::sign(&archive, key.as_deref()),
        Actions::Verify {
            archive,
            source,
            keyring,
            ..
        } => archive::verify(&archive, source.as_deref(), keyring.as_deref()),
    }
}
