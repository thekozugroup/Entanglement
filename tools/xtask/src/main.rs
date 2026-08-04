//! Entanglement xtask — workspace automation tasks (build, sign, package).
//!
//! This binary is invoked via `cargo xtask <task>` and is not a library crate.
//! It is excluded from rustdoc contracts.
//!
//! Usage:
//! ```text
//! cargo xtask plugin build <DIR> [--key PATH]   # any plugin directory
//! cargo xtask hello-world build [--key PATH]    # alias for examples/hello-world
//! cargo xtask hash-it build [--key PATH]        # alias for examples/hash-it
//! ```
//!
//! # Why this file no longer contains a build pipeline
//!
//! Building and signing a plugin used to live here, hardcoded to the two
//! bundled example names, which meant a third party had no supported way to
//! produce a signed package at all. That pipeline now lives in the shipped CLI
//! (`entangle plugins build <DIR>`, see `crates/entangle-cli/src/cmd/package.rs`)
//! because the audience for it is a plugin author who has the `entangle` binary
//! but not this repository checked out.
//!
//! xtask keeps working for contributors by *delegating* to that one
//! implementation rather than carrying a second copy of the signing and
//! manifest-rendering logic — the two must never be able to drift, since a
//! divergence in the rendered plugin id is exactly what produced the
//! `ENTANGLE-E0201` load failures. Shelling out to `cargo run -p entangle-cli`
//! is consistent with what xtask already does (it shells out to `cargo` and
//! `rustup`) and keeps `cargo xtask` free of heavy runtime dependencies.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "Entanglement workspace tasks")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Build and sign any plugin directory.
    Plugin {
        #[command(subcommand)]
        action: PluginAction,
    },
    /// Alias for `plugin build examples/hello-world`.
    #[command(name = "hello-world")]
    HelloWorld {
        #[command(subcommand)]
        action: ExampleAction,
    },
    /// Alias for `plugin build examples/hash-it`.
    #[command(name = "hash-it")]
    HashIt {
        #[command(subcommand)]
        action: ExampleAction,
    },
}

#[derive(Subcommand)]
enum PluginAction {
    /// Build the plugin at DIR and sign it into DIR/dist/.
    Build {
        /// Plugin project directory (contains Cargo.toml + entangle.toml).
        dir: PathBuf,
        /// Path to the identity key PEM file.
        /// Defaults to ~/.entangle/identity.key
        #[arg(long)]
        key: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ExampleAction {
    /// Build the example plugin and sign it into dist/.
    Build {
        /// Path to the identity key PEM file.
        /// Defaults to ~/.entangle/identity.key
        #[arg(long)]
        key: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Task::Plugin {
            action: PluginAction::Build { dir, key },
        } => build_plugin(&dir, key),
        Task::HelloWorld {
            action: ExampleAction::Build { key },
        } => build_plugin(&example_dir("hello-world"), key),
        Task::HashIt {
            action: ExampleAction::Build { key },
        } => build_plugin(&example_dir("hash-it"), key),
    }
}

/// Workspace root, resolved from this crate's `tools/xtask/` manifest dir.
fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    manifest_dir
        .parent() // tools/
        .and_then(|p| p.parent()) // workspace root
        .map(|p| p.to_owned())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Absolute path to a bundled example plugin directory.
fn example_dir(name: &str) -> PathBuf {
    workspace_root().join("examples").join(name)
}

/// Delegate to `entangle plugins build <dir>`, built from this workspace.
fn build_plugin(dir: &Path, key: Option<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    let root = workspace_root();

    println!("[xtask] delegating to `entangle plugins build` (crates/entangle-cli)");
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.arg("run")
        .arg("--quiet")
        .arg("--package")
        .arg("entangle-cli")
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .arg("--")
        .arg("plugins")
        .arg("build")
        .arg(dir);
    if let Some(k) = key {
        cmd.arg("--key").arg(k);
    }

    let status = cmd
        .status()
        .context("running `cargo run -p entangle-cli` — is cargo on PATH?")?;
    if !status.success() {
        bail!("entangle plugins build failed for {}", dir.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example aliases must resolve to real, buildable plugin directories —
    /// this is what used to be hardcoded string matching inside the pipeline.
    #[test]
    fn example_aliases_point_at_real_plugin_dirs() {
        for name in ["hello-world", "hash-it"] {
            let dir = example_dir(name);
            assert!(dir.is_dir(), "{} missing", dir.display());
            assert!(
                dir.join("Cargo.toml").is_file(),
                "{} has no Cargo.toml",
                dir.display()
            );
            assert!(
                dir.join("entangle.toml").is_file(),
                "{} has no entangle.toml",
                dir.display()
            );
        }
    }

    /// The generic task accepts a directory that is not a bundled example — the
    /// whole point of the generalisation. `build_plugin` rejects non-directories
    /// before it ever shells out.
    #[test]
    fn generic_build_rejects_a_non_directory() {
        let err = build_plugin(Path::new("definitely/not/here"), None)
            .expect_err("missing dir must fail");
        assert!(format!("{err:#}").contains("is not a directory"), "{err:#}");
    }

    #[test]
    fn workspace_root_contains_the_workspace_manifest() {
        assert!(workspace_root().join("Cargo.toml").is_file());
    }
}
