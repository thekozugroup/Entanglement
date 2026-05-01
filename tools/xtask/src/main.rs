//! Entanglement xtask — workspace automation tasks (build, sign, package).
//!
//! This binary is invoked via `cargo xtask <task>` and is not a library crate.
//! It is excluded from rustdoc contracts.
//!
//! Usage:
//! ```text
//! cargo xtask hello-world build [--key PATH]
//! ```

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use entangle_signing::{sign_artifact, IdentityKeyPair};

#[derive(Parser)]
#[command(name = "xtask", about = "Entanglement workspace tasks")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Tasks for the hello-world example plugin.
    #[command(name = "hello-world")]
    HelloWorld {
        #[command(subcommand)]
        action: HelloWorldAction,
    },
}

#[derive(Subcommand)]
enum HelloWorldAction {
    /// Build the hello-world plugin and sign it into dist/.
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
        Task::HelloWorld {
            action: HelloWorldAction::Build { key },
        } => hello_world_build(key),
    }
}

fn hello_world_build(key_path: Option<PathBuf>) -> Result<()> {
    // Resolve workspace root (two levels up from tools/xtask/).
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let workspace_root = manifest_dir
        .parent() // tools/
        .and_then(|p| p.parent()) // workspace root
        .map(|p| p.to_owned())
        .context("could not determine workspace root from CARGO_MANIFEST_DIR")?;

    let example_dir = workspace_root.join("examples/hello-world");
    let example_manifest = example_dir.join("Cargo.toml");
    let dist_dir = example_dir.join("dist");

    // Step 1: assert wasm32-wasip2 target is installed.
    println!("[xtask] checking wasm32-wasip2 target...");
    let rustup_out = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .context("rustup not found — install rustup")?;
    let installed = String::from_utf8_lossy(&rustup_out.stdout);
    if !installed.contains("wasm32-wasip2") {
        bail!(
            "wasm32-wasip2 target not installed.\n\
             Run: rustup target add wasm32-wasip2"
        );
    }

    // Step 2: cargo build --release --target wasm32-wasip2.
    println!("[xtask] building hello-world plugin...");
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--target",
            "wasm32-wasip2",
            "--manifest-path",
        ])
        .arg(&example_manifest)
        .status()
        .context("cargo build failed")?;
    if !status.success() {
        bail!("cargo build --release --target wasm32-wasip2 failed");
    }

    // Step 3: locate the built artifact.
    // The wasm ends up relative to the example's own Cargo.toml, under
    // examples/hello-world/target/ since the example has its own [workspace].
    let wasm_src = example_dir.join("target/wasm32-wasip2/release/entangle_hello_world.wasm");
    if !wasm_src.exists() {
        bail!(
            "built artifact not found at {}\n\
             Did the build succeed?",
            wasm_src.display()
        );
    }

    // Step 4: read the identity key.
    let key_path = key_path.unwrap_or_else(|| dirs_home().join(".entangle/identity.key"));
    println!("[xtask] reading identity key from {}", key_path.display());
    if !key_path.exists() {
        bail!(
            "identity key not found at {}\n\
             Run `entangle init` to generate one.",
            key_path.display()
        );
    }
    let pem = std::fs::read_to_string(&key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;
    let keypair = IdentityKeyPair::from_pem(&pem)
        .map_err(|e| anyhow::anyhow!("invalid identity key: {e}"))?;
    let fingerprint = keypair.fingerprint_hex();
    println!("[xtask] publisher fingerprint: {fingerprint}");

    // Step 5: copy wasm to dist/.
    std::fs::create_dir_all(&dist_dir).context("creating dist dir")?;
    let wasm_dst = dist_dir.join("plugin.wasm");
    std::fs::copy(&wasm_src, &wasm_dst)
        .with_context(|| format!("copying wasm to {}", wasm_dst.display()))?;
    println!("[xtask] wrote {}", wasm_dst.display());

    // Step 6: sign the wasm.
    let wasm_bytes = std::fs::read(&wasm_dst).context("reading wasm for signing")?;
    let bundle = sign_artifact(&wasm_bytes, &keypair);
    let sig_toml = toml::to_string(&bundle).context("serializing signature bundle")?;
    let sig_dst = dist_dir.join("plugin.wasm.sig");
    std::fs::write(&sig_dst, &sig_toml)
        .with_context(|| format!("writing {}", sig_dst.display()))?;
    println!("[xtask] wrote {}", sig_dst.display());

    // Step 7: rewrite dist/entangle.toml with real fingerprint.
    let plugin_id = format!("{fingerprint}/hello-world");
    let manifest_content = format!(
        r#"[plugin]
id = "{plugin_id}"
version = "0.1.0"
tier = 1
runtime = "wasm"
description = "§9.3 walkthrough — hello-world plugin"

[capabilities]
# tier 1: no capabilities; pure compute (logging-only)

[build]
wit_world = "entangle:plugin@0.1.0/plugin"
target = "wasm32-wasip2"
"#
    );
    let manifest_dst = dist_dir.join("entangle.toml");
    std::fs::write(&manifest_dst, &manifest_content)
        .with_context(|| format!("writing {}", manifest_dst.display()))?;
    println!("[xtask] wrote {}", manifest_dst.display());

    println!("[xtask] done. dist/:");
    println!("  plugin.wasm");
    println!("  plugin.wasm.sig");
    println!("  entangle.toml  (plugin id: {plugin_id})");
    println!();
    println!("Next steps:");
    println!("  entangle keyring add {fingerprint} --name self");
    println!("  entangle plugins load examples/hello-world/dist/");

    Ok(())
}

/// Return the user's home directory.
fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}
