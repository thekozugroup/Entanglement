//! `entangle plugins` subcommands — list, load, unload, invoke plugins via local kernel.
//!
//! Phase-1 builds a fresh in-process kernel per command invocation.
//! Phase 2 will RPC into the running daemon for persistent state.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Args, Subcommand};
use entangle_runtime::{Kernel, KernelConfig};
use entangle_signing::Keyring;
use entangle_types::plugin_id::PluginId;
use std::path::Path;
use std::str::FromStr;

use crate::config;

// ---------------------------------------------------------------------------
// Clap types
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct PluginsArgs {
    #[command(subcommand)]
    pub cmd: PluginsCmd,
}

#[derive(Subcommand)]
pub enum PluginsCmd {
    /// List currently loaded plugins (local kernel — not daemon state).
    List,
    /// Load a plugin package from a directory.
    Load {
        /// Path to the plugin directory.
        dir: String,
    },
    /// Unload a plugin by its ID.
    Unload {
        /// Plugin ID in `<publisher>/<name>@<version>` format.
        plugin_id: String,
    },
    /// Invoke a loaded plugin's `run` export.
    Invoke {
        /// Plugin ID in `<publisher>/<name>@<version>` format.
        plugin_id: String,
        /// Inline input string (UTF-8). Mutually exclusive with --input-file.
        #[arg(long, conflicts_with = "input_file")]
        input: Option<String>,
        /// Path to a file whose contents are used as input bytes.
        #[arg(long, conflicts_with = "input")]
        input_file: Option<String>,
        /// Timeout for the invocation in milliseconds (default: 30 000).
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
    },
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub async fn run(args: PluginsArgs) -> anyhow::Result<()> {
    match args.cmd {
        PluginsCmd::List => list().await,
        PluginsCmd::Load { dir } => load(dir).await,
        PluginsCmd::Unload { plugin_id } => unload(plugin_id).await,
        PluginsCmd::Invoke {
            plugin_id,
            input,
            input_file,
            timeout_ms,
        } => invoke(plugin_id, input, input_file, timeout_ms).await,
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn build_kernel() -> anyhow::Result<Kernel> {
    // Phase 2 will RPC into the running daemon for persistent state.
    let kr_path = config::keyring_path();
    let keyring = Keyring::load(&kr_path)?;
    let kernel = Kernel::new(KernelConfig::default(), keyring)?;
    Ok(kernel)
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

async fn list() -> anyhow::Result<()> {
    let kernel = build_kernel()?;
    let ids = kernel.list_plugins();
    if ids.is_empty() {
        println!("no plugins loaded (standalone kernel — load via `entangle plugins load <dir>`)");
    } else {
        for id in &ids {
            println!("{id}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------

async fn load(dir: String) -> anyhow::Result<()> {
    // Phase 2 will RPC into the running daemon for persistent state.
    let kernel = build_kernel()?;
    let id = kernel.load_plugin_from_dir(Path::new(&dir)).await?;
    println!("loaded {id}");
    Ok(())
}

// ---------------------------------------------------------------------------
// unload
// ---------------------------------------------------------------------------

async fn unload(plugin_id: String) -> anyhow::Result<()> {
    // Phase 2 will RPC into the running daemon for persistent state.
    let id =
        PluginId::from_str(&plugin_id).map_err(|e| anyhow::anyhow!("invalid plugin id: {e}"))?;
    let kernel = build_kernel()?;
    kernel.unload(&id).await?;
    println!("unloaded {plugin_id}");
    Ok(())
}

// ---------------------------------------------------------------------------
// invoke
// ---------------------------------------------------------------------------

async fn invoke(
    plugin_id: String,
    input: Option<String>,
    input_file: Option<String>,
    timeout_ms: u64,
) -> anyhow::Result<()> {
    let input_bytes: Vec<u8> = match (input, input_file) {
        (Some(s), _) => s.into_bytes(),
        (_, Some(path)) => tokio::fs::read(&path)
            .await
            .map_err(|e| anyhow::anyhow!("reading --input-file {path}: {e}"))?,
        (None, None) => Vec::new(),
    };

    let id =
        PluginId::from_str(&plugin_id).map_err(|e| anyhow::anyhow!("invalid plugin id: {e}"))?;

    // Phase 1: load the plugin in-process, invoke, then drop the kernel.
    // Phase 2 will RPC into the running daemon.
    let kernel = build_kernel()?;
    let output = kernel.invoke(&id, &input_bytes, timeout_ms).await?;

    // Print as plain text if the output is valid UTF-8, otherwise as base64.
    match std::str::from_utf8(&output) {
        Ok(text) if !text.is_empty() => println!("output: {text}"),
        Ok(_) => println!("output: (empty)"),
        Err(_) => println!("output (base64): {}", BASE64.encode(&output)),
    }
    Ok(())
}
