//! `entangle plugins` subcommands — list, load, unload plugins via local kernel.
//!
//! Phase-1 builds a fresh in-process kernel per command invocation.
//! Phase 2 will RPC into the running daemon for persistent state.

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
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub async fn run(args: PluginsArgs) -> anyhow::Result<()> {
    match args.cmd {
        PluginsCmd::List => list().await,
        PluginsCmd::Load { dir } => load(dir).await,
        PluginsCmd::Unload { plugin_id } => unload(plugin_id).await,
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
