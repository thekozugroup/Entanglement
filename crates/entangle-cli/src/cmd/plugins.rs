//! `entangle plugins` subcommands.
//!
//! Two groups live under this noun:
//!
//! * **authoring** — `new` (scaffold a project) and `build` (compile + sign an
//!   arbitrary plugin directory into `dist/`). These are pure local operations
//!   and never touch the daemon; see [`crate::cmd::scaffold`] and
//!   [`crate::cmd::package`].
//! * **runtime** — `list`, `load`, `unload`, `invoke`.
//!
//! Iter 4: attempt RPC to the running `entangled` daemon first.
//! Falls back to a local in-process kernel ONLY when:
//!   - The daemon is not running (`RpcError::DaemonNotRunning`), AND
//!   - The user passed `--allow-local` (or `ENTANGLE_ALLOW_LOCAL=1`).
//!
//! If the daemon is not running and `--allow-local` is absent, the command
//! prints a friendly error and exits non-zero.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Args, Subcommand};
use entangle_rpc::{Client as RpcClient, RpcError};
use entangle_runtime::{Kernel, KernelConfig};
use entangle_signing::Keyring;
use entangle_types::plugin_id::PluginId;
use std::path::{Path, PathBuf};
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
    /// Scaffold a new plugin project that builds and loads as-is.
    New {
        /// Plugin name — also the crate name (`^[a-z][a-z0-9-]{0,62}$`).
        name: String,
        /// Directory to create. Defaults to `./<name>`.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Declared tier ceiling, 1..=3 (wasm plugins; 4-5 require native).
        #[arg(long, default_value_t = 1)]
        tier: u8,
        /// Manifest description.
        #[arg(long)]
        description: Option<String>,
        /// Where to get `entangle-sdk` from:
        /// `auto`, `crates-io[:<req>]`, `git[:<url>[#<rev>]]`, or `path:<DIR>`.
        #[arg(long, default_value = "auto")]
        sdk: String,
        /// Overwrite files that already exist.
        #[arg(long)]
        force: bool,
    },
    /// Build and sign a plugin project into `<dir>/dist/`.
    ///
    /// Works on any plugin directory, not just the bundled examples.
    Build {
        /// Plugin project directory (contains Cargo.toml + entangle.toml).
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// Identity key PEM. Defaults to `~/.entangle/identity.key`.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Output directory. Defaults to `<dir>/dist`.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Package this pre-built `.wasm` instead of invoking cargo.
        #[arg(long)]
        wasm: Option<PathBuf>,
        /// Target triple to compile for.
        #[arg(long, default_value = crate::cmd::package::DEFAULT_TARGET)]
        target: String,
    },
    /// List currently loaded plugins.
    List {
        /// Emit machine-readable JSON instead of a plain ID per line.
        #[arg(long)]
        json: bool,
    },
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
        PluginsCmd::New {
            name,
            path,
            tier,
            description,
            sdk,
            force,
        } => crate::cmd::scaffold::run(crate::cmd::scaffold::NewOptions {
            name,
            path,
            tier,
            description,
            sdk,
            force,
        }),
        PluginsCmd::Build {
            dir,
            key,
            out,
            wasm,
            target,
        } => crate::cmd::package::run(crate::cmd::package::BuildOptions {
            dir,
            key,
            out,
            wasm,
            target,
        }),
        PluginsCmd::List { json } => list(json).await,
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
// RPC client helper
// ---------------------------------------------------------------------------

fn rpc_client() -> RpcClient {
    RpcClient::new(RpcClient::default_socket())
}

/// Returns true when `ENTANGLE_ALLOW_LOCAL` is set to a non-empty value.
fn allow_local() -> bool {
    std::env::var("ENTANGLE_ALLOW_LOCAL")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false)
}

use crate::daemon_not_running_error;

// ---------------------------------------------------------------------------
// Local-kernel helpers (fallback path)
// ---------------------------------------------------------------------------

fn build_kernel() -> anyhow::Result<Kernel> {
    let kr_path = config::keyring_path();
    let keyring = Keyring::load(&kr_path)?;
    let kernel = Kernel::new(KernelConfig::default(), keyring)?;
    Ok(kernel)
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

async fn list(json: bool) -> anyhow::Result<()> {
    let client = rpc_client();
    match client.plugins_list().await {
        Ok(r) => {
            if json {
                let body = serde_json::json!({ "plugins": r.plugins });
                println!("{}", serde_json::to_string(&body)?);
            } else if r.plugins.is_empty() {
                eprintln!("no plugins loaded — load one with `entangle plugins load <dir>`");
            } else {
                for p in &r.plugins {
                    println!("{p}");
                }
            }
            Ok(())
        }
        Err(RpcError::DaemonNotRunning(_)) => {
            if allow_local() {
                list_local(json).await
            } else {
                Err(daemon_not_running_error())
            }
        }
        Err(e) => Err(e.into()),
    }
}

async fn list_local(json: bool) -> anyhow::Result<()> {
    let kernel = build_kernel()?;
    let ids = kernel.list_plugins();
    let ids_str: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
    if json {
        let body = serde_json::json!({ "plugins": ids_str });
        println!("{}", serde_json::to_string(&body)?);
        return Ok(());
    }
    if ids.is_empty() {
        println!("no plugins loaded (local kernel — load via `entangle plugins load <dir>`)");
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
    let client = rpc_client();
    match client.plugins_load(&dir).await {
        Ok(r) => {
            println!("loaded {}", r.plugin_id);
            Ok(())
        }
        Err(RpcError::DaemonNotRunning(_)) => {
            if allow_local() {
                load_local(dir).await
            } else {
                Err(daemon_not_running_error())
            }
        }
        Err(e) => Err(e.into()),
    }
}

async fn load_local(dir: String) -> anyhow::Result<()> {
    let kernel = build_kernel()?;
    let id = kernel.load_plugin_from_dir(Path::new(&dir)).await?;
    println!("loaded {id}");
    Ok(())
}

// ---------------------------------------------------------------------------
// unload
// ---------------------------------------------------------------------------

async fn unload(plugin_id: String) -> anyhow::Result<()> {
    let client = rpc_client();
    match client.plugins_unload(&plugin_id).await {
        Ok(()) => {
            println!("unloaded {plugin_id}");
            Ok(())
        }
        Err(RpcError::DaemonNotRunning(_)) => {
            if allow_local() {
                unload_local(plugin_id).await
            } else {
                Err(daemon_not_running_error())
            }
        }
        Err(e) => Err(e.into()),
    }
}

async fn unload_local(plugin_id: String) -> anyhow::Result<()> {
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
    let input_bytes: Vec<u8> = match (input.as_deref(), input_file.as_deref()) {
        (Some(s), _) => s.as_bytes().to_vec(),
        (_, Some(path)) => tokio::fs::read(path)
            .await
            .map_err(|e| anyhow::anyhow!("reading --input-file {path}: {e}"))?,
        (None, None) => Vec::new(),
    };

    let client = rpc_client();
    match client
        .plugins_invoke(&plugin_id, input_bytes.clone(), timeout_ms)
        .await
    {
        Ok(r) => print_output(&r.output),
        Err(RpcError::DaemonNotRunning(_)) => {
            if allow_local() {
                invoke_local(plugin_id, input_bytes, timeout_ms).await
            } else {
                Err(daemon_not_running_error())
            }
        }
        Err(e) => Err(e.into()),
    }
}

async fn invoke_local(
    plugin_id: String,
    input_bytes: Vec<u8>,
    timeout_ms: u64,
) -> anyhow::Result<()> {
    let id =
        PluginId::from_str(&plugin_id).map_err(|e| anyhow::anyhow!("invalid plugin id: {e}"))?;
    let kernel = build_kernel()?;
    let output = kernel.invoke(&id, &input_bytes, timeout_ms).await?;
    print_output(&output)
}

fn print_output(output: &[u8]) -> anyhow::Result<()> {
    match std::str::from_utf8(output) {
        Ok(text) if !text.is_empty() => println!("output: {text}"),
        Ok(_) => println!("output: (empty)"),
        Err(_) => println!("output (base64): {}", BASE64.encode(output)),
    }
    Ok(())
}
