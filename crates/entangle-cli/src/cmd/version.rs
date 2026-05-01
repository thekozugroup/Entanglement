//! `entangle version` — print structured version information.
//!
//! Iter 4: also contacts the daemon via RPC to print its reported version.
//! If the daemon is not reachable, prints `daemon: not contacted`.

use entangle_rpc::{Client as RpcClient, RpcError};

pub async fn run() -> anyhow::Result<()> {
    let profile = if cfg!(debug_assertions) {
        "dev"
    } else {
        "release"
    };
    let rustc_version = rustc_version_string();
    let cli = env!("CARGO_PKG_VERSION");

    // Contact the daemon; best-effort — failure is not fatal.
    let daemon_line = match RpcClient::new(RpcClient::default_socket()).version().await {
        Ok(v) => format!("daemon             {}", v.entangled),
        Err(RpcError::DaemonNotRunning(_)) => "daemon             not contacted".to_string(),
        Err(e) => format!("daemon             error: {e}"),
    };

    println!(
        "entangle CLI       {cli}\n\
         entangle-runtime   0.1.0\n\
         entangle-types     0.1.0\n\
         build              {profile}\n\
         toolchain          {rustc}\n\
         {daemon_line}",
        rustc = rustc_version,
    );

    Ok(())
}

fn rustc_version_string() -> String {
    // RUSTC_VERSION is set by the build script (if present). Fallback gracefully.
    option_env!("RUSTC_VERSION")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
