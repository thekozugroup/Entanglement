//! `entangle version` — print structured version information.
//!
//! Contacts the daemon via RPC (best-effort).  Prints `(not reachable)` if the
//! daemon socket cannot be reached, `(not configured)` for missing files.

use crate::config;
use entangle_rpc::{Client as RpcClient, RpcError};

/// Single workspace version shared by all first-party crates.
const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn run() -> anyhow::Result<()> {
    let profile = if cfg!(debug_assertions) {
        "dev"
    } else {
        "release"
    };
    let rustc = rustc_version_string();

    // Daemon info — best-effort.
    let socket = RpcClient::default_socket();
    let (daemon_status, daemon_version, daemon_socket) =
        match RpcClient::new(&socket).version().await {
            Ok(v) => (
                "reachable".to_string(),
                v.entangled,
                socket.display().to_string(),
            ),
            Err(RpcError::DaemonNotRunning(_)) => (
                "(not reachable)".to_string(),
                "(not reachable)".to_string(),
                socket.display().to_string(),
            ),
            Err(e) => (
                format!("error: {e}"),
                "(not reachable)".to_string(),
                socket.display().to_string(),
            ),
        };

    // Identity info — best-effort.
    let id_path = config::identity_path();
    let (fingerprint_line, keyring_entries) = if id_path.exists() {
        (load_fingerprint(&id_path), load_keyring_count())
    } else {
        (
            "(not configured)".to_string(),
            "(not configured)".to_string(),
        )
    };

    println!("entangle {CRATE_VERSION}");
    println!("  {:<18} {CRATE_VERSION}", "CLI");
    println!("  {:<18} {CRATE_VERSION}", "Runtime");
    println!("  {:<18} {CRATE_VERSION}", "Types");
    println!("  {:<18} {CRATE_VERSION}", "Manifest");
    println!("  {:<18} {CRATE_VERSION}", "Signing");
    println!("  {:<18} {CRATE_VERSION}", "Wit");
    println!("  {:<18} {CRATE_VERSION}", "RPC");
    println!("  {:<18} {CRATE_VERSION}", "Pairing");
    println!("  {:<18} {CRATE_VERSION}", "Biscuits");
    println!("  {:<18} {CRATE_VERSION}", "Scheduler");
    println!("  {:<18} {CRATE_VERSION}", "Mesh-local");
    println!("  {:<18} {CRATE_VERSION}", "Peers");
    println!();
    println!("Daemon");
    println!("  {:<18} {daemon_status}", "Status");
    println!("  {:<18} {daemon_version}", "Version");
    println!("  {:<18} {daemon_socket}", "Socket");
    println!();
    println!("Build");
    println!("  {:<18} {profile}", "Profile");
    println!("  {:<18} {rustc}", "Toolchain");
    let wt = wasmtime_version();
    println!("  {:<18} {wt}", "Wasmtime");
    println!("  {:<18} 0.2", "WASI");
    println!();
    println!("Identity");
    println!("  {:<18} {fingerprint_line}", "Fingerprint");
    println!("  {:<18} {keyring_entries}", "Keyring entries");

    Ok(())
}

fn rustc_version_string() -> String {
    // RUSTC_VERSION is set by the build script (if present). Fallback gracefully.
    option_env!("RUSTC_VERSION")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn wasmtime_version() -> String {
    // WASMTIME_VERSION can be set by a build script; otherwise use the pinned major.
    option_env!("WASMTIME_VERSION")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "43.x".to_string())
}

fn load_fingerprint(id_path: &std::path::Path) -> String {
    let pem = match std::fs::read_to_string(id_path) {
        Ok(p) => p,
        Err(_) => return "(not configured)".to_string(),
    };
    use entangle_signing::IdentityKeyPair;
    match IdentityKeyPair::from_pem(&pem) {
        Ok(kp) => {
            let raw = kp.fingerprint_hex();
            let formatted = raw
                .chars()
                .collect::<Vec<_>>()
                .chunks(4)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("-");
            format!("{formatted} (loaded)")
        }
        Err(_) => "(not configured)".to_string(),
    }
}

fn load_keyring_count() -> String {
    use entangle_signing::Keyring;
    let kr_path = config::keyring_path();
    match Keyring::load(&kr_path) {
        Ok(kr) => kr.entries().count().to_string(),
        Err(_) => "(not configured)".to_string(),
    }
}
