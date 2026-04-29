//! `entangle version` — print structured version information.

pub async fn run() -> anyhow::Result<()> {
    let profile = if cfg!(debug_assertions) {
        "dev"
    } else {
        "release"
    };
    let rustc_version = rustc_version_string();

    let cli = env!("CARGO_PKG_VERSION");
    println!(
        "entangle CLI       {cli}\n\
         entangle-runtime   0.1.0\n\
         entangle-types     0.1.0\n\
         build              {profile}\n\
         toolchain          {rustc}\n\
         daemon             not contacted (this iteration)",
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
