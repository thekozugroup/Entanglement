//! `entangle init` — initialise the user's entangle directory.

use crate::{
    config::{self, entangle_dir, Config, MeshConfig},
    identity::ensure_identity,
};
use entangle_signing::Keyring;

pub async fn run() -> anyhow::Result<()> {
    let dir = entangle_dir();
    std::fs::create_dir_all(&dir)?;

    // --- identity.key ---
    let id_path = config::identity_path();
    let kp = ensure_identity(&id_path)?;
    let fingerprint = kp.fingerprint_hex();

    // --- config.toml ---
    let cfg_path = config::config_path();
    if !cfg_path.exists() {
        let default_cfg = Config {
            mesh: MeshConfig {
                transports: vec!["local".to_string()],
            },
            ..Default::default()
        };
        config::save(&cfg_path, &default_cfg)?;
    }

    // --- keyring.toml ---
    let kr_path = config::keyring_path();
    if !kr_path.exists() {
        Keyring::new().save(&kr_path)?;
    }

    println!(
        "entangle initialized at {dir}\n  identity:  ed25519 fingerprint {fingerprint}\n  config:    {cfg}\n  keyring:   {kr} (empty — add publisher keys with `entangle keyring add`)\n\nNext: pair a peer (`entangle pair`) or load a plugin (`entangle plugins load <dir>`)",
        dir = dir.display(),
        fingerprint = fingerprint,
        cfg = cfg_path.display(),
        kr = kr_path.display(),
    );

    Ok(())
}
