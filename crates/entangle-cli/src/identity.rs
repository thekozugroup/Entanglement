//! `~/.entangle/identity.key` persistence — generate or load the node keypair.

use anyhow::Context;
use entangle_signing::IdentityKeyPair;
use std::path::Path;

/// Load the identity keypair from `path`, or generate and save a new one.
///
/// The file is written with mode `0600` on Unix so only the owning user can
/// read the private key material.
pub fn ensure_identity(path: &Path) -> anyhow::Result<IdentityKeyPair> {
    if path.exists() {
        let pem = std::fs::read_to_string(path).context("read identity.key")?;
        IdentityKeyPair::from_pem(&pem)
            .context("parse identity.key")
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    } else {
        let kp = IdentityKeyPair::generate();
        let pem = kp.to_pem();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &pem)?;
        // Restrict permissions on Unix so the private key is not world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
        Ok(kp)
    }
}
