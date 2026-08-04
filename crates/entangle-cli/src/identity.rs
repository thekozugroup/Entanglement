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
        write_new_key_file(path, pem.as_bytes())?;
        Ok(kp)
    }
}

/// Create `path` and write `bytes`, ensuring the private key is never world- or
/// group-readable at any point.
///
/// On Unix the file is opened with `create_new` (fails if it already exists,
/// avoiding a TOCTOU clobber) and mode `0o600` applied atomically at creation
/// time — unlike write-then-chmod, there is no window where the key is
/// world-readable. Any I/O error is propagated rather than ignored.
fn write_new_key_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }

    let mut file = opts
        .open(path)
        .with_context(|| format!("create identity.key at {}", path.display()))?;
    file.write_all(bytes).context("write identity.key")?;
    file.flush().context("flush identity.key")?;
    Ok(())
}
