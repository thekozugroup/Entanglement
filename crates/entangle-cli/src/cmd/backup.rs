//! Offline, authenticated recovery of the node's managed state.

mod archive;

use crate::config;
use anyhow::{bail, ensure, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::AeadInPlace, KeyInit, XChaCha20Poly1305};
use clap::Args;
use rand_core::{OsRng, RngCore};
use rustix::fs::{open, Mode, OFlags};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

// Fixed parameters are part of the format. Untrusted input cannot request a higher KDF cost.
const MAGIC: &[u8; 8] = b"ENTBAK\0\x01";
const HEADER_LEN: usize = MAGIC.len() + 16 + 24;
const TAG_LEN: usize = 16;
const MAX_BODY: usize = 128 * 1024 * 1024;
const MAX_PASSWORD: usize = 1024;

#[derive(Args)]
pub struct BackupArgs {
    /// New backup file, outside the node's state directory.
    #[arg(long)]
    to: PathBuf,
    /// Read a passphrase from standard input instead of the secure terminal prompt.
    #[arg(long)]
    passphrase_stdin: bool,
    /// Daemon RPC socket, if started with entangled --socket.
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[derive(Args)]
pub struct RestoreArgs {
    /// Existing encrypted backup file.
    #[arg(long)]
    from: PathBuf,
    /// Read a passphrase from standard input instead of the secure terminal prompt.
    #[arg(long)]
    passphrase_stdin: bool,
}

fn password(stdin: bool, confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    if stdin {
        std::io::stdin()
            .lock()
            .take(MAX_PASSWORD as u64 + 3)
            .read_to_end(&mut bytes)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
    } else {
        let mut prompt = dialoguer::Password::new().with_prompt("Backup passphrase");
        if confirm {
            prompt = prompt.with_confirmation("Confirm passphrase", "Passphrases differ");
        }
        let entered = Zeroizing::new(prompt.interact()?);
        bytes.extend_from_slice(entered.as_bytes());
    }
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PASSWORD && !bytes.contains(&b'\n'),
        "supply one passphrase of 1–1024 bytes"
    );
    Ok(bytes)
}

fn cipher(secret: &[u8], header: &[u8; HEADER_LEN]) -> Result<XChaCha20Poly1305> {
    // RFC 9106's second recommended Argon2id profile, 64 MiB, 3 iterations, 4 lanes.
    let params = Params::new(65_536, 3, 4, Some(32)).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret, &header[8..24], &mut *key)
        .map_err(|e| anyhow::anyhow!("could not derive backup key: {e}"))?;
    Ok(XChaCha20Poly1305::new((&*key).into()))
}

fn open_regular(path: &Path) -> Result<File> {
    let file = File::from(open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    ensure!(
        file.metadata()?.is_file(),
        "{} must be a regular file",
        path.display()
    );
    Ok(file)
}

fn writer_lock(path: &Path) -> Result<File> {
    let name = path.with_added_extension("lock");
    let flags =
        OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let lock = File::from(open(&name, flags, Mode::RUSR | Mode::WUSR)?);
    let meta = lock.metadata()?;
    ensure!(
        meta.is_file() && meta.nlink() == 1,
        "invalid writer lock for {}",
        path.display()
    );
    lock.try_lock()
        .with_context(|| format!("writer busy for {}", path.display()))?;
    Ok(lock)
}

fn stopped_node(socket: &Path) -> Result<File> {
    let lock = writer_lock(socket).context("stop the daemon before backing up")?;
    // Older daemon versions do not hold the lock.
    match fs::symlink_metadata(socket) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
        Ok(_) => bail!("daemon socket still exists; stop the daemon before backing up, or restart and stop it to clear its stale socket"),
    }
    Ok(lock)
}

pub fn backup(args: BackupArgs) -> Result<()> {
    let source = config::entangle_dir();
    let meta = source.symlink_metadata()?;
    ensure!(
        meta.is_dir()
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.permissions().mode() & 0o022 == 0,
        "node state directory must be an owner-controlled directory"
    );
    let root = source.canonicalize()?;
    let parent = args
        .to
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    let dest = parent.join(args.to.file_name().context("backup needs a file name")?);
    ensure!(
        !parent.starts_with(&root),
        "choose a backup path outside {}",
        root.display()
    );
    ensure!(
        fs::symlink_metadata(&dest).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "backup destination already exists or is inaccessible"
    );
    let pass = password(args.passphrase_stdin, true)?;
    let mut body = {
        let _daemon = stopped_node(&args.socket.unwrap_or_else(|| root.join("sock")))?;
        let _config = entangle_runtime::config::lock_config_writer(&root.join("config.toml"))?;
        let _publishers = writer_lock(&root.join("keyring.toml"))?;
        let _peers = writer_lock(&root.join("peers.toml"))?;
        archive::snapshot(&root)?
    };
    let mut header = [0; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    OsRng
        .try_fill_bytes(&mut header[8..])
        .context("generating backup salt and nonce")?;
    let tag = cipher(&pass, &header)?
        .encrypt_in_place_detached((&header[24..]).into(), &header, &mut body)
        .map_err(|_| anyhow::anyhow!("backup encryption failed"))?;
    let mut staged = tempfile::NamedTempFile::new_in(&parent)?;
    staged.write_all(&header)?;
    staged.write_all(&body)?;
    staged.write_all(&tag)?;
    staged.as_file().sync_all()?;
    staged.persist_noclobber(&dest)?;
    File::open(parent)?.sync_all()?;
    println!("Encrypted backup saved to {}", dest.display());
    Ok(())
}

pub fn restore(args: RestoreArgs) -> Result<()> {
    let root = config::entangle_dir();
    let parent = root
        .parent()
        .context("missing destination parent")?
        .canonicalize()?;
    // Publishing with NOREPLACE below also covers a concurrent daemon/restore creating the target.
    ensure!(
        fs::symlink_metadata(&root).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "restore requires a fresh home without {}",
        root.display()
    );
    let parent_meta = parent.metadata()?;
    ensure!(
        parent_meta.uid() == rustix::process::geteuid().as_raw()
            && parent_meta.permissions().mode() & 0o022 == 0,
        "restore parent must be private to its owner for writes"
    );
    let mut file = open_regular(&args.from)?;
    let size = usize::try_from(file.metadata()?.len())?;
    ensure!(
        (HEADER_LEN + TAG_LEN..=HEADER_LEN + MAX_BODY + TAG_LEN).contains(&size),
        "invalid backup size"
    );
    let mut header = [0; HEADER_LEN];
    file.read_exact(&mut header)?;
    ensure!(
        header.starts_with(MAGIC),
        "unsupported backup format or version"
    );
    let pass = password(args.passphrase_stdin, false)?;
    let mut body = Zeroizing::new(Vec::with_capacity(size - HEADER_LEN));
    file.take((MAX_BODY + TAG_LEN + 1) as u64)
        .read_to_end(&mut body)?;
    ensure!(
        body.len() == size - HEADER_LEN,
        "backup length changed while reading"
    );
    let tag_at = body.len() - TAG_LEN;
    let tag: [u8; TAG_LEN] = body[tag_at..].try_into()?;
    body.truncate(tag_at);
    cipher(&pass, &header)?
        .decrypt_in_place_detached((&header[24..]).into(), &header, &mut body, (&tag).into())
        .map_err(|_| {
            anyhow::anyhow!("backup authentication failed: wrong passphrase or damaged archive")
        })?;
    let dest = parent.join(root.file_name().context("missing state directory name")?);
    publish(&body, &parent, &dest)?;
    println!("Restored node at {}", dest.display());
    Ok(())
}

fn publish(body: &[u8], parent: &Path, dest: &Path) -> Result<()> {
    let staged = tempfile::Builder::new()
        .prefix(".entangle-restore-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    archive::unpack(body, staged.path(), dest)?;
    use rustix::fs::{renameat_with, RenameFlags, CWD};
    renameat_with(CWD, staged.path(), CWD, dest, RenameFlags::NOREPLACE)
        .context("publishing restored node into its fresh destination")?;
    let _ = staged.keep();
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_late_restore_error_removes_the_staged_plaintext() {
        let temp = tempfile::tempdir().unwrap();
        let mut archive = tar::Builder::new(Vec::new());
        let data = b"snapshot bytes";
        let mut header = tar::Header::new_ustar();
        header.set_size(data.len() as u64);
        archive
            .append_data(&mut header, "identity.key", &data[..])
            .unwrap();
        let partial = archive.into_inner().unwrap();
        let destination = temp.path().join(".entangle");
        assert!(publish(&partial, temp.path(), &destination).is_err());
        assert_eq!(temp.path().read_dir().unwrap().count(), 0);
    }
}
