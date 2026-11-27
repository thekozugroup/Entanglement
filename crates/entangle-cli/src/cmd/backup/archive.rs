//! A bounded ustar payload. Only explicitly managed roots and regular files/directories are accepted.

use super::MAX_BODY;
use anyhow::{ensure, Context, Result};
use rustix::fs::{openat, Dir, Mode, OFlags};
use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

const FILES: [&str; 4] = ["identity.key", "config.toml", "keyring.toml", "peers.toml"];
const TREES: [&str; 2] = ["plugins", "data"];
const MAX_ENTRIES: usize = 16_384;
const MAX_DEPTH: usize = 32;
const MAX_NODE_FILE: u64 = 2 * 1024 * 1024;

#[derive(Default)]
struct BoundedBody(Zeroizing<Vec<u8>>);

impl Write for BoundedBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BODY - self.0.len() {
            return Err(io::Error::other("backup exceeds 128 MiB"));
        }
        self.0.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn header(path: &Path, directory: bool, size: u64) -> Result<tar::Header> {
    let mut h = tar::Header::new_ustar();
    h.set_path(path)
        .with_context(|| format!("path exceeds ustar limit: {}", path.display()))?;
    h.set_entry_type(if directory {
        tar::EntryType::Directory
    } else {
        tar::EntryType::Regular
    });
    h.set_mode(if directory { 0o700 } else { 0o600 });
    h.set_size(size);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mtime(0);
    h.set_cksum();
    Ok(h)
}

fn open_entry(parent: &File, relative: &Path) -> Result<File> {
    let name = relative.file_name().context("missing entry name")?;
    let entry = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
    ensure!(
        matches!(
            rustix::fs::FileType::from_raw_mode(entry.st_mode),
            rustix::fs::FileType::RegularFile | rustix::fs::FileType::Directory
        ),
        "unsupported filesystem entry {}",
        relative.display()
    );
    Ok(File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening {} without following links", relative.display()))?,
    ))
}

fn append(
    archive: &mut tar::Builder<BoundedBody>,
    count: &mut usize,
    parent: &File,
    relative: &Path,
    ledger_lock: Option<&Path>,
) -> Result<()> {
    if ledger_lock == Some(relative) {
        return Ok(());
    }
    *count += 1;
    ensure!(
        *count <= MAX_ENTRIES && relative.components().count() <= MAX_DEPTH,
        "too many backup entries or nested directories"
    );
    let file = open_entry(parent, relative)?;
    let meta = file.metadata()?;
    if meta.is_dir() {
        ensure!(
            allowed_tree(relative),
            "unexpected directory {}",
            relative.display()
        );
        archive.append(&header(relative, true, 0)?, io::empty())?;
        for entry in Dir::read_from(&file)? {
            let entry = entry?;
            let bytes = entry.file_name().to_bytes();
            if bytes != b"." && bytes != b".." {
                append(
                    archive,
                    count,
                    &file,
                    &relative.join(OsStr::from_bytes(bytes)),
                    ledger_lock,
                )?;
            }
        }
    } else {
        ensure!(
            meta.is_file() && meta.nlink() == 1,
            "backup accepts only regular files with a single hard link: {}",
            relative.display()
        );
        ensure!(
            meta.len() <= MAX_BODY as u64
                && (allowed_tree(relative) || meta.len() <= MAX_NODE_FILE),
            "file too large: {}",
            relative.display()
        );
        let mut data = (&file).take(meta.len());
        archive.append(&header(relative, false, meta.len())?, &mut data)?;
        let after = file.metadata()?;
        ensure!(
            data.limit() == 0
                && (
                    after.len(),
                    after.mtime(),
                    after.mtime_nsec(),
                    after.ctime(),
                    after.ctime_nsec()
                ) == (
                    meta.len(),
                    meta.mtime(),
                    meta.mtime_nsec(),
                    meta.ctime(),
                    meta.ctime_nsec()
                ),
            "file changed during backup: {}",
            relative.display()
        );
    }
    Ok(())
}

fn allowed_tree(path: &Path) -> bool {
    TREES.iter().any(|tree| path.starts_with(tree))
}

fn clean_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty() && path.components().all(|c| matches!(c, Component::Normal(_)))
}

fn rewrite_startup_paths(raw: String, map: impl Fn(&Path) -> Result<PathBuf>) -> Result<String> {
    let mut doc = raw.parse::<toml_edit::DocumentMut>()?;
    let Some(item) = doc.get_mut("runtime").and_then(|v| v.get_mut("plugins")) else {
        return Ok(raw);
    };
    let paths = item
        .as_array_mut()
        .context("runtime.plugins must be an array")?;
    for i in 0..paths.len() {
        let current = paths
            .get(i)
            .and_then(|v| v.as_str())
            .context("invalid startup plugin path")?;
        let new = map(Path::new(current))?;
        paths.replace(i, new.to_str().context("plugin path is not UTF-8")?);
    }
    Ok(doc.to_string())
}

fn portable_path(configured: &Path, root: &Path, tree: &str) -> Result<PathBuf> {
    ensure!(
        configured.is_absolute()
            && !configured
                .components()
                .any(|c| matches!(c, Component::ParentDir)),
        "state path must be absolute without parent traversal: {}",
        configured.display()
    );
    let resolved = configured
        .canonicalize()
        .with_context(|| format!("resolving managed state {}", configured.display()))?;
    let relative = resolved.strip_prefix(root).ok().filter(|p| clean_relative(p) && p.starts_with(tree))
        .with_context(|| format!("{} is outside the archived {} directory {}; move the existing state there and update config before backup", configured.display(), tree, root.join(tree).display()))?;
    Ok(relative.to_owned())
}

/// Return the rewritten config and the location selected by its bridge ledger entry.
fn rewrite_ledger(
    raw: String,
    map: impl FnOnce(&Path) -> Result<PathBuf>,
) -> Result<(String, Option<PathBuf>)> {
    let cfg: entangle_runtime::config::Config = toml::from_str(&raw)?;
    let bridge = cfg.mesh.bridge;
    let Some(path) = bridge.ledger else {
        ensure!(
            !bridge.enabled && !bridge.receive,
            "enabled bridge requires a recoverable ledger"
        );
        return Ok((raw, None));
    };
    let new = map(&path)?;
    let mut doc = raw.parse::<toml_edit::DocumentMut>()?;
    doc["mesh"]["bridge"]["ledger"] =
        toml_edit::value(new.to_str().context("ledger path is not UTF-8")?);
    Ok((doc.to_string(), Some(new)))
}

fn verify_ledger(ledger: &Path, identity: &entangle_signing::IdentityKeyPair) -> Result<()> {
    let public = identity.public();
    entangle_signing::BridgeReceiver::open(
        ledger,
        entangle_types::peer_id::PeerId::from_public_key_bytes(public.as_bytes()),
        entangle_signing::relay_endpoint_key(public.as_bytes())?,
    )
    .context("checking existing bridge ledger and byte counters")?;
    Ok(())
}

pub(super) fn snapshot(root: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let dir = File::from(rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let mut archive = tar::Builder::new(BoundedBody::default());
    let cfg_name = Path::new("config.toml");
    let cfg_file = open_entry(&dir, cfg_name)?;
    let cfg_meta = cfg_file.metadata()?;
    ensure!(
        cfg_meta.is_file() && cfg_meta.nlink() == 1 && cfg_meta.len() <= MAX_NODE_FILE,
        "invalid or oversized config.toml"
    );
    let mut raw = String::new();
    cfg_file.take(MAX_NODE_FILE + 1).read_to_string(&mut raw)?;
    ensure!(
        raw.len() as u64 == cfg_meta.len(),
        "configuration changed during backup"
    );
    let cfg = rewrite_startup_paths(raw, |p| portable_path(p, root, "plugins"))?;
    let (cfg, ledger) = rewrite_ledger(cfg, |p| portable_path(p, root, "data"))?;
    let ledger_guard = ledger
        .as_ref()
        .map(|p| super::writer_lock(&root.join(p)))
        .transpose()?;
    let lock_name = ledger.as_ref().map(|p| p.with_added_extension("lock"));
    ensure!(
        cfg.len() as u64 <= MAX_NODE_FILE,
        "portable config.toml exceeds limit"
    );
    archive.append(&header(cfg_name, false, cfg.len() as u64)?, cfg.as_bytes())?;
    let mut count = 1;
    for name in FILES.into_iter().filter(|n| *n != "config.toml") {
        append(
            &mut archive,
            &mut count,
            &dir,
            Path::new(name),
            lock_name.as_deref(),
        )?;
    }
    for name in TREES {
        match fs::symlink_metadata(root.join(name)) {
            Ok(meta) => {
                ensure!(meta.is_dir(), "managed tree {name} must be a directory");
                append(
                    &mut archive,
                    &mut count,
                    &dir,
                    Path::new(name),
                    lock_name.as_deref(),
                )?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    let bytes = archive.into_inner()?.0;
    // Validate the identity, config and startup paths against the captured archive itself.
    let mut captured_dirs = HashSet::new();
    let mut startup = Vec::new();
    for entry in tar::Archive::new(&bytes[..]).entries()?.raw(true) {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if entry.header().entry_type().is_dir() {
            captured_dirs.insert(path);
        } else if path == Path::new("config.toml") {
            let mut cfg = String::new();
            entry.read_to_string(&mut cfg)?;
            let config: entangle_runtime::config::Config = toml::from_str(&cfg)?;
            startup = config.runtime.plugins;
        } else if path == Path::new("identity.key") {
            let mut pem = Zeroizing::new(String::new());
            entry.read_to_string(&mut pem)?;
            let identity = entangle_signing::IdentityKeyPair::from_pem(&pem)?;
            if let Some(path) = &ledger {
                verify_ledger(&root.join(path), &identity)?;
            }
        }
    }
    for plugin in startup {
        ensure!(
            captured_dirs.contains(&plugin),
            "startup package {} was missing from the backup",
            plugin.display()
        );
    }
    drop(ledger_guard);
    Ok(bytes)
}

pub(super) fn unpack(bytes: &[u8], stage: &Path, dest: &Path) -> Result<()> {
    let mut names = HashSet::new();
    let mut directories = vec![stage.to_path_buf()];
    for entry in tar::Archive::new(bytes).entries()?.raw(true) {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        ensure!(
            clean_relative(&path)
                && path.components().count() <= MAX_DEPTH
                && names.len() < MAX_ENTRIES
                && names.insert(path.clone()),
            "invalid or duplicate backup entry"
        );
        let file = entry.header().entry_type() == tar::EntryType::Regular;
        let dir = entry.header().entry_type() == tar::EntryType::Directory;
        let managed_file = FILES.iter().any(|name| path == Path::new(name));
        ensure!(
            (file && managed_file && entry.size() <= MAX_NODE_FILE)
                || (allowed_tree(&path) && (dir || file)),
            "unsupported backup entry {}",
            path.display()
        );
        ensure!(
            !TREES.iter().any(|tree| path == Path::new(tree)) || dir,
            "managed root must be a directory"
        );
        let target = stage.join(path);
        if dir {
            ensure!(entry.size() == 0, "directory with unexpected payload");
            fs::DirBuilder::new().mode(0o700).create(&target)?;
            directories.push(target);
        } else {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&target)?;
            let size = entry.size();
            ensure!(
                io::copy(&mut entry, &mut output)? == size,
                "truncated backup entry"
            );
            output.sync_all()?;
        }
    }
    ensure!(
        FILES.iter().all(|name| names.contains(Path::new(name))),
        "backup is missing required node state"
    );
    let cfg = stage.join("config.toml");
    let rewritten = rewrite_startup_paths(fs::read_to_string(&cfg)?, |relative| {
        ensure!(
            clean_relative(relative) && relative.starts_with("plugins"),
            "invalid archived startup plugin path"
        );
        Ok(dest.join(relative))
    })?;
    let (rewritten, ledger) = rewrite_ledger(rewritten, |relative| {
        ensure!(
            clean_relative(relative) && relative.starts_with("data"),
            "invalid archived bridge ledger path"
        );
        Ok(dest.join(relative))
    })?;
    let mut out = OpenOptions::new().write(true).truncate(true).open(&cfg)?;
    out.write_all(rewritten.as_bytes())?;
    out.sync_all()?;
    let config = entangle_runtime::config::load_config(&cfg)?;
    for plugin in config.runtime.plugins {
        let captured = stage.join(plugin.strip_prefix(dest)?);
        ensure!(
            captured.is_dir(),
            "startup package {} was missing from the backup",
            plugin.display()
        );
    }
    let identity = entangle_signing::IdentityKeyPair::from_pem(&Zeroizing::new(
        fs::read_to_string(stage.join("identity.key"))?,
    ))?;
    if let Some(path) = ledger {
        verify_ledger(&stage.join(path.strip_prefix(dest)?), &identity)?;
    }
    entangle_signing::Keyring::load(&stage.join("keyring.toml"))?;
    entangle_peers::PeerStore::open(stage.join("peers.toml"))?;
    for dir in directories.into_iter().rev() {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn restored_bridge_keeps_exhausted_grant_counters_and_excludes_transient_lock() {
        use entangle_signing::{
            mint_relay, relay_endpoint_key, BridgeReceiver, IdentityKeyPair, RelayError,
        };
        use entangle_types::peer_id::PeerId;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("old");
        fs::create_dir_all(root.join("data")).unwrap();
        let ledger = root.join("data/bridge.toml");
        let identity = IdentityKeyPair::generate();
        let origin = IdentityKeyPair::generate();
        let bridge = PeerId::from_public_key_bytes(&[9; 32]);
        let destination = PeerId::from_public_key_bytes(identity.public().as_bytes());
        let local_signer = relay_endpoint_key(identity.public().as_bytes()).unwrap();
        let remote_signer = relay_endpoint_key(origin.public().as_bytes()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let grant = |key: &IdentityKeyPair| {
            mint_relay(&key.to_pem(), bridge, destination, 4096, 8, now + 300, now).unwrap()
        };
        let (a, b) = (grant(&origin), grant(&identity));
        BridgeReceiver::initialize(&ledger).unwrap();
        let before = BridgeReceiver::open(&ledger, destination, local_signer).unwrap();
        let session = before.authorize(&remote_signer, bridge, &a, &b).unwrap();
        before
            .receive(&session, b"consumed", &mut Vec::new())
            .unwrap();
        fs::write(root.join("identity.key"), identity.to_pem()).unwrap();
        fs::write(root.join("peers.toml"), "peers = []").unwrap();
        entangle_signing::Keyring::new()
            .save(&root.join("keyring.toml"))
            .unwrap();
        let cfg = |p: &Path| {
            format!(
                "[mesh.bridge]\nreceive=true\nledger={}\n",
                toml_edit::Value::from(p.to_str().unwrap())
            )
        };
        let outside = temp.path().join("external-ledger.toml");
        fs::copy(&ledger, &outside).unwrap();
        fs::write(root.join("config.toml"), cfg(&outside)).unwrap();
        assert!(snapshot(&root).is_err());
        fs::write(root.join("config.toml"), cfg(&ledger)).unwrap();
        let busy = super::super::writer_lock(&ledger).unwrap();
        assert!(
            snapshot(&root).is_err(),
            "must not snapshot during a counter update"
        );
        drop(busy);
        let bytes = snapshot(&root).unwrap();
        let fresh = root.with_file_name("fresh");
        super::super::publish(&bytes, temp.path(), &fresh).unwrap();
        let restored = entangle_runtime::config::load_config(&fresh.join("config.toml"))
            .unwrap()
            .mesh
            .bridge
            .ledger
            .unwrap();
        assert_eq!(restored, fresh.join("data/bridge.toml"));
        assert_eq!(fs::read(&ledger).unwrap(), fs::read(&restored).unwrap());
        assert!(!restored.with_added_extension("lock").exists());
        let after = BridgeReceiver::open(
            &restored,
            destination,
            relay_endpoint_key(identity.public().as_bytes()).unwrap(),
        )
        .unwrap();
        let session = after.authorize(&remote_signer, bridge, &a, &b).unwrap();
        let mut sink = Vec::new();
        assert!(matches!(
            after.receive(&session, b"x", &mut sink),
            Err(RelayError::BridgeBudgetExhausted)
        ));
        assert!(sink.is_empty());
    }

    #[test]
    fn snapshot_refuses_links_to_a_secret_outside_the_managed_tree() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        fs::create_dir_all(state.join("plugins")).unwrap();
        let secret = temp.path().join("external");
        fs::write(&secret, "private").unwrap();
        let root = File::open(&state).unwrap();
        for hard in [false, true] {
            let linked = state.join("plugins/payload");
            if hard {
                fs::hard_link(&secret, &linked).unwrap();
            } else {
                symlink(&secret, &linked).unwrap();
            }
            let mut archive = tar::Builder::new(BoundedBody::default());
            assert!(append(&mut archive, &mut 0, &root, Path::new("plugins"), None).is_err());
            fs::remove_file(linked).unwrap();
        }
    }

    #[test]
    fn extraction_rejects_parent_traversal_absolute_names_and_links() {
        let tmp = tempfile::tempdir().unwrap();
        let stage = tmp.path().join("stage");
        fs::create_dir(&stage).unwrap();
        let outside = tmp.path().join("exposed");
        for (name, kind) in [
            (Path::new("../exposed"), tar::EntryType::Regular),
            (outside.as_path(), tar::EntryType::Regular),
            (Path::new("identity.key"), tar::EntryType::Symlink),
            (Path::new("identity.key"), tar::EntryType::Link),
        ] {
            let mut blob = Vec::new();
            let mut archive = tar::Builder::new(&mut blob);
            let mut h = tar::Header::new_ustar();
            let bytes = name.as_os_str().as_bytes();
            h.as_mut_bytes()[..bytes.len()].copy_from_slice(bytes);
            h.set_entry_type(kind);
            h.set_size(0);
            h.set_cksum();
            archive.append(&h, io::empty()).unwrap();
            archive.into_inner().unwrap();
            assert!(unpack(&blob, &stage, &tmp.path().join("destination")).is_err());
            assert_eq!(stage.read_dir().unwrap().count(), 0);
            assert!(!outside.exists());
        }
    }

    #[test]
    fn external_or_parent_relative_startup_paths_require_operator_resolution() {
        let source = Path::new("/home/source/.entangle");
        for plugin in [
            "/elsewhere/plugin",
            "/home/source/.entangle/plugins/../../elsewhere",
            "plugins/relative",
        ] {
            assert!(portable_path(Path::new(plugin), source, "plugins").is_err());
        }
    }
}
