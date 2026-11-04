//! On-disk layout of plugin storage scopes, shared by both runtimes.
//!
//! A `storage.*` grant names a directory under the daemon's storage root
//! (`~/.entangle/data` by default). The wasm host preopens it for the guest
//! (see [`crate::capability`]); the native runtime (`entangle-runtime`)
//! grants it in the OS sandbox profile. Both derive the path here, so a
//! capability names the same directory whichever runtime the plugin uses:
//!
//! | capability | directory |
//! |---|---|
//! | `storage.local { scope = "plugin" }` | `<root>/plugins/<publisher>/<name>` |
//! | `storage.local { scope = "shared" }` | `<root>/shared` |
//! | `storage.share.<n>` (`ro`, `rw`) | `<root>/shares/<n>` |
//! | `storage.share.<n> { mode = "rw-scoped" }` | `<root>/shares/<n>/<publisher>/<name>` |
//!
//! The plugin directory is keyed by publisher and name, not version, so an
//! upgrade keeps its data. Every component that comes from a plugin id or a
//! share name is re-validated here, where it becomes a path, whatever
//! produced it: it must be one plain path component.

use entangle_types::capability::is_valid_share_name;
use entangle_types::plugin_id::{is_valid_name, PluginId};
use std::path::{Component, Path, PathBuf};

/// A plugin id or share name that cannot safely become a path component.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{what} {value:?} is not a safe path component")]
pub struct UnsafeComponent {
    /// What the value is (`"publisher"`, `"plugin name"`, `"share name"`).
    pub what: &'static str,
    /// The rejected value.
    pub value: String,
}

/// `<root>/plugins/<publisher>/<name>` — the plugin's private data directory.
pub fn plugin_data_dir(root: &Path, id: &PluginId) -> Result<PathBuf, UnsafeComponent> {
    let (publisher, name) = id_components(id)?;
    Ok(root.join("plugins").join(publisher).join(name))
}

/// `<root>/shared` — the directory every `storage.local { scope = "shared" }`
/// plugin shares.
pub fn shared_dir(root: &Path) -> PathBuf {
    root.join("shared")
}

/// `<root>/shares/<name>` — a named share.
pub fn share_dir(root: &Path, name: &str) -> Result<PathBuf, UnsafeComponent> {
    // `Path::join` replaces the base for an absolute name and keeps `..`,
    // so `/` or `../..` would escape `shares`.
    if !is_valid_share_name(name) {
        return Err(UnsafeComponent {
            what: "share name",
            value: name.to_owned(),
        });
    }
    Ok(root.join("shares").join(name))
}

/// `<root>/shares/<name>/<publisher>/<plugin name>` — the plugin's own
/// subdirectory of a share (`mode = "rw-scoped"`).
pub fn scoped_share_dir(
    root: &Path,
    name: &str,
    id: &PluginId,
) -> Result<PathBuf, UnsafeComponent> {
    let (publisher, plugin) = id_components(id)?;
    Ok(share_dir(root, name)?.join(publisher).join(plugin))
}

/// The publisher and name of `id`, re-validated (the fields are public, so
/// the `PluginId` invariant cannot be assumed where they become a path).
fn id_components(id: &PluginId) -> Result<(&str, &str), UnsafeComponent> {
    let publisher_ok = id.publisher.len() == 32
        && id
            .publisher
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    if !publisher_ok {
        return Err(UnsafeComponent {
            what: "publisher",
            value: id.publisher.clone(),
        });
    }
    if !is_valid_name(&id.name) {
        return Err(UnsafeComponent {
            what: "plugin name",
            value: id.name.clone(),
        });
    }
    Ok((&id.publisher, &id.name))
}

/// Resolve a *trusted* root — one no plugin can write to or above, such as
/// the daemon's data directory — to its canonical form. The longest existing
/// ancestor is canonicalised and the rest appended, so a data directory that
/// does not exist yet still loses the OS symlinks above it (`/home` →
/// `var/home`, `/var` → `private/var`).
///
/// A relative `p` is first made absolute against the working directory, so
/// the result is always absolute.
///
/// Scopes derived from these roots are then created without following any
/// link ([`create_private_dir`]), so a link a plugin plants *below* a root
/// can never redirect another plugin's grant.
pub fn resolve_trusted(p: &Path) -> PathBuf {
    let absolute = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let p = absolute.as_path();
    let mut existing = p;
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        if let Ok(mut c) = std::fs::canonicalize(existing) {
            c.extend(rest.iter().rev());
            return c;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                existing = parent;
            }
            _ => return p.to_path_buf(),
        }
    }
}

/// `mkdir -p` with mode 0700 on every directory it creates (Unix), without
/// following symbolic links: a plugin with write access to a share can plant
/// links beneath it, and following one would create directories wherever it
/// points. Every existing component must be a real directory. Callers pass
/// paths under a [`resolve_trusted`] root.
pub fn create_private_dir(d: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    let mut cur = PathBuf::new();
    for comp in d.components() {
        cur.push(comp);
        match comp {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "a storage path may not contain '..'",
                ))
            }
            Component::Normal(_) => {}
        }
        // Create if missing (an existing entry, e.g. from a concurrent load,
        // is then inspected like any other).
        match b.create(&cur) {
            Ok(()) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let meta = std::fs::symlink_metadata(&cur)?;
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is a symbolic link", cur.display()),
            ));
        }
        if !meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is not a directory", cur.display()),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> PluginId {
        "aabbccddeeff00112233445566778899/echo@0.1.0"
            .parse()
            .unwrap()
    }

    #[test]
    fn layout_matches_the_documented_table() {
        let root = Path::new("/data");
        let id = pid();
        assert_eq!(
            plugin_data_dir(root, &id).unwrap(),
            Path::new("/data/plugins/aabbccddeeff00112233445566778899/echo")
        );
        assert_eq!(shared_dir(root), Path::new("/data/shared"));
        assert_eq!(
            share_dir(root, "photos").unwrap(),
            Path::new("/data/shares/photos")
        );
        assert_eq!(
            scoped_share_dir(root, "inbox", &id).unwrap(),
            Path::new("/data/shares/inbox/aabbccddeeff00112233445566778899/echo")
        );
    }

    /// The `PluginId` fields are public; a value mutated after parsing must
    /// still never become a path outside `<root>/plugins`.
    #[test]
    fn tampered_ids_and_share_names_are_refused() {
        let root = Path::new("/data");
        for (publisher, name) in [
            ("..", "echo"),
            ("aabbccddeeff00112233445566778899", ".."),
            ("aabbccddeeff00112233445566778899", "a/b"),
            ("aabbccddeeff00112233445566778899", "/etc"),
            ("../../../../../../../../../../etc", "echo"),
            ("AABBCCDDEEFF00112233445566778899", "echo"),
        ] {
            let mut id = pid();
            id.publisher = publisher.to_owned();
            id.name = name.to_owned();
            assert!(plugin_data_dir(root, &id).is_err(), "{publisher}/{name}");
        }
        for bad in ["", "/", "..", "a/b", "/etc", "."] {
            assert!(share_dir(root, bad).is_err(), "{bad:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_dirs_are_0700_and_never_follow_links() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = resolve_trusted(tmp.path());
        let d = root.join("plugins/p/n");
        create_private_dir(&d).unwrap();
        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        // Idempotent.
        create_private_dir(&d).unwrap();

        let outside = root.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let err = create_private_dir(&root.join("link/victim")).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(!outside.join("victim").exists());
        assert!(create_private_dir(&root.join("a/../b")).is_err());
    }
}
