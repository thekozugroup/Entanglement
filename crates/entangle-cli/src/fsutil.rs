//! Small filesystem helpers shared by the commands that edit user files.

use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Resolve `path` through a symlink, so an edit lands in the real file.
///
/// Dotfile managers commonly symlink `~/.bashrc`; renaming a temp file over
/// the link would replace the link with a regular file and silently detach
/// the user's dotfiles repo. A dangling or non-link path is returned as is.
pub fn resolve_symlink(path: &Path) -> PathBuf {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
        }
        _ => path.to_path_buf(),
    }
}

/// Atomically replace `path` with `bytes`.
///
/// Writes a sibling temp file, fsyncs it, copies the existing file's
/// permissions (or uses `default_mode` for a new file, Unix only) and
/// renames it into place, so a crash leaves either the old or the new
/// content, never a torn file. Parent directories are created. A symlink at
/// `path` is followed (see [`resolve_symlink`]).
pub fn atomic_write(path: &Path, bytes: &[u8], default_mode: u32) -> std::io::Result<()> {
    let target = resolve_symlink(path);
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let tmp = parent.join(format!(".{name}.entangle-tmp-{}", std::process::id()));
    let result = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        match std::fs::metadata(&target) {
            Ok(m) => std::fs::set_permissions(&tmp, m.permissions())?,
            Err(_) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(default_mode))?;
                }
                #[cfg(not(unix))]
                let _ = default_mode;
            }
        }
        std::fs::rename(&tmp, &target)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_permissions_and_follows_symlinks() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::write(&real, "old").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o640)).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        atomic_write(&link, b"new", 0o644).unwrap();
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "new");
        let mode = std::fs::metadata(&real).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    fn new_file_gets_default_mode_and_parents() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a/b/c");
        atomic_write(&p, b"x", 0o600).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // no temp litter
        assert_eq!(std::fs::read_dir(p.parent().unwrap()).unwrap().count(), 1);
    }
}
