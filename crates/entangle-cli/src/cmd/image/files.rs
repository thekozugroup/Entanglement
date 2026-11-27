use anyhow::{bail, ensure, Context, Result};
use rand_core::{OsRng, RngCore};
use rustix::fs::{
    linkat, mkdirat, open, openat, renameat, statat, unlinkat, AtFlags, Dir, FileType, Mode, OFlags,
};
use rustix::io::Errno;
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const OPEN_FILE: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

pub(super) fn roots(input: &Path, output: &Path) -> Result<(File, File)> {
    let input = input
        .canonicalize()
        .with_context(|| format!("opening input directory {}", input.display()))?;

    // Resolve the existing prefix so a missing output root can be checked
    // against the input tree before it is created.
    let absolute = std::path::absolute(output)?;
    let mut path = absolute.as_path();
    let mut missing = Vec::new();
    let mut output = loop {
        match path.canonicalize() {
            Ok(resolved) => break resolved,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(path.file_name().context("invalid output directory")?);
                path = path.parent().context("invalid output directory")?;
            }
            Err(error) => return Err(error.into()),
        }
    };
    output.extend(missing.into_iter().rev());
    require_disjoint(&input, &output)?;
    fs::create_dir_all(&output)
        .with_context(|| format!("creating output directory {}", output.display()))?;
    require_disjoint(&input, &output.canonicalize()?)?;
    let source = open(&input, OPEN_DIRECTORY, Mode::empty())
        .with_context(|| format!("opening input directory {}", input.display()))?;
    let destination = open(&output, OPEN_DIRECTORY, Mode::empty())
        .with_context(|| format!("opening output directory {}", output.display()))?;
    Ok((source.into(), destination.into()))
}

fn require_disjoint(input: &Path, output: &Path) -> Result<()> {
    ensure!(
        !output.starts_with(input) && !input.starts_with(output),
        "input and output must be separate directory trees"
    );
    Ok(())
}

pub(super) fn directory(root: &File, path: &Path, create: bool) -> Result<File> {
    let mut parent = root.try_clone()?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            bail!("invalid relative directory {}", path.display());
        };
        if create {
            match mkdirat(&parent, name, Mode::RWXU) {
                Ok(()) => parent.sync_all()?,
                Err(Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        parent = openat(&parent, name, OPEN_DIRECTORY, Mode::empty())
            .with_context(|| {
                format!(
                    "opening directory {} without following links",
                    path.display()
                )
            })?
            .into();
    }
    Ok(parent)
}

pub(super) fn private_state(output: &File) -> Result<(File, File)> {
    let state = directory(output, Path::new(".entangle-image-dehaze"), true)?;
    let meta = state.metadata()?;
    ensure!(
        meta.uid() == rustix::process::geteuid().as_raw() && meta.mode() & 0o077 == 0,
        "image batch state directory must be private and owned by the current user"
    );
    let lock: File = openat(
        &state,
        "lock",
        OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?
    .into();
    let meta = lock.metadata()?;
    ensure!(
        meta.is_file() && meta.nlink() == 1,
        "invalid image batch lock"
    );
    lock.try_lock()
        .context("image output directory is already in use")?;
    Ok((state, lock))
}

pub(super) fn discover(
    parent: &File,
    prefix: &Path,
    files: &mut Vec<PathBuf>,
    skipped: &mut usize,
) -> Result<()> {
    for entry in Dir::read_from(parent).with_context(|| format!("listing {}", prefix.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let name = OsStr::from_bytes(name);
        let relative = prefix.join(name);
        let info = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .with_context(|| format!("examining {}", relative.display()))?;
        if FileType::from_raw_mode(info.st_mode) == FileType::Directory {
            ensure!(
                relative.components().count() <= 128,
                "image input nesting exceeds 128 directories at {}",
                relative.display()
            );
            let child = directory(parent, Path::new(name), false)?;
            discover(&child, &relative, files, skipped)?;
        } else if super::image_raw::is_raw(&relative) {
            ensure!(
                files.len() < 100_000,
                "image batch exceeds 100,000 RAW paths"
            );
            files.push(relative);
        } else {
            *skipped += 1;
        }
    }
    Ok(())
}

pub(super) fn leaf_exists(parent: &File, name: &OsStr) -> Result<bool> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn regular_file(parent: &File, name: &OsStr) -> Result<File> {
    let file: File = openat(parent, name, OPEN_FILE, Mode::empty())
        .with_context(|| format!("opening {} without following links", name.to_string_lossy()))?
        .into();
    ensure!(
        file.metadata()?.is_file(),
        "{} must be a regular file",
        name.to_string_lossy()
    );
    Ok(file)
}

pub(super) fn digest(file: &mut File, limit: u64) -> Result<blake3::Hash> {
    let mut hasher = blake3::Hasher::new();
    let bytes = io::copy(&mut file.take(limit + 1), &mut hasher)?;
    ensure!(bytes <= limit, "file exceeds {limit} bytes");
    Ok(hasher.finalize())
}

pub(super) struct StagedFile<'a> {
    directory: &'a File,
    name: OsString,
    linked: bool,
    pub file: File,
}

impl<'a> StagedFile<'a> {
    pub fn create(directory: &'a File) -> Result<Self> {
        let mut nonce = [0; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|error| anyhow::anyhow!("could not generate temporary file name: {error}"))?;
        let name: OsString = format!(".dehaze-{}.tmp", hex::encode(nonce)).into();
        let file = openat(
            directory,
            &name,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?
        .into();
        Ok(Self {
            directory,
            name,
            linked: true,
            file,
        })
    }

    /// Publish a durable file in the same directory, without overwriting an output.
    pub fn publish(mut self, name: &OsStr, replace_receipt: bool) -> Result<()> {
        self.file.sync_all()?;
        if replace_receipt {
            renameat(self.directory, &self.name, self.directory, name)?;
        } else {
            linkat(
                self.directory,
                &self.name,
                self.directory,
                name,
                AtFlags::empty(),
            )?;
            unlinkat(self.directory, &self.name, AtFlags::empty())?;
        }
        self.linked = false;
        self.directory.sync_all()?;
        Ok(())
    }
}

impl Drop for StagedFile<'_> {
    fn drop(&mut self) {
        if self.linked {
            let _ = unlinkat(self.directory, &self.name, AtFlags::empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::symlink;

    #[test]
    fn output_tree_cannot_overlap_input() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("source");
        fs::create_dir(&input).unwrap();
        let output = input.join("nested/output");
        assert!(roots(&input, &output).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn traversal_refuses_linked_directories_and_raw_leaves() {
        let temporary = tempfile::tempdir().unwrap();
        let outside = temporary.path().join("outside");
        let source = temporary.path().join("source");
        fs::create_dir(&outside).unwrap();
        fs::create_dir(&source).unwrap();
        fs::write(outside.join("photo.dng"), b"outside").unwrap();
        symlink(&outside, source.join("linked")).unwrap();
        symlink(outside.join("photo.dng"), source.join("linked.dng")).unwrap();
        let (root, _) = roots(&source, &temporary.path().join("output")).unwrap();
        let mut paths = Vec::new();
        let mut skipped = 0;
        discover(&root, Path::new(""), &mut paths, &mut skipped).unwrap();
        assert_eq!(paths, [Path::new("linked.dng")]);
        assert_eq!(skipped, 1);
        assert!(regular_file(&root, "linked.dng".as_ref()).is_err());
        assert!(directory(&root, Path::new("linked"), true).is_err());
    }

    #[test]
    fn staged_publication_never_overwrites_an_existing_output() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("source");
        let output = temporary.path().join("output");
        fs::create_dir(&input).unwrap();
        let (_, root) = roots(&input, &output).unwrap();
        fs::write(output.join("result"), b"original").unwrap();
        let mut pending = StagedFile::create(&root).unwrap();
        pending.file.write_all(b"replacement").unwrap();
        assert!(pending.publish("result".as_ref(), false).is_err());
        assert_eq!(fs::read(output.join("result")).unwrap(), b"original");
        assert_eq!(fs::read_dir(&output).unwrap().count(), 1);
    }
}
