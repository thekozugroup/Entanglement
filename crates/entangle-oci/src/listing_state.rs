//! Rollback protection for signed mirror listings.
//!
//! A listing's signature and expiry say it was genuine and is still within
//! its lifetime; they do not say it is the *latest*. A mirror (or anyone on
//! the path to it) can keep serving last week's correctly signed, unexpired
//! listing to hide a newer tag or a withdrawn one. To notice that, the client
//! remembers, per repository, the `generated_at` of the newest listing whose
//! signature it has verified, and refuses a verified listing that is older
//! ([`crate::ListingVerification::RolledBack`], `ENTANGLE-E0820`).
//!
//! `generated_at` is part of the signed listing bytes, so an attacker cannot
//! make an old listing look newer without a mirror key.
//!
//! The record is a small TOML file (mode 0600 on Unix), by default
//! `~/.entangle/mirror-listing-state.toml`:
//!
//! ```toml
//! version = 1
//!
//! [repositories."registry.example.org/acme/tool"]
//! generated_at = 1800000000
//! key_fingerprint = "…"
//! recorded_at = 1800000100
//! ```
//!
//! **Resetting.** A mirror that was legitimately rebuilt from an older
//! snapshot trips this check. An operator who has confirmed that out of band
//! clears one repository with [`ListingState::forget`] (CLI: `entangle
//! plugins tags <ref> --accept-older-listing`, or `entangle mirror forget
//! <ref>`), or deletes the file to clear all of them.
//!
//! The file is not secret and not signed: someone who can rewrite files in
//! `~/.entangle` can already replace the mirror keyring. A file that cannot
//! be parsed is an error (`ENTANGLE-E0821`), never silently treated as empty.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{OciError, Result};

/// What is remembered about the newest listing seen for one repository.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SeenListing {
    /// `generated_at` (unix seconds) of the newest verified listing.
    pub generated_at: u64,
    /// Fingerprint (hex) of the mirror key that signed it.
    pub key_fingerprint: String,
    /// Unix seconds when this record was written.
    pub recorded_at: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    version: u32,
    #[serde(default)]
    repositories: BTreeMap<String, SeenListing>,
}

/// Handle on the listing-state file. Cheap to clone; every operation reads
/// the file afresh, so concurrent `entangle` processes see each other's
/// records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListingState {
    path: PathBuf,
}

impl ListingState {
    /// Use the state file at `path` (created on first record).
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file this handle reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn err(&self, what: impl std::fmt::Display) -> OciError {
        OciError::ListingState(format!(
            "{}: {what}. If the file is damaged, delete it to start afresh (rollback \
             protection then restarts from the next listing seen)",
            self.path.display()
        ))
    }

    fn load(&self) -> Result<StateFile> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(StateFile {
                    version: 1,
                    repositories: BTreeMap::new(),
                })
            }
            Err(e) => return Err(self.err(e)),
        };
        let file: StateFile = toml::from_str(&text).map_err(|e| self.err(e))?;
        if file.version != 1 {
            return Err(self.err(format!("unsupported version {}", file.version)));
        }
        Ok(file)
    }

    fn save(&self, file: &StateFile) -> Result<()> {
        let text = toml::to_string(file).map_err(|e| self.err(e))?;
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir).map_err(|e| self.err(e))?;
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "listing-state".into());
        let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
        let write = || -> std::io::Result<()> {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            #[cfg(unix)]
            {
                // The mode above only applies when the file is created.
                use std::os::unix::fs::PermissionsExt as _;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        };
        write().map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            self.err(e)
        })
    }

    /// The newest listing recorded for `repository` (`registry/repository`).
    pub fn newest(&self, repository: &str) -> Result<Option<SeenListing>> {
        Ok(self.load()?.repositories.get(repository).cloned())
    }

    /// Every record, by `registry/repository`.
    pub fn entries(&self) -> Result<BTreeMap<String, SeenListing>> {
        Ok(self.load()?.repositories)
    }

    /// Remember `seen` for `repository`, replacing what was there. Returns
    /// `false` (and writes nothing) when the stored record is identical apart
    /// from `recorded_at`.
    pub fn record(&self, repository: &str, seen: SeenListing) -> Result<bool> {
        let mut file = self.load()?;
        if let Some(old) = file.repositories.get(repository) {
            if old.generated_at == seen.generated_at && old.key_fingerprint == seen.key_fingerprint
            {
                return Ok(false);
            }
        }
        file.repositories.insert(repository.to_owned(), seen);
        self.save(&file)?;
        Ok(true)
    }

    /// Drop the record for `repository`. Returns whether there was one.
    pub fn forget(&self, repository: &str) -> Result<bool> {
        let mut file = self.load()?;
        if file.repositories.remove(repository).is_none() {
            return Ok(false);
        }
        self.save(&file)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(t: u64) -> SeenListing {
        SeenListing {
            generated_at: t,
            key_fingerprint: "ab".repeat(16),
            recorded_at: 1,
        }
    }

    #[test]
    fn records_round_trip_and_the_file_is_private() {
        let d = tempfile::tempdir().unwrap();
        let s = ListingState::at(d.path().join("sub/state.toml"));
        assert_eq!(s.newest("r/a").unwrap(), None);
        assert!(s.record("r/a", seen(10)).unwrap());
        assert!(!s.record("r/a", seen(10)).unwrap(), "same record: no write");
        assert!(s.record("r/b", seen(20)).unwrap());
        assert_eq!(s.newest("r/a").unwrap().unwrap().generated_at, 10);
        assert_eq!(s.entries().unwrap().len(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(s.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        }
        assert!(s.forget("r/a").unwrap());
        assert!(!s.forget("r/a").unwrap());
        assert_eq!(s.newest("r/a").unwrap(), None);
        assert_eq!(s.newest("r/b").unwrap().unwrap().generated_at, 20);
    }

    /// A wider mode left by an earlier writer is tightened on the next write.
    #[cfg(unix)]
    #[test]
    fn an_existing_world_readable_file_is_replaced_by_a_private_one() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state.toml");
        std::fs::write(&p, "version = 1\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        ListingState::at(&p).record("r/a", seen(1)).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    #[test]
    fn a_damaged_file_is_an_error_not_an_empty_state() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state.toml");
        for bad in [
            "not = [toml",
            "version = 2\n",
            "version = 1\nextra = true\n",
        ] {
            std::fs::write(&p, bad).unwrap();
            let e = ListingState::at(&p).newest("r/a").unwrap_err().to_string();
            assert!(e.starts_with("ENTANGLE-E0821"), "{bad:?}: {e}");
            assert!(e.contains("delete it"), "{e}");
            // ...and a record does not overwrite it.
            assert!(ListingState::at(&p).record("r/a", seen(1)).is_err());
            assert_eq!(std::fs::read_to_string(&p).unwrap(), bad);
        }
    }
}
