//! Rollback protection for signed mirror listings.
//!
//! A listing's signature and expiry say it was genuine and is still within
//! its lifetime; they do not say it is the *latest*. A mirror (or anyone on
//! the path to it) can keep serving last week's correctly signed, unexpired
//! listing to hide a newer tag or a withdrawn one. To notice that, the client
//! remembers, per (repository, signing key), the `generated_at` and SHA-256
//! of the newest listing whose signature it has verified, and refuses a
//! verified listing that is older
//! ([`crate::ListingVerification::RolledBack`], `ENTANGLE-E0820`), or that
//! has the same `generated_at` but different bytes (equivocation by the
//! signer; reported as `Invalid`).
//!
//! `generated_at` is part of the signed listing bytes, so an attacker cannot
//! make an old listing look newer without a mirror key. The record is keyed
//! on what the signature binds, the listing's `repository` and the key
//! that signed it, not on the host that served it: the same signed listing
//! replayed through another mirror or the origin hits the same record.
//!
//! The record is a small TOML file (mode 0600 on Unix), by default
//! `~/.entangle/mirror-listing-state.toml`:
//!
//! ```toml
//! version = 2
//!
//! [repositories."acme/tool@<key fingerprint>"]
//! generated_at = 1800000000
//! key_fingerprint = "…"
//! listing_sha256 = "…"
//! recorded_at = 1800000100
//! ```
//!
//! The read-modify-write ([`ListingState::observe`], [`ListingState::record`],
//! [`ListingState::forget`]) runs under an exclusive advisory lock on the
//! sibling file `<state file>.lock`, so concurrent `entangle` processes do not
//! lose each other's records.
//!
//! **Resetting.** A mirror that was legitimately rebuilt from an older
//! snapshot trips this check. An operator who has confirmed that out of band
//! accepts the older listing once ([`crate::ListOptions::accept_older`]; CLI:
//! `entangle plugins tags <ref> --accept-older-listing`), which records it as
//! the new baseline. [`ListingState::forget`] drops one repository's records;
//! deleting the file clears all of them. A version 1 file (keyed on the
//! serving host, never released) is refused with `ENTANGLE-E0821`.
//!
//! The file is not secret and not signed: someone who can rewrite files in
//! `~/.entangle` can already replace the mirror keyring. A file that cannot
//! be parsed is an error (`ENTANGLE-E0821`), never silently treated as empty.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{OciError, Result};

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What is remembered about the newest listing seen for one repository.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SeenListing {
    /// `generated_at` (unix seconds) of the newest verified listing.
    pub generated_at: u64,
    /// Fingerprint (hex) of the mirror key that signed it.
    pub key_fingerprint: String,
    /// SHA-256 (hex) of the exact listing bytes that were signed.
    pub listing_sha256: String,
    /// Unix seconds when this record was written.
    pub recorded_at: u64,
}

/// What [`ListingState::observe`] concluded about a verified listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observation {
    /// Newer than the record (or the first one seen, or accepted as older
    /// with `accept_older`): recorded as the new baseline.
    Recorded,
    /// The listing already recorded (same `generated_at`, same bytes).
    Same,
    /// Older than the record: a rollback. Nothing was written.
    Older {
        /// `generated_at` of the newest listing recorded.
        newest_seen: u64,
    },
    /// Same `generated_at` as the record but different bytes: the signer
    /// published two listings for one instant. Nothing was written.
    Equivocation {
        /// SHA-256 recorded for that `generated_at`.
        recorded_sha256: String,
    },
}

/// The current state-file format version.
const STATE_VERSION: u32 = 2;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    version: u32,
    #[serde(default)]
    repositories: BTreeMap<String, SeenListing>,
}

/// Handle on the listing-state file. Cheap to clone; every operation reads
/// the file afresh under the lock, so concurrent `entangle` processes see
/// each other's records.
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
                    version: STATE_VERSION,
                    repositories: BTreeMap::new(),
                })
            }
            Err(e) => return Err(self.err(e)),
        };
        let file: StateFile = toml::from_str(&text).map_err(|e| self.err(e))?;
        if file.version != STATE_VERSION {
            return Err(self.err(format!(
                "unsupported version {} (this release writes version {STATE_VERSION})",
                file.version
            )));
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

    /// Exclusive advisory lock on `<state file>.lock`, held until dropped.
    fn lock(&self) -> Result<std::fs::File> {
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir).map_err(|e| self.err(e))?;
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".lock");
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let f = opts.open(dir.join(name)).map_err(|e| self.err(e))?;
        f.lock().map_err(|e| self.err(e))?;
        Ok(f)
    }

    /// The record key for `repository` signed by key `fingerprint`.
    pub fn key(repository: &str, fingerprint: &str) -> String {
        format!("{repository}@{}", fingerprint.to_ascii_lowercase())
    }

    /// The newest listing recorded for `repository` signed by the mirror key
    /// `fingerprint` (hex).
    pub fn newest(&self, repository: &str, fingerprint: &str) -> Result<Option<SeenListing>> {
        Ok(self
            .load()?
            .repositories
            .get(&Self::key(repository, fingerprint))
            .cloned())
    }

    /// Every record, by [`ListingState::key`].
    pub fn entries(&self) -> Result<BTreeMap<String, SeenListing>> {
        Ok(self.load()?.repositories)
    }

    /// Compare a verified listing (`repository`, signed by `fingerprint`,
    /// generated at `generated_at`, SHA-256 of its bytes `sha256`) with the
    /// record and record it when it is newer, or when `accept_older` is set
    /// and it is older or equivocates. The whole cycle runs under the lock.
    pub fn observe(
        &self,
        repository: &str,
        fingerprint: &str,
        generated_at: u64,
        sha256: &str,
        accept_older: bool,
    ) -> Result<Observation> {
        let _lock = self.lock()?;
        let mut file = self.load()?;
        let key = Self::key(repository, fingerprint);
        if let Some(seen) = file.repositories.get(&key) {
            let verdict = if generated_at < seen.generated_at {
                Some(Observation::Older {
                    newest_seen: seen.generated_at,
                })
            } else if generated_at == seen.generated_at {
                if seen.listing_sha256.eq_ignore_ascii_case(sha256) {
                    return Ok(Observation::Same);
                }
                Some(Observation::Equivocation {
                    recorded_sha256: seen.listing_sha256.clone(),
                })
            } else {
                None
            };
            if let Some(v) = verdict {
                if !accept_older {
                    return Ok(v);
                }
            }
        }
        file.repositories.insert(
            key,
            SeenListing {
                generated_at,
                key_fingerprint: fingerprint.to_ascii_lowercase(),
                listing_sha256: sha256.to_ascii_lowercase(),
                recorded_at: now_secs(),
            },
        );
        self.save(&file)?;
        Ok(Observation::Recorded)
    }

    /// Remember `seen` for `repository` (signed by `seen.key_fingerprint`),
    /// replacing what was there. Returns `false` (and writes nothing) when
    /// the stored record is identical apart from `recorded_at`.
    pub fn record(&self, repository: &str, seen: SeenListing) -> Result<bool> {
        let _lock = self.lock()?;
        let mut file = self.load()?;
        let key = Self::key(repository, &seen.key_fingerprint);
        if let Some(old) = file.repositories.get(&key) {
            if old.generated_at == seen.generated_at && old.listing_sha256 == seen.listing_sha256 {
                return Ok(false);
            }
        }
        file.repositories.insert(key, seen);
        self.save(&file)?;
        Ok(true)
    }

    /// Drop every record for `repository` (whatever key signed it). Returns
    /// whether there was one.
    pub fn forget(&self, repository: &str) -> Result<bool> {
        let _lock = self.lock()?;
        let mut file = self.load()?;
        let prefix = format!("{repository}@");
        let before = file.repositories.len();
        file.repositories.retain(|k, _| !k.starts_with(&prefix));
        if file.repositories.len() == before {
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
            listing_sha256: format!("{t:064x}"),
            recorded_at: 1,
        }
    }

    fn fp() -> String {
        "ab".repeat(16)
    }

    #[test]
    fn records_round_trip_and_the_file_is_private() {
        let d = tempfile::tempdir().unwrap();
        let s = ListingState::at(d.path().join("sub/state.toml"));
        assert_eq!(s.newest("r/a", &fp()).unwrap(), None);
        assert!(s.record("r/a", seen(10)).unwrap());
        assert!(!s.record("r/a", seen(10)).unwrap(), "same record: no write");
        assert!(s.record("r/b", seen(20)).unwrap());
        assert_eq!(s.newest("r/a", &fp()).unwrap().unwrap().generated_at, 10);
        assert_eq!(s.entries().unwrap().len(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(s.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        }
        assert!(s.forget("r/a").unwrap());
        assert!(!s.forget("r/a").unwrap());
        assert_eq!(s.newest("r/a", &fp()).unwrap(), None);
        assert_eq!(s.newest("r/b", &fp()).unwrap().unwrap().generated_at, 20);
    }

    /// A wider mode left by an earlier writer is tightened on the next write.
    #[cfg(unix)]
    #[test]
    fn an_existing_world_readable_file_is_replaced_by_a_private_one() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state.toml");
        std::fs::write(&p, "version = 2\n").unwrap();
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
            "version = 1\n",
            "version = 2\nextra = true\n",
        ] {
            std::fs::write(&p, bad).unwrap();
            let e = ListingState::at(&p)
                .newest("r/a", &fp())
                .unwrap_err()
                .to_string();
            assert!(e.starts_with("ENTANGLE-E0821"), "{bad:?}: {e}");
            assert!(e.contains("delete it"), "{e}");
            // ...and a record does not overwrite it.
            assert!(ListingState::at(&p).record("r/a", seen(1)).is_err());
            assert_eq!(std::fs::read_to_string(&p).unwrap(), bad);
        }
    }
}
