//! Trusted-publisher keyring, stored as TOML on disk.
//!
//! Default path: `~/.entangle/keyring.toml`

use std::{collections::HashMap, path::Path};

use thiserror::Error;

/// Errors from keyring I/O and parsing.
#[derive(Debug, Error)]
pub enum KeyringError {
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// TOML deserialization failure.
    #[error("toml parse: {0}")]
    Parse(#[from] toml::de::Error),
    /// TOML serialization failure.
    #[error("toml serialize: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// Hex decode failure (e.g. on raw bytes from a loaded file).
    #[error("hex decode: {0}")]
    Hex(String),
}

/// A single trusted-publisher record.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TrustEntry {
    /// 16-byte BLAKE3 fingerprint of the publisher key (hex-encoded on disk).
    #[serde(
        serialize_with = "serialize_fp_hex",
        deserialize_with = "deserialize_fp_hex"
    )]
    pub fingerprint: [u8; 16],
    /// Raw 32-byte verifying key (hex-encoded on disk).
    #[serde(
        serialize_with = "serialize_pk_hex",
        deserialize_with = "deserialize_pk_hex"
    )]
    pub public_key: [u8; 32],
    /// Human-readable publisher name.
    pub publisher_name: String,
    /// Unix timestamp (seconds) when this entry was added.
    pub added_at: u64,
    /// Free-form note, e.g. "vendor X official key".
    pub note: String,
}

// ---------------------------------------------------------------------------
// TOML on-disk schema wrapper
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyringFile {
    #[serde(default)]
    entries: Vec<TrustEntry>,
}

/// An in-memory set of trusted publisher keys, keyed by 16-byte fingerprint.
#[derive(Clone, Debug, Default)]
pub struct Keyring {
    entries: HashMap<[u8; 16], TrustEntry>,
}

impl Keyring {
    /// Create an empty keyring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a trust entry.
    pub fn add(&mut self, e: TrustEntry) {
        self.entries.insert(e.fingerprint, e);
    }

    /// Remove an entry by fingerprint, returning it if present.
    pub fn remove(&mut self, fp: &[u8; 16]) -> Option<TrustEntry> {
        self.entries.remove(fp)
    }

    /// Look up an entry by fingerprint.
    pub fn lookup(&self, fp: &[u8; 16]) -> Option<&TrustEntry> {
        self.entries.get(fp)
    }

    /// Iterate over all entries.
    pub fn entries(&self) -> impl Iterator<Item = &TrustEntry> {
        self.entries.values()
    }

    /// Load keyring from a TOML file. Missing file returns an empty keyring.
    pub fn load(path: &Path) -> Result<Self, KeyringError> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw = std::fs::read_to_string(path)?;
        let file: KeyringFile = toml::from_str(&raw)?;
        let mut kr = Self::new();
        for e in file.entries {
            kr.add(e);
        }
        Ok(kr)
    }

    /// Persist keyring to a TOML file, creating parent directories as needed.
    ///
    /// On Unix the file is written with mode `0600` (owner read/write only),
    /// matching the `identity.key` handling — the trust roots decide which
    /// plugins load, so other users must not be able to tamper with or
    /// pre-seed them.
    pub fn save(&self, path: &Path) -> Result<(), KeyringError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = KeyringFile {
            entries: self.entries.values().cloned().collect(),
        };
        let raw = toml::to_string_pretty(&file)?;
        write_owner_only(path, raw.as_bytes())?;
        Ok(())
    }
}

/// Write `contents` to `path` with owner-only (`0600`) permissions on Unix.
#[cfg(unix)]
fn write_owner_only(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents)?;
    // `.mode()` only applies when the file is created; enforce 0600 for
    // pre-existing files too.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Non-Unix fallback: plain write (no POSIX permission bits to set).
#[cfg(not(unix))]
fn write_owner_only(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

// ---------------------------------------------------------------------------
// Serde helpers: fixed-size byte arrays as hex strings
// ---------------------------------------------------------------------------

fn serialize_fp_hex<S>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&hex::encode(v))
}

fn deserialize_fp_hex<'de, D>(d: D) -> Result<[u8; 16], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let txt = <String as serde::Deserialize>::deserialize(d)?;
    let b = hex::decode(&txt).map_err(serde::de::Error::custom)?;
    b.try_into()
        .map_err(|_| serde::de::Error::custom("expected 16-byte fingerprint hex"))
}

fn serialize_pk_hex<S>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&hex::encode(v))
}

fn deserialize_pk_hex<'de, D>(d: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let txt = <String as serde::Deserialize>::deserialize(d)?;
    let b = hex::decode(&txt).map_err(serde::de::Error::custom)?;
    b.try_into()
        .map_err(|_| serde::de::Error::custom("expected 32-byte public key hex"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(byte: u8) -> TrustEntry {
        TrustEntry {
            fingerprint: [byte; 16],
            public_key: [byte; 32],
            publisher_name: format!("publisher-{byte}"),
            added_at: 0,
            note: String::new(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyring.toml");

        let mut kr = Keyring::new();
        kr.add(entry(1));
        kr.save(&path).expect("save must succeed");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "keyring file must be 0600, got {mode:04o}");
    }

    #[cfg(unix)]
    #[test]
    fn save_tightens_permissions_on_existing_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyring.toml");

        // Pre-create the file with loose permissions.
        std::fs::write(&path, "entries = []\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mut kr = Keyring::new();
        kr.add(entry(2));
        kr.save(&path).expect("save must succeed");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "save over an existing file must tighten to 0600, got {mode:04o}"
        );
    }

    #[test]
    fn save_load_round_trip_preserves_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyring.toml");

        let mut kr = Keyring::new();
        kr.add(entry(3));
        kr.add(entry(4));
        kr.save(&path).unwrap();

        let loaded = Keyring::load(&path).unwrap();
        assert!(loaded.lookup(&[3u8; 16]).is_some());
        assert!(loaded.lookup(&[4u8; 16]).is_some());
    }
}
