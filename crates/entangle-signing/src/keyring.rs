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
    pub fn save(&self, path: &Path) -> Result<(), KeyringError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = KeyringFile {
            entries: self.entries.values().cloned().collect(),
        };
        let raw = toml::to_string_pretty(&file)?;
        std::fs::write(path, raw)?;
        Ok(())
    }
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
