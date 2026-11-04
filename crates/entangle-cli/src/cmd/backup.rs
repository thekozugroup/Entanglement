//! `entangle backup` / `entangle restore` (spec §6.5, §9.6).
//!
//! `backup --to <path>` exports the node identity, the trust keyrings, the
//! paired-peer list (with the `mesh.peer` capability tokens each record
//! carries) and the local capability-token revocation set
//! (`revoked-tokens.toml`) into one passphrase-encrypted archive; `restore
//! --from <path>` imports it on a new device. Biscuits are bound to the
//! identity and the keyring, not to the device, so every issued biscuit stays
//! valid — and every revoked one stays revoked: the revocation set travels
//! with the identity key the tokens are rooted at, since restoring the key
//! without it would make every token revoked before the backup verify again.
//!
//! # Archive format (version 1)
//!
//! ```text
//! offset  size  field
//!      0     8  magic  "ENTBKUP\0"
//!      8     2  format version, big endian (1)
//!     10     1  KDF id (1 = Argon2id, version 0x13)
//!     11     4  Argon2 memory cost in KiB, big endian
//!     15     4  Argon2 time cost (passes), big endian
//!     19     4  Argon2 parallelism, big endian
//!     23    16  Argon2 salt (random)
//!     39    24  XChaCha20-Poly1305 nonce (random)
//!     63     …  ciphertext || 16-byte Poly1305 tag
//! ```
//!
//! The 63-byte header is the AEAD's associated data, so changing any header
//! byte (including the KDF parameters) makes decryption fail. The plaintext is
//! a JSON document listing the files. The default KDF cost (64 MiB, 3 passes,
//! 1 lane) exceeds the OWASP Password Storage Cheat Sheet's Argon2id minimums.
//!
//! # Error codes (E0860–E0879)
//!
//! | Code  | Meaning |
//! |-------|---------|
//! | E0860 | No usable passphrase (no TTY and no `--passphrase-file`/env, empty, too short, mismatch) |
//! | E0861 | Not an Entanglement backup (bad magic, unsupported version, truncated, KDF parameters out of range) |
//! | E0862 | Decryption failed: wrong passphrase, or the archive was modified |
//! | E0863 | The decrypted payload is invalid (bad identity, unknown or duplicate file, malformed TOML) |
//! | E0864 | Restore would overwrite existing state and `--force` was not given |
//! | E0865 | The output path of `backup` already exists |
//! | E0866 | Nothing to back up (no `identity.key`), or it is unreadable |
//! | E0867 | I/O error writing the archive or the restored files |

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context as _, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use clap::Args;
use entangle_signing::IdentityKeyPair;
use rand_core::RngCore as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::entangle_dir;

/// Environment variable read when no `--passphrase-file` is given.
pub const PASSPHRASE_ENV: &str = "ENTANGLE_BACKUP_PASSPHRASE";

const MAGIC: &[u8; 8] = b"ENTBKUP\0";
const FORMAT_VERSION: u16 = 1;
const KDF_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 8 + 2 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
const TAG_LEN: usize = 16;
/// Largest archive `restore` will read (a real one is a few KiB).
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
/// Minimum passphrase length enforced when *creating* a backup.
const MIN_PASSPHRASE_CHARS: usize = 8;

/// Upper bounds accepted from an archive header, so a hostile file cannot make
/// `restore` allocate gigabytes or spin for minutes before failing.
const MAX_M_COST_KIB: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 10;
const MAX_LANES: u32 = 16;

/// Files that can be in an archive; anything else is rejected on restore.
const IDENTITY: &str = "identity.key";
const KEYRING: &str = "keyring.toml";
const RELEASE_KEYRING: &str = "release-keyring.toml";
const PEERS: &str = "peers.toml";
/// The local set of revoked capability-token ids (spec §6.5).
const REVOCATIONS: &str = entangle_peers::REVOCATIONS_FILE;
const CONFIG: &str = "config.toml";
/// State that always belongs to the identity: restored (or removed) together,
/// committed in this order. The revocation set goes in before the peer list,
/// so a peer is never back on the allowlist while its revoked token is not
/// yet in the set.
const MANAGED: [&str; 5] = [IDENTITY, KEYRING, RELEASE_KEYRING, REVOCATIONS, PEERS];

// ---------------------------------------------------------------------------
// Clap types
// ---------------------------------------------------------------------------

/// Arguments of `entangle backup`.
#[derive(Args)]
pub struct BackupArgs {
    /// Where to write the encrypted archive (created with mode 0600).
    #[arg(long, value_name = "PATH")]
    pub to: PathBuf,
    /// Also include config.toml.
    #[arg(long)]
    pub include_config: bool,
    /// Read the passphrase from this file (first line). Without it,
    /// `ENTANGLE_BACKUP_PASSPHRASE` is used when set (even at a terminal);
    /// otherwise the passphrase is prompted for, twice, on the terminal.
    #[arg(long, value_name = "FILE")]
    pub passphrase_file: Option<PathBuf>,
    /// Overwrite an existing archive at --to.
    #[arg(long)]
    pub force: bool,
}

/// Arguments of `entangle restore`.
#[derive(Args)]
pub struct RestoreArgs {
    /// The archive written by `entangle backup`.
    #[arg(long, value_name = "PATH")]
    pub from: PathBuf,
    /// Replace an existing identity/keyring/peer list (the replaced files are
    /// first copied to ~/.entangle/restore-backup-<unix_ts>/).
    #[arg(long)]
    pub force: bool,
    /// Read the passphrase from this file (first line). Without it,
    /// `ENTANGLE_BACKUP_PASSPHRASE` is used when set (even at a terminal);
    /// otherwise the passphrase is prompted for on the terminal.
    #[arg(long, value_name = "FILE")]
    pub passphrase_file: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Archive format
// ---------------------------------------------------------------------------

/// Argon2id cost parameters, recorded in the archive header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost: u32,
    /// Passes over the memory.
    pub t_cost: u32,
    /// Lanes.
    pub lanes: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // Above the OWASP minimum (19 MiB, t=2, p=1).
        Self {
            m_cost: 64 * 1024,
            t_cost: 3,
            lanes: 1,
        }
    }
}

/// One file in the archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveFile {
    /// File name relative to `~/.entangle/` (no directories).
    pub name: String,
    /// Base64 of the file bytes.
    data: String,
    /// The file's time (seconds since the Unix epoch): the older of its
    /// creation and modification times. `restore` gives the restored file
    /// this modification time, so the maintenance loop's key-age check
    /// (which uses the older of the two) still sees a restored old identity
    /// key as old. Absent in archives written before it was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    modified_unix: Option<u64>,
}

impl ArchiveFile {
    /// Wrap `bytes` as the archive entry `name`.
    pub fn new(name: &str, bytes: &[u8]) -> Self {
        Self {
            name: name.to_string(),
            data: base64::engine::general_purpose::STANDARD.encode(bytes),
            modified_unix: None,
        }
    }

    /// Record the time of the file at `path` (see `modified_unix`).
    fn with_time_of(mut self, path: &Path) -> Self {
        self.modified_unix = std::fs::metadata(path).ok().and_then(|m| {
            [m.created().ok(), m.modified().ok()]
                .into_iter()
                .flatten()
                .min()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
        });
        self
    }

    /// The recorded time, if any (and representable).
    fn time(&self) -> Option<std::time::SystemTime> {
        std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(self.modified_unix?))
    }

    fn bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.data)
            .map(Zeroizing::new)
            .map_err(|e| anyhow!("ENTANGLE-E0863: {} is not valid base64: {e}", self.name))
    }
}

// The base64 holds the identity's private key: wiped when dropped.
impl Drop for ArchiveFile {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.data);
    }
}

impl zeroize::ZeroizeOnDrop for ArchiveFile {}

/// The decrypted contents of an archive. Not `Clone`: it holds the identity
/// key, and every copy is one more buffer to wipe.
#[derive(Debug, Serialize, Deserialize)]
pub struct Contents {
    /// Payload schema version (1).
    pub format: u32,
    /// Creation time, seconds since the Unix epoch.
    pub created_unix: u64,
    /// The identity's fingerprint (the node's PeerId), for display and cross-checking.
    pub peer_id: String,
    /// The files.
    pub files: Vec<ArchiveFile>,
}

fn derive_key(pass: &[u8], salt: &[u8], p: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(p.m_cost, p.t_cost, p.lanes, Some(32))
        .map_err(|e| anyhow!("ENTANGLE-E0861: invalid KDF parameters: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // Our own work area (`hash_password_into` frees its own unwiped): it is
    // derived from the passphrase, so it is wiped when dropped.
    let mut blocks = Zeroizing::new(vec![argon2::Block::default(); argon.params().block_count()]);
    argon
        .hash_password_into_with_memory(pass, salt, key.as_mut(), blocks.as_mut_slice())
        .map_err(|e| anyhow!("ENTANGLE-E0861: key derivation failed: {e}"))?;
    Ok(key)
}

fn cipher_for(key: &[u8; 32]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("ENTANGLE-E0862: bad key length"))
}

/// The payload serialized into a buffer of exactly its size: a buffer grown
/// while serializing would leave freed, unwiped copies of the plaintext.
fn plaintext(contents: &Contents) -> Result<Zeroizing<Vec<u8>>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut n = Count(0);
    serde_json::to_writer(&mut n, contents)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(n.0));
    serde_json::to_writer(&mut *buf, contents)?;
    Ok(buf)
}

/// Encrypt `contents` under `passphrase` into the archive byte format.
pub fn seal(contents: &Contents, passphrase: &str, kdf: KdfParams) -> Result<Vec<u8>> {
    let plain = plaintext(contents)?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut salt);
    rand_core::OsRng.fill_bytes(&mut nonce);

    let mut out = Vec::with_capacity(HEADER_LEN + plain.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.push(KDF_ARGON2ID);
    out.extend_from_slice(&kdf.m_cost.to_be_bytes());
    out.extend_from_slice(&kdf.t_cost.to_be_bytes());
    out.extend_from_slice(&kdf.lanes.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    debug_assert_eq!(out.len(), HEADER_LEN);

    let key = derive_key(passphrase.as_bytes(), &salt, kdf)?;
    let cipher = cipher_for(&key)?;
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plain,
                aad: &out,
            },
        )
        .map_err(|_| anyhow!("ENTANGLE-E0862: encryption failed"))?;
    out.extend_from_slice(&ct);
    Ok(out)
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Decrypt and parse an archive. Nothing is written anywhere.
pub fn open(archive: &[u8], passphrase: &str) -> Result<Contents> {
    if archive.len() < HEADER_LEN + TAG_LEN || &archive[..8] != MAGIC {
        bail!(
            "ENTANGLE-E0861: not an Entanglement backup archive \
             (bad magic or truncated file)"
        );
    }
    let version = u16::from_be_bytes([archive[8], archive[9]]);
    if version != FORMAT_VERSION {
        bail!(
            "ENTANGLE-E0861: unsupported backup format version {version} \
             (this build reads version {FORMAT_VERSION})"
        );
    }
    if archive[10] != KDF_ARGON2ID {
        bail!("ENTANGLE-E0861: unknown KDF id {}", archive[10]);
    }
    let kdf = KdfParams {
        m_cost: be32(&archive[11..15]),
        t_cost: be32(&archive[15..19]),
        lanes: be32(&archive[19..23]),
    };
    if kdf.m_cost > MAX_M_COST_KIB || kdf.t_cost > MAX_T_COST || kdf.lanes > MAX_LANES {
        bail!(
            "ENTANGLE-E0861: KDF parameters in the archive are out of range \
             (m={} KiB, t={}, p={}); refusing to run them",
            kdf.m_cost,
            kdf.t_cost,
            kdf.lanes
        );
    }
    let salt = &archive[23..23 + SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&archive[23 + SALT_LEN..HEADER_LEN]);
    let key = derive_key(passphrase.as_bytes(), salt, kdf)?;
    let cipher = cipher_for(&key)?;
    let plain = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &archive[HEADER_LEN..],
                aad: &archive[..HEADER_LEN],
            },
        )
        .map_err(|_| {
            anyhow!(
                "ENTANGLE-E0862: cannot decrypt the backup: wrong passphrase, \
                 or the archive is corrupt or was modified. Nothing was changed."
            )
        })?;
    let plain = Zeroizing::new(plain);
    let contents: Contents = serde_json::from_slice(&plain)
        .map_err(|e| anyhow!("ENTANGLE-E0863: backup payload is malformed: {e}"))?;
    validate(&contents)?;
    Ok(contents)
}

/// Check a decrypted payload before anything touches the disk.
fn validate(c: &Contents) -> Result<()> {
    if c.format != 1 {
        bail!("ENTANGLE-E0863: unsupported payload format {}", c.format);
    }
    let mut seen = std::collections::HashSet::new();
    for f in &c.files {
        if !MANAGED.contains(&f.name.as_str()) && f.name != CONFIG {
            bail!("ENTANGLE-E0863: unexpected file {:?} in backup", f.name);
        }
        if !seen.insert(f.name.as_str()) {
            bail!("ENTANGLE-E0863: duplicate file {:?} in backup", f.name);
        }
        let bytes = f.bytes()?;
        if f.name == IDENTITY {
            let pem = std::str::from_utf8(&bytes)
                .map_err(|_| anyhow!("ENTANGLE-E0863: identity.key is not UTF-8"))?;
            let kp = IdentityKeyPair::from_pem(pem)
                .map_err(|e| anyhow!("ENTANGLE-E0863: identity.key in backup is invalid: {e}"))?;
            if kp.fingerprint_hex() != c.peer_id {
                bail!("ENTANGLE-E0863: backup peer_id does not match its identity key");
            }
        } else {
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| anyhow!("ENTANGLE-E0863: {} is not UTF-8", f.name))?;
            toml::from_str::<toml::Value>(text).map_err(|e| {
                anyhow!(
                    "ENTANGLE-E0863: {} in backup is not valid TOML: {e}",
                    f.name
                )
            })?;
        }
    }
    if !seen.contains(IDENTITY) {
        bail!("ENTANGLE-E0863: backup contains no identity.key");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Passphrase
// ---------------------------------------------------------------------------

/// The passphrase, from (in this order) `file`, [`PASSPHRASE_ENV`], or a
/// terminal prompt (twice when `confirm`). The variable wins over the prompt,
/// as `RESTIC_PASSWORD` or `BORG_PASSPHRASE` do, so it is announced on
/// stderr: a variable exported for some automated job is never used
/// silently.
fn read_passphrase(file: Option<&Path>, confirm: bool) -> Result<Zeroizing<String>> {
    let raw = if let Some(path) = file {
        warn_if_group_readable(path);
        let text = Zeroizing::new(std::fs::read_to_string(path).with_context(|| {
            format!(
                "ENTANGLE-E0860: cannot read passphrase file {}",
                path.display()
            )
        })?);
        Zeroizing::new(text.lines().next().unwrap_or("").to_string())
    } else if let Some(v) = std::env::var_os(PASSPHRASE_ENV) {
        eprintln!("using the passphrase from the {PASSPHRASE_ENV} environment variable");
        Zeroizing::new(v.to_string_lossy().into_owned())
    } else if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        let mut p = dialoguer::Password::new().with_prompt("Backup passphrase");
        if confirm {
            p = p.with_confirmation("Repeat passphrase", "ENTANGLE-E0860: passphrases differ");
        }
        Zeroizing::new(p.interact().context("ENTANGLE-E0860: reading passphrase")?)
    } else {
        bail!(
            "ENTANGLE-E0860: no passphrase available: stdin is not a terminal; \
             pass --passphrase-file <file> or set {PASSPHRASE_ENV}"
        );
    };
    if raw.is_empty() {
        bail!("ENTANGLE-E0860: the passphrase is empty");
    }
    if confirm && raw.chars().count() < MIN_PASSPHRASE_CHARS {
        bail!("ENTANGLE-E0860: the passphrase must be at least {MIN_PASSPHRASE_CHARS} characters");
    }
    Ok(raw)
}

fn warn_if_group_readable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(m) = std::fs::metadata(path) {
            if m.permissions().mode() & 0o077 != 0 {
                eprintln!(
                    "warning: passphrase file {} is readable by other users; chmod 600 it",
                    path.display()
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

/// Write `bytes` to `path` (mode 0600 from creation, fsynced, renamed into
/// place). An existing file is replaced, never written through, so a stale
/// looser mode cannot survive.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = stage_private(path, bytes, None)?;
    let result = std::fs::rename(&tmp, path);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Write `bytes` to a new temporary file next to `path` (mode 0600 from
/// creation, modification time `mtime` when given, fsynced) and return its
/// path; renaming it over `path` is left to the caller. Nothing is left
/// behind on failure.
fn stage_private(
    path: &Path,
    bytes: &[u8],
    mtime: Option<std::time::SystemTime>,
) -> std::io::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    create_private_dir(parent)?;
    let mut nonce = [0u8; 6];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let tmp = parent.join(format!(".{name}.tmp-{}", hex::encode(nonce)));
    let result = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        if let Some(t) = mtime {
            // Best effort: only the key-age warning depends on it.
            let _ = f.set_modified(t);
        }
        f.sync_all()
    })();
    match result {
        Ok(()) => Ok(tmp),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// `create_dir_all`, with mode 0700 for directories this call creates.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        b.mode(0o700);
    }
    b.create(dir)
}

/// The file's bytes (wiped when dropped: these are the identity key and its
/// trust state), or `None` if it does not exist.
fn read_optional(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(Zeroizing::new(b))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// backup
// ---------------------------------------------------------------------------

/// Collect the files to export from `dir` (an `~/.entangle/` directory).
pub fn collect(dir: &Path, include_config: bool) -> Result<Contents> {
    let id_bytes = read_optional(&dir.join(IDENTITY))?.ok_or_else(|| {
        anyhow!(
            "ENTANGLE-E0866: no identity at {}; nothing to back up (run `entangle init`)",
            dir.join(IDENTITY).display()
        )
    })?;
    let pem = std::str::from_utf8(&id_bytes)
        .map_err(|_| anyhow!("ENTANGLE-E0866: identity.key is not UTF-8"))?;
    let kp = IdentityKeyPair::from_pem(pem)
        .map_err(|e| anyhow!("ENTANGLE-E0866: identity.key is unreadable: {e}"))?;
    let mut files = vec![ArchiveFile::new(IDENTITY, &id_bytes).with_time_of(&dir.join(IDENTITY))];
    let mut names = vec![KEYRING, RELEASE_KEYRING, PEERS, REVOCATIONS];
    if include_config {
        names.push(CONFIG);
    }
    for name in names {
        if let Some(b) = read_optional(&dir.join(name))? {
            files.push(ArchiveFile::new(name, &b).with_time_of(&dir.join(name)));
        }
    }
    Ok(Contents {
        format: 1,
        created_unix: now_unix(),
        peer_id: kp.fingerprint_hex(),
        files,
    })
}

/// `entangle backup`.
pub async fn run_backup(args: BackupArgs) -> Result<()> {
    let dir = entangle_dir();
    if args.to.exists() && !args.force {
        bail!(
            "ENTANGLE-E0865: {} already exists; choose another path or pass --force",
            args.to.display()
        );
    }
    let contents = collect(&dir, args.include_config)?;
    let pass = read_passphrase(args.passphrase_file.as_deref(), true)?;
    let archive = seal(&contents, &pass, KdfParams::default())?;
    write_private(&args.to, &archive)
        .with_context(|| format!("ENTANGLE-E0867: writing {}", args.to.display()))?;
    // Silence the daemon's "identity has no backup" nag (maintenance.rs).
    let _ = write_private(&dir.join(".identity_backed_up"), b"");
    println!("backup written to {} (mode 0600)", args.to.display());
    println!("  peer id: {}", contents.peer_id);
    for f in &contents.files {
        println!("  includes {}", f.name);
    }
    println!("Keep the passphrase safe: without it the archive cannot be opened.");
    Ok(())
}

// ---------------------------------------------------------------------------
// restore
// ---------------------------------------------------------------------------

/// What `restore` will do to one managed file.
#[derive(Debug)]
struct Change {
    name: &'static str,
    /// New bytes, or `None` to remove a stale file the archive does not have.
    new: Option<Zeroizing<Vec<u8>>>,
    /// The new file's recorded time (see `ArchiveFile::modified_unix`).
    time: Option<std::time::SystemTime>,
    existing: Option<Zeroizing<Vec<u8>>>,
}

// Both byte buffers are `Zeroizing`.
impl zeroize::ZeroizeOnDrop for Change {}

fn plan(dir: &Path, c: &Contents) -> Result<Vec<Change>> {
    let mut out = Vec::new();
    for name in MANAGED.iter().copied().chain([CONFIG]) {
        let file = c.files.iter().find(|f| f.name == name);
        let new = match file {
            Some(f) => Some(f.bytes()?),
            None => None,
        };
        let time = file.and_then(ArchiveFile::time);
        let existing = read_optional(&dir.join(name))?;
        // config.toml is only touched when the archive carries it.
        if name == CONFIG && new.is_none() {
            continue;
        }
        if new.is_none() && existing.is_none() {
            continue;
        }
        out.push(Change {
            name,
            new,
            time,
            existing,
        });
    }
    Ok(out)
}

/// Apply an archive's `contents` to `dir`. Returns the directory holding
/// copies of replaced files, if any were replaced.
///
/// All or nothing as far as the file system allows: every new file is first
/// written to a temporary file next to its target, so a write failure (a
/// full disk, a file-size limit) changes nothing; only then are they renamed
/// into place, and if a rename fails the files already replaced are put
/// back. The identity is never left next to another identity's keyring or
/// peer list.
pub fn apply(dir: &Path, contents: &Contents, force: bool) -> Result<Option<PathBuf>> {
    apply_with(dir, contents, force, &mut |from, to| {
        std::fs::rename(from, to)
    })
}

/// [`apply`], with the commit step's rename injectable (tests).
fn apply_with(
    dir: &Path,
    contents: &Contents,
    force: bool,
    rename: &mut dyn FnMut(&Path, &Path) -> std::io::Result<()>,
) -> Result<Option<PathBuf>> {
    let changes = plan(dir, contents)?;
    let differs = |c: &Change| c.existing.is_some() && c.existing != c.new;
    let conflicts: Vec<&str> = changes
        .iter()
        .filter(|c| differs(c))
        .map(|c| c.name)
        .collect();
    if !conflicts.is_empty() && !force {
        bail!(
            "ENTANGLE-E0864: refusing to overwrite existing state in {} ({}). \
             Restoring replaces this device's identity; pass --force to continue \
             (the replaced files are first copied to a restore-backup directory).",
            dir.display(),
            conflicts.join(", ")
        );
    }
    create_private_dir(dir)
        .with_context(|| format!("ENTANGLE-E0867: creating {}", dir.display()))?;
    let mut backup_dir = None;
    if !conflicts.is_empty() {
        let base = now_unix();
        let mut n = 0u32;
        let bd = loop {
            let cand = dir.join(if n == 0 {
                format!("restore-backup-{base}")
            } else {
                format!("restore-backup-{base}-{n}")
            });
            if !cand.exists() {
                break cand;
            }
            n += 1;
        };
        create_private_dir(&bd)
            .with_context(|| format!("ENTANGLE-E0867: creating {}", bd.display()))?;
        for c in changes.iter().filter(|c| differs(c)) {
            if let Some(old) = &c.existing {
                write_private(&bd.join(c.name), old)
                    .with_context(|| format!("ENTANGLE-E0867: backing up {}", c.name))?;
            }
        }
        backup_dir = Some(bd);
    }
    let discard = |staged: &[Option<PathBuf>]| {
        for t in staged.iter().flatten() {
            let _ = std::fs::remove_file(t);
        }
    };
    // 1. Stage every new file (identical content too: that makes sure the
    //    mode is private). A failure here has changed nothing.
    let mut staged: Vec<Option<PathBuf>> = Vec::with_capacity(changes.len());
    for c in &changes {
        let path = dir.join(c.name);
        let tmp = match &c.new {
            Some(bytes) => match stage_private(&path, bytes, c.time) {
                Ok(t) => Some(t),
                Err(e) => {
                    discard(&staged);
                    // Nothing was replaced, so the copies are not needed.
                    if let Some(bd) = &backup_dir {
                        let _ = std::fs::remove_dir_all(bd);
                    }
                    bail!(
                        "ENTANGLE-E0867: writing {}: {e}; nothing was changed",
                        path.display()
                    );
                }
            },
            None => None,
        };
        staged.push(tmp);
    }
    // 2. Commit, in MANAGED order: rename into place, or remove a stale file
    //    the archive does not have. On failure put back what was replaced.
    for (i, (c, tmp)) in changes.iter().zip(&staged).enumerate() {
        let path = dir.join(c.name);
        let result = match tmp {
            Some(t) => rename(t, &path),
            None => std::fs::remove_file(&path),
        };
        if let Err(e) = result {
            discard(&staged[i..]);
            let state = match roll_back(dir, &changes[..i]) {
                Ok(()) => "the files already replaced were put back".to_string(),
                Err(failed) => format!(
                    "could not put back {failed}, so this node may hold a mix of old and \
                     restored files"
                ),
            };
            let copies = backup_dir
                .as_ref()
                .map(|bd| format!("; the previous files are in {}", bd.display()))
                .unwrap_or_default();
            bail!(
                "ENTANGLE-E0867: replacing {}: {e}; {state}{copies}",
                path.display()
            );
        }
    }
    Ok(backup_dir)
}

/// Undo `done` (changes already committed, in order): restore each file's
/// previous bytes, or remove it if it did not exist. `Err` names the files
/// that could not be put back.
fn roll_back(dir: &Path, done: &[Change]) -> std::result::Result<(), String> {
    let mut failed = Vec::new();
    for c in done.iter().rev() {
        let path = dir.join(c.name);
        let result = match &c.existing {
            Some(old) => write_private(&path, old),
            None => match std::fs::remove_file(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                r => r,
            },
        };
        if result.is_err() {
            failed.push(c.name);
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join(", "))
    }
}

/// `entangle restore`.
pub async fn run_restore(args: RestoreArgs) -> Result<()> {
    let len = std::fs::metadata(&args.from)
        .with_context(|| format!("cannot read {}", args.from.display()))?
        .len();
    if len > MAX_ARCHIVE_BYTES {
        bail!(
            "ENTANGLE-E0861: {} is too large to be a backup",
            args.from.display()
        );
    }
    let archive = std::fs::read(&args.from)
        .with_context(|| format!("cannot read {}", args.from.display()))?;
    let pass = read_passphrase(args.passphrase_file.as_deref(), false)?;
    let contents = open(&archive, &pass)?;
    let dir = entangle_dir();
    let backup = apply(&dir, &contents, args.force)?;
    println!(
        "restored identity {} into {}",
        contents.peer_id,
        dir.display()
    );
    for f in &contents.files {
        println!("  restored {}", f.name);
    }
    if let Some(b) = backup {
        println!("previous files were copied to {}", b.display());
    }
    println!("Restart the daemon (`entangled run`) to use the restored identity.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap KDF so byte-exhaustive tests run fast; the format is identical.
    const CHEAP: KdfParams = KdfParams {
        m_cost: 16,
        t_cost: 1,
        lanes: 1,
    };

    fn sample(dir: &Path) -> Contents {
        let kp = IdentityKeyPair::generate();
        std::fs::write(dir.join(IDENTITY), kp.to_pem()).unwrap();
        std::fs::write(dir.join(PEERS), "[[peers]]\nname = \"a\"\n").unwrap();
        std::fs::write(dir.join(KEYRING), "# keys\n").unwrap();
        collect(dir, false).unwrap()
    }

    #[test]
    fn default_kdf_meets_owasp_minimum() {
        let d = KdfParams::default();
        assert!(d.m_cost >= 19 * 1024 && d.t_cost >= 2 && d.lanes >= 1);
    }

    #[test]
    fn round_trip() {
        let t = tempfile::tempdir().unwrap();
        let c = sample(t.path());
        let ar = seal(&c, "correct horse", CHEAP).unwrap();
        let back = open(&ar, "correct horse").unwrap();
        assert_eq!(back.peer_id, c.peer_id);
        assert_eq!(back.files, c.files);
    }

    #[test]
    fn wrong_passphrase_is_a_clear_error() {
        let t = tempfile::tempdir().unwrap();
        let ar = seal(&sample(t.path()), "correct horse", CHEAP).unwrap();
        let e = open(&ar, "wrong horse").unwrap_err().to_string();
        assert!(
            e.contains("ENTANGLE-E0862") && e.contains("wrong passphrase"),
            "{e}"
        );
    }

    #[test]
    fn every_single_byte_flip_is_rejected() {
        let t = tempfile::tempdir().unwrap();
        let ar = seal(&sample(t.path()), "correct horse", CHEAP).unwrap();
        for i in 0..ar.len() {
            let mut bad = ar.clone();
            bad[i] ^= 0x01;
            assert!(
                open(&bad, "correct horse").is_err(),
                "flip at byte {i} accepted"
            );
        }
    }

    #[test]
    fn every_truncation_is_rejected() {
        let t = tempfile::tempdir().unwrap();
        let ar = seal(&sample(t.path()), "correct horse", CHEAP).unwrap();
        for n in 0..ar.len() {
            assert!(
                open(&ar[..n], "correct horse").is_err(),
                "prefix {n} accepted"
            );
        }
        let mut extended = ar.clone();
        extended.push(0);
        assert!(open(&extended, "correct horse").is_err());
    }

    #[test]
    fn hostile_kdf_parameters_are_refused_before_running() {
        let t = tempfile::tempdir().unwrap();
        let mut ar = seal(&sample(t.path()), "correct horse", CHEAP).unwrap();
        ar[11..15].copy_from_slice(&u32::MAX.to_be_bytes());
        let e = open(&ar, "correct horse").unwrap_err().to_string();
        assert!(e.contains("E0861") && e.contains("out of range"), "{e}");
    }

    #[test]
    fn archive_does_not_contain_plaintext() {
        let t = tempfile::tempdir().unwrap();
        let c = sample(t.path());
        let ar = seal(&c, "correct horse", CHEAP).unwrap();
        let pem = std::fs::read(t.path().join(IDENTITY)).unwrap();
        assert!(!ar.windows(16).any(|w| pem.windows(16).any(|p| p == w)));
        assert!(!ar.windows(8).any(|w| w == &c.peer_id.as_bytes()[..8]));
    }

    #[test]
    fn restore_refuses_existing_identity_without_force_and_keeps_a_copy_with_it() {
        let src = tempfile::tempdir().unwrap();
        let c = sample(src.path());
        let dst = tempfile::tempdir().unwrap();
        let other = IdentityKeyPair::generate().to_pem();
        std::fs::write(dst.path().join(IDENTITY), &other).unwrap();
        let e = apply(dst.path(), &c, false).unwrap_err().to_string();
        assert!(e.contains("ENTANGLE-E0864"), "{e}");
        assert_eq!(
            std::fs::read_to_string(dst.path().join(IDENTITY)).unwrap(),
            other
        );
        assert!(!dst.path().join(PEERS).exists(), "nothing may be written");

        let bd = apply(dst.path(), &c, true).unwrap().expect("backup dir");
        assert_eq!(std::fs::read_to_string(bd.join(IDENTITY)).unwrap(), other);
        let restored = std::fs::read_to_string(dst.path().join(IDENTITY)).unwrap();
        assert_eq!(
            IdentityKeyPair::from_pem(&restored)
                .unwrap()
                .fingerprint_hex(),
            c.peer_id
        );
    }

    /// A rename that fails during the commit step: what was already
    /// replaced is put back, and the error says so and names the copies.
    #[test]
    fn a_failed_commit_puts_back_what_it_replaced() {
        let src = tempfile::tempdir().unwrap();
        let c = sample(src.path());
        let dst = tempfile::tempdir().unwrap();
        let old_id = IdentityKeyPair::generate().to_pem();
        std::fs::write(dst.path().join(IDENTITY), &old_id).unwrap();
        std::fs::write(dst.path().join(KEYRING), "# old keys\n").unwrap();
        let mut n = 0;
        let e = apply_with(dst.path(), &c, true, &mut |from, to| {
            n += 1;
            if n == 2 {
                return Err(std::io::Error::other("injected"));
            }
            std::fs::rename(from, to)
        })
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("ENTANGLE-E0867") && e.contains("put back") && e.contains("restore-backup-"),
            "{e}"
        );
        assert_eq!(
            std::fs::read_to_string(dst.path().join(IDENTITY)).unwrap(),
            old_id
        );
        assert_eq!(
            std::fs::read_to_string(dst.path().join(KEYRING)).unwrap(),
            "# old keys\n"
        );
        assert!(!dst.path().join(PEERS).exists(), "{e}");
        let tmp: Vec<_> = std::fs::read_dir(dst.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(tmp.is_empty(), "{tmp:?}");
    }

    /// The maintenance loop warns once the identity key is older than
    /// `key_rotation_warn_days`, measured from the file's times. A restore
    /// brings back the same old key, so it must not look new afterwards.
    #[test]
    fn restore_keeps_the_identity_keys_age() {
        let src = tempfile::tempdir().unwrap();
        let _ = sample(src.path());
        let then = std::time::SystemTime::now() - std::time::Duration::from_secs(400 * 86_400);
        std::fs::File::options()
            .write(true)
            .open(src.path().join(IDENTITY))
            .unwrap()
            .set_modified(then)
            .unwrap();
        let c = collect(src.path(), false).unwrap();
        let back = open(&seal(&c, "correct horse", CHEAP).unwrap(), "correct horse").unwrap();
        let dst = tempfile::tempdir().unwrap();
        apply(dst.path(), &back, false).unwrap();
        let restored = std::fs::metadata(dst.path().join(IDENTITY))
            .unwrap()
            .modified()
            .unwrap();
        let off = restored
            .duration_since(then)
            .unwrap_or_else(|e| e.duration());
        assert!(off < std::time::Duration::from_secs(2), "off by {off:?}");
    }

    /// The identity key passes through several buffers on its way into or
    /// out of an archive; each is wiped when dropped, not just the
    /// passphrase, the key and the decrypted payload.
    #[test]
    fn secret_buffers_are_wiped_on_drop() {
        fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        fn wipeable<T: zeroize::Zeroize>() {}
        // The base64 of each file, as decoded from or encoded into the payload.
        wiped_on_drop::<ArchiveFile>();
        // What `restore` holds of each file, new and replaced.
        wiped_on_drop::<Change>();
        // Argon2's work area (64 MiB derived from the passphrase), wiped
        // through argon2's `zeroize` feature.
        wipeable::<argon2::Block>();
        // The serialized payload is written into a buffer of exactly its
        // size: a growing buffer would leave freed, unwiped copies of it.
        let t = tempfile::tempdir().unwrap();
        let plain = plaintext(&sample(t.path())).unwrap();
        assert_eq!(plain.capacity(), plain.len());
        assert!(serde_json::from_slice::<Contents>(&plain).is_ok());
    }

    #[test]
    fn rejects_unknown_file_names_and_bad_identity() {
        let t = tempfile::tempdir().unwrap();
        let mut c = sample(t.path());
        c.files.push(ArchiveFile::new("../evil", b"x"));
        assert!(validate(&c).unwrap_err().to_string().contains("E0863"));
        let mut c = sample(t.path());
        c.files[0] = ArchiveFile::new(IDENTITY, b"not a pem");
        assert!(validate(&c).unwrap_err().to_string().contains("E0863"));
    }
}
