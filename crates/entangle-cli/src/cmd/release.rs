//! `entangle release` — verify and sign release artifacts, and run the
//! release-key ceremony (ATC-REL-1, ATC-REL-2).
//!
//! # `release verify` (ATC-REL-1)
//! A release artifact is trusted only if **both** hold:
//! 1. an Ed25519 signature (`<artifact>.ed25519`) by a key in the **release
//!    keyring** (`~/.entangle/release-keyring.toml`, a different trust class
//!    from the plugin-publisher keyring) or by the key given with
//!    `--release-key`; and
//! 2. a cosign bundle (`<artifact>.sigstore`) accepted by
//!    `cosign verify-blob --bundle <bundle> --certificate-identity-regexp <re>
//!    --certificate-oidc-issuer <issuer> <artifact>`.
//!
//! Both checks always run and every failure is reported; either failing fails
//! the command. A missing `cosign` binary is an error (`ENTANGLE-E0845`),
//! never a pass. The defaults for identity and issuer match the keyless
//! signing in `.github/workflows/release.yml`.
//!
//! # `release key split` / `combine` (ATC-REL-2)
//! Shamir sharing of a release key file; see `docs/governance/key-ceremony.md`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use entangle_signing::release::{sign_release, verify_release, ReleaseSignature};
use entangle_signing::shamir::{self, Share};
use entangle_signing::{IdentityKeyPair, IdentityPublicKey, Keyring, TrustEntry};

use crate::config;

/// Default cosign certificate identity (the release workflow's repository).
pub const DEFAULT_CERT_IDENTITY_REGEXP: &str = "https://github.com/thekozugroup/Entanglement/.+";
/// Default cosign OIDC issuer (GitHub Actions).
pub const DEFAULT_CERT_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

#[derive(Args)]
pub struct ReleaseArgs {
    #[command(subcommand)]
    pub cmd: ReleaseCmd,
}

#[derive(Subcommand)]
pub enum ReleaseCmd {
    /// Verify a release artifact: Ed25519 release-key signature AND cosign bundle.
    Verify {
        /// The artifact (e.g. `entanglement-v1.0.0-x86_64-unknown-linux-gnu.tar.gz`).
        artifact: PathBuf,
        /// Ed25519 signature file. Defaults to `<artifact>.ed25519`.
        #[arg(long)]
        signature: Option<PathBuf>,
        /// Cosign bundle. Defaults to `<artifact>.sigstore`.
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Trust exactly this release public key (64 hex chars) instead of the
        /// release keyring.
        #[arg(long)]
        release_key: Option<String>,
        /// Release keyring file. Defaults to `~/.entangle/release-keyring.toml`.
        #[arg(long)]
        release_keyring: Option<PathBuf>,
        /// The cosign binary.
        #[arg(long, default_value = "cosign")]
        cosign: PathBuf,
        /// `--certificate-identity-regexp` passed to cosign.
        #[arg(long, default_value = DEFAULT_CERT_IDENTITY_REGEXP)]
        certificate_identity_regexp: String,
        /// `--certificate-oidc-issuer` passed to cosign.
        #[arg(long, default_value = DEFAULT_CERT_OIDC_ISSUER)]
        certificate_oidc_issuer: String,
    },
    /// Write `<artifact>.ed25519`, signing with a release key.
    Sign {
        /// Artifact to sign.
        artifact: PathBuf,
        /// Release key (PKCS#8 PEM).
        #[arg(long)]
        key: PathBuf,
        /// Output path. Defaults to `<artifact>.ed25519`.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Release-key management and the key ceremony.
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
}

#[derive(Subcommand)]
pub enum KeyCmd {
    /// Generate a release key (PEM, mode 0600) and print its public key.
    Generate {
        /// Where to write the PEM. Refuses to overwrite.
        #[arg(long)]
        out: PathBuf,
    },
    /// Trust a release public key (stored in the release keyring).
    Add {
        /// 32-byte public key in hex (64 hex chars).
        public_key_hex: String,
        /// Name for this key.
        #[arg(long)]
        name: String,
        /// Release keyring file. Defaults to `~/.entangle/release-keyring.toml`.
        #[arg(long)]
        release_keyring: Option<PathBuf>,
    },
    /// Split a key file into Shamir shares (one file per share).
    Split {
        /// The key file to split.
        key: PathBuf,
        /// Shares needed to reconstruct (>= 2).
        #[arg(long, default_value_t = 2)]
        threshold: u8,
        /// Total shares to produce.
        #[arg(long, default_value_t = 3)]
        shares: u8,
        /// Directory for the share files. Defaults to the key's directory.
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// Reconstruct a key from share files.
    Combine {
        /// Share files (each holding one `entangle-share-v1:...` line).
        #[arg(required = true)]
        shares: Vec<PathBuf>,
        /// Where to write the reconstructed key. Refuses to overwrite.
        #[arg(long)]
        out: PathBuf,
    },
}

pub async fn run(args: ReleaseArgs) -> Result<()> {
    match args.cmd {
        ReleaseCmd::Verify {
            artifact,
            signature,
            bundle,
            release_key,
            release_keyring,
            cosign,
            certificate_identity_regexp,
            certificate_oidc_issuer,
        } => verify(&VerifyOptions {
            signature: signature.unwrap_or_else(|| sidecar(&artifact, "ed25519")),
            bundle: bundle.unwrap_or_else(|| sidecar(&artifact, "sigstore")),
            artifact,
            release_key,
            release_keyring: release_keyring.unwrap_or_else(config::release_keyring_path),
            cosign,
            certificate_identity_regexp,
            certificate_oidc_issuer,
        }),
        ReleaseCmd::Sign { artifact, key, out } => sign(&artifact, &key, out),
        ReleaseCmd::Key { cmd } => match cmd {
            KeyCmd::Generate { out } => generate(&out),
            KeyCmd::Add {
                public_key_hex,
                name,
                release_keyring,
            } => add_key(
                &public_key_hex,
                &name,
                &release_keyring.unwrap_or_else(config::release_keyring_path),
            ),
            KeyCmd::Split {
                key,
                threshold,
                shares,
                out_dir,
            } => split_key(&key, threshold, shares, out_dir.as_deref()),
            KeyCmd::Combine { shares, out } => combine_key(&shares, &out),
        },
    }
}

fn sidecar(artifact: &Path, ext: &str) -> PathBuf {
    let mut s = artifact.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// Inputs to [`verify`].
pub struct VerifyOptions {
    /// Artifact under test.
    pub artifact: PathBuf,
    /// Ed25519 signature file.
    pub signature: PathBuf,
    /// Cosign bundle.
    pub bundle: PathBuf,
    /// Explicit release public key (hex), overriding the keyring.
    pub release_key: Option<String>,
    /// Release keyring path (used when `release_key` is `None`).
    pub release_keyring: PathBuf,
    /// Cosign executable.
    pub cosign: PathBuf,
    /// Cosign identity regexp.
    pub certificate_identity_regexp: String,
    /// Cosign OIDC issuer.
    pub certificate_oidc_issuer: String,
}

fn release_trust(opts: &VerifyOptions) -> Result<Keyring> {
    match &opts.release_key {
        Some(hex_key) => {
            let mut ring = Keyring::new();
            ring.add(entry_from_hex(hex_key, "explicit --release-key")?);
            Ok(ring)
        }
        None => Keyring::load(&opts.release_keyring)
            .with_context(|| format!("loading {}", opts.release_keyring.display())),
    }
}

fn check_ed25519(opts: &VerifyOptions, artifact: &[u8]) -> Result<String> {
    let ring = release_trust(opts)?;
    let raw = std::fs::read_to_string(&opts.signature).with_context(|| {
        format!(
            "ENTANGLE-E0841: reading Ed25519 signature {}",
            opts.signature.display()
        )
    })?;
    let sig: ReleaseSignature = toml::from_str(&raw)
        .with_context(|| format!("ENTANGLE-E0841: parsing {}", opts.signature.display()))?;
    let entry = verify_release(artifact, &sig, &ring).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(format!(
        "{} ({})",
        entry.publisher_name,
        hex::encode(entry.fingerprint)
    ))
}

fn check_cosign(opts: &VerifyOptions) -> Result<()> {
    let out = Command::new(&opts.cosign)
        .arg("verify-blob")
        .arg("--bundle")
        .arg(&opts.bundle)
        .arg("--certificate-identity-regexp")
        .arg(&opts.certificate_identity_regexp)
        .arg("--certificate-oidc-issuer")
        .arg(&opts.certificate_oidc_issuer)
        .arg(&opts.artifact)
        .output();
    match out {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "ENTANGLE-E0845: cosign binary {:?} not found; the cosign (Rekor) signature cannot be \
             verified, so the release is NOT verified. Install cosign or pass --cosign <path>.",
            opts.cosign
        ),
        Err(e) => bail!("ENTANGLE-E0845: could not run {:?}: {e}", opts.cosign),
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => bail!(
            "ENTANGLE-E0846: cosign verify-blob rejected {}: {}",
            opts.artifact.display(),
            String::from_utf8_lossy(&o.stderr).trim()
        ),
    }
}

/// Verify both signatures. Both checks run; any failure fails the call.
pub fn verify(opts: &VerifyOptions) -> Result<()> {
    let artifact = std::fs::read(&opts.artifact)
        .with_context(|| format!("reading {}", opts.artifact.display()))?;
    let ed = check_ed25519(opts, &artifact);
    let cs = check_cosign(opts);
    match (&ed, &cs) {
        (Ok(signer), Ok(())) => {
            println!("ed25519: OK, signed by release key {signer}");
            println!(
                "cosign:  OK, identity ~ {} issuer {}",
                opts.certificate_identity_regexp, opts.certificate_oidc_issuer
            );
            println!("PASS: {} verified", opts.artifact.display());
            Ok(())
        }
        _ => {
            let mut problems = Vec::new();
            if let Err(e) = ed {
                problems.push(format!("ed25519: {e:#}"));
            }
            if let Err(e) = cs {
                problems.push(format!("cosign: {e:#}"));
            }
            bail!(
                "FAIL: {} NOT verified\n  {}",
                opts.artifact.display(),
                problems.join("\n  ")
            )
        }
    }
}

// ---------------------------------------------------------------------------
// sign / keys
// ---------------------------------------------------------------------------

fn sign(artifact: &Path, key: &Path, out: Option<PathBuf>) -> Result<()> {
    let pem = std::fs::read_to_string(key).with_context(|| format!("reading {}", key.display()))?;
    let kp = IdentityKeyPair::from_pem(&pem).map_err(|e| anyhow::anyhow!("invalid key: {e}"))?;
    let bytes =
        std::fs::read(artifact).with_context(|| format!("reading {}", artifact.display()))?;
    let sig = sign_release(&bytes, &kp);
    let out = out.unwrap_or_else(|| sidecar(artifact, "ed25519"));
    std::fs::write(&out, toml::to_string(&sig)?)
        .with_context(|| format!("writing {}", out.display()))?;
    println!("wrote {} (key {})", out.display(), kp.fingerprint_hex());
    Ok(())
}

fn entry_from_hex(public_key_hex: &str, name: &str) -> Result<TrustEntry> {
    let raw = hex::decode(public_key_hex.trim()).context("public key must be hex")?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes (64 hex chars)"))?;
    let pk = IdentityPublicKey::from_bytes(&arr).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(TrustEntry {
        fingerprint: pk.fingerprint(),
        public_key: arr,
        publisher_name: name.to_owned(),
        added_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        note: "release key".into(),
    })
}

fn add_key(public_key_hex: &str, name: &str, ring_path: &Path) -> Result<()> {
    let entry = entry_from_hex(public_key_hex, name)?;
    let fp = hex::encode(entry.fingerprint);
    let mut ring = Keyring::load(ring_path)?;
    ring.add(entry);
    ring.save(ring_path)?;
    println!("added release key {fp} \"{name}\" to {}", ring_path.display());
    Ok(())
}

/// Write `bytes` to a new file with mode 0600, refusing to overwrite.
fn write_secret_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {} (refusing to overwrite)", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

fn generate(out: &Path) -> Result<()> {
    let kp = IdentityKeyPair::generate();
    write_secret_new(out, kp.to_pem().as_bytes())?;
    println!("wrote {}", out.display());
    println!("fingerprint: {}", kp.fingerprint_hex());
    println!("public key:  {}", hex::encode(kp.public().as_bytes()));
    Ok(())
}

fn split_key(key: &Path, threshold: u8, shares: u8, out_dir: Option<&Path>) -> Result<()> {
    let secret = std::fs::read(key).with_context(|| format!("reading {}", key.display()))?;
    let parts = shamir::split(&secret, threshold, shares).map_err(|e| anyhow::anyhow!("{e}"))?;
    let dir = out_dir
        .map(Path::to_path_buf)
        .or_else(|| key.parent().map(Path::to_path_buf))
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir)?;
    let stem = key
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "key".into());
    for s in &parts {
        let path = dir.join(format!("{stem}.share-{}", s.index));
        write_secret_new(&path, format!("{}\n", s.encode()).as_bytes())?;
        println!("wrote {}", path.display());
    }
    println!(
        "{threshold}-of-{shares} split of {} (set id {}). Distribute one share per custodian, \
         then destroy the original key file.",
        key.display(),
        hex::encode(parts[0].set_id)
    );
    Ok(())
}

fn combine_key(files: &[PathBuf], out: &Path) -> Result<()> {
    let mut parts = Vec::new();
    for f in files {
        let text =
            std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
        parts.push(
            Share::decode(text.trim()).map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?,
        );
    }
    let secret = shamir::combine(&parts).map_err(|e| anyhow::anyhow!("{e}"))?;
    write_secret_new(out, &secret)?;
    println!("reconstructed {} bytes into {}", secret.len(), out.display());
    if let Some(kp) = std::str::from_utf8(&secret)
        .ok()
        .and_then(|p| IdentityKeyPair::from_pem(p).ok())
    {
        println!("key fingerprint: {}", kp.fingerprint_hex());
    }
    Ok(())
}
