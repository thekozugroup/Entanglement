//! Installing a signed package that came from somewhere: the steps every
//! such path shares, plus the plain-HTTPS URL, local archive and
//! `.entanglepack` paths (spec §3.6 path B and "offline / air-gapped").
//!
//! Whatever delivered the bytes (a registry, a mirror, a web server, a USB
//! stick), the order is the same and nothing is written until all of it has
//! passed:
//!
//! 1. [`entangle_oci::verify_package`] against the user's publisher keyring;
//! 2. [`check_policy`]: the manifest is valid, its effective tier is within
//!    `[security] max_tier_allowed` (`ENTANGLE-E0043`), the plugin is not in
//!    `[plugins] disabled` (`ENTANGLE-E0759`), and the artifact is what the
//!    manifest's `runtime` says it is (`ENTANGLE-E0507`);
//! 3. [`write_verified`]: staged next to the destination and swapped in whole;
//! 4. [`load_installed`]: the kernel verifies the signature again.
//!
//! The URL path adds a step **before** 1: the detached signature
//! (`<url>.sig`) is checked on the raw archive bytes, so an archive nobody in
//! the keyring vouches for is never even decompressed.

use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use anyhow::{bail, Context, Result};
use entangle_oci::{
    archive_signature_signer, fetch_url, parse_download_url, read_pack, signature_url,
    verify_archive_signature, verify_package, FetchOptions, OciError, VerifiedPackage,
    MAX_ARCHIVE_SIGNATURE_BYTES, MAX_PACK_BYTES,
};
use entangle_signing::{Keyring, TrustEntry, VerificationError};
use entangle_types::plugin_id::PluginId;

use crate::cmd::plugins::Session;
use crate::config;

/// Largest package archive accepted from a URL or a local file.
pub const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

/// What to tell the user when a publisher is not in their keyring.
const TRUST_HINT: &str = "Only plugins signed by a publisher in your keyring are accepted, \
     wherever the bytes came from; trust a publisher with \
     `entangle keyring add <PUBLIC_KEY_HEX> --name <NAME>`";

// ---------------------------------------------------------------------------
// Shared steps
// ---------------------------------------------------------------------------

/// A verified package that also passed [`check_policy`].
pub(crate) struct Cleared {
    /// The verified package.
    pub verified: VerifiedPackage,
    /// Its parsed plugin id.
    pub id: PluginId,
    /// Its effective tier.
    pub tier: u8,
}

/// The policy checks every install path applies to a verified package before
/// anything is written. `max_tier` and `disabled` come from config.toml.
pub(crate) fn check_policy_with(
    verified: VerifiedPackage,
    max_tier: u8,
    disabled: &[String],
) -> Result<Cleared> {
    let text =
        std::str::from_utf8(&verified.files.manifest).context("entangle.toml is not UTF-8")?;
    let parsed: entangle_manifest::Manifest =
        toml::from_str(text).context("parsing entangle.toml from the package")?;
    let validated = entangle_manifest::validate::validate(parsed)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("the package's entangle.toml is not a valid plugin manifest")?;
    let tier = validated.effective_tier as u8;
    if tier > max_tier {
        bail!(
            "ENTANGLE-E0043: {} declares effective tier {tier}, above this machine's \
             security.max_tier_allowed = {max_tier} (~/.entangle/config.toml); not installed",
            verified.plugin_id
        );
    }
    let id = PluginId::from_str(&verified.plugin_id)
        .map_err(|e| anyhow::anyhow!("plugin id {}: {e}", verified.plugin_id))?;
    if disabled.iter().any(|d| *d == id.to_string()) {
        bail!(
            "ENTANGLE-E0759: plugin {id} is disabled in config.toml ([plugins] disabled); not \
             installed. Allow it again with `entangle plugins enable {id}`"
        );
    }
    let declared = match validated.runtime {
        entangle_manifest::Runtime::Native => entangle_host::DeclaredRuntime::Native,
        _ => entangle_host::DeclaredRuntime::Wasm,
    };
    entangle_host::check_runtime_kind(declared, &verified.files.wasm)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("{id} was NOT installed"))?;
    Ok(Cleared { verified, id, tier })
}

/// [`check_policy_with`] using this machine's `~/.entangle/config.toml`.
pub(crate) fn check_policy(verified: VerifiedPackage) -> Result<Cleared> {
    let cfg = config::load(&config::config_path())?;
    check_policy_with(
        verified,
        cfg.security.max_tier_allowed,
        &cfg.plugins.disabled,
    )
}

/// The default install directory is keyed on the plugin name only; do not let
/// one trusted publisher's plugin silently replace another's there.
fn refuse_other_publishers_install(dir: &Path, id: &PluginId) -> Result<()> {
    let Ok(text) = std::fs::read_to_string(dir.join("entangle.toml")) else {
        return Ok(());
    };
    let existing = toml::from_str::<toml::Value>(&text)
        .ok()
        .and_then(|v| v.get("plugin")?.get("id")?.as_str().map(str::to_owned))
        .and_then(|s| PluginId::from_str(&s).ok());
    if let Some(old) = existing {
        if old.publisher != id.publisher {
            bail!(
                "{} already holds `{old}`, installed from a different publisher than `{id}`; \
                 not overwriting it. Pick another directory with --out",
                dir.display()
            );
        }
    }
    Ok(())
}

/// Write `files` into `out` so that a failure never leaves a mixed directory:
/// stage in a sibling directory, then swap it into place.
fn write_package_atomically(files: &entangle_oci::PackageFiles, out: &Path) -> Result<()> {
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    std::fs::create_dir_all(&parent)?;
    let base = out
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "plugin".into());
    let pid = std::process::id();
    let staging = parent.join(format!(".{base}.staging-{pid}"));
    let backup = parent.join(format!(".{base}.old-{pid}"));
    let _ = std::fs::remove_dir_all(&staging);
    let _ = std::fs::remove_dir_all(&backup);
    if let Err(e) = files.write_dir(&staging) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e.into());
    }
    let had_old = std::fs::symlink_metadata(out).is_ok();
    if had_old {
        if let Err(e) = std::fs::rename(out, &backup) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e.into());
        }
    }
    if let Err(e) = std::fs::rename(&staging, out) {
        if had_old {
            let _ = std::fs::rename(&backup, out);
        }
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e.into());
    }
    if had_old {
        // Best effort: the new package is already in place.
        if std::fs::remove_dir_all(&backup).is_err() {
            let _ = std::fs::remove_file(&backup);
        }
    }
    Ok(())
}

/// Where a cleared package goes: `out`, or `~/.entangle/plugins/<name>`.
/// The default directory is guarded against a different publisher's plugin
/// of the same name; an explicit `--out` is the user's own choice.
pub(crate) fn destination(cleared: &Cleared, out: Option<&Path>) -> Result<PathBuf> {
    match out {
        Some(p) => Ok(p.to_path_buf()),
        None => {
            let dir = crate::cmd::catalog::default_out_dir(&cleared.id.name);
            refuse_other_publishers_install(&dir, &cleared.id)?;
            Ok(dir)
        }
    }
}

/// Write a cleared package to `out`, whole or not at all.
pub(crate) fn write_verified(cleared: &Cleared, out: &Path) -> Result<()> {
    write_package_atomically(&cleared.verified.files, out)
        .with_context(|| format!("writing package to {}", out.display()))
}

/// Load an installed package (or say how to, with `--no-load`).
pub(crate) async fn load_installed(
    step: &str,
    out: &Path,
    plugin_id: &str,
    no_load: bool,
) -> Result<()> {
    if no_load {
        println!("{step} skipped loading (--no-load)");
        println!(
            "      load it with: entangle plugins load {}",
            out.display()
        );
        return Ok(());
    }
    println!("{step} loading (the kernel verifies the signature again)");
    let session = Session::connect().await?;
    let report = session
        .load_package(out, plugin_id)
        .await
        .with_context(|| {
            format!(
                "loading {plugin_id} (the verified package is at {}; retry with `entangle plugins load {}`)",
                out.display(),
                out.display()
            )
        })?;
    if report.already_loaded {
        println!("      {} was already loaded — nothing to do", report.id);
    } else {
        println!("      loaded {} into the {}", report.id, session.describe());
    }
    if !session.is_daemon() {
        println!("      NOTE: no daemon is running, so that load was temporary.");
    }
    Ok(())
}

/// Read a local file that may be large, refusing one over `limit` before
/// reading it.
fn read_capped(path: &Path, limit: u64, what: &str) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if meta.len() > limit {
        return Err(OciError::TooLarge {
            what: format!("{what} {}", path.display()),
            size: meta.len(),
            limit,
        }
        .into());
    }
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

// ---------------------------------------------------------------------------
// `entangle plugins install https://…/x.tar.zst`
// ---------------------------------------------------------------------------

/// Options for [`install_url`].
pub struct UrlInstallOptions {
    /// `https://…/<name>.tar.zst` (plain `http://` for a loopback host only).
    pub url: String,
    /// Where to write the verified package (default `~/.entangle/plugins/<name>`).
    pub out: Option<PathBuf>,
    /// Verify and write, but do not load.
    pub no_load: bool,
}

/// `entangle plugins install <URL>`: fetch `<URL>.sig` and `<URL>`, check the
/// detached signature against the keyring before the archive is opened, then
/// the shared steps.
pub async fn install_url(opts: UrlInstallOptions) -> Result<()> {
    let url = parse_download_url(&opts.url)?;
    let sig_url = signature_url(&url);

    println!("[1/5] fetching {sig_url}");
    let sig = fetch_url(
        &sig_url,
        "detached signature",
        &FetchOptions {
            max_bytes: MAX_ARCHIVE_SIGNATURE_BYTES,
            ..FetchOptions::default()
        },
    )
    .await
    .map_err(|e| match e {
        OciError::Status { status: 404, .. } => OciError::DetachedSignature(format!(
            "there is no detached signature at {sig_url} (HTTP 404). A package served over \
             plain HTTPS needs the `<name>.tar.zst.sig` file that `entangle plugins build` \
             writes next to the archive, published at the same URL plus `.sig`"
        )),
        other => other,
    })
    .with_context(|| format!("{url} was NOT installed; nothing was written"))?;
    println!("      fetching {url}");
    let archive = fetch_url(
        &url,
        "package archive",
        &FetchOptions {
            max_bytes: MAX_ARCHIVE_BYTES,
            ..FetchOptions::default()
        },
    )
    .await
    .with_context(|| format!("{url} was NOT installed; nothing was written"))?;
    println!(
        "      {} bytes, sha256 {}",
        archive.len(),
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&archive))
    );

    println!("[2/5] checking the detached signature against your keyring (the archive is not opened yet)");
    let keyring = Keyring::load(&config::keyring_path())?;
    let detached_signer = verify_archive_signature(&archive, &sig, &keyring)
        .map_err(anyhow::Error::from)
        .with_context(|| match archive_signature_signer(&sig) {
            Some(fp) => format!(
                "{url} was NOT installed (its detached signature names publisher key {fp}). \
                 {TRUST_HINT}"
            ),
            None => format!("{url} was NOT installed. {TRUST_HINT}"),
        })?;
    println!("      archive signed by trusted key {detached_signer}");

    println!("[3/5] verifying the package (publisher signature over artifact and manifest)");
    let verified = verify_package(&archive, &keyring)
        .with_context(|| format!("{url} was NOT installed. {TRUST_HINT}"))?;
    if verified.signer_fingerprint != detached_signer {
        return Err(OciError::DetachedSignature(format!(
            "the detached signature is by {detached_signer}, but the package inside is {} \
             signed by {}; the two must be the same publisher. It was NOT installed",
            verified.plugin_id, verified.signer_fingerprint
        ))
        .into());
    }
    let cleared = check_policy(verified)?;
    println!(
        "      {} signed by trusted key {} (effective tier {})",
        cleared.verified.plugin_id, cleared.verified.signer_fingerprint, cleared.tier
    );

    let out = destination(&cleared, opts.out.as_deref())?;
    println!("[4/5] writing package to {}", out.display());
    write_verified(&cleared, &out)?;
    load_installed("[5/5]", &out, &cleared.verified.plugin_id, opts.no_load).await
}

// ---------------------------------------------------------------------------
// `entangle plugins install ./x.tar.zst`
// ---------------------------------------------------------------------------

/// `entangle plugins install <FILE.tar.zst>`: a package archive on disk.
pub async fn install_archive_file(path: &Path, out: Option<PathBuf>, no_load: bool) -> Result<()> {
    println!("[1/4] reading {}", path.display());
    let archive = read_capped(path, MAX_ARCHIVE_BYTES, "package archive")?;
    println!("[2/4] verifying the publisher signature against your keyring");
    let keyring = Keyring::load(&config::keyring_path())?;
    let verified = verify_package(&archive, &keyring)
        .with_context(|| format!("{} was NOT installed. {TRUST_HINT}", path.display()))?;
    let cleared = check_policy(verified)?;
    println!(
        "      {} signed by trusted key {} (effective tier {})",
        cleared.verified.plugin_id, cleared.verified.signer_fingerprint, cleared.tier
    );
    let out = destination(&cleared, out.as_deref())?;
    println!("[3/4] writing package to {}", out.display());
    write_verified(&cleared, &out)?;
    load_installed("[4/4]", &out, &cleared.verified.plugin_id, no_load).await
}

// ---------------------------------------------------------------------------
// `entangle plugins install ./x.entanglepack`
// ---------------------------------------------------------------------------

/// Options for [`install_pack`].
pub struct PackInstallOptions {
    /// The `.entanglepack` file.
    pub path: PathBuf,
    /// Parent directory for the packages (each goes to `<out>/<name>`);
    /// default `~/.entangle/plugins`.
    pub out: Option<PathBuf>,
    /// Verify and write, but do not load.
    pub no_load: bool,
    /// Add the pack's publisher keys that are not yet in the keyring, after
    /// printing their fingerprints.
    pub trust_pack_keys: bool,
}

/// `entangle plugins install <FILE.entanglepack>`: verify every package in
/// the pack offline against the keyring, then install all of them or none.
pub async fn install_pack(opts: PackInstallOptions) -> Result<()> {
    let path = &opts.path;
    println!("[1/4] reading {}", path.display());
    let bytes = read_capped(path, MAX_PACK_BYTES, "pack")?;
    let pack =
        read_pack(&bytes).with_context(|| format!("{} was NOT installed", path.display()))?;
    println!(
        "      {} package(s), signed by {} publisher key(s)",
        pack.packages.len(),
        pack.index.keys.len()
    );

    println!("[2/4] verifying every package against your keyring (offline)");
    let keyring_path = config::keyring_path();
    let mut keyring = Keyring::load(&keyring_path)?;

    // Publisher keys the pack needs that the user has not trusted.
    let mut unknown: Vec<(&entangle_oci::PackKey, Vec<&str>)> = Vec::new();
    for key in &pack.index.keys {
        let fp = hex::decode(&key.fingerprint)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .with_context(|| format!("malformed key fingerprint {:?}", key.fingerprint))?;
        if keyring.lookup(&fp).is_some() {
            continue;
        }
        let ids: Vec<&str> = pack
            .packages
            .iter()
            .filter(|p| p.entry.publisher == key.fingerprint)
            .map(|p| p.entry.plugin_id.as_str())
            .collect();
        if !ids.is_empty() {
            unknown.push((key, ids));
        }
    }
    let mut newly_trusted: Vec<TrustEntry> = Vec::new();
    if !unknown.is_empty() {
        if !opts.trust_pack_keys {
            let mut msg = format!(
                "ENTANGLE-E0940: {} holds package(s) signed by {} publisher key(s) that are \
                 not in your keyring. A key inside a pack is never trusted automatically. \
                 Nothing was installed.\n",
                path.display(),
                unknown.len()
            );
            for (key, ids) in &unknown {
                msg.push_str(&format!(
                    "\n  fingerprint {}\n    signs: {}\n    to trust it: entangle keyring add {} --name <NAME>\n",
                    key.fingerprint,
                    ids.join(", "),
                    key.public_key
                ));
            }
            msg.push_str(
                "\nCheck each fingerprint with the publisher through another channel first. \
                 To add all of them in one step, re-run with --trust-pack-keys.",
            );
            bail!(msg);
        }
        println!(
            "      --trust-pack-keys: adding {} publisher key(s) from the pack to your keyring",
            unknown.len()
        );
        for (key, ids) in &unknown {
            println!("        fingerprint {}", key.fingerprint);
            println!("          public key {}", key.public_key);
            println!("          signs      {}", ids.join(", "));
            let public_key: [u8; 32] = hex::decode(&key.public_key)
                .ok()
                .and_then(|b| b.try_into().ok())
                .with_context(|| format!("malformed public key for {}", key.fingerprint))?;
            // `read_pack` already checked the fingerprint is this key's own.
            let fingerprint = entangle_signing::IdentityPublicKey::from_bytes(&public_key)
                .map_err(|e| anyhow::anyhow!("public key for {}: {e}", key.fingerprint))?
                .fingerprint();
            let entry = TrustEntry {
                fingerprint,
                public_key,
                publisher_name: format!("pack-{}", &key.fingerprint[..8]),
                added_at: crate::cmd::pairlog::now(),
                note: format!(
                    "added by `plugins install --trust-pack-keys` from {}",
                    path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ),
            };
            keyring.add(entry.clone());
            newly_trusted.push(entry);
        }
    }

    // Everything is verified and cleared before anything is written.
    let cfg = config::load(&config::config_path())?;
    let mut cleared = Vec::with_capacity(pack.packages.len());
    for p in &pack.packages {
        let verified = verify_package(&p.bytes, &keyring).map_err(|e| {
            let unknown_publisher = matches!(
                &e,
                OciError::Verification(VerificationError::UnknownPublisher)
            );
            anyhow::Error::from(e).context(if unknown_publisher {
                format!(
                    "{} in {} was NOT installed, and neither was anything else from the pack. \
                     {TRUST_HINT}",
                    p.entry.plugin_id,
                    path.display()
                )
            } else {
                format!(
                    "{} in {} does not verify; nothing from the pack was installed",
                    p.entry.plugin_id,
                    path.display()
                )
            })
        })?;
        if verified.plugin_id != p.entry.plugin_id {
            bail!(
                "ENTANGLE-E0824: the pack index lists {} but the signed manifest says {}; \
                 nothing was installed",
                p.entry.plugin_id,
                verified.plugin_id
            );
        }
        let c = check_policy_with(
            verified,
            cfg.security.max_tier_allowed,
            &cfg.plugins.disabled,
        )
        .context("nothing from the pack was installed")?;
        println!(
            "      {} signed by trusted key {} (effective tier {})",
            c.verified.plugin_id, c.verified.signer_fingerprint, c.tier
        );
        cleared.push(c);
    }
    let mut targets = Vec::with_capacity(cleared.len());
    for c in &cleared {
        let out = match &opts.out {
            Some(parent) => parent.join(&c.id.name),
            None => destination(c, None)?,
        };
        if targets.contains(&out) {
            bail!(
                "two packages in the pack would be written to {}; install them one at a time \
                 with different --out directories",
                out.display()
            );
        }
        targets.push(out);
    }

    if !newly_trusted.is_empty() {
        // Persist only now: a pack that fails verification leaves the keyring alone.
        keyring
            .save(&keyring_path)
            .with_context(|| format!("saving {}", keyring_path.display()))?;
        println!(
            "      saved {} new key(s) to {}",
            newly_trusted.len(),
            keyring_path.display()
        );
        println!(
            "      note: a running entangled reads keyring.toml only at startup; restart it \
             before loading these plugins into it"
        );
    }

    println!("[3/4] writing {} package(s)", cleared.len());
    for (c, out) in cleared.iter().zip(&targets) {
        write_verified(c, out)?;
        println!("      {} -> {}", c.verified.plugin_id, out.display());
    }
    if opts.no_load {
        println!("[4/4] skipped loading (--no-load)");
        for out in &targets {
            println!(
                "      load with: entangle plugins load {}",
                out.display()
            );
        }
        return Ok(());
    }
    for (c, out) in cleared.iter().zip(&targets) {
        load_installed("[4/4]", out, &c.verified.plugin_id, false).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_oci::{pack, PackageFiles};
    use entangle_signing::{sign_artifact, IdentityKeyPair};

    fn package(k: &IdentityKeyPair, tier: u8, runtime: &str, artifact: &[u8]) -> VerifiedPackage {
        let manifest = format!(
            "[plugin]\nid = \"{}/tool@0.1.0\"\nversion = \"0.1.0\"\ntier = {tier}\n\
             runtime = \"{runtime}\"\ndescription = \"t\"\n\n[capabilities]\n",
            k.fingerprint_hex()
        );
        let bundle = sign_artifact(artifact, manifest.as_bytes(), k);
        let bytes = pack(&PackageFiles {
            manifest: manifest.into_bytes(),
            wasm: artifact.to_vec(),
            signature: toml::to_string(&bundle).unwrap().into_bytes(),
            provenance: None,
        })
        .unwrap();
        let mut ring = Keyring::new();
        ring.add(TrustEntry {
            fingerprint: k.fingerprint(),
            public_key: *k.public().as_bytes(),
            publisher_name: "t".into(),
            added_at: 0,
            note: String::new(),
        });
        verify_package(&bytes, &ring).unwrap()
    }

    const WASM: &[u8] = b"\0asm\x0d\x00\x01\x00";
    const ELF: &[u8] = b"\x7fELF\x02\x01\x01\x00rest";

    #[test]
    fn policy_refuses_tier_disabled_and_runtime_kind_and_accepts_the_rest() {
        let k = IdentityKeyPair::from_seed(&[4; 32]);
        let id = format!("{}/tool@0.1.0", k.fingerprint_hex());

        let ok = check_policy_with(package(&k, 1, "wasm", WASM), 5, &[]).unwrap();
        assert_eq!((ok.tier, ok.id.to_string()), (1, id.clone()));
        // Equal to the ceiling is allowed.
        assert!(check_policy_with(package(&k, 1, "wasm", WASM), 1, &[]).is_ok());

        let e = check_policy_with(package(&k, 3, "wasm", WASM), 2, &[])
            .err()
            .unwrap();
        assert!(format!("{e:#}").contains("ENTANGLE-E0043"), "{e:#}");

        let e = check_policy_with(package(&k, 1, "wasm", WASM), 5, &[id])
            .err()
            .unwrap();
        assert!(format!("{e:#}").contains("ENTANGLE-E0759"), "{e:#}");

        // A native executable shipped as a wasm plugin.
        let e = check_policy_with(package(&k, 1, "wasm", ELF), 5, &[])
            .err()
            .unwrap();
        assert!(format!("{e:#}").contains("ENTANGLE-E0507"), "{e:#}");
    }
}
