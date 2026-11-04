//! OCI-registry plugin distribution: `plugins install oci://…`,
//! `plugins publish`, `plugins tags`, `plugins mirror-sign`.
//!
//! Trust is entirely local. Pulled bytes go through
//! [`entangle_oci::verify_package`] with the user's publisher keyring
//! (`~/.entangle/keyring.toml`) — the same Ed25519 check the kernel applies to
//! a local directory, which then runs again at load. Registry credentials and
//! mirror keys (`~/.entangle/mirror-keys.toml`) never feed into that decision.

use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use anyhow::{bail, Context, Result};
use entangle_oci::{
    build_listing, list_tags, pack_dir, publish_listing, pull_artifact, push_artifact, unpack,
    verify_package, ClientConfig, Credential, ListOptions, ListingVerification, MirrorKeyring,
    OciClient, Reference, Selector,
};
use entangle_signing::{IdentityKeyPair, Keyring};
use entangle_types::plugin_id::PluginId;

use crate::cmd::plugins::Session;
use crate::config;

/// `~/.entangle/oci-auth.toml`.
fn auth_file() -> PathBuf {
    config::entangle_dir().join("oci-auth.toml")
}

/// `~/.entangle/mirror-keys.toml`.
pub fn mirror_keys_path() -> PathBuf {
    config::entangle_dir().join("mirror-keys.toml")
}

/// Build a client for `reference`'s registry with credentials from the
/// environment / `oci-auth.toml` (never printed).
fn client_for(reference: &Reference, insecure: bool) -> Result<OciClient> {
    let credential = Credential::resolve(&reference.registry, Some(&auth_file()))?;
    let cfg = ClientConfig {
        insecure_registry: insecure,
        credential,
        ..ClientConfig::default()
    };
    Ok(OciClient::for_reference(reference, cfg)?)
}

/// Options for [`install`].
pub struct InstallOptions {
    /// `oci://…` reference.
    pub reference: String,
    /// Allow plain HTTP to a non-loopback registry.
    pub insecure_registry: bool,
    /// Where to write the verified package (default `~/.entangle/plugins/<name>`).
    pub out: Option<PathBuf>,
    /// Verify and write, but do not load.
    pub no_load: bool,
}

/// Highest tier this machine accepts (`security.max_tier_allowed`).
fn max_tier_allowed() -> Result<u8> {
    Ok(config::load(&config::config_path())?
        .security
        .max_tier_allowed)
}

/// Parse and validate the signed manifest, returning its effective tier.
///
/// Runs the same manifest validation the kernel runs (tier/capability
/// consistency, id syntax) so a bad package is refused before it touches disk.
fn effective_tier(manifest: &[u8]) -> Result<u8> {
    let text = std::str::from_utf8(manifest).context("entangle.toml is not UTF-8")?;
    let parsed: entangle_manifest::Manifest =
        toml::from_str(text).context("parsing entangle.toml from the package")?;
    let validated = entangle_manifest::validate::validate(parsed)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("the package's entangle.toml is not a valid plugin manifest")?;
    Ok(validated.effective_tier as u8)
}

/// Does `tag` look like a full `MAJOR.MINOR.PATCH` version (optionally `v`-prefixed)?
fn version_like(tag: &str) -> Option<&str> {
    let t = tag.strip_prefix('v').unwrap_or(tag);
    let core = t.split(['-', '+']).next().unwrap_or(t);
    let parts: Vec<&str> = core.split('.').collect();
    (parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())))
    .then_some(t)
}

/// Bind the verified package to what the user asked for.
///
/// Signature verification proves *who* signed the bytes, not that they are the
/// plugin the user named: a registry or mirror could answer any tag with some
/// other validly signed package. Require the plugin name to equal the last
/// repository component, and a version-looking tag to equal the package's
/// version. A floating tag (`latest`, `stable`) or a digest makes no version
/// claim.
fn check_binding(reference: &Reference, id: &PluginId) -> Result<()> {
    let last = reference
        .repository
        .rsplit('/')
        .next()
        .unwrap_or(&reference.repository);
    if id.name != last {
        bail!(
            "the package served for {reference} is the plugin `{id}`, whose name does not match \
             the request (repository `{last}`); the signature is valid but this is not what you \
             asked for, so it was NOT installed"
        );
    }
    if let Selector::Tag(tag) = &reference.selector {
        if let Some(want) = version_like(tag) {
            if want != id.version.to_string() {
                bail!(
                    "the package served for {reference} is `{id}` (version {}), which does not \
                     match the requested version {want}; it was NOT installed",
                    id.version
                );
            }
        }
    }
    Ok(())
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

/// `entangle plugins install oci://…`.
pub async fn install(opts: InstallOptions) -> Result<()> {
    let reference = Reference::parse(&opts.reference)?;
    let client = client_for(&reference, opts.insecure_registry)?;

    println!("[1/4] pulling {reference}");
    let pulled = pull_artifact(&client, &reference).await?;
    println!(
        "      manifest {}  package {} ({} bytes)",
        pulled.manifest_digest,
        pulled.layer_digest,
        pulled.package.len()
    );

    println!("[2/4] verifying the publisher signature against your keyring");
    let keyring = Keyring::load(&config::keyring_path())?;
    let verified = verify_package(&pulled.package, &keyring).with_context(|| {
        format!(
            "{reference} was NOT installed. Only plugins signed by a publisher in your \
             keyring are accepted, whichever registry served them; trust a publisher with \
             `entangle keyring add <PUBLIC_KEY_HEX> --name <NAME>`"
        )
    })?;
    println!(
        "      {} signed by trusted key {}",
        verified.plugin_id, verified.signer_fingerprint
    );

    let tier = effective_tier(&verified.files.manifest)?;
    let max = max_tier_allowed()?;
    if tier > max {
        bail!(
            "ENTANGLE-E0043: {} declares effective tier {tier}, above this machine's \
             security.max_tier_allowed = {max} (~/.entangle/config.toml); not installed",
            verified.plugin_id
        );
    }
    println!("      effective tier {tier} (max_tier_allowed {max})");

    let id = PluginId::from_str(&verified.plugin_id)
        .map_err(|e| anyhow::anyhow!("plugin id {}: {e}", verified.plugin_id))?;
    check_binding(&reference, &id)?;
    let default_dir = opts.out.is_none();
    let out = opts
        .out
        .unwrap_or_else(|| crate::cmd::catalog::default_out_dir(&id.name));
    if default_dir {
        refuse_other_publishers_install(&out, &id)?;
    }
    println!("[3/4] writing package to {}", out.display());
    write_package_atomically(&verified.files, &out)
        .with_context(|| format!("writing package to {}", out.display()))?;

    if opts.no_load {
        println!("[4/4] skipped loading (--no-load)");
        println!(
            "      load it with: entangle plugins load {}",
            out.display()
        );
        return Ok(());
    }
    println!("[4/4] loading (the kernel verifies the signature again)");
    let session = Session::connect().await?;
    let report = session
        .load_package(&out, &verified.plugin_id)
        .await
        .with_context(|| {
            format!(
                "loading {} (the verified package is at {}; retry with `entangle plugins load {}`)",
                verified.plugin_id,
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

/// `entangle plugins publish <package> oci://…`.
///
/// `package` is a build directory (`dist/`) or an already packed `.tar.zst`.
pub async fn publish(package: &Path, reference: &str, insecure: bool) -> Result<()> {
    let reference = Reference::parse(reference)?;
    let bytes = if package.is_dir() {
        pack_dir(package)?
    } else {
        std::fs::read(package).with_context(|| format!("reading {}", package.display()))?
    };
    unpack(&bytes).with_context(|| format!("{} is not a plugin package", package.display()))?;

    // Advisory only: tell the publisher if their own keyring would reject it.
    if let Ok(keyring) = Keyring::load(&config::keyring_path()) {
        if let Err(e) = verify_package(&bytes, &keyring) {
            eprintln!(
                "warning: this package does not verify against your own keyring ({e}); \
                 consumers need the signing key in theirs"
            );
        }
    }

    let client = client_for(&reference, insecure)?;
    println!("publishing {} bytes to {reference}", bytes.len());
    let pushed = push_artifact(&client, &reference, &bytes).await?;
    println!("published {}", pushed.by_digest);
    println!("  manifest {}", pushed.manifest_digest);
    println!("  package  {}", pushed.layer_digest);
    Ok(())
}

/// `entangle plugins tags oci://registry/repo`.
pub async fn tags(
    reference: &str,
    insecure: bool,
    mirror_keys: Option<PathBuf>,
    json: bool,
    require_verified: bool,
) -> Result<()> {
    let reference = Reference::parse(reference)?;
    let client = client_for(&reference, insecure)?;
    let keys = MirrorKeyring::load(&mirror_keys.unwrap_or_else(mirror_keys_path))?;
    if let Ok(publishers) = Keyring::load(&config::keyring_path()) {
        for fp in keys.overlap_with(&publishers) {
            eprintln!(
                "warning: key {fp} is trusted both as a publisher and as a mirror; \
                 keep the two roles on separate keys"
            );
        }
    }
    let listing = list_tags(&client, &reference, &keys, &ListOptions::default()).await?;
    let status = listing.verification.to_string();
    if json {
        let verification = match &listing.verification {
            ListingVerification::Verified { key_fingerprint } => {
                serde_json::json!({"status": "verified", "key_fingerprint": key_fingerprint})
            }
            ListingVerification::Unsigned => serde_json::json!({"status": "unsigned"}),
            ListingVerification::Invalid { reason } => {
                serde_json::json!({"status": "invalid", "reason": reason})
            }
            ListingVerification::Expired => serde_json::json!({"status": "expired"}),
        };
        let tags: Vec<_> = listing
            .tags
            .iter()
            .map(
                |(t, d)| serde_json::json!({"tag": t, "digest": d.as_ref().map(|d| d.to_string())}),
            )
            .collect();
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "repository": listing.repository,
                "verification": verification,
                "tags": tags,
            }))?
        );
    } else {
        println!("repository: {}/{}", reference.registry, listing.repository);
        println!("listing:    {status}");
        if listing.tags.is_empty() {
            println!("tags:       (none)");
        }
        for (tag, digest) in &listing.tags {
            match digest {
                Some(d) => println!("  {tag:<24} {d}"),
                None => println!("  {tag:<24} (digest not covered by a verified listing)"),
            }
        }
    }
    if require_verified && !matches!(listing.verification, ListingVerification::Verified { .. }) {
        bail!("listing is not verified ({status}); --require-verified was given");
    }
    Ok(())
}

/// `entangle plugins mirror-sign oci://registry/repo --key <PEM>`.
///
/// Snapshots the repository's current tags into a listing, signs it with a
/// **mirror** key and publishes it at the well-known listing tag.
pub async fn mirror_sign(reference: &str, key: &Path, ttl_days: u64, insecure: bool) -> Result<()> {
    let reference = Reference::parse(reference)?.with_selector(Selector::Tag("latest".into()));
    let pem = std::fs::read_to_string(key).with_context(|| format!("reading {}", key.display()))?;
    let kp =
        IdentityKeyPair::from_pem(&pem).map_err(|e| anyhow::anyhow!("{}: {e}", key.display()))?;
    if let Ok(publishers) = Keyring::load(&config::keyring_path()) {
        if publishers.lookup(&kp.fingerprint()).is_some() {
            bail!(
                "key {} is trusted as a publisher in your keyring; sign listings with a \
                 dedicated mirror key (generate one with `entangle init` on another account)",
                kp.fingerprint_hex()
            );
        }
    }
    let client = client_for(&reference, insecure)?;
    let listing = build_listing(&client, &reference, ttl_days.saturating_mul(86_400), None).await?;
    let digest = publish_listing(&client, &reference, &listing, &kp).await?;
    println!(
        "published listing for {} ({} tags, expires in {ttl_days} days) signed by mirror key {}",
        listing.repository,
        listing.tags.len(),
        kp.fingerprint_hex()
    );
    println!("  manifest {digest}");
    Ok(())
}
