//! OCI-registry plugin distribution: `plugins install oci://…`,
//! `plugins publish`, `plugins tags`, `plugins mirror-sign`.
//!
//! Trust is entirely local. Pulled bytes go through
//! [`entangle_oci::verify_package`] with the user's publisher keyring
//! (`~/.entangle/keyring.toml`) — the same Ed25519 check the kernel applies to
//! a local directory, which then runs again at load. Registry credentials and
//! mirror keys (`~/.entangle/mirror-keys.toml`) never feed into that decision.
//!
//! Pulls and listing fetches try the mirror configured with `entangle mirror
//! set` first and the origin registry second ([`sources_for`]); publishing
//! always goes to the registry the reference names.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use entangle_oci::{
    build_listing, list_tags, pack_dir, publish_listing, pull_artifact, push_artifact, unpack,
    verify_package, ClientConfig, Credential, ListOptions, ListingState, ListingVerification,
    MirrorKeyring, OciClient, Reference, Selector,
};
use entangle_signing::{IdentityKeyPair, Keyring};
use entangle_types::plugin_id::PluginId;

use crate::cmd::dist;
use crate::config;

/// `~/.entangle/oci-auth.toml`.
fn auth_file() -> PathBuf {
    config::entangle_dir().join("oci-auth.toml")
}

/// `~/.entangle/mirror-keys.toml`.
pub fn mirror_keys_path() -> PathBuf {
    config::entangle_dir().join("mirror-keys.toml")
}

/// `~/.entangle/mirror-listing-state.toml`: the newest signed listing seen
/// per repository (rollback protection; see `entangle_oci::listing_state`).
pub fn listing_state_path() -> PathBuf {
    config::entangle_dir().join("mirror-listing-state.toml")
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
    /// The publisher fingerprint (32 hex) the package must be signed by;
    /// also (re)pins the repository to it.
    pub publisher: Option<String>,
    /// Allow replacing an installed plugin with a lower version.
    pub allow_downgrade: bool,
}

/// `~/.entangle/oci-publishers.toml`: the publisher each OCI repository is
/// pinned to (trust on first install).
pub fn publisher_pins_path() -> PathBuf {
    config::entangle_dir().join("oci-publishers.toml")
}

/// The publisher pinned per OCI repository (`registry/repository` of the
/// origin, whichever source delivered the bytes).
///
/// The first install from a repository records the publisher whose key
/// signed the package; later installs from it must be signed by the same
/// publisher (`ENTANGLE-E0947`), so a registry, mirror or name squatter
/// cannot answer `oci://…/tool` with another trusted publisher's `tool`.
/// `--publisher <FP>` states the publisher explicitly and re-pins the
/// repository to it. The file is TOML, mode 0600, replaced atomically, and
/// the read-modify-write runs under an advisory lock on `<file>.lock`.
pub struct PublisherPins {
    path: PathBuf,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PinsFile {
    version: u32,
    #[serde(default)]
    repositories: std::collections::BTreeMap<String, String>,
}

impl PublisherPins {
    /// Pins stored at `path`.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn damaged(&self, e: impl std::fmt::Display) -> anyhow::Error {
        anyhow::anyhow!(
            "ENTANGLE-E0947: {}: {e}. Fix or delete the file (every OCI repository is then \
             pinned afresh on its next install)",
            self.path.display()
        )
    }

    fn load(&self) -> Result<PinsFile> {
        match std::fs::read_to_string(&self.path) {
            Ok(t) => {
                let f: PinsFile = toml::from_str(&t).map_err(|e| self.damaged(e))?;
                if f.version != 1 {
                    return Err(self.damaged(format!("unsupported version {}", f.version)));
                }
                Ok(f)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PinsFile {
                version: 1,
                ..PinsFile::default()
            }),
            Err(e) => Err(self.damaged(e)),
        }
    }

    /// The publisher `repository` is pinned to, if any.
    pub fn get(&self, repository: &str) -> Result<Option<String>> {
        Ok(self.load()?.repositories.get(repository).cloned())
    }

    /// Check `signer` against the pin for `repository`: no pin, the same
    /// publisher, or an explicit `--publisher` equal to `signer` pass.
    pub fn check(&self, repository: &str, signer: &str, explicit: bool) -> Result<()> {
        match self.get(repository)? {
            Some(pinned) if pinned != signer && !explicit => bail!(
                "ENTANGLE-E0947: {repository} is pinned to publisher {pinned} (since its first \
                 install), but the package served is signed by {signer}; it was NOT \
                 installed. Both keys are in your keyring, but this repository has always come \
                 from {pinned}. If the repository really changed hands, confirm the new \
                 fingerprint with its owner and re-run with --publisher {signer}, which \
                 re-pins it (the pins are in {})",
                self.path.display()
            ),
            _ => Ok(()),
        }
    }

    /// Record `signer` for `repository` under the lock. Without `explicit`,
    /// a pin that changed since [`Self::check`] (another install) is an
    /// error, not overwritten.
    pub fn record(&self, repository: &str, signer: &str, explicit: bool) -> Result<()> {
        let _lock = crate::fsutil::lock_exclusive(&self.path)?;
        let mut file = self.load()?;
        match file.repositories.get(repository) {
            Some(p) if p == signer => return Ok(()),
            Some(_) if !explicit => return self.check(repository, signer, false),
            _ => {}
        }
        file.repositories
            .insert(repository.to_owned(), signer.to_owned());
        let text = toml::to_string(&file).map_err(|e| self.damaged(e))?;
        crate::fsutil::write_private_atomically(&self.path, text.as_bytes())
            .with_context(|| format!("writing {}", self.path.display()))
    }
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

/// Bind the verified package to what the user asked for (`ENTANGLE-E0945`).
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
            "ENTANGLE-E0945: the package served for {reference} is the plugin `{id}`, whose name does not match \
             the request (repository `{last}`); the signature is valid but this is not what you \
             asked for, so it was NOT installed"
        );
    }
    if let Selector::Tag(tag) = &reference.selector {
        if let Some(want) = version_like(tag) {
            if want != id.version.to_string() {
                bail!(
                    "ENTANGLE-E0945: the package served for {reference} is `{id}` (version {}), which does not \
                     match the requested version {want}; it was NOT installed",
                    id.version
                );
            }
        }
    }
    Ok(())
}

/// One place a reference can be pulled from.
struct Source {
    /// `mirror https://…` or `registry host:port`, for messages.
    label: String,
    /// Client bound to it.
    client: OciClient,
    /// Whether this is the configured mirror (as opposed to the origin).
    mirror: bool,
}

/// The sources to try for `reference`, in order: the mirror configured with
/// `entangle mirror set` (if any), then the origin registry the reference
/// names. There is no built-in mirror: without `mirror set` the only source
/// is the origin.
///
/// The mirror gets its own credential lookup (by the mirror's host), so the
/// origin's credentials are never sent to it.
fn sources_for(reference: &Reference, insecure: bool) -> Result<Vec<Source>> {
    let mut sources = Vec::new();
    if let Some(url) = crate::cmd::mirror::configured()? {
        let host = url::Url::parse(&url)
            .ok()
            .and_then(|u| {
                let h = u.host_str()?.to_owned();
                Some(match u.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h,
                })
            })
            .unwrap_or_default();
        let cfg = ClientConfig {
            credential: Credential::resolve(&host, Some(&auth_file()))?,
            ..ClientConfig::default()
        };
        let client = OciClient::with_base_url(&url, cfg).with_context(|| {
            format!(
                "the configured mirror {url} is not usable; fix it with `entangle mirror set \
                 <URL>` or remove it with `entangle mirror unset`"
            )
        })?;
        sources.push(Source {
            label: format!("mirror {url}"),
            client,
            mirror: true,
        });
    }
    sources.push(Source {
        label: format!("registry {}", reference.registry),
        client: client_for(reference, insecure)?,
        mirror: false,
    });
    Ok(sources)
}

/// Resolve a floating tag (`latest`, `stable`: anything but a full
/// version) to a digest through `source`'s signed listing, when mirror keys
/// are configured. The listing must verify against the mirror keyring and
/// must not be older than the newest one seen (rollback state); otherwise
/// this source cannot be used for the tag (`ENTANGLE-E0945`). Returns the
/// reference to pull: by digest when resolved, unchanged otherwise.
async fn resolve_floating(
    source: &Source,
    reference: &Reference,
    keys: &MirrorKeyring,
) -> Result<Reference> {
    let Selector::Tag(tag) = &reference.selector else {
        return Ok(reference.clone());
    };
    if version_like(tag).is_some() || keys.entries().next().is_none() {
        return Ok(reference.clone());
    }
    let opts = ListOptions {
        state: Some(ListingState::at(listing_state_path())),
        ..ListOptions::default()
    };
    let listing = list_tags(&source.client, reference, keys, &opts).await?;
    if !matches!(listing.verification, ListingVerification::Verified { .. }) {
        bail!(
            "ENTANGLE-E0945: {reference} names the floating tag `{tag}`, and mirror keys are \
             configured, so it is resolved only through a verified signed listing; the \
             listing from {} is {}. Pull a full version (`:1.2.3`) or a digest instead",
            source.label,
            listing.verification
        );
    }
    let Some(Some(digest)) = listing.tags.get(tag) else {
        bail!(
            "ENTANGLE-E0945: the verified listing from {} has no tag `{tag}` for {}",
            source.label,
            reference.repository
        );
    };
    println!("      tag {tag} -> {digest} (from the verified signed listing)");
    Ok(reference.with_selector(Selector::Digest(digest.clone())))
}

/// Everything decided about one source's package before anything is
/// written.
struct Accepted {
    cleared: dist::Cleared,
    out: PathBuf,
}

/// `entangle plugins install oci://…`.
///
/// Sources are tried in order (the configured mirror, then the origin). For
/// each, the whole decision runs inside the attempt: pull, publisher
/// signature against the keyring, policy (tier, disabled, runtime kind),
/// binding to the request (name, version tag, floating tag through a verified
/// listing when mirror keys are configured), the repository's publisher pin
/// and the downgrade check. A source that fails any of them is skipped with
/// a warning and the next one is tried; nothing is written until one passes.
///
/// A mirror cannot make an unsigned or tampered package install, nor (with
/// these checks) another plugin, another publisher's plugin or an older
/// version than the one installed; for a floating tag without mirror keys
/// it can still choose which validly signed version of this plugin, no older
/// than the installed one, you get. Pull an exact version to rule that out.
pub async fn install(opts: InstallOptions) -> Result<()> {
    let reference = Reference::parse(&opts.reference)?;
    let sources = sources_for(&reference, opts.insecure_registry)?;
    let keyring = Keyring::load(&config::keyring_path())?;
    let mirror_keys = MirrorKeyring::load(&mirror_keys_path())?;
    let pins = PublisherPins::at(publisher_pins_path());
    let pin_key = format!("{}/{}", reference.registry, reference.repository);
    let explicit = match &opts.publisher {
        Some(p) => {
            let p = p.trim().to_ascii_lowercase();
            if p.len() != 32 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!(
                    "--publisher takes a publisher key fingerprint (32 hex characters), got {p:?}"
                );
            }
            Some(p)
        }
        None => None,
    };

    let mut accepted = None;
    let mut failures: Vec<String> = Vec::new();
    let last = sources.len() - 1;
    for (i, source) in sources.iter().enumerate() {
        println!("[1/4] pulling {reference} from {}", source.label);
        let attempt = async {
            let pull_ref = resolve_floating(source, &reference, &mirror_keys).await?;
            let pulled = pull_artifact(&source.client, &pull_ref).await?;
            println!(
                "      manifest {}  package {} ({} bytes)",
                pulled.manifest_digest,
                pulled.layer_digest,
                pulled.package.len()
            );
            println!("[2/4] verifying the publisher signature against your keyring");
            let verified = verify_package(&pulled.package, &keyring).with_context(|| {
                format!(
                    "{reference} was NOT installed. Only plugins signed by a publisher in your \
                     keyring are accepted, whichever registry served them; trust a publisher \
                     with `entangle keyring add <PUBLIC_KEY_HEX> --name <NAME>`"
                )
            })?;
            println!(
                "      {} signed by trusted key {}",
                verified.plugin_id, verified.signer_fingerprint
            );
            let cleared = dist::check_policy(verified)?;
            check_binding(&reference, &cleared.id)?;
            let signer = cleared.verified.signer_fingerprint.clone();
            if let Some(want) = &explicit {
                if *want != signer {
                    bail!(
                        "ENTANGLE-E0945: {reference} served a package signed by {signer}, but \
                         --publisher asked for {want}; it was NOT installed"
                    );
                }
            }
            pins.check(&pin_key, &signer, explicit.is_some())?;
            let out = dist::destination(&cleared, opts.out.as_deref(), opts.allow_downgrade)?;
            anyhow::Ok(Accepted { cleared, out })
        };
        match attempt.await {
            Ok(a) => {
                accepted = Some(a);
                break;
            }
            Err(e) if i < last => {
                eprintln!(
                    "warning: {} could not supply {reference}: {e:#}; trying the next source",
                    source.label
                );
                failures.push(format!("{}: {e:#}", source.label));
            }
            Err(e) => {
                return Err(if failures.is_empty() {
                    e
                } else {
                    e.context(format!(
                        "every source failed (earlier: {})",
                        failures.join("; ")
                    ))
                });
            }
        }
    }
    // The loop either breaks with a package or returns the last error.
    let Some(Accepted { cleared, out }) = accepted else {
        bail!("no source for {reference}");
    };
    println!(
        "      effective tier {} (max_tier_allowed {})",
        cleared.tier,
        config::load(&config::config_path())?
            .security
            .max_tier_allowed
    );
    pins.record(
        &pin_key,
        &cleared.verified.signer_fingerprint,
        explicit.is_some(),
    )?;
    println!("[3/4] writing package to {}", out.display());
    dist::write_verified(&cleared, &out)?;
    dist::load_installed("[4/4]", &out, &cleared.verified.plugin_id, opts.no_load).await
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
    accept_older_listing: bool,
) -> Result<()> {
    let reference = Reference::parse(reference)?;
    let sources = sources_for(&reference, insecure)?;
    let keys = MirrorKeyring::load(&mirror_keys.unwrap_or_else(mirror_keys_path))?;
    if let Ok(publishers) = Keyring::load(&config::keyring_path()) {
        for fp in keys.overlap_with(&publishers) {
            eprintln!(
                "warning: key {fp} is trusted both as a publisher and as a mirror; \
                 keep the two roles on separate keys"
            );
        }
    }
    // Newest listing seen per repository: an older one is refused even when
    // its signature and expiry are fine (rollback protection).
    let list_opts = ListOptions {
        state: Some(ListingState::at(listing_state_path())),
        accept_older: accept_older_listing,
        ..ListOptions::default()
    };
    let mut served = None;
    let last = sources.len() - 1;
    for (i, source) in sources.iter().enumerate() {
        match list_tags(&source.client, &reference, &keys, &list_opts).await {
            Ok(l) => {
                served = Some((l, source));
                break;
            }
            Err(e) if i < last => eprintln!(
                "warning: {} could not list {}: {e}; trying the next source",
                source.label, reference.repository
            ),
            Err(e) => return Err(e.into()),
        }
    }
    let Some((listing, source)) = served else {
        bail!("no source for {reference}");
    };
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
            ListingVerification::RolledBack {
                newest_seen,
                offered,
            } => serde_json::json!({
                "status": "rolled_back",
                "code": "ENTANGLE-E0820",
                "newest_seen": newest_seen,
                "offered": offered,
            }),
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
                "source": if source.mirror { "mirror" } else { "origin" },
                "served_by": source.client.base_url().as_str(),
                "verification": verification,
                "tags": tags,
            }))?
        );
    } else {
        println!("repository: {}/{}", reference.registry, listing.repository);
        if source.mirror {
            println!("served by:  {}", source.label);
        }
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
    if let ListingVerification::RolledBack {
        newest_seen,
        offered,
    } = &listing.verification
    {
        eprintln!(
            "warning: the listing for {} was refused as a rollback: it was generated at \
             {offered}, older than the newest one this machine has seen ({newest_seen}). The \
             tags above are the registry's own, unauthenticated. If the mirror was \
             deliberately restored from an older snapshot, accept it once with \
             --accept-older-listing (the record is in {}).",
            listing.repository,
            listing_state_path().display()
        );
        if require_verified {
            return Err(
                anyhow::Error::from(entangle_oci::OciError::ListingRollback {
                    repository: listing.repository.clone(),
                    newest_seen: *newest_seen,
                    offered: *offered,
                })
                .context("--require-verified was given"),
            );
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
    if ttl_days == 0 || ttl_days.saturating_mul(86_400) > entangle_oci::MAX_LISTING_LIFETIME_SECS {
        bail!(
            "--ttl-days must be between 1 and {}: clients refuse a listing that claims a longer \
             lifetime",
            entangle_oci::MAX_LISTING_LIFETIME_SECS / 86_400
        );
    }
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
