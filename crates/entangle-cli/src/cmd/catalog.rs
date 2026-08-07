//! Plugin **catalog**: discovery (`entangle plugins available`) and
//! one-command installation (`entangle plugins install <NAME>`).
//!
//! # What a catalog is
//! A catalog is an ordinary directory whose subdirectories are plugin projects
//! — each with a `Cargo.toml` and an `entangle.toml`. The `plugins/` directory
//! of the Entanglement repository is one; so is a directory you assemble
//! yourself, or a copy at `~/.entangle/catalog`.
//!
//! There is deliberately **no network fetch**. No plugin registry is published,
//! so "install" means: find the named project in a local catalog, compile it,
//! sign it with *your* identity key, trust that key, and load the result.
//! Pretending to download a signed artifact from somewhere would be a lie about
//! where the code came from and who vouched for it.
//!
//! # Resolution order
//! A binary installed with `cargo install entangle-cli` has no repository
//! checkout next to it, so the catalog is looked up in this order and the
//! winning source is always printed:
//!
//! 1. `--catalog <DIR>`
//! 2. `$ENTANGLE_CATALOG`
//! 3. `./plugins` — relative to the current directory (a repo checkout)
//! 4. `~/.entangle/catalog` — the "installed for good" location
//!
//! The first two are *explicit*: if they name something that is not a
//! directory, that is an error rather than a silent fall-through to a
//! surprising catalog. When nothing is found at all,
//! [`CatalogLookup::resolve`] fails with every path it tried and the exact
//! commands that fix it — see [`no_catalog_error`].

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::cmd::keyring::{ensure_trusted, TrustOutcome};
use crate::cmd::package::{self, plugin_name_from_id, BuildOptions};
use crate::cmd::plugins::Session;
use crate::config;

/// Environment variable naming a catalog directory (source #2).
pub const CATALOG_ENV: &str = "ENTANGLE_CATALOG";

/// Directory looked for under the current working directory (source #3).
pub const CWD_CATALOG_DIR: &str = "plugins";

/// Directory looked for under `~/.entangle/` (source #4).
pub const HOME_CATALOG_DIR: &str = "catalog";

/// Keyring name used for the user's own publisher key.
pub const SELF_TRUST_NAME: &str = "self";

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Where a resolved catalog came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogSource {
    /// `--catalog <DIR>`.
    Flag,
    /// `$ENTANGLE_CATALOG`.
    Env,
    /// `./plugins`.
    Cwd,
    /// `~/.entangle/catalog`.
    Home,
}

impl CatalogSource {
    /// How this source is spelled in help text and error messages.
    pub fn origin(self) -> &'static str {
        match self {
            CatalogSource::Flag => "--catalog",
            CatalogSource::Env => "$ENTANGLE_CATALOG",
            CatalogSource::Cwd => "./plugins",
            CatalogSource::Home => "~/.entangle/catalog",
        }
    }

    /// Stable machine-readable tag for `--json` output.
    pub fn tag(self) -> &'static str {
        match self {
            CatalogSource::Flag => "flag",
            CatalogSource::Env => "env",
            CatalogSource::Cwd => "cwd",
            CatalogSource::Home => "home",
        }
    }

    /// Explicit sources were named by the user, so a bad value is an error
    /// rather than something to skip past.
    fn is_explicit(self) -> bool {
        matches!(self, CatalogSource::Flag | CatalogSource::Env)
    }
}

/// A catalog directory that exists, plus which source produced it.
#[derive(Debug, Clone)]
pub struct Catalog {
    /// The directory itself.
    pub dir: PathBuf,
    /// Which of the four sources won.
    pub source: CatalogSource,
}

/// The four candidate locations, as data.
///
/// Kept free of ambient state (no `std::env` reads, no cwd) so resolution order
/// is unit-testable without mutating process-global state.
#[derive(Debug, Clone)]
pub struct CatalogLookup {
    /// `--catalog <DIR>`, if passed.
    pub flag: Option<PathBuf>,
    /// `$ENTANGLE_CATALOG`, if set and non-empty.
    pub env: Option<PathBuf>,
    /// Directory that `./plugins` is relative to.
    pub cwd: PathBuf,
    /// Full path of the home catalog (`~/.entangle/catalog`).
    pub home_catalog: PathBuf,
}

impl CatalogLookup {
    /// Build a lookup from the real environment.
    pub fn from_env(flag: Option<PathBuf>) -> Self {
        let env = std::env::var_os(CATALOG_ENV)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        Self {
            flag,
            env,
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            home_catalog: config::entangle_dir().join(HOME_CATALOG_DIR),
        }
    }

    /// The candidate paths in resolution order.
    pub fn candidates(&self) -> Vec<(CatalogSource, Option<PathBuf>)> {
        vec![
            (CatalogSource::Flag, self.flag.clone()),
            (CatalogSource::Env, self.env.clone()),
            (CatalogSource::Cwd, Some(self.cwd.join(CWD_CATALOG_DIR))),
            (CatalogSource::Home, Some(self.home_catalog.clone())),
        ]
    }

    /// Resolve the first candidate that is a directory.
    ///
    /// Explicit sources (`--catalog`, `$ENTANGLE_CATALOG`) that do not name a
    /// directory fail immediately: silently ignoring them and using `./plugins`
    /// instead would install something the user did not ask for.
    pub fn resolve(&self) -> Result<Catalog> {
        for (source, path) in self.candidates() {
            let Some(path) = path else { continue };
            if path.is_dir() {
                return Ok(Catalog { dir: path, source });
            }
            if source.is_explicit() {
                bail!(explicit_catalog_error(source, &path));
            }
        }
        bail!(no_catalog_error(self))
    }
}

/// Convenience: [`CatalogLookup::from_env`] + [`CatalogLookup::resolve`].
pub fn resolve(flag: Option<PathBuf>) -> Result<Catalog> {
    CatalogLookup::from_env(flag).resolve()
}

/// Error for an explicitly named catalog that is not a directory.
pub fn explicit_catalog_error(source: CatalogSource, path: &Path) -> String {
    let fix = match source {
        CatalogSource::Env => {
            format!("Point {CATALOG_ENV} at a real catalog, unset it, or pass --catalog <DIR>.")
        }
        _ => "Pass --catalog <DIR> with a directory that exists.".to_owned(),
    };
    format!(
        "{} names {}, which is not a directory.\n\n\
         A catalog is a directory of plugin projects — each subdirectory holding a\n\
         Cargo.toml and an entangle.toml (the `plugins/` directory of the Entanglement\n\
         repository is one).\n\n\
         {fix}",
        source.origin(),
        path.display()
    )
}

/// The "nothing found anywhere" error: every path tried, and how to get a catalog.
///
/// This is the single most likely first failure for a brand-new user, so it
/// names the four locations it looked in *with the concrete paths* and gives
/// three working fixes rather than a diagnosis.
pub fn no_catalog_error(lookup: &CatalogLookup) -> String {
    let mut s = String::from(
        "no plugin catalog found.\n\n\
         Entanglement has no published plugin registry, so `install` builds plugins from\n\
         a local catalog: a directory of plugin projects, each with its own entangle.toml.\n\n\
         Looked for, in order:\n",
    );
    for (source, path) in lookup.candidates() {
        match path {
            Some(p) => s.push_str(&format!(
                "  {:<22} {} (not a directory)\n",
                source.origin(),
                p.display()
            )),
            None => s.push_str(&format!("  {:<22} (not set)\n", source.origin())),
        }
    }
    s.push_str(&format!(
        "\nTo get one, pick any of:\n\
         \n  # 1. use the catalog that ships with the repository\n\
         \x20 git clone https://github.com/entanglement-dev/entanglement\n\
         \x20 cd entanglement && entangle plugins available\n\
         \n  # 2. point at a checkout you already have\n\
         \x20 entangle plugins available --catalog /path/to/entanglement/plugins\n\
         \n  # 3. install a catalog once, for every future command\n\
         \x20 cp -r /path/to/entanglement/plugins {}\n",
        lookup.home_catalog.display()
    ));
    s
}

// ---------------------------------------------------------------------------
// Catalog entries
// ---------------------------------------------------------------------------

/// One plugin project in a catalog, as described by its `entangle.toml`.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    /// Plugin name (from `plugin.id`, falling back to the directory name).
    pub name: String,
    /// The project directory.
    pub dir: PathBuf,
    /// `plugin.version`.
    pub version: String,
    /// `plugin.tier` as declared by the author.
    pub tier: u8,
    /// `plugin.runtime` — `wasm` or `native`.
    pub runtime: String,
    /// `plugin.description` (empty when omitted).
    pub description: String,
}

/// Subdirectories that are never plugin projects.
fn is_ignored_dir(name: &str) -> bool {
    name.starts_with('.') || matches!(name, "target" | "dist" | "node_modules")
}

/// Read one plugin project directory into a [`CatalogEntry`].
pub fn read_entry(dir: &Path) -> Result<CatalogEntry> {
    let manifest_path = dir.join("entangle.toml");
    let text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest: entangle_manifest::Manifest =
        toml::from_str(&text).with_context(|| format!("parsing {}", manifest_path.display()))?;

    let dir_name = dir
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut name = plugin_name_from_id(&manifest.plugin.id).to_owned();
    if name.is_empty() || name == package::PUBLISHER_PLACEHOLDER {
        name = dir_name;
    }

    Ok(CatalogEntry {
        name,
        dir: dir.to_path_buf(),
        version: manifest.plugin.version.to_string(),
        tier: manifest.plugin.tier,
        runtime: match manifest.plugin.runtime {
            entangle_manifest::Runtime::Wasm => "wasm".to_owned(),
            entangle_manifest::Runtime::Native => "native".to_owned(),
        },
        description: manifest.plugin.description,
    })
}

/// Everything a catalog scan found: usable entries, and directories that look
/// like plugins but could not be read.
#[derive(Debug, Default)]
pub struct CatalogListing {
    /// Readable plugin projects, sorted by name.
    pub entries: Vec<CatalogEntry>,
    /// `(directory, why)` for each project whose manifest could not be read.
    pub problems: Vec<(PathBuf, String)>,
}

/// Scan a catalog directory.
///
/// A subdirectory without an `entangle.toml` is not a plugin and is skipped
/// silently. One whose manifest is unreadable *is* reported — but as a problem
/// rather than a hard error, so one broken plugin never hides the other five.
pub fn scan(catalog: &Path) -> Result<CatalogListing> {
    let mut listing = CatalogListing::default();
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();

    let rd = std::fs::read_dir(catalog)
        .with_context(|| format!("reading catalog directory {}", catalog.display()))?;
    for ent in rd {
        let ent = ent.with_context(|| format!("reading entry in {}", catalog.display()))?;
        let path = ent.path();
        if !path.is_dir() {
            continue;
        }
        let name: OsString = ent.file_name();
        let name = name.to_string_lossy().into_owned();
        if is_ignored_dir(&name) {
            continue;
        }
        if !path.join("entangle.toml").exists() {
            continue;
        }
        dirs.push((name, path));
    }
    dirs.sort_by(|a, b| a.0.cmp(&b.0));

    for (_, dir) in dirs {
        match read_entry(&dir) {
            Ok(e) => listing.entries.push(e),
            Err(e) => listing.problems.push((dir, format!("{e:#}"))),
        }
    }
    listing.entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(listing)
}

/// Find the entry named `name` (case-insensitive; directory name also matches).
pub fn find_entry(catalog: &Catalog, name: &str) -> Result<CatalogEntry> {
    let listing = scan(&catalog.dir)?;
    let wanted = name.trim().to_ascii_lowercase();

    if let Some(e) = listing.entries.iter().find(|e| {
        e.name.eq_ignore_ascii_case(&wanted)
            || e.dir
                .file_name()
                .map(|d| d.to_string_lossy().eq_ignore_ascii_case(&wanted))
                .unwrap_or(false)
    }) {
        return Ok(e.clone());
    }

    let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    let near: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| n.contains(&wanted) || wanted.contains(n))
        .collect();

    let mut msg = format!(
        "no plugin named {:?} in the catalog at {}",
        name,
        catalog.dir.display()
    );
    if !near.is_empty() {
        msg.push_str(&format!("\n\nDid you mean: {}", near.join(", ")));
    }
    if names.is_empty() {
        msg.push_str(
            "\n\nThat catalog contains no plugin projects (no subdirectory has an entangle.toml).\n\
             Point at a real catalog with --catalog <DIR>, or clone the Entanglement repository\n\
             and run this from its root so ./plugins is used.",
        );
    } else {
        msg.push_str(&format!("\n\nAvailable: {}", names.join(", ")));
        msg.push_str("\nList them with details: entangle plugins available");
    }
    bail!(msg)
}

// ---------------------------------------------------------------------------
// `entangle plugins available`
// ---------------------------------------------------------------------------

/// List the plugins in the resolved catalog.
pub fn available(catalog_flag: Option<PathBuf>, json: bool) -> Result<()> {
    let catalog = resolve(catalog_flag)?;
    let listing = scan(&catalog.dir)?;

    if json {
        let plugins: Vec<serde_json::Value> = listing
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "name": e.name,
                    "tier": e.tier,
                    "version": e.version,
                    "runtime": e.runtime,
                    "description": e.description,
                    "dir": e.dir.to_string_lossy(),
                })
            })
            .collect();
        let problems: Vec<serde_json::Value> = listing
            .problems
            .iter()
            .map(|(d, why)| serde_json::json!({ "dir": d.to_string_lossy(), "error": why }))
            .collect();
        let body = serde_json::json!({
            "catalog": catalog.dir.to_string_lossy(),
            "source": catalog.source.tag(),
            "plugins": plugins,
            "problems": problems,
        });
        println!("{}", serde_json::to_string(&body)?);
        return Ok(());
    }

    println!(
        "catalog: {} (from {})",
        catalog.dir.display(),
        catalog.source.origin()
    );
    println!();

    if listing.entries.is_empty() {
        println!("No plugins found — no subdirectory here has an entangle.toml.");
        println!();
        println!("Expected layout:");
        println!("  <catalog>/<plugin-name>/entangle.toml");
        println!("  <catalog>/<plugin-name>/Cargo.toml");
        println!();
        println!("Pass --catalog <DIR> to point somewhere else, or run this from a clone of the");
        println!("Entanglement repository so ./plugins is used.");
    } else {
        let width = listing
            .entries
            .iter()
            .map(|e| e.name.len())
            .max()
            .unwrap_or(4)
            .max(4);
        println!("{:<width$}  TIER  VERSION  DESCRIPTION", "NAME");
        for e in &listing.entries {
            println!(
                "{:<width$}  {:<4}  {:<7}  {}",
                e.name, e.tier, e.version, e.description
            );
        }
        println!();
        println!(
            "Install one with: entangle plugins install {}",
            listing.entries[0].name
        );
    }

    for (dir, why) in &listing.problems {
        eprintln!("warning: skipped {} — {}", dir.display(), why);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `entangle plugins install`
// ---------------------------------------------------------------------------

/// Options for [`install`].
#[derive(Debug, Clone)]
pub struct InstallOptions {
    /// Plugin name to install.
    pub name: String,
    /// `--catalog <DIR>`.
    pub catalog: Option<PathBuf>,
    /// Identity key PEM to sign with.
    pub key: Option<PathBuf>,
    /// Output directory. Defaults to `~/.entangle/plugins/<name>`.
    pub out: Option<PathBuf>,
    /// Target triple.
    pub target: String,
    /// Pre-built wasm to package instead of compiling.
    pub wasm: Option<PathBuf>,
    /// Skip the load step.
    pub no_load: bool,
}

/// A built, signed, trusted package that has not been loaded yet.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// The entry that was built.
    pub entry: CatalogEntry,
    /// What the signing pipeline produced.
    pub outcome: package::BuildOutcome,
    /// Whether trusting the publisher key was a no-op.
    pub trust: TrustOutcome,
}

/// Default install location for a plugin's signed package.
pub fn default_out_dir(name: &str) -> PathBuf {
    config::entangle_dir().join("plugins").join(name)
}

/// Build + sign `entry` with the user's own key, then make sure that key is
/// trusted.
///
/// The trust step is what turns a self-signed build into something that
/// actually loads: the kernel verifies `plugin.wasm.sig` against the keyring, so
/// a plugin you just signed yourself is rejected until your own publisher key is
/// in it. Doing that by hand is the single most confusing step in the old flow,
/// so it happens here — idempotently, via
/// [`crate::cmd::keyring::ensure_trusted`].
pub fn prepare(entry: &CatalogEntry, opts: &InstallOptions) -> Result<Prepared> {
    // Fail before the slow build when there is no key to sign with.
    let key_path = opts.key.clone().unwrap_or_else(config::identity_path);
    if !key_path.exists() {
        bail!(
            "no identity key at {} — nothing to sign with.\n\n\
             Create one with:\n  entangle init --non-interactive\n\n\
             Or do the whole thing in one step:\n  entangle quickstart",
            key_path.display()
        );
    }

    // Fail before the slow build when the wasm target is missing, with the
    // exact rustup command instead of a wall of cargo output.
    if opts.wasm.is_none() {
        package::ensure_target_installed(&opts.target)?;
    }

    let out = opts
        .out
        .clone()
        .unwrap_or_else(|| default_out_dir(&entry.name));

    let outcome = package::build(BuildOptions {
        dir: entry.dir.clone(),
        key: Some(key_path),
        out: Some(out),
        wasm: opts.wasm.clone(),
        target: opts.target.clone(),
    })
    .with_context(|| {
        format!(
            "building plugin {} from {}",
            entry.name,
            entry.dir.display()
        )
    })?;

    let trust = ensure_trusted(
        &outcome.public_key_hex,
        SELF_TRUST_NAME,
        "your own publisher key, added by `entangle plugins install`",
    )
    .context("trusting your own publisher key so the plugin you just signed can load")?;

    Ok(Prepared {
        entry: entry.clone(),
        outcome,
        trust,
    })
}

/// Trust the public half of the identity key at `key_path`, idempotently.
///
/// Anything you sign yourself is worthless to the kernel until the key that
/// signed it is in your keyring — this is that step, available on its own so
/// `quickstart` can do it before the slow build rather than after.
pub fn trust_own_key(key_path: &Path) -> Result<TrustOutcome> {
    let pem = std::fs::read_to_string(key_path).with_context(|| {
        format!(
            "reading identity key {} — create one with `entangle init --non-interactive`",
            key_path.display()
        )
    })?;
    let kp = entangle_signing::IdentityKeyPair::from_pem(&pem).map_err(|e| {
        anyhow::anyhow!(
            "{} is not a valid identity key: {e}\n\
             Move it aside and run `entangle init --non-interactive` to generate a fresh one.",
            key_path.display()
        )
    })?;
    ensure_trusted(
        &hex::encode(kp.public().as_bytes()),
        SELF_TRUST_NAME,
        "your own publisher key, added by `entangle quickstart`",
    )
    .context("trusting your own publisher key so plugins you sign yourself can load")
}

/// Print the trust step's result.
pub fn print_trust(trust: &TrustOutcome) {
    match trust {
        TrustOutcome::Added { fp_hex } => println!(
            "      trusted your own publisher key {fp_hex} as \"{SELF_TRUST_NAME}\" \
             (~/.entangle/keyring.toml)"
        ),
        TrustOutcome::AlreadyTrusted { fp_hex, name } => {
            println!("      publisher key {fp_hex} already trusted as \"{name}\" — no change")
        }
    }
}

/// `entangle plugins install <NAME>`.
pub async fn install(opts: InstallOptions) -> Result<()> {
    let catalog = resolve(opts.catalog.clone())?;
    println!(
        "[1/4] catalog: {} (from {})",
        catalog.dir.display(),
        catalog.source.origin()
    );

    let entry = find_entry(&catalog, &opts.name)?;
    println!(
        "      found {} v{} (tier {}, {}) in {}",
        entry.name,
        entry.version,
        entry.tier,
        entry.runtime,
        entry.dir.display()
    );
    if !entry.description.is_empty() {
        println!("      {}", entry.description);
    }

    println!("[2/4] building and signing with your own identity key");
    let prepared = prepare(&entry, &opts)?;
    println!(
        "      signed package: {} (effective tier {})",
        prepared.outcome.dist.display(),
        prepared.outcome.effective_tier
    );

    println!("[3/4] trusting the signing key");
    print_trust(&prepared.trust);

    if opts.no_load {
        println!("[4/4] skipped loading (--no-load)");
        print_ready(&prepared.outcome.plugin_id, Some(&prepared.outcome.dist));
        return Ok(());
    }

    println!("[4/4] loading");
    let session = Session::connect().await?;
    let report = session
        .load_package(&prepared.outcome.dist, &prepared.outcome.plugin_id)
        .await
        .with_context(|| {
            format!(
                "loading {} (the signed package is on disk at {} — you can retry with \
                 `entangle plugins load {}`)",
                prepared.outcome.plugin_id,
                prepared.outcome.dist.display(),
                prepared.outcome.dist.display()
            )
        })?;

    if report.already_loaded {
        println!("      {} was already loaded — nothing to do", report.id);
    } else {
        println!("      loaded {} into the {}", report.id, session.describe());
    }
    if !session.is_daemon() {
        println!();
        println!("      NOTE: no daemon is running, so that load was temporary and ended with");
        println!("            this command. Start the daemon to keep plugins loaded:");
        println!("              entangled run");
        println!(
            "              entangle plugins load {}",
            prepared.outcome.dist.display()
        );
    }

    print_ready(&report.id, None);
    Ok(())
}

/// The closing "now run this" banner.
fn print_ready(plugin_id: &str, dist: Option<&Path>) {
    println!();
    println!("Ready. Run it with:");
    if let Some(dist) = dist {
        println!("  entangle plugins load {}", dist.display());
    }
    println!("  entangle plugins invoke {plugin_id} --input '<your input>'");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a plugin project (manifest only — enough for catalog scanning).
    fn plugin(catalog: &Path, name: &str, tier: u8, description: &str) -> PathBuf {
        let dir = catalog.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("entangle.toml"),
            format!(
                r#"[plugin]
id = "PUBLISHER_PLACEHOLDER/{name}@0.1.0"
version = "0.1.0"
tier = {tier}
runtime = "wasm"
description = "{description}"

[capabilities]

[build]
target = "wasm32-wasip2"
"#
            ),
        )
        .unwrap();
        dir
    }

    fn lookup(flag: Option<&Path>, env: Option<&Path>, cwd: &Path, home: &Path) -> CatalogLookup {
        CatalogLookup {
            flag: flag.map(|p| p.to_path_buf()),
            env: env.map(|p| p.to_path_buf()),
            cwd: cwd.to_path_buf(),
            home_catalog: home.to_path_buf(),
        }
    }

    // -- resolution order ---------------------------------------------------

    #[test]
    fn flag_wins_over_every_other_source() {
        let tmp = tempfile::tempdir().unwrap();
        let flag = tmp.path().join("flag");
        let env = tmp.path().join("env");
        let cwd = tmp.path().join("cwd");
        let home = tmp.path().join("home");
        for d in [&flag, &env, &cwd.join(CWD_CATALOG_DIR), &home] {
            std::fs::create_dir_all(d).unwrap();
        }

        let got = lookup(Some(&flag), Some(&env), &cwd, &home)
            .resolve()
            .unwrap();
        assert_eq!(got.dir, flag);
        assert_eq!(got.source, CatalogSource::Flag);
    }

    #[test]
    fn env_wins_when_no_flag_is_passed() {
        let tmp = tempfile::tempdir().unwrap();
        let env = tmp.path().join("env");
        let cwd = tmp.path().join("cwd");
        let home = tmp.path().join("home");
        for d in [&env, &cwd.join(CWD_CATALOG_DIR), &home] {
            std::fs::create_dir_all(d).unwrap();
        }

        let got = lookup(None, Some(&env), &cwd, &home).resolve().unwrap();
        assert_eq!(got.dir, env);
        assert_eq!(got.source, CatalogSource::Env);
    }

    #[test]
    fn cwd_plugins_wins_over_the_home_catalog() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("cwd");
        let home = tmp.path().join("home");
        std::fs::create_dir_all(cwd.join(CWD_CATALOG_DIR)).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        let got = lookup(None, None, &cwd, &home).resolve().unwrap();
        assert_eq!(got.dir, cwd.join(CWD_CATALOG_DIR));
        assert_eq!(got.source, CatalogSource::Cwd);
    }

    #[test]
    fn home_catalog_is_the_last_resort() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("cwd"); // no ./plugins inside
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        let got = lookup(None, None, &cwd, &home).resolve().unwrap();
        assert_eq!(got.dir, home);
        assert_eq!(got.source, CatalogSource::Home);
    }

    /// An explicitly named catalog that does not exist must NOT fall through to
    /// `./plugins`: installing from a directory the user did not name is worse
    /// than failing.
    #[test]
    fn a_missing_explicit_catalog_is_an_error_not_a_fallthrough() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("cwd");
        std::fs::create_dir_all(cwd.join(CWD_CATALOG_DIR)).unwrap();
        let home = tmp.path().join("home");
        let missing = tmp.path().join("nope");

        let err = lookup(Some(&missing), None, &cwd, &home)
            .resolve()
            .expect_err("a missing --catalog must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("--catalog"), "{msg}");
        assert!(msg.contains("not a directory"), "{msg}");

        let err = lookup(None, Some(&missing), &cwd, &home)
            .resolve()
            .expect_err("a missing $ENTANGLE_CATALOG must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains(CATALOG_ENV), "{msg}");
    }

    /// The not-found error must name every location tried *and* the exact ways
    /// to fix it. This is the first wall a new user can hit.
    #[test]
    fn nothing_found_names_all_four_locations_and_the_fix() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("cwd");
        std::fs::create_dir_all(&cwd).unwrap();
        let home = tmp.path().join("home/.entangle/catalog");

        let err = lookup(None, None, &cwd, &home)
            .resolve()
            .expect_err("no catalog anywhere must fail");
        let msg = format!("{err:#}");

        assert!(msg.contains("no plugin catalog found"), "{msg}");
        for needle in ["--catalog", CATALOG_ENV, "./plugins", "~/.entangle/catalog"] {
            assert!(msg.contains(needle), "missing {needle} in:\n{msg}");
        }
        // Concrete paths, not just source names.
        assert!(
            msg.contains(&cwd.join(CWD_CATALOG_DIR).display().to_string()),
            "{msg}"
        );
        assert!(msg.contains(&home.display().to_string()), "{msg}");
        // Actionable fixes.
        assert!(msg.contains("git clone"), "{msg}");
        assert!(msg.contains("--catalog /path/to"), "{msg}");
        // And it must not pretend a registry exists.
        assert!(
            msg.contains("no published plugin registry"),
            "must not imply a download: {msg}"
        );
    }

    // -- scanning -----------------------------------------------------------

    #[test]
    fn scan_reads_name_tier_and_description_from_each_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let cat = tmp.path();
        plugin(cat, "json-query", 1, "query JSON");
        plugin(cat, "csv-stats", 2, "summarise CSV columns");

        let listing = scan(cat).unwrap();
        assert!(listing.problems.is_empty(), "{:?}", listing.problems);
        let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["csv-stats", "json-query"], "must be sorted");

        let json = &listing.entries[1];
        assert_eq!(json.name, "json-query");
        assert_eq!(json.tier, 1);
        assert_eq!(json.version, "0.1.0");
        assert_eq!(json.runtime, "wasm");
        assert_eq!(json.description, "query JSON");
    }

    /// Non-plugin directories are skipped silently; a *broken* plugin is
    /// reported but must not hide the healthy ones.
    #[test]
    fn scan_skips_noise_and_isolates_broken_manifests() {
        let tmp = tempfile::tempdir().unwrap();
        let cat = tmp.path();
        plugin(cat, "good", 1, "fine");
        std::fs::create_dir_all(cat.join("target")).unwrap();
        std::fs::create_dir_all(cat.join(".git")).unwrap();
        std::fs::create_dir_all(cat.join("not-a-plugin")).unwrap();
        std::fs::write(cat.join("README.md"), "# catalog").unwrap();
        let broken = cat.join("broken");
        std::fs::create_dir_all(&broken).unwrap();
        std::fs::write(broken.join("entangle.toml"), "this is not toml = = =").unwrap();

        let listing = scan(cat).unwrap();
        let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["good"]);
        assert_eq!(listing.problems.len(), 1);
        assert!(listing.problems[0].0.ends_with("broken"));
    }

    /// The name comes from the manifest id even when the directory disagrees,
    /// and a placeholder-only id falls back to the directory name.
    #[test]
    fn entry_name_prefers_the_manifest_id() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dir-name");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("entangle.toml"),
            "[plugin]\nid = \"PUBLISHER_PLACEHOLDER/real-name@0.1.0\"\nversion = \"0.3.0\"\n\
             tier = 1\nruntime = \"wasm\"\ndescription = \"d\"\n",
        )
        .unwrap();
        assert_eq!(read_entry(&dir).unwrap().name, "real-name");
    }

    // -- lookup by name -----------------------------------------------------

    #[test]
    fn find_entry_is_case_insensitive_and_suggests_on_a_miss() {
        let tmp = tempfile::tempdir().unwrap();
        let cat = tmp.path().to_path_buf();
        plugin(&cat, "json-query", 1, "query JSON");
        plugin(&cat, "qr-encode", 1, "make QR codes");
        let catalog = Catalog {
            dir: cat,
            source: CatalogSource::Flag,
        };

        assert_eq!(
            find_entry(&catalog, "JSON-Query").unwrap().name,
            "json-query"
        );

        let err = find_entry(&catalog, "json").expect_err("must not match a prefix");
        let msg = format!("{err:#}");
        assert!(msg.contains("Did you mean: json-query"), "{msg}");
        assert!(msg.contains("entangle plugins available"), "{msg}");

        let err = find_entry(&catalog, "totally-absent").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Available: json-query, qr-encode"), "{msg}");
    }

    #[test]
    fn find_entry_in_an_empty_catalog_explains_the_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let catalog = Catalog {
            dir: tmp.path().to_path_buf(),
            source: CatalogSource::Home,
        };
        let err = find_entry(&catalog, "json-query").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no plugin projects"), "{msg}");
        assert!(msg.contains("--catalog"), "{msg}");
    }
}
