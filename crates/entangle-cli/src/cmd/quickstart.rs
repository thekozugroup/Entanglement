//! `entangle quickstart` — zero to a working plugin in one command.
//!
//! Six steps, all of them things the user would otherwise have to know about:
//!
//! 1. **identity** — create `~/.entangle/` and an Ed25519 key if absent
//!    (delegated wholesale to [`crate::cmd::init::ensure_initialised`]; no
//!    identity-writing code lives here).
//! 2. **trust** — put the user's own publisher key in their keyring, without
//!    which nothing they sign themselves can load. Done before the slow build
//!    so a keyring problem surfaces in milliseconds.
//! 3. **catalog** — resolve a plugin catalog and pick a starter plugin.
//! 4. **build + sign** — compile the starter to wasm and sign it with that key
//!    ([`crate::cmd::catalog::prepare`], the same pipeline `plugins build` uses).
//! 5. **load** — into the daemon if one is running, otherwise into a temporary
//!    in-process kernel that lives for the rest of this command.
//! 6. **invoke** — with a sample input, printing the real output.
//!
//! # Idempotency
//! Running it twice must be safe, so every mutating step is a no-op the second
//! time: `init` keeps existing files, `ensure_trusted` leaves an already-trusted
//! key alone, the build overwrites its own output directory, and a plugin that
//! is already loaded is reported rather than treated as a failure.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;

use crate::cmd::catalog::{self, CatalogEntry, InstallOptions};
use crate::cmd::init::InitArgs;
use crate::cmd::plugins::{render_output, Session};
use crate::config;

/// Timeout for the demo invocation.
const INVOKE_TIMEOUT_MS: u64 = 30_000;

/// Starter plugins, best first, with an input that shows each one off.
///
/// Preference order only — the catalog is the authority on what exists, and a
/// catalog holding none of these still works (the first entry is used).
/// `image-resize` is deliberately absent: its input is a binary image, which
/// makes a poor one-line demo.
const STARTERS: &[(&str, &str)] = &[
    ("json-query", r#"{"hello":"entanglement","tier":1}"#),
    ("markdown-html", "# Hello from Entanglement\n"),
    ("csv-stats", "name,score\nalice,10\nbob,32\n"),
    ("compress", "entanglement runs signed wasm plugins"),
    (
        "qr-encode",
        "https://github.com/entanglement-dev/entanglement",
    ),
];

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Args, Debug, Default)]
pub struct QuickstartArgs {
    /// Catalog directory to install from.
    ///
    /// Same resolution order as `plugins install`: --catalog, $ENTANGLE_CATALOG,
    /// ./plugins, ~/.entangle/catalog.
    #[arg(long)]
    pub catalog: Option<PathBuf>,

    /// Starter plugin to install. Defaults to the first recommended plugin
    /// present in the catalog.
    #[arg(long)]
    pub plugin: Option<String>,

    /// Input to invoke the starter plugin with. Defaults to a sample suited to
    /// the chosen plugin.
    #[arg(long)]
    pub input: Option<String>,

    /// Target triple to compile for.
    #[arg(long, default_value = crate::cmd::package::DEFAULT_TARGET)]
    pub target: String,

    /// Identity key PEM to sign with. Defaults to `~/.entangle/identity.key`.
    #[arg(long)]
    pub key: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Starter selection (pure)
// ---------------------------------------------------------------------------

/// The sample input for `name`, if we know one.
fn sample_input_for(name: &str) -> Option<&'static str> {
    STARTERS
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, input)| *input)
}

/// Choose which catalog entry to demo.
///
/// Prefers [`STARTERS`] order, then any wasm plugin, then whatever is first —
/// the six bundled plugins are not assumed to exist.
pub fn pick_starter(entries: &[CatalogEntry]) -> Result<&CatalogEntry> {
    for (name, _) in STARTERS {
        if let Some(e) = entries.iter().find(|e| e.name.eq_ignore_ascii_case(name)) {
            return Ok(e);
        }
    }
    if let Some(e) = entries.iter().find(|e| e.runtime == "wasm") {
        return Ok(e);
    }
    entries.first().ok_or_else(|| {
        anyhow::anyhow!(
            "the catalog contains no plugin projects, so there is nothing to demo.\n\n\
             A catalog is a directory whose subdirectories each hold an entangle.toml.\n\
             List what a catalog contains with:\n  entangle plugins available --catalog <DIR>"
        )
    })
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

pub async fn run(args: QuickstartArgs) -> Result<()> {
    println!("entangle quickstart — identity, one plugin, one invocation.");
    println!();

    // -- 1. identity ------------------------------------------------------
    println!("[1/6] identity");
    crate::cmd::init::ensure_initialised(
        InitArgs {
            non_interactive: true,
        },
        false,
    )
    .await?;

    // -- 2. trust our own key --------------------------------------------
    // Before the slow build, not after: this is the step that makes a
    // self-signed plugin loadable at all, and it costs milliseconds.
    println!();
    println!("[2/6] trust");
    let key_path = args.key.clone().unwrap_or_else(config::identity_path);
    let trust = catalog::trust_own_key(&key_path)?;
    catalog::print_trust(&trust);

    // -- 3. catalog + starter --------------------------------------------
    println!();
    println!("[3/6] catalog");
    let catalog = catalog::resolve(args.catalog.clone())?;
    println!(
        "      {} (from {})",
        catalog.dir.display(),
        catalog.source.origin()
    );
    let listing = catalog::scan(&catalog.dir)?;
    for (dir, why) in &listing.problems {
        eprintln!("warning: skipped {} — {}", dir.display(), why);
    }
    let entry = match &args.plugin {
        Some(name) => catalog::find_entry(&catalog, name)?,
        None => pick_starter(&listing.entries)?.clone(),
    };
    println!(
        "      starter: {} v{} (tier {}) — {}",
        entry.name,
        entry.version,
        entry.tier,
        if entry.description.is_empty() {
            "(no description)"
        } else {
            &entry.description
        }
    );
    if listing.entries.len() > 1 {
        println!(
            "      ({} plugins in this catalog — see `entangle plugins available`)",
            listing.entries.len()
        );
    }

    // -- 4. build + sign -------------------------------------------------
    println!();
    println!("[4/6] build and sign");
    let prepared = catalog::prepare(
        &entry,
        &InstallOptions {
            name: entry.name.clone(),
            catalog: args.catalog.clone(),
            key: Some(key_path.clone()),
            out: None,
            target: args.target.clone(),
            wasm: None,
            no_load: false,
        },
    )?;
    println!(
        "      signed package: {} (effective tier {})",
        prepared.outcome.dist.display(),
        prepared.outcome.effective_tier
    );

    // -- 5. load ----------------------------------------------------------
    println!();
    println!("[5/6] load");
    let session = Session::connect().await?;
    let report = session
        .load_package(&prepared.outcome.dist, &prepared.outcome.plugin_id)
        .await?;
    if report.already_loaded {
        println!("      {} was already loaded", report.id);
    } else {
        println!("      loaded {} into the {}", report.id, session.describe());
    }

    // -- 6. invoke --------------------------------------------------------
    let input = args
        .input
        .clone()
        .or_else(|| sample_input_for(&entry.name).map(|s| s.to_owned()))
        .unwrap_or_default();

    println!();
    println!("[6/6] invoke");
    println!(
        "      entangle plugins invoke {} --input {:?}",
        report.id, input
    );
    match session
        .invoke_bytes(&report.id, input.as_bytes(), INVOKE_TIMEOUT_MS)
        .await
    {
        Ok(output) => {
            println!();
            println!("{}", render_output(&output));
            print_summary(&prepared, &report.id, &input, session.is_daemon());
        }
        Err(e) => {
            // The plugin is installed and loaded; only the sample input failed.
            // Say exactly that, and hand back a command the user can retry.
            eprintln!();
            eprintln!("warning: the sample invocation failed: {e:#}");
            eprintln!(
                "         {} is installed, signed, and trusted — only this input was rejected.",
                report.id
            );
            eprintln!("         Try your own input:");
            eprintln!(
                "           entangle plugins invoke {} --input '<your input>'",
                report.id
            );
            if let Ok(readme) = readme_hint(&entry) {
                eprintln!("         Input format: {readme}");
            }
            print_summary(&prepared, &report.id, &input, session.is_daemon());
        }
    }

    Ok(())
}

/// Point at the plugin's README for the expected input format, if it has one.
fn readme_hint(entry: &CatalogEntry) -> Result<String> {
    let readme = entry.dir.join("README.md");
    if readme.exists() {
        Ok(readme.display().to_string())
    } else {
        bail!("no README.md")
    }
}

/// The closing "what just happened" + "what next" banner.
fn print_summary(prepared: &catalog::Prepared, plugin_id: &str, input: &str, via_daemon: bool) {
    let dir = config::entangle_dir();
    println!();
    println!("What just happened");
    println!(
        "  1. identity  {} — your Ed25519 key; its fingerprint {} is the",
        config::identity_path().display(),
        prepared.outcome.fingerprint
    );
    println!("               <publisher> segment of every plugin you sign.");
    println!(
        "  2. trusted   your own publisher key in {} — the kernel only loads",
        dir.join("keyring.toml").display()
    );
    println!("               plugins signed by a key in that keyring, including your own.");
    println!(
        "  3. built     {} → {} (compiled to wasm and signed with that key)",
        prepared.entry.dir.display(),
        prepared.outcome.dist.display()
    );
    println!("  4. loaded    {plugin_id}");
    println!("  5. invoked   it with --input {input:?} and printed the output above.");

    if !via_daemon {
        println!();
        println!("  No daemon was running, so steps 4-5 used a temporary in-process kernel that");
        println!("  ended with this command. Everything on disk (identity, keyring, the signed");
        println!("  package) persists. Start the daemon to keep plugins loaded between commands:");
        println!("    entangled run");
    }

    println!();
    println!("What to try next");
    println!("  entangle plugins available                     # every plugin in the catalog");
    println!("  entangle plugins install <NAME>                # install another one");
    println!("  entangle plugins invoke {plugin_id} --input '...'");
    println!("  entangle plugins list                          # what is loaded right now");
    println!("  entangle doctor                                # check identity, keyring, daemon");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, runtime: &str) -> CatalogEntry {
        CatalogEntry {
            name: name.to_owned(),
            dir: PathBuf::from("/catalog").join(name),
            version: "0.1.0".to_owned(),
            tier: 1,
            runtime: runtime.to_owned(),
            description: String::new(),
        }
    }

    #[test]
    fn starter_preference_is_honoured() {
        let entries = vec![
            entry("zzz-last", "wasm"),
            entry("csv-stats", "wasm"),
            entry("json-query", "wasm"),
        ];
        assert_eq!(pick_starter(&entries).unwrap().name, "json-query");
    }

    /// The bundled six are a preference, not a requirement: an unrelated catalog
    /// still gets a starter.
    #[test]
    fn an_unknown_catalog_still_yields_a_starter() {
        let entries = vec![
            entry("native-thing", "native"),
            entry("some-plugin", "wasm"),
        ];
        assert_eq!(pick_starter(&entries).unwrap().name, "some-plugin");
    }

    #[test]
    fn an_empty_catalog_explains_itself() {
        let err = pick_starter(&[]).expect_err("nothing to demo");
        let msg = format!("{err:#}");
        assert!(msg.contains("no plugin projects"), "{msg}");
        assert!(msg.contains("entangle plugins available"), "{msg}");
    }

    #[test]
    fn every_starter_has_a_sample_input() {
        for (name, _) in STARTERS {
            assert!(
                sample_input_for(name).is_some(),
                "no sample input for {name}"
            );
        }
        assert!(sample_input_for("json-QUERY").is_some(), "case-insensitive");
        assert!(sample_input_for("unheard-of").is_none());
    }
}
