//! `entangle plugins new` — scaffold a ready-to-build plugin project.
//!
//! The generated project builds and loads with **no boilerplate editing**:
//!
//! ```text
//! <name>/
//!   Cargo.toml     cdylib crate-type, wasm-sized release profile, SDK dependency
//!   entangle.toml  manifest with a documented tier + capability table
//!   src/lib.rs     a working `run` wired up by `entangle_plugin!`
//!   README.md      the exact build/sign/load/invoke commands for this plugin
//!   .gitignore     target/ and dist/
//! ```
//!
//! # Why the SDK dependency is a choice
//! A generated project cannot use `path = "../../crates/entangle-sdk"` — that
//! only resolves inside this repository. [`SdkSource`] models the three real
//! options (crates.io, git, local path) and [`SdkSource::resolve_auto`] picks
//! the one that actually works on the machine running the command. See
//! `docs/plugin-authoring.md` for the tradeoffs.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use entangle_types::plugin_id::is_valid_name;

use crate::cmd::package::PUBLISHER_PLACEHOLDER;

/// Upstream repository, used for the `git` SDK source.
pub const REPO_URL: &str = env!("CARGO_PKG_REPOSITORY");

/// Version requirement written for the crates.io SDK source.
pub const SDK_VERSION_REQ: &str = "0.1";

/// Environment variable that points `--sdk auto` at a local checkout.
pub const SDK_PATH_ENV: &str = "ENTANGLE_SDK_PATH";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Options for [`run`].
#[derive(Debug, Clone)]
pub struct NewOptions {
    /// Plugin name — also the crate name. Must match `^[a-z][a-z0-9-]{0,62}$`.
    pub name: String,
    /// Directory to create. Defaults to `./<name>`.
    pub path: Option<PathBuf>,
    /// Declared tier (1..=3 for wasm plugins).
    pub tier: u8,
    /// Manifest description.
    pub description: Option<String>,
    /// SDK dependency source spec — see [`SdkSource::parse`].
    pub sdk: String,
    /// Overwrite files that already exist.
    pub force: bool,
}

// ---------------------------------------------------------------------------
// SDK dependency source
// ---------------------------------------------------------------------------

/// Where a scaffolded project gets `entangle-sdk` from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkSource {
    /// `entangle-sdk = "<req>"` — requires the crate to be published.
    CratesIo(String),
    /// `entangle-sdk = { git = "<url>", ... }`.
    Git {
        /// Repository URL.
        url: String,
        /// Optional `rev`/branch/tag pin.
        rev: Option<String>,
    },
    /// `entangle-sdk = { path = "<dir>" }` — local development.
    Path(PathBuf),
}

impl SdkSource {
    /// Parse a `--sdk` spec.
    ///
    /// | Spec | Result |
    /// |------|--------|
    /// | `auto` (default) | local checkout if one is detectable, else `git` |
    /// | `crates-io` / `crates-io:<req>` | [`SdkSource::CratesIo`] |
    /// | `git` / `git:<url>` / `git:<url>#<rev>` | [`SdkSource::Git`] |
    /// | `path:<dir>` | [`SdkSource::Path`] |
    pub fn parse(spec: &str) -> Result<Self> {
        let (kind, rest) = match spec.split_once(':') {
            Some((k, r)) => (k, Some(r)),
            None => (spec, None),
        };
        match kind {
            "auto" => Ok(Self::resolve_auto()),
            "crates-io" | "crates.io" | "cratesio" => Ok(SdkSource::CratesIo(
                rest.unwrap_or(SDK_VERSION_REQ).to_owned(),
            )),
            "git" => {
                let spec = rest.unwrap_or(REPO_URL);
                let (url, rev) = match spec.split_once('#') {
                    Some((u, r)) => (u, Some(r.to_owned())),
                    None => (spec, None),
                };
                let url = if url.is_empty() { REPO_URL } else { url };
                Ok(SdkSource::Git {
                    url: url.to_owned(),
                    rev,
                })
            }
            "path" => {
                let p = rest.filter(|s| !s.is_empty()).context(
                    "--sdk path:<DIR> needs a directory, e.g. --sdk path:../Entanglement/crates/entangle-sdk",
                )?;
                Ok(SdkSource::Path(PathBuf::from(p)))
            }
            other => bail!(
                "unknown --sdk source {other:?}.\n\
                 Expected one of: auto, crates-io[:<req>], git[:<url>[#<rev>]], path:<DIR>"
            ),
        }
    }

    /// Pick the source that will actually resolve on this machine.
    ///
    /// Prefers an explicit `ENTANGLE_SDK_PATH`, then a checkout detected by
    /// walking up from the current directory, and otherwise falls back to git —
    /// **not** crates.io, because `entangle-sdk` is not published yet and a
    /// crates.io dependency would produce a project that cannot build.
    pub fn resolve_auto() -> Self {
        if let Some(p) = std::env::var_os(SDK_PATH_ENV) {
            return SdkSource::Path(PathBuf::from(p));
        }
        if let Some(p) = detect_local_sdk() {
            return SdkSource::Path(p);
        }
        SdkSource::Git {
            url: REPO_URL.to_owned(),
            rev: None,
        }
    }

    /// The `[dependencies]` line(s) for this source.
    pub fn dependency_line(&self) -> String {
        match self {
            SdkSource::CratesIo(req) => format!("entangle-sdk = \"{req}\""),
            SdkSource::Git { url, rev: None } => {
                format!("entangle-sdk = {{ git = \"{url}\" }}")
            }
            SdkSource::Git {
                url,
                rev: Some(rev),
            } => format!("entangle-sdk = {{ git = \"{url}\", rev = \"{rev}\" }}"),
            SdkSource::Path(p) => {
                format!("entangle-sdk = {{ path = \"{}\" }}", p.display())
            }
        }
    }

    /// One-line human summary printed after scaffolding.
    pub fn summary(&self) -> String {
        match self {
            SdkSource::CratesIo(req) => format!("crates.io (entangle-sdk = \"{req}\")"),
            SdkSource::Git { url, .. } => format!("git ({url})"),
            SdkSource::Path(p) => format!("local path ({})", p.display()),
        }
    }
}

/// Walk up from the current directory looking for `crates/entangle-sdk`.
fn detect_local_sdk() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    for dir in cwd.ancestors() {
        let candidate = dir.join("crates").join("entangle-sdk");
        if candidate.join("Cargo.toml").is_file() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// File rendering (pure — unit tested below)
// ---------------------------------------------------------------------------

/// Render the generated `Cargo.toml`.
///
/// The `[workspace]` stanza is deliberate: without it, scaffolding into a
/// directory that happens to sit inside another cargo workspace fails with
/// "current package believes it's in a workspace when it's not".
pub fn render_cargo_toml(name: &str, sdk: &SdkSource) -> String {
    let dep = sdk.dependency_line();
    format!(
        r#"[workspace]
# Stand-alone project — not a member of any surrounding cargo workspace.

[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
publish = false

# A wasm component plugin MUST be a cdylib. `entangle plugins build` refuses to
# package anything else.
[lib]
crate-type = ["cdylib"]

[dependencies]
# --- entangle-sdk dependency ------------------------------------------------
# Three supported sources; exactly one may be active.
#
#   1. crates.io  (requires entangle-sdk to have been published):
#        entangle-sdk = "{version_req}"
#   2. git        (works today, tracks the default branch):
#        entangle-sdk = {{ git = "{repo}" }}
#      pin it for reproducible builds:
#        entangle-sdk = {{ git = "{repo}", rev = "<commit-sha>" }}
#   3. local path (for hacking on the SDK alongside your plugin):
#        entangle-sdk = {{ path = "../Entanglement/crates/entangle-sdk" }}
#
# Regenerate with a different source: entangle plugins new {name} --sdk <SPEC>
{dep}

# Small wasm binaries load faster and hash faster. Keep these settings.
[profile.release]
strip = true
lto = true
codegen-units = 1
opt-level = "s"
"#,
        version_req = SDK_VERSION_REQ,
        repo = REPO_URL,
    )
}

/// Render the generated `src/lib.rs` — a complete, working plugin.
pub fn render_lib_rs(name: &str) -> String {
    format!(
        r#"//! {name} — an Entanglement wasm component plugin.
//!
//! Build and sign it with:
//!
//! ```text
//! entangle plugins build .
//! ```

use entangle_sdk::{{entangle_plugin, log, PluginError}};

/// The plugin entrypoint.
///
/// `input` is the raw byte payload passed to `entangle plugins invoke`; the
/// returned bytes are handed straight back to the caller. Returning
/// `Err(PluginError::...)` surfaces as a failed invocation.
fn run(input: Vec<u8>) -> Result<Vec<u8>, PluginError> {{
    let name = std::str::from_utf8(&input)
        .map_err(|e| PluginError::InvalidInput(e.to_string()))?;
    let name = if name.is_empty() {{ "world" }} else {{ name }};

    log::info(&format!("{name} received: {{name}}"));

    Ok(format!("Hello, {{name}}! — from {name}").into_bytes())
}}

entangle_plugin!(run);
"#
    )
}

/// Render the generated `entangle.toml` manifest.
///
/// The `[capabilities]` table is emitted fully commented with each capability's
/// minimum tier, so an author can uncomment one and immediately see what tier
/// it forces them up to.
pub fn render_manifest(name: &str, tier: u8, description: &str) -> String {
    format!(
        r#"# Entanglement plugin manifest (spec §4.4).
#
# `entangle plugins build` rewrites `id` before signing: the
# {PUBLISHER_PLACEHOLDER} segment becomes your identity key's fingerprint and
# `@<version>` is forced to match `version` below. Both parts are required —
# the kernel rejects an id without `@<version>` (ENTANGLE-E0201).
[plugin]
id = "{PUBLISHER_PLACEHOLDER}/{name}@0.1.0"
version = "0.1.0"

# Declared tier ceiling, 1..=5. `runtime = "wasm"` supports tiers 1-3;
# tiers 4-5 require `runtime = "native"`.
#   1 pure        no I/O at all (logging is host-provided and always available)
#   2 sandboxed   scoped local storage
#   3 networked   outbound network to declared hosts
tier = {tier}
runtime = "wasm"
description = "{description}"

# Declaring a capability whose minimum tier is ABOVE `tier` above fails
# validation with ENTANGLE-E0042. Declaring a tier higher than your
# capabilities need is allowed (the effective tier is the max of the two),
# but grant the least privilege you can.
#
#   capability                  min tier
#   "compute.cpu" = {{}}           2
#   "compute.gpu" = {{}}           3
#   "compute.npu" = {{}}           3
#   "storage.local" = {{ scope = "plugin" }}   1
#   "storage.local" = {{ scope = "shared" }}   2
#   "net.lan" = {{}}               3
#   "net.wan" = {{}}               3
#   "agent.invoke" = {{}}          2
#   "storage.share.<name>" = {{ mode = "ro" }} 4   (requires runtime = "native")
#   "mesh.peer" = {{}}             4               (requires runtime = "native")
#   "host.docker-socket" = {{}}    5               (requires runtime = "native")
[capabilities]

[build]
wit_world = "entangle:plugin@0.1.0/plugin"
target = "wasm32-wasip2"
"#
    )
}

/// Render the generated `README.md`.
pub fn render_readme(name: &str, tier: u8, sdk: &SdkSource) -> String {
    format!(
        r#"# {name}

An [Entanglement]({REPO_URL}) wasm component plugin, scaffolded with
`entangle plugins new {name}`.

- **tier**: {tier}
- **capabilities**: none declared (see `entangle.toml`)
- **SDK source**: {sdk_summary}

## Build and sign

```sh
rustup target add wasm32-wasip2   # once per machine
entangle init                     # once per machine — creates your publisher key
entangle plugins build .
```

That writes `dist/plugin.wasm`, `dist/entangle.toml` (with your real publisher
fingerprint in the plugin id) and `dist/plugin.wasm.sig`.

## Trust your own key, then load and run

`entangle plugins build` finishes by printing the exact three commands to run,
with your public key and fully-qualified plugin id already filled in:

```text
entangle keyring add <YOUR_PUBLIC_KEY_HEX> --name self
entangle plugins load dist/
entangle plugins invoke <PUBLISHER_FINGERPRINT>/{name}@0.1.0 --input 'world'
```

## Editing

- `src/lib.rs` — your `run` function.
- `entangle.toml` — tier and capabilities. Raising a capability above the
  declared tier fails the build with `ENTANGLE-E0042`.

Full guide: `docs/plugin-authoring.md` in the Entanglement repository.
"#,
        sdk_summary = sdk.summary(),
    )
}

/// Render the generated `.gitignore`.
pub fn render_gitignore() -> String {
    "target/\ndist/\nCargo.lock\n".to_owned()
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Scaffold a new plugin project.
pub fn run(opts: NewOptions) -> Result<()> {
    if !is_valid_name(&opts.name) {
        bail!(
            "invalid plugin name {:?}.\n\
             Names must match ^[a-z][a-z0-9-]{{0,62}}$ (lowercase, digits, dashes; \
             starting with a letter) — the same rule the kernel applies to plugin ids.",
            opts.name
        );
    }
    if !(1..=3).contains(&opts.tier) {
        bail!(
            "--tier {} is out of range for a wasm plugin.\n\
             Tiers 1-3 run on `runtime = \"wasm\"`; tiers 4-5 require \
             `runtime = \"native\"`, which this template does not generate.",
            opts.tier
        );
    }

    let sdk = SdkSource::parse(&opts.sdk)?;
    let dir = opts
        .path
        .clone()
        .unwrap_or_else(|| PathBuf::from(&opts.name));
    let description = opts
        .description
        .clone()
        .unwrap_or_else(|| format!("{} — an Entanglement plugin", opts.name));

    std::fs::create_dir_all(dir.join("src"))
        .with_context(|| format!("creating {}", dir.join("src").display()))?;

    let files: [(PathBuf, String); 5] = [
        (dir.join("Cargo.toml"), render_cargo_toml(&opts.name, &sdk)),
        (dir.join("src/lib.rs"), render_lib_rs(&opts.name)),
        (
            dir.join("entangle.toml"),
            render_manifest(&opts.name, opts.tier, &description),
        ),
        (
            dir.join("README.md"),
            render_readme(&opts.name, opts.tier, &sdk),
        ),
        (dir.join(".gitignore"), render_gitignore()),
    ];

    if !opts.force {
        let existing: Vec<&Path> = files
            .iter()
            .map(|(p, _)| p.as_path())
            .filter(|p| p.exists())
            .collect();
        if !existing.is_empty() {
            bail!(
                "refusing to overwrite existing files (pass --force to replace them):\n  {}",
                existing
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join("\n  ")
            );
        }
    }

    for (path, contents) in &files {
        std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
        println!("  created {}", path.display());
    }

    println!();
    println!("Scaffolded plugin '{}' in {}", opts.name, dir.display());
    println!("  tier:       {}", opts.tier);
    println!("  SDK source: {}", sdk.summary());
    println!();
    println!("Next steps:");
    println!(
        "  rustup target add {}",
        crate::cmd::package::DEFAULT_TARGET
    );
    println!("  entangle init                     # once, creates your publisher key");
    println!("  entangle plugins build {}", dir.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::package::render_dist_manifest;

    const FP: &str = "aabbccddeeff00112233445566778899";

    #[test]
    fn sdk_spec_parsing() {
        assert_eq!(
            SdkSource::parse("crates-io").unwrap(),
            SdkSource::CratesIo(SDK_VERSION_REQ.into())
        );
        assert_eq!(
            SdkSource::parse("crates-io:0.2").unwrap(),
            SdkSource::CratesIo("0.2".into())
        );
        assert_eq!(
            SdkSource::parse("git").unwrap(),
            SdkSource::Git {
                url: REPO_URL.into(),
                rev: None
            }
        );
        assert_eq!(
            SdkSource::parse("git:https://example.com/x.git#abc123").unwrap(),
            SdkSource::Git {
                url: "https://example.com/x.git".into(),
                rev: Some("abc123".into())
            }
        );
        assert_eq!(
            SdkSource::parse("path:../sdk").unwrap(),
            SdkSource::Path("../sdk".into())
        );
        assert!(SdkSource::parse("nope").is_err());
        assert!(SdkSource::parse("path:").is_err());
    }

    #[test]
    fn dependency_lines_are_valid_toml() {
        for src in [
            SdkSource::CratesIo("0.1".into()),
            SdkSource::Git {
                url: REPO_URL.into(),
                rev: None,
            },
            SdkSource::Git {
                url: REPO_URL.into(),
                rev: Some("deadbeef".into()),
            },
            SdkSource::Path("../entangle-sdk".into()),
        ] {
            let line = src.dependency_line();
            let parsed: toml::Value =
                toml::from_str(&line).unwrap_or_else(|e| panic!("not valid TOML: {line}\n{e}"));
            assert!(parsed.get("entangle-sdk").is_some(), "{line}");
        }
    }

    /// The generated Cargo.toml must parse, be a cdylib, and depend on the SDK.
    #[test]
    fn generated_cargo_toml_is_well_formed() {
        let toml_text = render_cargo_toml("my-plugin", &SdkSource::CratesIo("0.1".into()));
        let v: toml::Value = toml::from_str(&toml_text).expect("Cargo.toml must parse");
        assert_eq!(v["package"]["name"].as_str(), Some("my-plugin"));
        assert_eq!(
            v["lib"]["crate-type"].as_array().unwrap()[0].as_str(),
            Some("cdylib")
        );
        assert!(v["dependencies"].get("entangle-sdk").is_some());
        // Detached from any surrounding workspace.
        assert!(v.get("workspace").is_some());
        // Release profile tuned for small wasm.
        assert_eq!(v["profile"]["release"]["opt-level"].as_str(), Some("s"));
    }

    /// The scaffolded manifest is valid TOML and, once `entangle plugins build`
    /// substitutes the real publisher fingerprint, parses AND validates through
    /// entangle-manifest. (The raw file cannot validate on its own: its
    /// publisher is a placeholder by design.)
    #[test]
    fn scaffolded_manifest_validates_after_id_substitution() {
        for tier in 1..=3u8 {
            let src = render_manifest("my-plugin", tier, "scaffolded");
            // Parses as TOML on its own.
            let _: toml::Value = toml::from_str(&src).expect("manifest must parse");
            // Placeholder publisher is intentional and must be present.
            assert!(src.contains(PUBLISHER_PLACEHOLDER));

            let rendered = render_dist_manifest(&src, FP).expect("must validate");
            assert_eq!(rendered.plugin_id, format!("{FP}/my-plugin@0.1.0"));
            assert_eq!(rendered.effective_tier, tier);
        }
    }

    /// The generated plugin id is fully qualified — `<publisher>/<name>@<version>`.
    #[test]
    fn scaffolded_plugin_id_is_fully_qualified() {
        let src = render_manifest("my-plugin", 1, "scaffolded");
        let rendered = render_dist_manifest(&src, FP).unwrap();
        let id: entangle_types::plugin_id::PluginId =
            rendered.plugin_id.parse().expect("id must parse");
        assert_eq!(id.publisher, FP);
        assert_eq!(id.name, "my-plugin");
        assert_eq!(id.version.to_string(), "0.1.0");
    }

    /// The commented capability table must not accidentally declare anything.
    #[test]
    fn scaffolded_manifest_declares_no_capabilities() {
        let src = render_manifest("my-plugin", 1, "scaffolded");
        let m: entangle_manifest::Manifest = toml::from_str(&src).unwrap();
        assert!(m.capabilities.is_empty(), "got: {:?}", m.capabilities);
    }

    #[test]
    fn generated_lib_rs_mentions_the_sdk_entrypoint() {
        let src = render_lib_rs("my-plugin");
        assert!(src.contains("entangle_plugin!(run)"));
        assert!(src.contains("fn run(input: Vec<u8>) -> Result<Vec<u8>, PluginError>"));
    }

    #[test]
    fn scaffold_writes_all_files_and_refuses_to_clobber() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("my-plugin");
        let opts = NewOptions {
            name: "my-plugin".into(),
            path: Some(dir.clone()),
            tier: 1,
            description: None,
            sdk: "crates-io".into(),
            force: false,
        };
        run(opts.clone()).expect("scaffold should succeed");

        for f in [
            "Cargo.toml",
            "entangle.toml",
            "src/lib.rs",
            "README.md",
            ".gitignore",
        ] {
            assert!(dir.join(f).exists(), "{f} not generated");
        }

        // Second run without --force must fail rather than clobber.
        let err = run(opts).expect_err("second scaffold must refuse");
        assert!(
            format!("{err:#}").contains("refusing to overwrite"),
            "got: {err:#}"
        );
    }

    #[test]
    fn invalid_names_and_tiers_are_rejected() {
        let base = NewOptions {
            name: "MyPlugin".into(),
            path: Some(PathBuf::from("/nonexistent-should-not-be-created")),
            tier: 1,
            description: None,
            sdk: "crates-io".into(),
            force: false,
        };
        let err = run(base.clone()).expect_err("uppercase name must be rejected");
        assert!(
            format!("{err:#}").contains("invalid plugin name"),
            "{err:#}"
        );

        let mut bad_tier = base.clone();
        bad_tier.name = "ok-name".into();
        bad_tier.tier = 5;
        let err = run(bad_tier).expect_err("tier 5 wasm must be rejected");
        assert!(format!("{err:#}").contains("out of range"), "{err:#}");
    }
}
