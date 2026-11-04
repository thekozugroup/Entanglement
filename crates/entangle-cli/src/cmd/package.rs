//! `entangle plugins build` — build and sign an **arbitrary** plugin project.
//!
//! This is the supported third-party build path. It works on any directory that
//! contains a `Cargo.toml` (a `cdylib` crate depending on `entangle-sdk`) and an
//! `entangle.toml` manifest — it is **not** limited to the two bundled examples
//! the way `cargo xtask hello-world build` used to be. `cargo xtask` now
//! delegates here rather than carrying a second copy of this pipeline.
//!
//! Output layout (what [`entangle_runtime`]'s loader expects):
//!
//! ```text
//! <dir>/dist/plugin.wasm       compiled component            (runtime = "wasm")
//! <dir>/dist/plugin.bin        host executable               (runtime = "native")
//! <dir>/dist/entangle.toml     manifest, id rewritten to the real publisher
//! <dir>/dist/plugin.*.sig      detached signature bundle over artifact + manifest
//! ```
//!
//! # Native plugins
//! When the manifest declares `runtime = "native"` (tier 4–5) the project is a
//! Rust **binary** crate: it is built with `cargo build --release` for the
//! host (no `--target`), and the executable is packaged as `plugin.bin`. The
//! signature covers it exactly as it covers a wasm component.
//!
//! # Plugin id rewriting
//! The author writes a placeholder publisher in their source `entangle.toml`
//! (they cannot know their own fingerprint before `entangle init`). At build
//! time the `<publisher>` segment is replaced with the fingerprint of the
//! signing key, and `@<version>` is forced to equal `plugin.version`. The
//! fully-qualified `<publisher>/<name>@<version>` form is mandatory: an id
//! without `@<version>` is rejected by the kernel with `ENTANGLE-E0201`, which
//! is exactly the bug that made every previously-built example unloadable.
//! [`render_dist_manifest`] is the single place that decides this string, and
//! it is covered by unit tests below.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use entangle_signing::{sign_artifact_at, IdentityKeyPair};

use crate::cmd::repro;
use crate::config;

/// Default rustup/cargo target triple for wasm plugins.
pub const DEFAULT_TARGET: &str = "wasm32-wasip2";

/// Placeholder publisher segment written by `entangle plugins new`.
pub const PUBLISHER_PLACEHOLDER: &str = "PUBLISHER_PLACEHOLDER";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Options for [`run`].
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// Plugin project directory (contains `Cargo.toml` + `entangle.toml`).
    pub dir: PathBuf,
    /// Identity key PEM. Defaults to `~/.entangle/identity.key`.
    pub key: Option<PathBuf>,
    /// Output directory. Defaults to `<dir>/dist`.
    pub out: Option<PathBuf>,
    /// Pre-built `.wasm` to package instead of invoking cargo (wasm plugins).
    pub wasm: Option<PathBuf>,
    /// Pre-built host executable to package instead of invoking cargo
    /// (native plugins).
    pub bin: Option<PathBuf>,
    /// Target triple to build for (wasm plugins; native ones build for the host).
    pub target: String,
}

// ---------------------------------------------------------------------------
// Rendered manifest — the pure, unit-testable core
// ---------------------------------------------------------------------------

/// A `dist/entangle.toml` rendered from an author's source manifest.
#[derive(Debug, Clone)]
pub struct RenderedManifest {
    /// Exact bytes written to `dist/entangle.toml` (and covered by the signature).
    pub toml: String,
    /// Fully-qualified `<publisher>/<name>@<version>` plugin id.
    pub plugin_id: String,
    /// Effective tier after validation (`max(declared, implied)`).
    pub effective_tier: u8,
    /// `runtime = "native"`: package a host executable as `plugin.bin`.
    pub native: bool,
}

/// What [`build`] produced — everything a caller needs to trust, load, and
/// invoke the package without re-deriving it from disk.
///
/// `entangle plugins install` and `entangle quickstart` consume this instead of
/// re-implementing the signing pipeline; [`run`] is just `build` plus the
/// "next steps" banner that `plugins build` prints.
#[derive(Debug, Clone)]
pub struct BuildOutcome {
    /// Fully-qualified `<publisher>/<name>@<version>` id of the signed package.
    pub plugin_id: String,
    /// Directory holding `plugin.wasm`, `entangle.toml`, and `plugin.wasm.sig`.
    pub dist: PathBuf,
    /// Signing key fingerprint (32 hex chars) — the `<publisher>` segment.
    pub fingerprint: String,
    /// Signing key's public key (64 hex chars) — what `keyring add` takes.
    pub public_key_hex: String,
    /// Effective tier of the signed manifest.
    pub effective_tier: u8,
    /// Reproducible package archive (`<dist>/<name>-<version>.tar.zst`); wasm
    /// plugins only.
    pub archive: Option<PathBuf>,
    /// SHA-256 (hex) of [`BuildOutcome::archive`].
    pub archive_sha256: Option<String>,
}

/// Split an `entangle.toml` `plugin.id` into its bare `<name>` segment.
///
/// Accepts every shape an author might plausibly write:
/// `PUBLISHER_PLACEHOLDER/my-plugin@0.1.0`, `<fingerprint>/my-plugin`, or a
/// bare `my-plugin`. Only the name survives — the publisher always comes from
/// the signing key and the version always comes from `plugin.version`, so a
/// stale or hand-edited id can never leak into the signed artifact.
pub fn plugin_name_from_id(id: &str) -> &str {
    let after_slash = match id.rfind('/') {
        Some(i) => &id[i + 1..],
        None => id,
    };
    match after_slash.rfind('@') {
        Some(i) => &after_slash[..i],
        None => after_slash,
    }
}

/// Rewrite an author's `entangle.toml` into the signed `dist/entangle.toml`.
///
/// * `source` — the author's manifest text.
/// * `fingerprint_hex` — 32 lowercase hex chars from [`IdentityKeyPair::fingerprint_hex`].
///
/// The returned manifest is guaranteed to have passed
/// [`entangle_manifest::validate`], so tier/capability violations
/// (`ENTANGLE-E0042`) and malformed ids (`ENTANGLE-E0201`) surface at build
/// time rather than at load time on someone else's machine.
pub fn render_dist_manifest(source: &str, fingerprint_hex: &str) -> Result<RenderedManifest> {
    let mut doc: toml::Value =
        toml::from_str(source).context("parsing entangle.toml (source manifest)")?;

    let table = doc
        .as_table_mut()
        .context("entangle.toml must be a TOML table")?;

    let plugin = table
        .get_mut("plugin")
        .context("entangle.toml is missing the required [plugin] section")?
        .as_table_mut()
        .context("[plugin] must be a TOML table")?;

    let version = plugin
        .get("version")
        .and_then(|v| v.as_str())
        .context("[plugin] is missing a `version` string (e.g. version = \"0.1.0\")")?
        .to_owned();

    let raw_id = plugin
        .get("id")
        .and_then(|v| v.as_str())
        .context("[plugin] is missing an `id` string (e.g. id = \"PUBLISHER_PLACEHOLDER/my-plugin@0.1.0\")")?
        .to_owned();

    let name = plugin_name_from_id(&raw_id).to_owned();
    if name.is_empty() {
        bail!("could not derive a plugin name from id {raw_id:?}");
    }

    // The fully-qualified form. Both `/` and `@<version>` are mandatory.
    let plugin_id = format!("{fingerprint_hex}/{name}@{version}");
    plugin.insert("id".into(), toml::Value::String(plugin_id.clone()));

    // An optional `[signature]` section pins the expected signer. It is NOT
    // rewritten the way `id` is: it exists to narrow trust, so silently
    // retargeting it at whatever key happens to be signing would defeat its
    // only purpose. Disagreement is the author's mistake, and the kernel would
    // reject the load anyway (ENTANGLE-E0105) — say so now instead.
    if let Some(declared) = table
        .get("signature")
        .and_then(|s| s.get("publisher"))
        .and_then(|p| p.as_str())
    {
        if !declared.eq_ignore_ascii_case(fingerprint_hex) {
            bail!(
                "[signature] publisher = {declared:?} does not match the signing key \
                 ({fingerprint_hex}).\n\
                 Either remove the [signature] section or sign with that key (--key <PEM>)."
            );
        }
    }

    let rendered = toml::to_string_pretty(&doc).context("serializing dist/entangle.toml")?;

    // Validate the exact bytes we are about to sign.
    let parsed: entangle_manifest::Manifest = toml::from_str(&rendered)
        .context("re-parsing the rendered manifest (this is a bug in `entangle plugins build`)")?;
    let validated = entangle_manifest::validate::validate(parsed)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("the rendered entangle.toml is not a valid plugin manifest")?;

    // Belt and braces: the kernel parses the id back out of the manifest, so a
    // regression here is a load-time ENTANGLE-E0201 for every consumer.
    let validated_id = validated.plugin_id.to_string();
    if validated_id != plugin_id {
        bail!(
            "internal error: rendered id {plugin_id:?} did not round-trip (got {validated_id:?})"
        );
    }

    Ok(RenderedManifest {
        toml: rendered,
        plugin_id,
        effective_tier: validated.effective_tier as u8,
        native: validated.runtime == entangle_manifest::Runtime::Native,
    })
}

// ---------------------------------------------------------------------------
// Cargo metadata
// ---------------------------------------------------------------------------

/// The bits of `cargo metadata` output we need to find the built artifact.
#[derive(Debug, Clone)]
struct CrateInfo {
    /// Package name from `[package] name`.
    name: String,
    /// Cargo's `target_directory` for this package's workspace.
    target_dir: PathBuf,
    /// Whether the lib target declares `crate-type = ["cdylib"]`.
    is_cdylib: bool,
    /// Names of the package's `bin` targets.
    bins: Vec<String>,
}

/// The cdylib output stem: cargo replaces `-` with `_` in artifact filenames.
fn artifact_stem(package_name: &str) -> String {
    package_name.replace('-', "_")
}

fn cargo_metadata(manifest_path: &Path) -> Result<CrateInfo> {
    let out = Command::new(cargo_bin())
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .arg("--manifest-path")
        .arg(manifest_path)
        .output()
        .context("running `cargo metadata` — is cargo on PATH?")?;
    if !out.status.success() {
        bail!(
            "cargo metadata failed for {}:\n{}",
            manifest_path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("parsing cargo metadata JSON")?;

    let target_dir = json
        .get("target_directory")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .context("cargo metadata had no target_directory")?;

    let pkg = json
        .get("packages")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .context("cargo metadata listed no packages")?;

    let name = pkg
        .get("name")
        .and_then(|v| v.as_str())
        .context("cargo metadata package had no name")?
        .to_owned();

    let is_cdylib = pkg
        .get("targets")
        .and_then(|v| v.as_array())
        .map(|targets| {
            targets.iter().any(|t| {
                t.get("crate_types")
                    .and_then(|v| v.as_array())
                    .map(|ct| ct.iter().any(|c| c.as_str() == Some("cdylib")))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    let bins = pkg
        .get("targets")
        .and_then(|v| v.as_array())
        .map(|targets| {
            targets
                .iter()
                .filter(|t| {
                    t.get("kind")
                        .and_then(|k| k.as_array())
                        .map(|k| k.iter().any(|c| c.as_str() == Some("bin")))
                        .unwrap_or(false)
                })
                .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    Ok(CrateInfo {
        name,
        target_dir,
        is_cdylib,
        bins,
    })
}

/// Honour cargo's `$CARGO` when we are invoked from a cargo subcommand.
fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned())
}

// ---------------------------------------------------------------------------
// Build driver
// ---------------------------------------------------------------------------

/// Fail early with an actionable message when the wasm target is missing.
pub fn ensure_target_installed(target: &str) -> Result<()> {
    let out = match Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        // No rustup (distro toolchain, nix, ...) — let cargo produce the error.
        _ => return Ok(()),
    };
    let installed = String::from_utf8_lossy(&out.stdout);
    if !installed.lines().any(|l| l.trim() == target) {
        bail!("the {target} target is not installed.\nRun: rustup target add {target}");
    }
    Ok(())
}

/// `entangle plugins build` — [`build`] plus the "next steps" banner.
///
/// The banner is deliberately *not* part of [`build`]: `plugins install` and
/// `quickstart` perform those next steps themselves, and printing a list of
/// commands the user does not need to run is how onboarding output becomes
/// noise.
pub fn run(opts: BuildOptions) -> Result<()> {
    let outcome = build(opts)?;

    if let (Some(a), Some(h)) = (&outcome.archive, &outcome.archive_sha256) {
        println!();
        println!("Package archive: {} (sha256 {h})", a.display());
    }
    println!();
    println!("Next steps:");
    println!(
        "  entangle keyring add {} --name self",
        outcome.public_key_hex
    );
    println!("  entangle plugins load {}", outcome.dist.display());
    println!(
        "  entangle plugins invoke {} --input 'world'",
        outcome.plugin_id
    );
    Ok(())
}

/// Options for [`run_verify`].
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Package archive or build output directory.
    pub package: PathBuf,
    /// Rebuild from source and compare.
    pub rebuild: bool,
    /// Source directory (default `.`).
    pub source: Option<PathBuf>,
    /// Publisher keyring (default `~/.entangle/keyring.toml`).
    pub keyring: Option<PathBuf>,
    /// Target triple of the package.
    pub target: String,
}

/// `entangle plugins verify`. Prints `PASS ...` and returns `Ok`, or prints
/// `FAIL: <first difference>` and returns an error (non-zero exit).
pub fn run_verify(opts: VerifyOptions) -> Result<()> {
    let kr_path = opts.keyring.clone().unwrap_or_else(config::keyring_path);
    let keyring = entangle_signing::Keyring::load(&kr_path)
        .with_context(|| format!("loading {}", kr_path.display()))?;
    if !opts.rebuild {
        let files = repro::load_package(&opts.package)?;
        let bundle: entangle_signing::SignatureBundle = toml::from_str(
            std::str::from_utf8(&files.signature).context("signature bundle is not UTF-8")?,
        )
        .context("parsing the package's signature bundle")?;
        entangle_signing::verify_artifact(&files.wasm, &files.manifest, &bundle, &keyring)
            .map_err(|e| anyhow::anyhow!("FAIL: {e}"))?;
        println!("PASS: signature verifies against the keyring (no rebuild requested)");
        return Ok(());
    }
    let source = opts.source.clone().unwrap_or_else(|| PathBuf::from("."));
    match repro::verify_rebuild(&opts.package, &source, Some(&keyring), &opts.target)? {
        repro::RebuildVerdict::Pass(notes) => {
            for n in &notes {
                println!("[entangle] {n}");
            }
            println!(
                "PASS: rebuild from {} reproduces the package",
                source.display()
            );
            Ok(())
        }
        repro::RebuildVerdict::Fail(first) => {
            println!("FAIL: {first}");
            bail!("ENTANGLE-E0832: rebuild verification failed: {first}")
        }
    }
}

/// Build + sign the plugin project described by `opts`.
///
/// This is the single implementation of the signing pipeline: render the
/// manifest, compile (or accept) the wasm, and write a signed `dist/`. Every
/// other command that needs a signed package calls this.
pub fn build(opts: BuildOptions) -> Result<BuildOutcome> {
    let dir = opts.dir.clone();
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    let cargo_manifest = dir.join("Cargo.toml");
    let source_manifest = dir.join("entangle.toml");
    if !source_manifest.exists() {
        bail!(
            "{} not found.\n\
             A plugin project needs an entangle.toml manifest next to its Cargo.toml.\n\
             Scaffold one with: entangle plugins new <name>",
            source_manifest.display()
        );
    }

    // Step 1 — read the signing key first: a missing key should fail before we
    // spend minutes compiling wasm.
    let key_path = opts.key.clone().unwrap_or_else(config::identity_path);
    if !key_path.exists() {
        bail!(
            "identity key not found at {}\n\
             Run `entangle init --non-interactive` to generate one \
             (or `entangle quickstart` to do everything at once).",
            key_path.display()
        );
    }
    let pem = std::fs::read_to_string(&key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;
    let keypair = IdentityKeyPair::from_pem(&pem)
        .map_err(|e| anyhow::anyhow!("invalid identity key: {e}"))?;
    let fingerprint = keypair.fingerprint_hex();

    // Step 2 — render + validate the manifest before building, for the same
    // reason: a tier/capability mistake (ENTANGLE-E0042) is a one-second failure.
    let source_text = std::fs::read_to_string(&source_manifest)
        .with_context(|| format!("reading {}", source_manifest.display()))?;
    let rendered = render_dist_manifest(&source_text, &fingerprint)?;

    println!("[entangle] publisher fingerprint: {fingerprint}");
    println!("[entangle] plugin id:             {}", rendered.plugin_id);
    println!(
        "[entangle] effective tier:        {}",
        rendered.effective_tier
    );

    // Step 3 — obtain the artifact.
    let mut recipe: Option<repro::BuildRecipe> = None;
    let artifact_src = if rendered.native {
        if opts.wasm.is_some() {
            bail!(
                "--wasm was given, but entangle.toml declares runtime = \"native\".\n\
                 Pass a pre-built executable with --bin <FILE>, or omit it to build with cargo."
            );
        }
        match &opts.bin {
            Some(p) => {
                if !p.exists() {
                    bail!("--bin {} does not exist", p.display());
                }
                p.clone()
            }
            None => {
                if !cargo_manifest.exists() {
                    bail!(
                        "{} not found.\n\
                         Pass --bin <FILE> to package an executable built elsewhere.",
                        cargo_manifest.display()
                    );
                }
                build_native(&cargo_manifest)?
            }
        }
    } else {
        if opts.bin.is_some() {
            bail!(
                "--bin was given, but entangle.toml declares runtime = \"wasm\".\n\
                 Pass a pre-built component with --wasm <FILE> instead."
            );
        }
        match &opts.wasm {
            Some(p) => {
                if !p.exists() {
                    bail!("--wasm {} does not exist", p.display());
                }
                p.clone()
            }
            None => {
                if !cargo_manifest.exists() {
                    bail!(
                        "{} not found.\n\
                         Pass --wasm <FILE> to package an artifact built elsewhere.",
                        cargo_manifest.display()
                    );
                }
                let built = build_wasm_in(&cargo_manifest, &opts.target, None)?;
                recipe = Some(built.recipe);
                built.wasm
            }
        }
    };

    // Step 4 — write dist/.
    let dist = opts.out.clone().unwrap_or_else(|| dir.join("dist"));
    let artifact_name = if rendered.native {
        entangle_runtime::loader::NATIVE_ARTIFACT
    } else {
        entangle_runtime::loader::WASM_ARTIFACT
    };
    write_dist_artifact(&dist, &artifact_src, artifact_name, &rendered, &keypair)?;

    // Step 5 — reproducible archive + provenance (wasm packages).
    let archive = if rendered.native {
        None
    } else {
        let info = repro::write_archive(&dist, &dir, &rendered.plugin_id, recipe)?;
        println!("[entangle] wrote {}", info.path.display());
        println!("[entangle] package sha256: {}", info.sha256);
        Some(info)
    };

    Ok(BuildOutcome {
        archive_sha256: archive.as_ref().map(|a| a.sha256.clone()),
        archive: archive.map(|a| a.path),
        plugin_id: rendered.plugin_id,
        dist,
        fingerprint,
        public_key_hex: hex::encode(keypair.public().as_bytes()),
        effective_tier: rendered.effective_tier,
    })
}

/// A compiled wasm artifact and the recipe that produced it.
pub struct WasmBuild {
    /// Path of the built `.wasm`.
    pub wasm: PathBuf,
    /// Toolchain, flags and epoch used (recorded in provenance).
    pub recipe: repro::BuildRecipe,
}

/// Compile the plugin to wasm reproducibly (`--locked`, path-remapped,
/// `SOURCE_DATE_EPOCH` fixed). `target_dir` overrides cargo's target
/// directory (used by `verify --rebuild` to leave the source tree untouched).
pub fn build_wasm_in(
    cargo_manifest: &Path,
    target: &str,
    target_dir: Option<&Path>,
) -> Result<WasmBuild> {
    // ATC-PKG-3: refuse before touching rustup, cargo, or the network.
    let project = cargo_manifest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    repro::require_lockfile(project)?;
    ensure_target_installed(target)?;

    let info = cargo_metadata(cargo_manifest)?;
    if !info.is_cdylib {
        bail!(
            "{} does not declare `crate-type = [\"cdylib\"]`.\n\
             A wasm component plugin must be a cdylib:\n\n  [lib]\n  crate-type = [\"cdylib\"]\n",
            cargo_manifest.display()
        );
    }

    let prepared = repro::prepare_build(cargo_manifest, target, &cargo_bin())?;

    // A release wasm build takes tens of seconds to minutes (and longer on the
    // first run, when the SDK and wit-bindgen have to be fetched and compiled).
    // Say so *before* handing the terminal to cargo, so a long silence reads as
    // "working" rather than "hung".
    println!("[entangle] compiling {} for {target}...", info.name);
    println!(
        "[entangle] this is a cargo release build: expect 30s-2min, and longer the first\n\
         [entangle] time while dependencies are fetched and compiled."
    );
    println!("[entangle] toolchain: {}", prepared.recipe.toolchain);
    let mut cmd = Command::new(cargo_bin());
    cmd.args([
        "build",
        "--release",
        "--locked",
        "--target",
        target,
        "--manifest-path",
    ])
    .arg(cargo_manifest)
    // Run from the project so its rust-toolchain.toml / .cargo/config apply.
    .current_dir(project_dir_for(cargo_manifest))
    // Encoded form: the remap flags carry real paths, which may contain
    // spaces (cargo splits `RUSTFLAGS` on whitespace).
    .env("CARGO_ENCODED_RUSTFLAGS", prepared.encoded_rustflags())
    .env_remove("RUSTFLAGS")
    .env(
        "SOURCE_DATE_EPOCH",
        prepared.recipe.source_date_epoch.to_string(),
    )
    .env("CARGO_INCREMENTAL", "0")
    .env("LC_ALL", "C")
    .env("TZ", "UTC");
    if let Some(td) = target_dir {
        cmd.env("CARGO_TARGET_DIR", td);
    }
    let status = cmd.status().context("running cargo build")?;
    if !status.success() {
        bail!("cargo build --release --locked --target {target} failed");
    }

    let target_root = match target_dir {
        Some(td) => td.to_path_buf(),
        None => info.target_dir.clone(),
    };
    let wasm = target_root
        .join(target)
        .join("release")
        .join(format!("{}.wasm", artifact_stem(&info.name)));
    if !wasm.exists() {
        bail!(
            "built artifact not found at {}\n\
             Expected a cdylib named {}.wasm — check the [package] name and [lib] crate-type.",
            wasm.display(),
            artifact_stem(&info.name)
        );
    }
    Ok(WasmBuild {
        wasm,
        recipe: prepared.recipe,
    })
}

fn project_dir_for(cargo_manifest: &Path) -> PathBuf {
    cargo_manifest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Compile a native plugin for the host and return the executable's path.
fn build_native(cargo_manifest: &Path) -> Result<PathBuf> {
    repro::require_lockfile(&project_dir_for(cargo_manifest))?;
    let info = cargo_metadata(cargo_manifest)?;
    let bin = match info.bins.as_slice() {
        [] => bail!(
            "{} has no binary target.\n\
             A native plugin is an executable: add src/main.rs (or a [[bin]] section).",
            cargo_manifest.display()
        ),
        [only] => only.clone(),
        many => many
            .iter()
            .find(|b| **b == info.name)
            .cloned()
            .with_context(|| {
                format!(
                    "{} has several binaries ({}) and none is named after the package; \
                     pass the one to package with --bin <FILE>",
                    cargo_manifest.display(),
                    many.join(", ")
                )
            })?,
    };
    println!(
        "[entangle] compiling native plugin {} ({bin}) for this host ({}-{})...",
        info.name,
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    let status = Command::new(cargo_bin())
        .args([
            "build",
            "--release",
            "--locked",
            "--bin",
            &bin,
            "--manifest-path",
        ])
        .arg(cargo_manifest)
        .current_dir(project_dir_for(cargo_manifest))
        .status()
        .context("running cargo build")?;
    if !status.success() {
        bail!("cargo build --release --bin {bin} failed");
    }
    let exe = info
        .target_dir
        .join("release")
        .join(format!("{bin}{}", std::env::consts::EXE_SUFFIX));
    if !exe.exists() {
        bail!("built executable not found at {}", exe.display());
    }
    Ok(exe)
}

/// Write `<artifact_name>` (`plugin.wasm` or `plugin.bin`), `entangle.toml`,
/// and `<artifact_name>.sig` into `dist`.
///
/// Split out of [`run`] so the packaging half is testable without a
/// toolchain: it takes an already-built artifact and an already-rendered
/// manifest, and does nothing but copy, sign, and write. A stale artifact of
/// the other kind is removed (the loader prefers
/// `plugin.wasm` when both exist, so a leftover would shadow a native build).
pub fn write_dist_artifact(
    dist: &Path,
    artifact_src: &Path,
    artifact_name: &str,
    rendered: &RenderedManifest,
    keypair: &IdentityKeyPair,
) -> Result<()> {
    std::fs::create_dir_all(dist).with_context(|| format!("creating {}", dist.display()))?;

    for stale in [
        entangle_runtime::loader::WASM_ARTIFACT,
        entangle_runtime::loader::NATIVE_ARTIFACT,
    ] {
        if stale != artifact_name {
            for p in [dist.join(stale), dist.join(format!("{stale}.sig"))] {
                if p.exists() {
                    std::fs::remove_file(&p)
                        .with_context(|| format!("removing stale {}", p.display()))?;
                }
            }
        }
    }

    let wasm_dst = dist.join(artifact_name);
    std::fs::copy(artifact_src, &wasm_dst).with_context(|| {
        format!(
            "copying {} to {}",
            artifact_src.display(),
            wasm_dst.display()
        )
    })?;
    println!("[entangle] wrote {}", wasm_dst.display());

    // The manifest must be on disk *before* signing: the bundle covers both the
    // wasm bytes and the manifest bytes, so tier/capabilities are bound to the
    // signature and cannot be raised after the fact.
    let manifest_dst = dist.join("entangle.toml");
    std::fs::write(&manifest_dst, &rendered.toml)
        .with_context(|| format!("writing {}", manifest_dst.display()))?;
    println!("[entangle] wrote {}", manifest_dst.display());

    let wasm_bytes = std::fs::read(&wasm_dst).context("reading the artifact for signing")?;
    let bundle = sign_artifact_at(
        &wasm_bytes,
        rendered.toml.as_bytes(),
        keypair,
        repro::signing_epoch(),
    );
    let sig_toml = toml::to_string(&bundle).context("serializing signature bundle")?;
    let sig_dst = dist.join(format!("{artifact_name}.sig"));
    std::fs::write(&sig_dst, &sig_toml)
        .with_context(|| format!("writing {}", sig_dst.display()))?;
    println!("[entangle] wrote {}", sig_dst.display());

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 32 lowercase hex chars, as produced by `IdentityKeyPair::fingerprint_hex`.
    const FP: &str = "aabbccddeeff00112233445566778899";

    fn source(tier: u8, caps: &str, id: &str) -> String {
        format!(
            r#"[plugin]
id = "{id}"
version = "0.2.3"
tier = {tier}
runtime = "wasm"
description = "test plugin"

[capabilities]
{caps}

[build]
wit_world = "entangle:plugin@0.1.0/plugin"
target = "wasm32-wasip2"
"#
        )
    }

    #[test]
    fn name_is_extracted_from_every_id_shape() {
        assert_eq!(
            plugin_name_from_id("PUBLISHER_PLACEHOLDER/foo@0.1.0"),
            "foo"
        );
        assert_eq!(plugin_name_from_id("aabb/foo"), "foo");
        assert_eq!(plugin_name_from_id("foo@1.0.0"), "foo");
        assert_eq!(plugin_name_from_id("foo"), "foo");
    }

    /// The regression this whole module exists to prevent: the rendered id must
    /// always carry `@<version>`, or the kernel rejects the load with
    /// ENTANGLE-E0201.
    #[test]
    fn rendered_id_is_always_fully_qualified() {
        // Even when the author's id has no version suffix at all.
        for raw in [
            "PUBLISHER_PLACEHOLDER/my-plugin@0.1.0",
            "PUBLISHER_PLACEHOLDER/my-plugin",
            "my-plugin",
        ] {
            let r = render_dist_manifest(&source(1, "", raw), FP).expect("should render");
            assert_eq!(r.plugin_id, format!("{FP}/my-plugin@0.2.3"));
            assert!(
                r.plugin_id.contains('@'),
                "id not fully qualified: {}",
                r.plugin_id
            );
            // and the version in the id agrees with plugin.version
            assert!(r.plugin_id.ends_with("@0.2.3"));
        }
    }

    /// The id embedded in the rendered TOML (the bytes that get signed) is the
    /// one we report — not just the string we returned.
    #[test]
    fn rendered_toml_contains_the_qualified_id() {
        let r = render_dist_manifest(&source(1, "", "PUBLISHER_PLACEHOLDER/my-plugin@0.1.0"), FP)
            .unwrap();
        assert!(
            r.toml.contains(&format!("{FP}/my-plugin@0.2.3")),
            "rendered manifest missing qualified id:\n{}",
            r.toml
        );
        assert!(!r.toml.contains(PUBLISHER_PLACEHOLDER));
    }

    /// A stale publisher fingerprint baked into the source id is replaced, so a
    /// copied manifest can never be signed under someone else's publisher.
    #[test]
    fn stale_publisher_is_replaced() {
        let stale = "00112233445566778899aabbccddeeff";
        let r =
            render_dist_manifest(&source(1, "", &format!("{stale}/my-plugin@9.9.9")), FP).unwrap();
        assert_eq!(r.plugin_id, format!("{FP}/my-plugin@0.2.3"));
        assert!(!r.toml.contains(stale));
    }

    /// Author-declared tier and capabilities survive the rewrite untouched —
    /// only the id is machine-controlled.
    #[test]
    fn tier_and_capabilities_are_preserved() {
        let r = render_dist_manifest(
            &source(
                2,
                "\"compute.cpu\" = {}",
                "PUBLISHER_PLACEHOLDER/my-plugin@0.1.0",
            ),
            FP,
        )
        .unwrap();
        assert_eq!(r.effective_tier, 2);
        assert!(r.toml.contains("compute.cpu"));
        assert!(r.toml.contains("tier = 2"));
    }

    /// Under-declaring a tier fails at build time with ENTANGLE-E0042 rather
    /// than at load time on a user's machine.
    #[test]
    fn under_declared_tier_fails_with_e0042() {
        let err = render_dist_manifest(
            &source(
                1,
                "\"net.wan\" = {}",
                "PUBLISHER_PLACEHOLDER/my-plugin@0.1.0",
            ),
            FP,
        )
        .expect_err("tier 1 + net.wan must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("ENTANGLE-E0042"), "got: {msg}");
    }

    /// A `[signature]` section pinning a different signer is a hard error, not
    /// something we silently retarget at the current key.
    #[test]
    fn mismatched_signature_publisher_is_rejected() {
        let other = "00112233445566778899aabbccddeeff";
        let src = format!(
            "{}\n[signature]\npublisher = \"{other}\"\n",
            source(1, "", "PUBLISHER_PLACEHOLDER/my-plugin@0.1.0")
        );
        let err = render_dist_manifest(&src, FP).expect_err("must reject a foreign signer");
        assert!(format!("{err:#}").contains("does not match the signing key"));

        // The same section naming *our* key is fine.
        let ok = format!(
            "{}\n[signature]\npublisher = \"{FP}\"\n",
            source(1, "", "PUBLISHER_PLACEHOLDER/my-plugin@0.1.0")
        );
        render_dist_manifest(&ok, FP).expect("matching signer must be accepted");
    }

    #[test]
    fn missing_plugin_section_is_a_clear_error() {
        let err = render_dist_manifest("[capabilities]\n", FP).expect_err("must fail");
        assert!(format!("{err:#}").contains("[plugin]"));
    }

    #[test]
    fn artifact_stem_underscores_dashes() {
        assert_eq!(artifact_stem("my-cool-plugin"), "my_cool_plugin");
        assert_eq!(artifact_stem("plain"), "plain");
    }

    /// End-to-end packaging on a directory that is not one of the bundled
    /// examples: render → write dist → verify the signature against a keyring.
    #[test]
    fn packaging_an_arbitrary_directory_produces_a_verifiable_bundle() {
        use entangle_signing::{verify_artifact, Keyring, TrustEntry};

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("some-third-party-plugin");
        std::fs::create_dir_all(&dir).unwrap();
        let fake_wasm = dir.join("prebuilt.wasm");
        std::fs::write(&fake_wasm, b"\0asm\x01\x00\x00\x00").unwrap();

        let kp = IdentityKeyPair::from_seed(&[7u8; 32]);
        let rendered = render_dist_manifest(
            &source(1, "", "PUBLISHER_PLACEHOLDER/third-party@0.1.0"),
            &kp.fingerprint_hex(),
        )
        .unwrap();

        let dist = dir.join("dist");
        write_dist_artifact(&dist, &fake_wasm, "plugin.wasm", &rendered, &kp).unwrap();

        assert!(dist.join("plugin.wasm").exists());
        assert!(dist.join("entangle.toml").exists());
        assert!(dist.join("plugin.wasm.sig").exists());

        // The signature must verify over exactly the bytes we wrote.
        let wasm = std::fs::read(dist.join("plugin.wasm")).unwrap();
        let manifest = std::fs::read(dist.join("entangle.toml")).unwrap();
        let sig_text = std::fs::read_to_string(dist.join("plugin.wasm.sig")).unwrap();
        let bundle: entangle_signing::SignatureBundle = toml::from_str(&sig_text).unwrap();

        let mut keyring = Keyring::new();
        keyring.add(TrustEntry {
            fingerprint: kp.fingerprint(),
            public_key: *kp.public().as_bytes(),
            publisher_name: "self".into(),
            added_at: 0,
            note: String::new(),
        });
        verify_artifact(&wasm, &manifest, &bundle, &keyring).expect("signature must verify");

        // And the shipped manifest still loads + validates from disk.
        let vm = entangle_manifest::load_manifest(&dist.join("entangle.toml")).unwrap();
        assert_eq!(vm.plugin_id.to_string(), rendered.plugin_id);
        assert_eq!(vm.plugin_id.name, "third-party");
    }
}
