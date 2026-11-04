//! Reproducible packaging and rebuild verification (ATC-PKG-1..4).
//!
//! `entangle plugins build` must turn the same plugin source into the same
//! package bytes on any machine. This module holds everything that makes that
//! true and everything that checks it:
//!
//! * **What varies, and how it is pinned.**
//!   - absolute build-machine paths embedded in the wasm (panic locations,
//!     debug info): rustc is run with `--remap-path-prefix` for the project
//!     directory, every path dependency, the cargo target directory (build
//!     script output), `$CARGO_HOME`, `$RUSTUP_HOME` and the toolchain
//!     sysroot ([`remap_flags`]);
//!   - `created_at` in the signature bundle: fixed to `SOURCE_DATE_EPOCH`, or
//!     [`REPRODUCIBLE_EPOCH`] when unset ([`signing_epoch`]). Ed25519 signing
//!     itself is deterministic, so with a fixed `created_at` the whole bundle
//!     is a function of (artifact, manifest, key);
//!   - archive layout (tar order, mtimes, owners, modes) and zstd parameters:
//!     fixed in `entangle_oci::pack`;
//!   - manifest serialisation: `toml::to_string_pretty` over an ordered table;
//!   - dependency resolution: `cargo build --locked` against the project's
//!     `Cargo.lock`, which must exist ([`require_lockfile`], ATC-PKG-3).
//! * **Provenance** ([`Provenance`], ATC-PKG-4): `provenance.json` in the
//!   package records the source-tree digest, the git commit when available,
//!   the toolchain and the build flags.
//! * **Rebuild verification** ([`verify_rebuild`]): rebuild from source and
//!   compare with the package.
//!
//! # Limits
//! The build runs with `CARGO_ENCODED_RUSTFLAGS` (user flags from
//! `CARGO_ENCODED_RUSTFLAGS` or `RUSTFLAGS`, then the remap flags), which
//! replaces (cargo semantics) any `build.rustflags` from `.cargo/config.toml`;
//! the reproducible build owns the flag set. `provenance.json` is not covered
//! by the publisher signature (which binds artifact and manifest);
//! `verify --rebuild` is what validates it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use entangle_oci::{PackageFiles, FILE_PROVENANCE};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Epoch used for signature timestamps when `SOURCE_DATE_EPOCH` is unset
/// (2024-01-01T00:00:00Z).
pub const REPRODUCIBLE_EPOCH: u64 = 1_704_067_200;

/// Directory names never hashed into a source digest, at any depth.
const DIGEST_SKIP_DIRS: &[&str] = &[".git", ".hg", ".svn"];

/// Directory names skipped only directly below the digest root: cargo's
/// default target dir and `plugins build`'s default output dir. Deeper down
/// these names are ordinary source directories (`src/dist/mod.rs`).
const DIGEST_SKIP_ROOT_DIRS: &[&str] = &["target", "dist"];

/// `created_at` for signature bundles: `SOURCE_DATE_EPOCH` if set and valid,
/// else [`REPRODUCIBLE_EPOCH`].
pub fn signing_epoch() -> u64 {
    std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(REPRODUCIBLE_EPOCH)
}

// ---------------------------------------------------------------------------
// Cargo.lock requirement (ATC-PKG-3)
// ---------------------------------------------------------------------------

/// Fail with `ENTANGLE-E0830` ("Cargo.lock missing") unless the lockfile that
/// cargo would use for `project` exists: the one at its workspace root
/// ([`workspace_root`]). Pure filesystem check: no cargo invocation, no
/// network, nothing written.
pub fn require_lockfile(project: &Path) -> Result<()> {
    let project = std::fs::canonicalize(project)
        .with_context(|| format!("resolving {}", project.display()))?;
    let root = workspace_root(&project);
    if root.join("Cargo.lock").is_file() {
        return Ok(());
    }
    bail!(
        "ENTANGLE-E0830: Cargo.lock missing in {}.\n\
         A reproducible package needs pinned dependencies. Create and commit one with\n  \
         (cd {} && cargo generate-lockfile)\n\
         and build again. Nothing was fetched or written.",
        root.display(),
        root.display()
    )
}

fn read_manifest(dir: &Path) -> Option<toml::Table> {
    let text = std::fs::read_to_string(dir.join("Cargo.toml")).ok()?;
    toml::from_str(&text).ok()
}

/// `true` when the `[workspace]` table `ws` of the manifest in `root`
/// excludes the package in `project`: some `exclude` entry is a path prefix
/// of it and no `members` entry is (cargo's `WorkspaceRootConfig::is_excluded`,
/// which compares the entries as literal paths, globs unexpanded).
fn excludes(root: &Path, ws: &toml::Table, project: &Path) -> bool {
    let prefixes = |key: &str| -> Vec<PathBuf> {
        ws.get(key)
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
            .map(|p| root.join(p))
            .collect()
    };
    let excluded = prefixes("exclude").iter().any(|p| project.starts_with(p));
    let member = prefixes("members").iter().any(|p| project.starts_with(p));
    excluded && !member
}

/// The workspace root cargo uses for the package in `project` (an absolute,
/// canonical directory), found from the manifests alone the way cargo finds
/// it: the project itself when its manifest has a `[workspace]` table; the
/// directory named by `package.workspace` when that is set; otherwise the
/// nearest ancestor whose manifest has a `[workspace]` table that does not
/// exclude the project; otherwise the project itself.
pub fn workspace_root(project: &Path) -> PathBuf {
    let Some(own) = read_manifest(project) else {
        return project.to_path_buf();
    };
    if own.contains_key("workspace") {
        return project.to_path_buf();
    }
    if let Some(p) = own
        .get("package")
        .and_then(|p| p.get("workspace"))
        .and_then(|w| w.as_str())
    {
        let root = project.join(p);
        return std::fs::canonicalize(&root).unwrap_or(root);
    }
    for anc in project.ancestors().skip(1) {
        let Some(ws) = read_manifest(anc).and_then(|mut m| match m.remove("workspace") {
            Some(toml::Value::Table(t)) => Some(t),
            _ => None,
        }) else {
            continue;
        };
        if !excludes(anc, &ws, project) {
            return anc.to_path_buf();
        }
    }
    project.to_path_buf()
}

// ---------------------------------------------------------------------------
// Path remapping and build recipe
// ---------------------------------------------------------------------------

/// The reproducible build recipe, as recorded in provenance. Contains no
/// absolute paths: remap sources are written as `$PROJECT`, `$CARGO_HOME`, ...
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRecipe {
    /// `release` and `commit-hash` of the rustc that built the artifact.
    pub toolchain: String,
    /// Cargo arguments (without `--manifest-path`).
    pub cargo_args: Vec<String>,
    /// Logical RUSTFLAGS (remap sources as placeholders).
    pub rustflags: Vec<String>,
    /// `SOURCE_DATE_EPOCH` exported to the build.
    pub source_date_epoch: u64,
}

/// A build recipe plus the concrete rustc flags to run it with.
pub struct PreparedBuild {
    /// What gets recorded.
    pub recipe: BuildRecipe,
    /// The actual flags (real paths), one rustc argument per element.
    pub rustflags: Vec<String>,
}

impl PreparedBuild {
    /// The flags as a `CARGO_ENCODED_RUSTFLAGS` value (`0x1f`-separated).
    ///
    /// The remap flags carry real paths, which may contain spaces; cargo
    /// splits `RUSTFLAGS` on whitespace, so it cannot carry them.
    pub fn encoded_rustflags(&self) -> String {
        self.rustflags.join("\x1f")
    }
}

/// The user's rustc flags from the environment, read the way cargo reads
/// them: `CARGO_ENCODED_RUSTFLAGS` (`0x1f`-separated; set but empty means
/// none) takes precedence over `RUSTFLAGS` (whitespace-separated).
fn env_rustflags() -> Vec<String> {
    if let Ok(enc) = std::env::var("CARGO_ENCODED_RUSTFLAGS") {
        if enc.is_empty() {
            return Vec::new();
        }
        return enc.split('\x1f').map(str::to_owned).collect();
    }
    std::env::var("RUSTFLAGS")
        .ok()
        .map(|s| s.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

fn home_dir(var: &str, default_sub: &str) -> Option<PathBuf> {
    if let Some(v) = std::env::var_os(var) {
        return Some(PathBuf::from(v));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(default_sub))
}

/// Every spelling of `p` (as given and canonical) that exists.
fn spellings(p: &Path) -> Vec<PathBuf> {
    let mut v = vec![p.to_path_buf()];
    if let Ok(c) = std::fs::canonicalize(p) {
        if c != p {
            v.push(c);
        }
    }
    v
}

/// Path-dependency directories of the package at `manifest`, transitively
/// (those reachable through `path = ...` dependencies), as `(name, dir)`.
pub fn path_dependencies(manifest: &Path, cargo: &str) -> Result<Vec<(String, PathBuf)>> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut queue = vec![manifest.to_path_buf()];
    while let Some(m) = queue.pop() {
        let o = Command::new(cargo)
            .args(["metadata", "--format-version", "1", "--no-deps"])
            .arg("--manifest-path")
            .arg(&m)
            .output()
            .context("running `cargo metadata` — is cargo on PATH?")?;
        if !o.status.success() {
            bail!(
                "cargo metadata failed for {}:\n{}",
                m.display(),
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        let json: serde_json::Value = serde_json::from_slice(&o.stdout)?;
        let canon_m = std::fs::canonicalize(&m).unwrap_or_else(|_| m.clone());
        let Some(pkgs) = json.get("packages").and_then(|p| p.as_array()) else {
            continue;
        };
        for pkg in pkgs {
            let pm = pkg
                .get("manifest_path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from);
            if pm.as_deref() != Some(canon_m.as_path()) && pm.as_deref() != Some(m.as_path()) {
                continue;
            }
            for dep in pkg
                .get("dependencies")
                .and_then(|d| d.as_array())
                .into_iter()
                .flatten()
            {
                let (Some(name), Some(path)) = (
                    dep.get("name").and_then(|v| v.as_str()),
                    dep.get("path").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                let dir = PathBuf::from(path);
                if seen.insert(dir.clone()) {
                    out.push((name.to_owned(), dir.clone()));
                    queue.push(dir.join("Cargo.toml"));
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Build the `--remap-path-prefix` flags: `(logical, actual)` pairs.
/// Later entries win in rustc, so the most specific go last.
fn remap_flags(
    project: &Path,
    deps: &[(String, PathBuf)],
    target_dir: Option<&Path>,
    sysroot: Option<&Path>,
) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = Vec::new();
    let mut add = |placeholder: &str, real: &Path, to: &str| {
        for s in spellings(real) {
            v.push((
                format!("--remap-path-prefix={placeholder}={to}"),
                format!("--remap-path-prefix={}={to}", s.display()),
            ));
        }
    };
    if let Some(r) = home_dir("RUSTUP_HOME", ".rustup") {
        add("$RUSTUP_HOME", &r, "/entangle/rustup");
    }
    if let Some(c) = home_dir("CARGO_HOME", ".cargo") {
        add("$CARGO_HOME", &c, "/entangle/cargo");
    }
    add("$PROJECT", project, "/entangle/src");
    for (name, dir) in deps {
        add(
            &format!("$PATHDEP({name})"),
            dir,
            &format!("/entangle/deps/{name}"),
        );
    }
    // The target dir holds build-script output (`OUT_DIR`) that generated
    // code `include!`s, so its path reaches panic locations. After `$PROJECT`:
    // the default target dir is inside the project and must win.
    if let Some(t) = target_dir {
        add("$TARGET", t, "/entangle/target");
    }
    if let Some(s) = sysroot {
        add("$SYSROOT", s, "/entangle/sysroot");
    }
    // Logical form deduplicated (canonical and non-canonical share a placeholder).
    let mut seen = BTreeSet::new();
    let mut flags = Vec::new();
    for (logical, actual) in v {
        // Keep every actual spelling; dedupe only identical (logical, actual).
        if seen.insert((logical.clone(), actual.clone())) {
            flags.push((logical, actual));
        }
    }
    flags
}

/// `release` + `commit-hash` from `rustc -vV` run in `dir` (so a project's
/// `rust-toolchain.toml` applies). Host triple deliberately omitted: the same
/// toolchain on different hosts must record the same string.
pub fn toolchain_id(dir: &Path) -> Result<String> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = Command::new(rustc)
        .arg("-vV")
        .current_dir(dir)
        .output()
        .context("running `rustc -vV` — is rustc on PATH?")?;
    if !out.status.success() {
        bail!("rustc -vV failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k))
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|| "unknown".into())
    };
    Ok(format!(
        "rustc {} ({})",
        field("release:"),
        field("commit-hash:")
    ))
}

fn sysroot(dir: &Path) -> Option<PathBuf> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = Command::new(rustc)
        .args(["--print", "sysroot"])
        .current_dir(dir)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
}

/// Assemble the recipe and the concrete rustc flags for building `manifest`
/// into `target_dir` (cargo's effective target directory for this build)
/// with `SOURCE_DATE_EPOCH = source_date_epoch`.
pub fn prepare_build(
    manifest: &Path,
    target: &str,
    cargo: &str,
    target_dir: &Path,
    source_date_epoch: u64,
) -> Result<PreparedBuild> {
    let project = manifest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let project = std::fs::canonicalize(project)
        .with_context(|| format!("resolving {}", project.display()))?;
    let deps = path_dependencies(manifest, cargo)?;
    let sysroot = sysroot(&project);
    let remaps = remap_flags(&project, &deps, Some(target_dir), sysroot.as_deref());

    // User-provided flags are kept (and recorded) ahead of ours.
    let user = env_rustflags();

    let mut logical = user.clone();
    let mut actual = user;
    for (l, a) in remaps {
        // Canonical and as-given spellings share one logical flag.
        if !logical.contains(&l) {
            logical.push(l);
        }
        actual.push(a);
    }
    Ok(PreparedBuild {
        recipe: BuildRecipe {
            toolchain: toolchain_id(&project)?,
            cargo_args: ["build", "--release", "--locked", "--target", target]
                .map(str::to_owned)
                .to_vec(),
            rustflags: logical,
            source_date_epoch,
        },
        rustflags: actual,
    })
}

// ---------------------------------------------------------------------------
// Source digest
// ---------------------------------------------------------------------------

/// `true` for a directory `entangle plugins build` wrote a package into
/// (`--out`, by default `dist/`): it holds a `plugin.wasm.sig` or
/// `plugin.bin.sig`. Recognised by content, not by name, so the publisher and
/// a verifier skip the same directories without knowing the `--out` used.
fn is_package_output_dir(dir: &Path) -> bool {
    [
        entangle_runtime::loader::WASM_ARTIFACT,
        entangle_runtime::loader::NATIVE_ARTIFACT,
    ]
    .iter()
    .any(|a| dir.join(format!("{a}.sig")).is_file())
}

/// `true` for a cargo target directory (cargo writes `CACHEDIR.TAG` into
/// every target dir it creates), wherever it is and whatever its name.
fn is_cargo_target_dir(dir: &Path) -> bool {
    dir.join("CACHEDIR.TAG").is_file()
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            let name = entry.file_name();
            let skip_name = DIGEST_SKIP_DIRS.iter().any(|s| name == *s)
                || (dir == root && DIGEST_SKIP_ROOT_DIRS.iter().any(|s| name == *s));
            if skip_name || is_package_output_dir(&path) || is_cargo_target_dir(&path) {
                continue;
            }
            collect_files(root, &path, out)?;
        } else if ty.is_file() {
            out.push(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
        }
    }
    Ok(())
}

/// SHA-256 over a source tree: for every regular file (sorted by
/// `/`-separated relative path; top-level `target/` and `dist/`, VCS dirs,
/// cargo target dirs and package output directories skipped)
/// `path \0 len(u64 LE) content`. Independent of mtimes, permissions, owners
/// and the checkout location.
pub fn source_digest(dir: &Path) -> Result<String> {
    let mut files = Vec::new();
    collect_files(dir, dir, &mut files)?;
    let mut keyed: Vec<(String, PathBuf)> = files
        .into_iter()
        .map(|rel| {
            let key = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            (key, rel)
        })
        .collect();
    keyed.sort();
    let mut h = Sha256::new();
    for (key, rel) in keyed {
        let bytes = std::fs::read(dir.join(&rel))
            .with_context(|| format!("reading {}", dir.join(&rel).display()))?;
        h.update(key.as_bytes());
        h.update([0u8]);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
    }
    Ok(format!("sha256:{}", hex::encode(h.finalize())))
}

/// `git rev-parse HEAD` for the repository containing `dir`, if any.
pub fn git_commit(dir: &Path) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (s.len() >= 40 && s.chars().all(|c| c.is_ascii_hexdigit())).then_some(s)
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Digest of one path dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathDepDigest {
    /// Crate name.
    pub name: String,
    /// [`source_digest`] of its directory.
    pub digest: String,
}

/// `provenance.json`: how a package was built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Schema version (1).
    pub schema: u32,
    /// Plugin id of the signed manifest.
    pub plugin_id: String,
    /// [`source_digest`] of the project directory.
    pub source_digest: String,
    /// Digests of path dependencies (outside the project directory).
    pub path_dependencies: Vec<PathDepDigest>,
    /// Git commit of the source, when it was in a repository.
    pub git_commit: Option<String>,
    /// Build recipe; `None` when a pre-built artifact was packaged (`--wasm`).
    pub build: Option<BuildRecipe>,
    /// BLAKE3 (hex) of `plugin.wasm`.
    pub artifact_blake3: String,
    /// BLAKE3 (hex) of `entangle.toml`.
    pub manifest_blake3: String,
}

/// Compute the provenance for a project and its built artifact.
pub fn make_provenance(
    project: &Path,
    manifest_path: &Path,
    plugin_id: &str,
    recipe: Option<BuildRecipe>,
    wasm: &[u8],
    manifest: &[u8],
) -> Result<Provenance> {
    let mut deps = Vec::new();
    // A project packaging a pre-built artifact (`--wasm`) may have no
    // Cargo.toml at all; it then has no path dependencies to digest.
    let dep_dirs = if manifest_path.is_file() {
        path_dependencies(manifest_path, &cargo_bin())?
    } else {
        Vec::new()
    };
    for (name, dir) in dep_dirs {
        deps.push(PathDepDigest {
            name,
            digest: source_digest(&dir)?,
        });
    }
    Ok(Provenance {
        schema: 1,
        plugin_id: plugin_id.to_owned(),
        source_digest: source_digest(project)?,
        path_dependencies: deps,
        git_commit: git_commit(project),
        build: recipe,
        artifact_blake3: blake3::hash(wasm).to_hex().to_string(),
        manifest_blake3: blake3::hash(manifest).to_hex().to_string(),
    })
}

fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned())
}

/// Result of [`write_archive`].
pub struct ArchiveInfo {
    /// Path of the `.tar.zst`.
    pub path: PathBuf,
    /// SHA-256 hex of the archive bytes.
    pub sha256: String,
}

/// Write `dist/provenance.json` and the package archive
/// `dist/<name>-<version>.tar.zst`, returning the archive path and SHA-256.
pub fn write_archive(
    dist: &Path,
    project: &Path,
    plugin_id: &str,
    recipe: Option<BuildRecipe>,
) -> Result<ArchiveInfo> {
    let mut files = PackageFiles::read_dir(dist).map_err(|e| anyhow::anyhow!("{e}"))?;
    let prov = make_provenance(
        project,
        &project.join("Cargo.toml"),
        plugin_id,
        recipe,
        &files.wasm,
        &files.manifest,
    )?;
    let json = serde_json::to_vec_pretty(&prov)?;
    std::fs::write(dist.join(FILE_PROVENANCE), &json)
        .with_context(|| format!("writing {}", dist.join(FILE_PROVENANCE).display()))?;
    files.provenance = Some(json);

    let bytes = entangle_oci::pack(&files).map_err(|e| anyhow::anyhow!("{e}"))?;
    let stem = plugin_id
        .rsplit('/')
        .next()
        .unwrap_or(plugin_id)
        .replace('@', "-");
    let path = dist.join(format!("{stem}.tar.zst"));
    std::fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(ArchiveInfo {
        path,
        sha256: hex::encode(Sha256::digest(&bytes)),
    })
}

// ---------------------------------------------------------------------------
// Rebuild verification (ATC-PKG-4)
// ---------------------------------------------------------------------------

/// Outcome of [`verify_rebuild`].
#[derive(Debug)]
pub enum RebuildVerdict {
    /// The rebuild matches the package.
    Pass(Vec<String>),
    /// First difference found.
    Fail(String),
}

fn first_byte_difference(a: &[u8], b: &[u8]) -> String {
    match a.iter().zip(b).position(|(x, y)| x != y) {
        Some(i) => format!(
            "first differing byte at offset {i} (lengths {} vs {})",
            a.len(),
            b.len()
        ),
        None => format!(
            "lengths differ ({} vs {}) but common prefix is identical",
            a.len(),
            b.len()
        ),
    }
}

/// Load a package from a `.tar.zst` file or a build output directory.
pub fn load_package(p: &Path) -> Result<PackageFiles> {
    if p.is_dir() {
        return PackageFiles::read_dir(p).map_err(|e| anyhow::anyhow!("{e}"));
    }
    let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
    entangle_oci::unpack(&bytes)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("{} is not a plugin package", p.display()))
}

/// Rebuild `package` from `source` and compare. See the module docs.
///
/// Comparison order (the first mismatch is the one reported): source digest,
/// path-dependency digests, toolchain,
/// build flags, rendered manifest, wasm artifact, then the signature
/// bundle's recorded hashes and `created_at`, then the Ed25519 signature
/// against `keyring` (a publisher not in it is a failure). The rebuild runs
/// with the recorded `SOURCE_DATE_EPOCH`.
pub fn verify_rebuild(
    package: &Path,
    source: &Path,
    keyring: Option<&entangle_signing::Keyring>,
    target: &str,
) -> Result<RebuildVerdict> {
    use RebuildVerdict::{Fail, Pass};
    let files = load_package(package)?;
    let Some(prov_bytes) = &files.provenance else {
        return Ok(Fail(format!(
            "ENTANGLE-E0831: package has no {FILE_PROVENANCE}; it was not built by a provenance-recording `entangle plugins build`"
        )));
    };
    let prov: Provenance = serde_json::from_slice(prov_bytes)
        .context("ENTANGLE-E0831: provenance.json is malformed")?;
    let mut notes = Vec::new();

    // 1. Source identity.
    let digest = source_digest(source)?;
    if digest != prov.source_digest {
        return Ok(Fail(format!(
            "source digest differs: package recorded {}, {} hashes to {digest}",
            prov.source_digest,
            source.display()
        )));
    }
    notes.push(format!("source digest {digest}"));
    let manifest_path = source.join("Cargo.toml");
    let deps = path_dependencies(&manifest_path, &cargo_bin())?;
    let mut local_deps = Vec::new();
    for (name, dir) in &deps {
        local_deps.push(PathDepDigest {
            name: name.clone(),
            digest: source_digest(dir)?,
        });
    }
    if local_deps != prov.path_dependencies {
        let detail = prov
            .path_dependencies
            .iter()
            .find(|r| !local_deps.contains(r))
            .map(|r| {
                format!(
                    "path dependency {} differs from the recorded digest",
                    r.name
                )
            })
            .unwrap_or_else(|| "set of path dependencies differs".into());
        return Ok(Fail(detail));
    }
    // The commit is informational: identical source at a different commit
    // (a later release branch, a squash) still reproduces the package, and the
    // source digest above already pins the content.
    match (&prov.git_commit, git_commit(source)) {
        (Some(rec), Some(now)) if *rec == now => notes.push(format!("git commit {now}")),
        (Some(rec), Some(now)) => notes.push(format!(
            "note: package recorded git commit {rec}; {} is at {now} (source digest identical)",
            source.display()
        )),
        (Some(rec), None) => notes.push(format!("package recorded git commit {rec}")),
        _ => {}
    }

    // 2. Recipe: toolchain and flags.
    let Some(recipe) = &prov.build else {
        return Ok(Fail(
            "package was assembled from a pre-built artifact (--wasm); there is no build recipe to rebuild".into(),
        ));
    };
    // Scratch target dir: the source tree is untouched.
    let scratch = tempfile::tempdir().context("creating scratch target dir")?;
    // The rebuild runs with the recorded epoch, whatever the verifier's
    // environment says (a build script may embed it).
    let epoch = recipe.source_date_epoch;
    let prepared = prepare_build(&manifest_path, target, &cargo_bin(), scratch.path(), epoch)?;
    if prepared.recipe.toolchain != recipe.toolchain {
        return Ok(Fail(format!(
            "toolchain differs: package built with {}, local is {}",
            recipe.toolchain, prepared.recipe.toolchain
        )));
    }
    if prepared.recipe.cargo_args != recipe.cargo_args {
        return Ok(Fail(format!(
            "cargo arguments differ: recorded {:?}, local {:?}",
            recipe.cargo_args, prepared.recipe.cargo_args
        )));
    }
    if prepared.recipe.rustflags != recipe.rustflags {
        return Ok(Fail(format!(
            "build flags differ: recorded {:?}, local {:?}",
            recipe.rustflags, prepared.recipe.rustflags
        )));
    }

    // 3. Rebuild (into a scratch target dir; the source tree is untouched).
    let bundle: entangle_signing::SignatureBundle = toml::from_str(
        std::str::from_utf8(&files.signature).context("signature bundle is not UTF-8")?,
    )
    .context("parsing the package's signature bundle")?;
    let fingerprint = hex::encode(bundle.publisher_fingerprint);
    let source_manifest = std::fs::read_to_string(source.join("entangle.toml"))
        .with_context(|| format!("reading {}", source.join("entangle.toml").display()))?;
    let rendered = crate::cmd::package::render_dist_manifest(&source_manifest, &fingerprint)?;
    if rendered.toml.as_bytes() != files.manifest.as_slice() {
        return Ok(Fail(format!(
            "entangle.toml differs from the manifest rendered from source: {}",
            first_byte_difference(rendered.toml.as_bytes(), &files.manifest)
        )));
    }
    if epoch != signing_epoch() {
        notes.push(format!(
            "rebuilt with the recorded SOURCE_DATE_EPOCH {epoch} (this environment would use {})",
            signing_epoch()
        ));
    }
    let built = crate::cmd::package::build_wasm_in(
        &manifest_path,
        target,
        Some(scratch.path()),
        Some(epoch),
    )?;
    let wasm = std::fs::read(&built.wasm)?;
    if wasm != files.wasm {
        return Ok(Fail(format!(
            "plugin.wasm differs from the rebuild: {} (package blake3 {}, rebuild blake3 {})",
            first_byte_difference(&wasm, &files.wasm),
            blake3::hash(&files.wasm).to_hex(),
            blake3::hash(&wasm).to_hex()
        )));
    }
    notes.push(format!(
        "plugin.wasm blake3 {}",
        blake3::hash(&wasm).to_hex()
    ));

    // 4. Recorded hashes, then the signature itself.
    if bundle.artifact_blake3 != *blake3::hash(&wasm).as_bytes()
        || prov.artifact_blake3 != blake3::hash(&wasm).to_hex().to_string()
    {
        return Ok(Fail(
            "recorded artifact hash (signature bundle / provenance) does not match the rebuilt wasm".into(),
        ));
    }
    if bundle.manifest_blake3 != *blake3::hash(rendered.toml.as_bytes()).as_bytes() {
        return Ok(Fail(
            "recorded manifest hash in the signature bundle does not match the rebuilt manifest"
                .into(),
        ));
    }
    // `plugins build` signs with created_at = SOURCE_DATE_EPOCH; any other
    // value is a bundle the reproducible build did not produce.
    if bundle.created_at != epoch {
        return Ok(Fail(format!(
            "signature bundle created_at {} differs from the recorded SOURCE_DATE_EPOCH {epoch}",
            bundle.created_at
        )));
    }
    // The signature is part of the package: an unchecked or bad one is a
    // FAIL, so `--rebuild` is never weaker than the plain signature check.
    let Some(kr) = keyring.filter(|kr| kr.lookup(&bundle.publisher_fingerprint).is_some()) else {
        return Ok(Fail(format!(
            "publisher {fingerprint} is not in the keyring, so the package signature cannot be \
             checked; trust the publisher's key with `entangle keyring add <public-key-hex>` \
             (or pass --keyring <file>) and verify again"
        )));
    };
    if let Err(e) = entangle_signing::verify_artifact(&files.wasm, &files.manifest, &bundle, kr) {
        return Ok(Fail(format!("signature does not verify: {e}")));
    }
    notes.push("publisher signature verified".into());
    Ok(Pass(notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_lockfile_message_is_stable() {
        let d = tempfile::tempdir().unwrap();
        let e = require_lockfile(d.path()).unwrap_err().to_string();
        assert!(e.contains("Cargo.lock missing"), "{e}");
        assert!(e.contains("ENTANGLE-E0830"), "{e}");
        std::fs::write(d.path().join("Cargo.lock"), "").unwrap();
        assert!(require_lockfile(d.path()).is_ok());
    }

    fn write(p: &Path, text: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    const PKG: &str = "[package]\nname = \"p\"\nversion = \"0.1.0\"\n";

    #[test]
    fn lockfile_is_required_at_the_workspace_root_cargo_would_use() {
        let d = tempfile::tempdir().unwrap();
        let ws = d.path();
        write(
            &ws.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\nexclude = [\"excluded\", \"own\"]\n",
        );
        write(&ws.join("Cargo.lock"), "");

        // A member uses the outer lockfile.
        write(&ws.join("member/Cargo.toml"), PKG);
        require_lockfile(&ws.join("member")).unwrap();

        // Its own [workspace]: it is the root, the outer lockfile is not its.
        write(&ws.join("own/Cargo.toml"), &format!("{PKG}\n[workspace]\n"));
        let e = require_lockfile(&ws.join("own")).unwrap_err().to_string();
        assert!(e.contains("ENTANGLE-E0830"), "{e}");
        write(&ws.join("own/Cargo.lock"), "");
        require_lockfile(&ws.join("own")).unwrap();

        // Excluded and no [workspace] of its own: cargo keeps looking upward,
        // finds nothing, and the package is its own root.
        write(&ws.join("excluded/Cargo.toml"), PKG);
        let e = require_lockfile(&ws.join("excluded"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("ENTANGLE-E0830"), "{e}");

        // `package.workspace` names the root explicitly; the ancestor walk
        // (which would find `ws`) does not apply.
        write(&ws.join("other/Cargo.toml"), "[workspace]\n");
        write(
            &ws.join("elsewhere/pointed/Cargo.toml"),
            "[package]\nname = \"q\"\nversion = \"0.1.0\"\nworkspace = \"../../other\"\n",
        );
        let e = require_lockfile(&ws.join("elsewhere/pointed"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("ENTANGLE-E0830"), "{e}");
        write(&ws.join("other/Cargo.lock"), "");
        require_lockfile(&ws.join("elsewhere/pointed")).unwrap();
    }

    #[test]
    fn source_digest_ignores_build_outputs_and_mtimes_but_not_content() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("src")).unwrap();
        std::fs::write(d.path().join("src/lib.rs"), "a").unwrap();
        let base = source_digest(d.path()).unwrap();
        std::fs::create_dir_all(d.path().join("target/x")).unwrap();
        std::fs::write(d.path().join("target/x/y"), "junk").unwrap();
        std::fs::create_dir_all(d.path().join("dist")).unwrap();
        std::fs::write(d.path().join("dist/z"), "junk").unwrap();
        assert_eq!(source_digest(d.path()).unwrap(), base);
        std::fs::write(d.path().join("src/lib.rs"), "b").unwrap();
        assert_ne!(source_digest(d.path()).unwrap(), base);
    }

    #[test]
    fn source_digest_covers_nested_dirs_named_target_or_dist() {
        let d = tempfile::tempdir().unwrap();
        write(&d.path().join("src/lib.rs"), "mod dist; mod target;");
        write(&d.path().join("src/dist/mod.rs"), "a");
        write(&d.path().join("src/target/mod.rs"), "a");
        let base = source_digest(d.path()).unwrap();
        write(&d.path().join("src/dist/mod.rs"), "b");
        let edited = source_digest(d.path()).unwrap();
        assert_ne!(edited, base, "src/dist/mod.rs is source");
        write(&d.path().join("src/target/mod.rs"), "b");
        assert_ne!(
            source_digest(d.path()).unwrap(),
            edited,
            "src/target/mod.rs is source"
        );

        // A nested cargo target dir (CACHEDIR.TAG) is still build output.
        let before = source_digest(d.path()).unwrap();
        write(
            &d.path().join("sub/target/CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55",
        );
        write(&d.path().join("sub/target/release/junk"), "x");
        assert_eq!(source_digest(d.path()).unwrap(), before);
    }

    #[test]
    fn signing_epoch_honours_source_date_epoch() {
        // Read-only check of the default; env mutation is avoided (tests run
        // in parallel threads).
        if std::env::var_os("SOURCE_DATE_EPOCH").is_none() {
            assert_eq!(signing_epoch(), REPRODUCIBLE_EPOCH);
        }
    }

    #[test]
    fn remap_flags_cover_project_and_homes_without_leaking_paths_in_the_logical_form() {
        let d = tempfile::tempdir().unwrap();
        let flags = remap_flags(d.path(), &[], None, None);
        assert!(flags
            .iter()
            .any(|(_, a)| a.contains(&d.path().display().to_string())));
        assert!(flags
            .iter()
            .all(|(l, _)| !l.contains(&d.path().display().to_string())));
        assert!(flags.iter().any(|(l, _)| l.contains("$PROJECT")));
    }
}
