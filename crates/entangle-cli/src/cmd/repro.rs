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
//!     `Cargo.lock`, which must exist ([`require_lockfile`], ATC-PKG-3);
//!   - the compiler: a `rust-toolchain.toml` pinned to an exact release that
//!     is also the compiler in use ([`require_pinned_toolchain`],
//!     `ENTANGLE-E0943`);
//!   - interface versions: `[build] wit_world` and every WIT import of
//!     another package must name an exact `@x.y.z`
//!     ([`require_pinned_wit_world`], [`require_pinned_wit_imports`],
//!     `ENTANGLE-E0942`).
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
// Pinned toolchain (spec §9.3 "Toolchain")
// ---------------------------------------------------------------------------

/// Is `channel` an exact stable release (`MAJOR.MINOR.PATCH`, digits only)?
/// `stable`, `beta`, `nightly`, a dated nightly and a bare `1.91` (which
/// rustup resolves to whatever the latest 1.91.x is) are not.
pub fn is_exact_toolchain(channel: &str) -> bool {
    let parts: Vec<&str> = channel.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The toolchain file that pins `project`: the nearest `rust-toolchain.toml`
/// (or legacy `rust-toolchain`) from the project directory up to its cargo
/// workspace root, the same span in which `Cargo.lock` is required. A file
/// further up (a stray one in a home directory) does not count: the pin has
/// to travel with the source. When the workspace root is not an ancestor of
/// the project (`package.workspace` pointing sideways), only the project
/// directory itself is searched: rustup, run in the project, would never see
/// a file at that root, and the search must not walk on to `/`.
fn toolchain_file(project: &Path, root: &Path) -> Option<PathBuf> {
    let bounded = project.starts_with(root);
    for dir in project.ancestors() {
        if !bounded && dir != project {
            break;
        }
        for name in ["rust-toolchain.toml", "rust-toolchain"] {
            let p = dir.join(name);
            if p.is_file() {
                return Some(p);
            }
        }
        if dir == root {
            break;
        }
    }
    None
}

/// The `channel` a toolchain file names. `rust-toolchain.toml` is TOML with
/// a `[toolchain]` table; the legacy `rust-toolchain` file may also be a bare
/// channel on one line.
fn toolchain_channel(path: &Path) -> Result<String> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let legacy = path.file_name().and_then(|n| n.to_str()) == Some("rust-toolchain");
    match toml::from_str::<toml::Table>(&text) {
        Ok(doc) => doc
            .get("toolchain")
            .and_then(|t| t.get("channel"))
            .and_then(|c| c.as_str())
            .map(str::to_owned)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "ENTANGLE-E0943: {} has no `[toolchain] channel`.\n\
                     A reproducible package pins its compiler to an exact release, e.g.\n\n  \
                     [toolchain]\n  channel = \"1.91.1\"\n",
                    path.display()
                )
            }),
        Err(_) if legacy && text.trim().lines().count() == 1 => Ok(text.trim().to_owned()),
        Err(e) => bail!("ENTANGLE-E0943: {} is not valid TOML: {e}", path.display()),
    }
}

/// The `release:` field of `rustc -vV` run in `dir` (e.g. `1.91.1`).
fn rustc_release(dir: &Path) -> Result<String> {
    let id = toolchain_id(dir)?;
    Ok(id
        .strip_prefix("rustc ")
        .and_then(|r| r.split_whitespace().next())
        .unwrap_or("unknown")
        .to_owned())
}

/// The `release:` field of `<rustc> -vV` run in `dir`, with rustup's
/// automatic toolchain installation switched off (`RUSTUP_AUTO_INSTALL=0`),
/// so that probing a pinned toolchain never downloads it. A probe that fails
/// (the pinned toolchain is not installed) is an error naming the program.
fn probe_release(rustc: &std::ffi::OsStr, dir: &Path) -> Result<String> {
    let out = Command::new(rustc)
        .arg("-vV")
        .current_dir(dir)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .output()
        .with_context(|| format!("running `{} -vV`", rustc.to_string_lossy()))?;
    if !out.status.success() {
        bail!(
            "`{} -vV` in {} failed: {}",
            rustc.to_string_lossy(),
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("release:"))
        .map(|r| r.trim().to_owned())
        .context("`rustc -vV` printed no release")
}

/// The rustc program the build uses: `$RUSTC`, else `rustc`.
fn rustc_program() -> std::ffi::OsString {
    std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into())
}

/// The active compiler's release when it is an exact stable one (what
/// `entangle plugins new` writes into the scaffolded `rust-toolchain.toml`).
/// `dir` need not exist yet: `rustc` is then asked from its nearest existing
/// ancestor.
pub fn active_exact_release(dir: &Path) -> Option<String> {
    let from = dir
        .ancestors()
        .find(|d| d.is_dir())
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    rustc_release(from).ok().filter(|r| is_exact_toolchain(r))
}

/// How [`require_pinned_toolchain`] treats a missing, floating or
/// mismatched pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPolicy {
    /// `entangle plugins build` of a project: the pin is a hard error
    /// (`ENTANGLE-E0943`).
    Require,
    /// Builds the CLI makes on the user's behalf (`plugins install NAME`,
    /// `quickstart`) and the rebuild of `verify --rebuild`: print the same
    /// message as a warning and go on. `verify --rebuild` still compares the
    /// recorded toolchain with the local one and reports a difference as its
    /// verdict.
    Warn,
}

/// Check that the project pins its Rust toolchain to an exact release
/// **and** that this is the compiler about to be used.
///
/// 1. A `rust-toolchain.toml` must exist in the project or between it and
///    its workspace root ([`toolchain_file`]); a project with both
///    `rust-toolchain` and `rust-toolchain.toml` in one directory is refused
///    (rustup prefers the legacy file, so the `.toml` one would be a dead
///    letter).
/// 2. Its `channel` must be an exact stable release ([`is_exact_toolchain`]).
/// 3. `rustc -vV`, run in the project directory with the current
///    environment (and rustup's auto-install off), must report that
///    release. This catches a `RUSTUP_TOOLCHAIN` override and a toolchain
///    not managed by rustup, both of which make the file a dead letter.
///
/// With [`PinPolicy::Require`] a failed check is an `ENTANGLE-E0943` error;
/// with [`PinPolicy::Warn`] it is printed to stderr as a warning and the
/// result is `Ok(None)`. Returns the pinned release when the check passes.
/// Reads files and runs `rustc -vV`; nothing is fetched, built or written.
pub fn require_pinned_toolchain(project: &Path, policy: PinPolicy) -> Result<Option<String>> {
    match check_pinned_toolchain(project, &rustc_program()) {
        Ok(v) => Ok(Some(v)),
        Err(e) if policy == PinPolicy::Warn => {
            eprintln!(
                "warning: {e:#}\n(continuing: the exact pin is enforced by `entangle plugins \
                 build`; this build may not reproduce a published package)"
            );
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// [`require_pinned_toolchain`]'s check with an explicit rustc program.
fn check_pinned_toolchain(project: &Path, rustc: &std::ffi::OsStr) -> Result<String> {
    let project = std::fs::canonicalize(project)
        .with_context(|| format!("resolving {}", project.display()))?;
    let root = workspace_root(&project);
    let example = || {
        probe_release(rustc, &project)
            .ok()
            .filter(|r| is_exact_toolchain(r))
            .unwrap_or_else(|| "1.91.1".to_owned())
    };
    let Some(file) = toolchain_file(&project, &root) else {
        let v = example();
        bail!(
            "ENTANGLE-E0943: rust-toolchain.toml missing in {}.\n\
             A reproducible package pins the compiler that builds it. Create {} with\n\n  \
             [toolchain]\n  channel = \"{v}\"\n\n\
             (an exact release, not \"stable\"), commit it, and build again. Nothing was \
             built or written.",
            project.display(),
            project.join("rust-toolchain.toml").display(),
        );
    };
    if let Some(dir) = file.parent() {
        if dir.join("rust-toolchain").is_file() && dir.join("rust-toolchain.toml").is_file() {
            bail!(
                "ENTANGLE-E0943: {} holds both `rust-toolchain` and `rust-toolchain.toml`.\n\
                 rustup uses the legacy `rust-toolchain` file and ignores the other, so the \
                 pin is ambiguous. Keep one (`rust-toolchain.toml`) and build again. Nothing \
                 was built or written.",
                dir.display()
            );
        }
    }
    let channel = toolchain_channel(&file)?;
    if !is_exact_toolchain(&channel) {
        let v = example();
        bail!(
            "ENTANGLE-E0943: {} pins channel = {channel:?}, which is not an exact release: it \
             names whatever toolchain that resolves to on the day of the build.\n\
             Pin a full version instead, e.g.\n\n  [toolchain]\n  channel = \"{v}\"\n\n\
             Nothing was built or written.",
            file.display()
        );
    }
    let active = probe_release(rustc, &project).map_err(|e| {
        anyhow::anyhow!(
            "ENTANGLE-E0943: {} pins Rust {channel}, but asking the compiler for its version \
             failed ({e:#}).\n\
             With rustup, install the pinned toolchain first:\n  \
             rustup toolchain install {channel} --target wasm32-wasip2\n\
             Nothing was built or written.",
            file.display()
        )
    })?;
    if active != channel {
        bail!(
            "ENTANGLE-E0943: {} pins Rust {channel}, but the compiler that would build this \
             package is Rust {active}.\n\
             Something overrides the file (the RUSTUP_TOOLCHAIN variable, `cargo +<toolchain>`, \
             or a toolchain not managed by rustup). Build with Rust {channel}, or change the \
             pin. Nothing was built or written.",
            file.display()
        );
    }
    Ok(channel)
}

// ---------------------------------------------------------------------------
// Exact WIT versions (spec §9.3 "WIT versions")
// ---------------------------------------------------------------------------

/// Is `v` a full semantic version (`MAJOR.MINOR.PATCH`, optional
/// `-prerelease` / `+build`)?
fn is_exact_wit_version(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn is_wit_ident(s: &str) -> bool {
    let s = s.strip_prefix('%').unwrap_or(s);
    s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// If `word` is a reference to something in another WIT package
/// (`ns:pkg/item`, with the version after the item as WIT writes it or after
/// the package as `entangle.toml` writes it), return whether it carries an
/// exact version. `None` for anything else (`name: type` has no `/`).
fn wit_reference_is_pinned(word: &str) -> Option<bool> {
    let word = word.trim_end_matches('.');
    let (ns, rest) = word.split_once(':')?;
    if !is_wit_ident(ns) || !rest.contains('/') {
        return None;
    }
    let pkg_end = rest.find(['/', '@'])?;
    if !is_wit_ident(&rest[..pkg_end]) {
        return None;
    }
    Some(match rest.split_once('@') {
        None => false,
        Some((_, after)) => {
            // The version ends at the next `/` (toml form) or at the end.
            let version = after.split('/').next().unwrap_or(after);
            is_exact_wit_version(version.trim_end_matches('.'))
        }
    })
}

/// WIT source with `//` and `/* */` comments blanked out.
fn strip_wit_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                if b[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i = (i + 2).min(b.len());
            out.push(' ');
        } else {
            // Comment markers are ASCII, so slicing on them keeps UTF-8 intact.
            let start = i;
            i += 1;
            while i < b.len() && !text.is_char_boundary(i) {
                i += 1;
            }
            out.push_str(&text[start..i]);
        }
    }
    out
}

/// The floating references in one WIT file: `(line, reference)` for every
/// `import` / `export` / `use` / `include` of another package's item that
/// does not name an exact `@x.y.z` version.
pub fn floating_wit_references(text: &str) -> Vec<(usize, String)> {
    let clean = strip_wit_comments(text);
    let mut out = Vec::new();
    for (n, line) in clean.lines().enumerate() {
        for word in line.split(|c: char| c.is_whitespace() || ";{},()<>=".contains(c)) {
            if wit_reference_is_pinned(word) == Some(false) {
                out.push((n + 1, word.trim_end_matches('.').to_owned()));
            }
        }
    }
    out
}

fn collect_wit_files(dir: &Path, top: bool, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let Ok(ty) = entry.file_type() else { continue };
        if ty.is_dir() {
            let name = entry.file_name();
            let skip = DIGEST_SKIP_DIRS.iter().any(|s| name == *s)
                || (top && DIGEST_SKIP_ROOT_DIRS.iter().any(|s| name == *s))
                || is_package_output_dir(&path)
                || is_cargo_target_dir(&path);
            if !skip {
                collect_wit_files(&path, false, out);
            }
        } else if ty.is_file() && path.extension().and_then(|e| e.to_str()) == Some("wit") {
            out.push(path);
        }
    }
}

/// Fail with `ENTANGLE-E0942` if `[build] wit_world` in the source manifest
/// names a WIT world without an exact version (`entangle:plugin/plugin`,
/// `entangle:plugin@0.1/plugin`).
pub fn require_pinned_wit_world(manifest_text: &str, manifest_path: &Path) -> Result<()> {
    let Some(world) = toml::from_str::<toml::Table>(manifest_text)
        .ok()
        .and_then(|d| {
            d.get("build")?
                .get("wit_world")?
                .as_str()
                .map(str::to_owned)
        })
    else {
        return Ok(());
    };
    if wit_reference_is_pinned(&world) == Some(true) {
        return Ok(());
    }
    bail!(
        "ENTANGLE-E0942: floating WIT import: [build] wit_world = {world:?} in {} does not name \
         an exact version.\n\
         A reproducible package states the interface version it was built against. Write it \
         in full, e.g. wit_world = \"entangle:plugin@0.1.0/plugin\". Nothing was built or \
         written.",
        manifest_path.display()
    )
}

/// Fail with `ENTANGLE-E0942` if any `.wit` file under `dirs` (the project
/// and its path dependencies; build output and VCS directories skipped)
/// imports, exports, uses or includes another package's item without an
/// exact `@x.y.z` version. The error names every such import.
pub fn require_pinned_wit_imports(dirs: &[PathBuf]) -> Result<()> {
    let mut findings = Vec::new();
    for dir in dirs {
        let mut files = Vec::new();
        collect_wit_files(dir, true, &mut files);
        for file in files {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            for (line, reference) in floating_wit_references(&text) {
                findings.push(format!("  {}:{line}: {reference}", file.display()));
            }
        }
    }
    if findings.is_empty() {
        return Ok(());
    }
    bail!(
        "ENTANGLE-E0942: floating WIT import{}:\n{}\n\
         Every WIT import of another package must pin an exact version \
         (`wasi:io/streams@0.2.0`, not `wasi:io/streams` or `@0.2`): otherwise the same \
         source resolves to whatever version is on disk on the day of the build. Nothing was \
         built or written.",
        if findings.len() == 1 { "" } else { "s" },
        findings.join("\n")
    )
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
    /// Host triple the artifact was built on and for. Recorded for native
    /// plugins only (a wasm component does not depend on the build host, and
    /// its provenance must not either).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
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

/// The `host:` triple of the rustc that runs in `dir`.
pub fn host_triple(dir: &Path) -> Result<String> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = Command::new(rustc)
        .arg("-vV")
        .current_dir(dir)
        .output()
        .context("running `rustc -vV` — is rustc on PATH?")?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host:"))
        .map(|h| h.trim().to_owned())
        .context("`rustc -vV` printed no host triple")
}

/// The cargo arguments of the reproducible wasm build for `target`.
pub fn wasm_cargo_args(target: &str) -> Vec<String> {
    ["build", "--release", "--locked", "--target", target]
        .map(str::to_owned)
        .to_vec()
}

/// Assemble the recipe and the concrete rustc flags for building `manifest`
/// with `cargo <cargo_args>` into `target_dir` (cargo's effective target
/// directory for this build) with `SOURCE_DATE_EPOCH = source_date_epoch`.
/// `host` is recorded as given (native builds; `None` for wasm).
pub fn prepare_build(
    manifest: &Path,
    cargo_args: Vec<String>,
    host: Option<String>,
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
            cargo_args,
            rustflags: logical,
            source_date_epoch,
            host,
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
    /// BLAKE3 (hex) of the artifact (`plugin.wasm` or `plugin.bin`).
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
    /// Path of the detached signature, `<archive>.sig`.
    pub signature: PathBuf,
}

/// Write `dist/provenance.json`, the package archive
/// `dist/<name>-<version>.tar.zst` and its detached signature
/// `dist/<name>-<version>.tar.zst.sig` (what a plain-HTTPS install fetches
/// from `<url>.sig`; see `entangle_oci::detached`), returning the archive
/// path and SHA-256.
///
/// `threads` > 1 compresses with that many threads; the archive is then not
/// bit-stable across thread counts (`entangle_oci::pack_with_threads`).
pub fn write_archive(
    dist: &Path,
    project: &Path,
    plugin_id: &str,
    recipe: Option<BuildRecipe>,
    keypair: &entangle_signing::IdentityKeyPair,
    threads: u32,
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

    let bytes =
        entangle_oci::pack_with_threads(&files, threads).map_err(|e| anyhow::anyhow!("{e}"))?;
    let stem = plugin_id
        .rsplit('/')
        .next()
        .unwrap_or(plugin_id)
        .replace('@', "-");
    let path = dist.join(format!("{stem}.tar.zst"));
    std::fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
    let signature = dist.join(format!("{stem}.tar.zst.sig"));
    let sig = entangle_oci::sign_archive(&bytes, plugin_id, keypair)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::write(&signature, sig).with_context(|| format!("writing {}", signature.display()))?;
    Ok(ArchiveInfo {
        path,
        sha256: hex::encode(Sha256::digest(&bytes)),
        signature,
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
            "package was assembled from a pre-built artifact (--wasm / --bin); there is no build recipe to rebuild".into(),
        ));
    };
    // Scratch target dir: the source tree is untouched.
    let scratch = tempfile::tempdir().context("creating scratch target dir")?;
    // The rebuild runs with the recorded epoch, whatever the verifier's
    // environment says (a build script may embed it).
    let epoch = recipe.source_date_epoch;
    // A native package is rebuilt for this host; a wasm one for `target`.
    let (cargo_args, host) = if files.native {
        (
            crate::cmd::package::native_cargo_args(&manifest_path)?,
            Some(host_triple(source)?),
        )
    } else {
        (wasm_cargo_args(target), None)
    };
    if files.native && recipe.host != host {
        return Ok(Fail(format!(
            "host differs: the native package was built on {}, this machine is {}; a native \
             executable can only be reproduced on the kind of host it was built for",
            recipe.host.as_deref().unwrap_or("an unrecorded host"),
            host.as_deref().unwrap_or("unknown")
        )));
    }
    let prepared = prepare_build(
        &manifest_path,
        cargo_args,
        host,
        &cargo_bin(),
        scratch.path(),
        epoch,
    )?;
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
    let rebuilt = if files.native {
        crate::cmd::package::build_native_in(
            &manifest_path,
            Some(scratch.path()),
            Some(epoch),
            PinPolicy::Warn,
        )?
        .exe
    } else {
        crate::cmd::package::build_wasm_in(
            &manifest_path,
            target,
            Some(scratch.path()),
            Some(epoch),
            PinPolicy::Warn,
        )?
        .wasm
    };
    let artifact = files.artifact_name();
    let wasm = std::fs::read(&rebuilt)?;
    if wasm != files.wasm {
        return Ok(Fail(format!(
            "{artifact} differs from the rebuild: {} (package blake3 {}, rebuild blake3 {})",
            first_byte_difference(&wasm, &files.wasm),
            blake3::hash(&files.wasm).to_hex(),
            blake3::hash(&wasm).to_hex()
        )));
    }
    notes.push(format!(
        "{artifact} blake3 {}",
        blake3::hash(&wasm).to_hex()
    ));

    // 4. Recorded hashes, then the signature itself.
    if bundle.artifact_blake3 != *blake3::hash(&wasm).as_bytes()
        || prov.artifact_blake3 != blake3::hash(&wasm).to_hex().to_string()
    {
        return Ok(Fail(
            "recorded artifact hash (signature bundle / provenance) does not match the rebuilt artifact".into(),
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
    fn exact_toolchain_versions_are_told_from_floating_channels() {
        for ok in ["1.91.1", "1.83.0", "2.0.10"] {
            assert!(is_exact_toolchain(ok), "{ok}");
        }
        for bad in [
            "stable",
            "beta",
            "nightly",
            "nightly-2025-01-01",
            "1.91",
            "1",
            "1.91.x",
            "1.91.1-beta.2",
            "",
            "1..1",
            "v1.91.1",
        ] {
            assert!(!is_exact_toolchain(bad), "{bad}");
        }
    }

    #[test]
    fn toolchain_pin_is_found_between_the_project_and_its_workspace_root_only() {
        let d = tempfile::tempdir().unwrap();
        let ws = std::fs::canonicalize(d.path()).unwrap();
        write(
            &ws.join("outer/rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.91.1\"\n",
        );
        write(
            &ws.join("outer/ws/Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\n",
        );
        write(&ws.join("outer/ws/member/Cargo.toml"), PKG);
        let member = ws.join("outer/ws/member");
        let root = workspace_root(&member);
        assert_eq!(root, ws.join("outer/ws"));
        // The file above the workspace root does not pin this project.
        assert_eq!(toolchain_file(&member, &root), None);
        let e = require_pinned_toolchain(&member, PinPolicy::Require)
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("ENTANGLE-E0943"), "{e}");
        assert!(e.contains("rust-toolchain.toml missing"), "{e}");
        assert!(e.contains("[toolchain]") && e.contains("channel = "), "{e}");

        // At the workspace root it does; in the project it wins.
        write(
            &root.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"stable\"\n",
        );
        assert_eq!(
            toolchain_file(&member, &root),
            Some(root.join("rust-toolchain.toml"))
        );
        let e = require_pinned_toolchain(&member, PinPolicy::Require)
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("ENTANGLE-E0943") && e.contains("\"stable\""),
            "{e}"
        );
        assert!(e.contains("not an exact release"), "{e}");
        write(
            &member.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.91\"\n",
        );
        assert_eq!(
            toolchain_file(&member, &root),
            Some(member.join("rust-toolchain.toml"))
        );
        let e = require_pinned_toolchain(&member, PinPolicy::Require)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("\"1.91\"") && e.contains("not an exact release"),
            "{e}"
        );

        // No channel at all, and the legacy one-line file.
        write(
            &member.join("rust-toolchain.toml"),
            "[toolchain]\nprofile = \"minimal\"\n",
        );
        let e = require_pinned_toolchain(&member, PinPolicy::Require)
            .unwrap_err()
            .to_string();
        assert!(e.contains("has no `[toolchain] channel`"), "{e}");
        std::fs::remove_file(member.join("rust-toolchain.toml")).unwrap();
        std::fs::remove_file(root.join("rust-toolchain.toml")).unwrap();
        write(&member.join("rust-toolchain"), "nightly\n");
        let e = require_pinned_toolchain(&member, PinPolicy::Require)
            .unwrap_err()
            .to_string();
        assert!(e.contains("\"nightly\""), "{e}");
    }

    /// A fake `rustc` that reports `release` from `-vV` (and nothing else).
    #[cfg(unix)]
    fn fake_rustc(dir: &Path, release: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let p = dir.join("fake-rustc");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\necho \"rustc {release} (0000000 2025-01-01)\"\n\
                 echo \"release: {release}\"\necho \"commit-hash: 0000000\"\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// An exact pin that is not the compiler in use is refused; the pin
    /// equal to the active compiler passes. A fake rustc makes this
    /// independent of the toolchain running the test.
    #[cfg(unix)]
    #[test]
    fn toolchain_pin_must_be_the_compiler_in_use() {
        let d = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        write(
            &d.path().join("Cargo.toml"),
            &format!("{PKG}\n[workspace]\n"),
        );
        let rustc = fake_rustc(bin.path(), "1.92.0");
        write(
            &d.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.91.1\"\n",
        );
        let e = check_pinned_toolchain(d.path(), rustc.as_os_str())
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("ENTANGLE-E0943"), "{e}");
        assert!(
            e.contains("pins Rust 1.91.1") && e.contains("Rust 1.92.0"),
            "{e}"
        );
        assert!(e.contains("Nothing was built or written"), "{e}");
        assert!(!e.contains("fetched"), "{e}");
        let rustc = fake_rustc(bin.path(), "1.91.1");
        assert_eq!(
            check_pinned_toolchain(d.path(), rustc.as_os_str()).unwrap(),
            "1.91.1"
        );
        // A compiler that cannot be asked (the pinned rustup toolchain is not
        // installed, and auto-install is off for the probe) names the fix.
        let missing = bin.path().join("no-such-rustc");
        let e = check_pinned_toolchain(d.path(), missing.as_os_str())
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("ENTANGLE-E0943"), "{e}");
        assert!(e.contains("rustup toolchain install 1.91.1"), "{e}");
    }

    /// `PinPolicy::Warn` (catalog self-builds, `verify --rebuild`) turns every
    /// refusal into a warning and goes on.
    #[test]
    fn warn_policy_does_not_stop_the_build() {
        let d = tempfile::tempdir().unwrap();
        write(
            &d.path().join("Cargo.toml"),
            &format!("{PKG}\n[workspace]\n"),
        );
        assert_eq!(
            require_pinned_toolchain(d.path(), PinPolicy::Warn).unwrap(),
            None
        );
        assert!(require_pinned_toolchain(d.path(), PinPolicy::Require).is_err());
    }

    /// Both toolchain files in one directory: rustup would use the legacy
    /// one, so the pin is ambiguous and refused.
    #[test]
    fn both_toolchain_files_are_refused() {
        let d = tempfile::tempdir().unwrap();
        write(
            &d.path().join("Cargo.toml"),
            &format!("{PKG}\n[workspace]\n"),
        );
        write(
            &d.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.91.1\"\n",
        );
        write(&d.path().join("rust-toolchain"), "nightly\n");
        let e = require_pinned_toolchain(d.path(), PinPolicy::Require)
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("ENTANGLE-E0943"), "{e}");
        assert!(
            e.contains("both `rust-toolchain` and `rust-toolchain.toml`"),
            "{e}"
        );
    }

    /// `package.workspace` pointing sideways: the search covers the project
    /// directory only and never walks on to `/`.
    #[test]
    fn toolchain_search_stops_when_the_workspace_root_is_not_an_ancestor() {
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        write(
            &base.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.91.1\"\n",
        );
        write(&base.join("ws/Cargo.toml"), "[workspace]\nmembers = []\n");
        write(
            &base.join("a/member/Cargo.toml"),
            "[package]\nname = \"m\"\nversion = \"0.1.0\"\nworkspace = \"../../ws\"\n",
        );
        let member = base.join("a/member");
        let root = workspace_root(&member);
        assert_eq!(root, base.join("ws"));
        assert_eq!(toolchain_file(&member, &root), None);
        write(
            &member.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.91.1\"\n",
        );
        assert_eq!(
            toolchain_file(&member, &root),
            Some(member.join("rust-toolchain.toml"))
        );
    }

    #[test]
    fn wit_references_without_an_exact_version_are_floating() {
        for (word, want) in [
            ("wasi:io/streams@0.2.0", Some(true)),
            ("wasi:io/streams@0.2.0-rc.1", Some(true)),
            ("wasi:io/streams@0.2.0.", Some(true)), // `use a:b/c@1.0.0.{x}`
            ("entangle:plugin@0.1.0/plugin", Some(true)), // entangle.toml form
            ("wasi:io/streams", Some(false)),
            ("wasi:io/streams@0.2", Some(false)),
            ("wasi:io/streams@0", Some(false)),
            ("entangle:plugin@0.1/plugin", Some(false)),
            ("entangle:plugin/plugin", Some(false)),
            // Not references to another package's item.
            ("input:list", None),
            ("logging", None),
            ("entangle:plugin@0.1.0", None),
            ("x:", None),
            ("9a:b/c", None),
        ] {
            assert_eq!(wit_reference_is_pinned(word), want, "{word}");
        }
    }

    #[test]
    fn floating_imports_are_found_by_line_and_comments_are_ignored() {
        let wit = "package acme:tool@1.0.0;\n\
                   // import wasi:io/streams;   (a comment, not an import)\n\
                   /* use wasi:clocks/wall-clock.{now};\n   still a comment */\n\
                   world tool {\n\
                     import logging;\n\
                     import wasi:io/streams@0.2.0;\n\
                     import wasi:clocks/wall-clock;\n\
                     use wasi:random/random@0.2.{get-random-bytes};\n\
                     include entangle:plugin/plugin@0.1.0;\n\
                     export run: func(input:list<u8>) -> result<list<u8>, string>;\n\
                   }\n";
        assert_eq!(
            floating_wit_references(wit),
            vec![
                (8, "wasi:clocks/wall-clock".to_owned()),
                (9, "wasi:random/random@0.2".to_owned()),
            ]
        );
        // The repository's own WIT (what every plugin is built against) is clean.
        for dir in ["wit", "wit-integrity"] {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../entangle-wit")
                .join(dir);
            require_pinned_wit_imports(&[root]).unwrap();
        }
    }

    #[test]
    fn floating_wit_in_a_project_is_refused_naming_the_import() {
        let d = tempfile::tempdir().unwrap();
        write(
            &d.path().join("wit/world.wit"),
            "world w {\n  import wasi:io/streams;\n}\n",
        );
        write(
            &d.path().join("wit/deps/io/streams.wit"),
            "package wasi:io@0.2.0;\ninterface streams {}\n",
        );
        // Build output is not source.
        write(
            &d.path().join("target/x.wit"),
            "world t { import a:b/c; }\n",
        );
        let e = require_pinned_wit_imports(&[d.path().to_path_buf()])
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("ENTANGLE-E0942: floating WIT import:"), "{e}");
        assert!(e.contains("world.wit:2: wasi:io/streams"), "{e}");
        assert!(!e.contains("a:b/c"), "{e}");
        write(
            &d.path().join("wit/world.wit"),
            "world w {\n  import wasi:io/streams@0.2.0;\n}\n",
        );
        require_pinned_wit_imports(&[d.path().to_path_buf()]).unwrap();

        let m = Path::new("entangle.toml");
        require_pinned_wit_world("[build]\nwit_world = \"entangle:plugin@0.1.0/plugin\"\n", m)
            .unwrap();
        require_pinned_wit_world("[plugin]\nid = \"x\"\n", m).unwrap();
        for bad in [
            "entangle:plugin/plugin",
            "entangle:plugin@0.1/plugin",
            "plugin",
        ] {
            let e = require_pinned_wit_world(&format!("[build]\nwit_world = \"{bad}\"\n"), m)
                .unwrap_err()
                .to_string();
            assert!(e.starts_with("ENTANGLE-E0942") && e.contains(bad), "{e}");
        }
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
