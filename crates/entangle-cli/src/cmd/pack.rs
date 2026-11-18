//! `entangle pack` — bundle signed plugin packages into one `.entanglepack`
//! file for machines without a route to a registry (spec §3.6, §6.1).
//!
//! ```text
//! entangle pack hello-world ./my-plugin/dist ./other-0.2.0.tar.zst -o plugins.entanglepack
//! ```
//!
//! Each argument names one package:
//!
//! * a package archive (`*.tar.zst`), as `entangle plugins build` writes;
//! * a build or install directory (`entangle.toml`, `plugin.wasm`,
//!   `plugin.wasm.sig`), or a project directory with such a `dist/` in it;
//! * an installed plugin under `~/.entangle/plugins`, by full id
//!   (`<publisher>/<name>@<version>`), `<name>@<version>`, or `<name>`.
//!
//! Every package is verified against **your** keyring before it is packed
//! (an unverifiable one is refused), and the public keys of the signers are
//! written into the pack so the recipient can see whose signatures to
//! expect. The recipient still has to trust those keys themselves: see
//! `entangle plugins install <file>.entanglepack`.
//!
//! The format and its determinism are documented in `entangle_oci::offline`.
//! Plugin manifests carry no plugin-to-plugin dependencies, so the
//! "dependency closure" of the plugins you name is exactly those plugins.

use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use anyhow::{bail, Context, Result};
use clap::Args;
use entangle_oci::{pack_dir, read_pack, unpack, write_pack, PACK_EXTENSION};
use entangle_signing::Keyring;
use entangle_types::plugin_id::PluginId;
use sha2::Digest as _;

use crate::config;

/// `entangle pack` arguments.
#[derive(Args, Debug)]
pub struct PackArgs {
    /// Packages to include: an archive (`*.tar.zst`), a package directory,
    /// or the id / name of a plugin installed under `~/.entangle/plugins`.
    #[arg(required = true, value_name = "PLUGIN-ID|PACKAGE")]
    pub packages: Vec<String>,
    /// File to write (conventionally `<something>.entanglepack`).
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: PathBuf,
    /// Replace the output file if it exists.
    #[arg(long)]
    pub force: bool,
    /// Publisher keyring to verify against. Defaults to `~/.entangle/keyring.toml`.
    #[arg(long)]
    pub keyring: Option<PathBuf>,
}

fn is_package_dir(dir: &Path) -> bool {
    dir.join(entangle_oci::FILE_MANIFEST).is_file() && dir.join(entangle_oci::FILE_WASM).is_file()
}

/// The package directory `dir` denotes: itself, or its `dist/`.
fn package_dir(dir: &Path) -> Result<PathBuf> {
    if is_package_dir(dir) {
        return Ok(dir.to_path_buf());
    }
    let dist = dir.join("dist");
    if is_package_dir(&dist) {
        return Ok(dist);
    }
    if dir.join("plugin.bin").is_file() || dist.join("plugin.bin").is_file() {
        bail!(
            "ENTANGLE-E0941: {} holds a native plugin (plugin.bin). Package archives, and so \
             packs, carry wasm plugins only; copy a native plugin's signed directory as it is",
            dir.display()
        );
    }
    bail!(
        "ENTANGLE-E0941: {} is not a plugin package: expected entangle.toml, plugin.wasm and \
         plugin.wasm.sig in it or in its dist/ (build one with `entangle plugins build`)",
        dir.display()
    )
}

/// Installed package directories under `~/.entangle/plugins` whose manifest
/// id matches `spec` (`<publisher>/<name>@<version>`, `<name>@<version>` or
/// `<name>`).
fn installed_matching(spec: &str) -> Vec<(PluginId, PathBuf)> {
    let root = config::entangle_dir().join("plugins");
    let mut hits = Vec::new();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    dirs.sort();
    for dir in dirs {
        for candidate in [dir.clone(), dir.join("dist")] {
            if !is_package_dir(&candidate) {
                continue;
            }
            let id = std::fs::read_to_string(candidate.join(entangle_oci::FILE_MANIFEST))
                .ok()
                .and_then(|t| toml::from_str::<toml::Value>(&t).ok())
                .and_then(|v| v.get("plugin")?.get("id")?.as_str().map(str::to_owned))
                .and_then(|s| PluginId::from_str(&s).ok());
            let Some(id) = id else { continue };
            let matches = spec == id.to_string()
                || spec == format!("{}@{}", id.name, id.version)
                || spec == id.name;
            if matches {
                hits.push((id, candidate));
            }
            break;
        }
    }
    hits
}

/// Resolve one command-line argument to package archive bytes.
fn resolve(spec: &str) -> Result<(String, Vec<u8>)> {
    let path = Path::new(spec);
    if path.is_dir() {
        let dir = package_dir(path)?;
        let bytes = pack_dir(&dir).with_context(|| format!("packing {}", dir.display()))?;
        return Ok((dir.display().to_string(), bytes));
    }
    if path.is_file() {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        unpack(&bytes).with_context(|| {
            format!(
                "ENTANGLE-E0941: {} is not a plugin package archive",
                path.display()
            )
        })?;
        return Ok((path.display().to_string(), bytes));
    }
    let hits = installed_matching(spec);
    match hits.as_slice() {
        [(_, dir)] => {
            let bytes = pack_dir(dir).with_context(|| format!("packing {}", dir.display()))?;
            Ok((dir.display().to_string(), bytes))
        }
        [] => bail!(
            "ENTANGLE-E0941: {spec:?} is neither a package file, a package directory, nor a \
             plugin installed under {}. Give a path, or an installed plugin's \
             <publisher>/<name>@<version>, <name>@<version> or <name>",
            config::entangle_dir().join("plugins").display()
        ),
        many => bail!(
            "ENTANGLE-E0941: {spec:?} matches several installed plugins ({}); name one by its \
             full id",
            many.iter()
                .map(|(id, _)| id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// `entangle pack`.
pub async fn run(args: PackArgs) -> Result<()> {
    if args.output.exists() && !args.force {
        bail!(
            "ENTANGLE-E0941: {} already exists; pass --force to replace it",
            args.output.display()
        );
    }
    let keyring_path = args.keyring.clone().unwrap_or_else(config::keyring_path);
    let keyring = Keyring::load(&keyring_path)
        .with_context(|| format!("loading {}", keyring_path.display()))?;

    let mut archives = Vec::with_capacity(args.packages.len());
    for spec in &args.packages {
        let (from, bytes) = resolve(spec)?;
        println!("[entangle] adding {from}");
        archives.push(bytes);
    }
    let pack_bytes = write_pack(&archives, &keyring).with_context(|| {
        format!(
            "nothing was written. A pack only holds packages that verify against your own \
             keyring ({})",
            keyring_path.display()
        )
    })?;
    // Re-read what is about to be written: the file must be one `plugins
    // install` accepts.
    let pack = read_pack(&pack_bytes).context("internal error: the pack does not read back")?;

    crate::fsutil::atomic_write(&args.output, &pack_bytes, 0o644)
        .with_context(|| format!("writing {}", args.output.display()))?;
    println!(
        "[entangle] wrote {} ({} bytes, {} package(s))",
        args.output.display(),
        pack_bytes.len(),
        pack.packages.len()
    );
    println!(
        "[entangle] sha256: {}",
        hex::encode(sha2::Sha256::digest(&pack_bytes))
    );
    for p in &pack.packages {
        println!(
            "  {}  (publisher {})",
            p.entry.plugin_id, p.entry.publisher
        );
    }
    if args.output.extension().and_then(|e| e.to_str()) != Some(PACK_EXTENSION) {
        eprintln!(
            "note: `entangle plugins install` recognises a pack by its .{PACK_EXTENSION} \
             extension; rename the file before handing it over"
        );
    }
    println!();
    println!("On the other machine:");
    println!(
        "  entangle plugins install {}",
        args.output
            .file_name()
            .map(|n| format!("./{}", n.to_string_lossy()))
            .unwrap_or_else(|| args.output.display().to_string())
    );
    println!(
        "The recipient must already trust the publisher key(s) below, or check the \
         fingerprints with you and pass --trust-pack-keys:"
    );
    for k in &pack.index.keys {
        println!("  {}", k.fingerprint);
    }
    Ok(())
}
