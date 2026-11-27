use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) const TARGET: &str = "wasm32-wasip2";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Provenance {
    pub version: u32,
    pub source_url: String,
    pub source_commit: String,
    pub project: String,
    pub source_date_epoch: u64,
    pub rust_toolchain: String,
    pub lock_sha256: String,
    pub zstd_version: String,
    pub zstd_threads: u32,
}

impl Provenance {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported rebuild metadata version");
        https_url(&self.source_url)?;
        ensure!(
            hex_string(&self.source_commit, &[40, 64]),
            "invalid Git source commit"
        );
        relative_project(&self.project)?;
        exact_toolchain(&self.rust_toolchain)?;
        ensure!(
            hex_string(&self.lock_sha256, &[64]),
            "invalid Cargo.lock SHA-256"
        );
        ensure!(
            (1..=32).contains(&self.zstd_threads),
            "invalid zstd thread count"
        );
        ensure!(
            self.zstd_version == zstd::zstd_safe::version_string(),
            "package needs Zstandard {}, current version is {}",
            self.zstd_version,
            zstd::zstd_safe::version_string()
        );
        Ok(())
    }
}

fn hex_string(text: &str, lengths: &[usize]) -> bool {
    lengths.contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

fn https_url(text: &str) -> Result<()> {
    let url = url::Url::parse(text).context("source URL must be an absolute HTTPS Git URL")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "source URL must be HTTPS without credentials, a query, or a fragment"
    );
    Ok(())
}

fn relative_project(path: &str) -> Result<&Path> {
    let relative = Path::new(path);
    ensure!(
        path == "."
            || (!path.is_empty()
                && !path.contains('\\')
                && relative
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)))),
        "invalid project path in rebuild metadata"
    );
    Ok(relative)
}

fn display_relative(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .context("build input is outside the Git checkout")?;
    if relative.as_os_str().is_empty() {
        return Ok(".".into());
    }
    relative
        .components()
        .map(|c| c.as_os_str().to_str().context("build path is not UTF-8"))
        .collect::<Result<Vec<_>>>()
        .map(|parts| parts.join("/"))
}

fn git() -> Command {
    let mut command = Command::new("git");
    command
        .args([
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.ext.allow=never",
        ])
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES");
    command
}

fn checked(output: Output, command: &str) -> Result<Vec<u8>> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{command} failed: {}", stderr.trim());
    }
    Ok(output.stdout)
}

fn git_text(dir: &Path, args: &[&str]) -> Result<String> {
    let output = git()
        .current_dir(dir)
        .args(args)
        .output()
        .context("running git")?;
    let text = String::from_utf8(checked(output, "git")?).context("non-UTF-8 git output")?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")))
}

fn cargo_lock(project: &Path) -> Result<PathBuf> {
    let mut command = cargo();
    let output = command
        .current_dir(project)
        .args(["locate-project", "--workspace", "--message-format", "plain"])
        .output()
        .context("running cargo locate-project")?;
    let manifest = String::from_utf8(checked(output, "cargo locate-project")?)?;
    let lock = Path::new(manifest.trim_end_matches(['\r', '\n'])).with_file_name("Cargo.lock");
    ensure!(lock.is_file(), "Cargo.lock missing in {}", lock.display());
    fs::canonicalize(&lock).with_context(|| format!("resolving {}", lock.display()))
}

fn check_path_dependencies(root: &Path, project: &Path) -> Result<()> {
    let output = cargo()
        .current_dir(project)
        .args([
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--filter-platform",
            TARGET,
        ])
        .output()
        .context("resolving the committed dependency closure")?;
    let metadata: Value = serde_json::from_slice(&checked(output, "cargo metadata --locked")?)?;
    for package in metadata["packages"]
        .as_array()
        .context("Cargo metadata omitted packages")?
    {
        if package["source"].is_null() {
            let manifest = package["manifest_path"]
                .as_str()
                .context("Cargo metadata omitted a manifest path")?;
            let manifest = fs::canonicalize(manifest)?;
            ensure!(
                manifest.starts_with(root),
                "Cargo dependency {} is outside the signed source checkout",
                manifest.display()
            );
        }
    }
    Ok(())
}

fn exact_toolchain(channel: &str) -> Result<()> {
    let version = semver::Version::parse(channel)
        .context("rust-toolchain.toml must pin a stable Rust x.y.z version")?;
    ensure!(
        version.pre.is_empty() && version.build.is_empty(),
        "rust-toolchain.toml must pin a stable Rust x.y.z version"
    );
    Ok(())
}

fn toolchain(root: &Path, project: &Path) -> Result<String> {
    let file = project
        .ancestors()
        .take_while(|dir| dir.starts_with(root))
        .map(|dir| dir.join("rust-toolchain.toml"))
        .find(|file| file.is_file())
        .context("rust-toolchain.toml missing from the source checkout")?;
    let resolved = fs::canonicalize(&file)?;
    ensure!(
        resolved.starts_with(root),
        "toolchain pin points outside the checkout"
    );
    let doc: toml::Value = toml::from_str(&fs::read_to_string(file)?)?;
    let channel = doc
        .get("toolchain")
        .and_then(|t| t.get("channel"))
        .and_then(toml::Value::as_str)
        .context("rust-toolchain.toml missing [toolchain] channel")?;
    exact_toolchain(channel)?;
    Ok(channel.to_owned())
}

fn pinned_wit(path: &Path) -> Result<()> {
    let group = if path.is_dir() {
        wit_parser::UnresolvedPackageGroup::parse_dir(path)
    } else {
        wit_parser::UnresolvedPackageGroup::parse_file(path)
    }
    .with_context(|| format!("parsing WIT at {}", path.display()))?;
    for package in std::iter::once(&group.main).chain(&group.nested) {
        for foreign in package.foreign_deps.keys() {
            ensure!(
                foreign.version.is_some(),
                "WIT import {foreign} requires a pinned @x.y.z version"
            );
        }
    }
    Ok(())
}

fn check_wit(project: &Path, manifest: &entangle_manifest::Manifest) -> Result<()> {
    if let Some(build) = &manifest.build {
        ensure!(
            build.target.as_deref().is_none_or(|t| t == TARGET),
            "build.target must be {TARGET}"
        );
        if let Some(world) = &build.wit_world {
            let (_, rest) = world
                .split_once('@')
                .context("build.wit_world requires a pinned @x.y.z version")?;
            semver::Version::parse(rest.split('/').next().unwrap_or_default())
                .context("build.wit_world requires a pinned @x.y.z version")?;
        }
    }
    for candidate in [project.join("wit"), project.join("world.wit")] {
        if candidate.exists() {
            pinned_wit(&candidate)?;
        }
    }
    Ok(())
}

pub(crate) struct Snapshot {
    temp: tempfile::TempDir,
    root: PathBuf,
    project: PathBuf,
    pub manifest_text: String,
    pub rust_toolchain: String,
    pub lock_sha256: String,
}

impl Snapshot {
    pub fn clone(origin: &OsStr, commit: &str, relative: &str) -> Result<Self> {
        ensure!(hex_string(commit, &[40, 64]), "invalid Git source commit");
        let project_rel = relative_project(relative)?;
        let temp = tempfile::Builder::new()
            .prefix("entangle source ")
            .tempdir()?;
        let checkout = fs::canonicalize(temp.path())?.join("checkout");
        let output = git()
            .args(["clone", "--no-checkout", "--no-hardlinks", "--"])
            .arg(origin)
            .arg(&checkout)
            .output()
            .context("cloning plugin source")?;
        checked(output, "git clone")?;
        git_text(&checkout, &["checkout", "--detach", commit, "--"])?;
        ensure!(
            git_text(&checkout, &["rev-parse", "HEAD"])? == commit,
            "checked-out source commit differs from the recorded commit"
        );
        let root = fs::canonicalize(&checkout)?;
        let project = fs::canonicalize(root.join(project_rel))
            .context("resolving the plugin project in the source checkout")?;
        ensure!(
            project.starts_with(&root),
            "plugin project points outside the source checkout"
        );
        ensure!(
            fs::canonicalize(project.join("Cargo.toml"))?.starts_with(&root),
            "Cargo.toml points outside the source checkout"
        );
        let lock = cargo_lock(&project)?;
        let lock_rel = display_relative(&root, &lock)?;
        git_text(&root, &["ls-files", "--error-unmatch", "--", &lock_rel])
            .context("Cargo.lock must be committed")?;
        let lock_sha256 = hex::encode(Sha256::digest(fs::read(&lock)?));
        let rust_toolchain = toolchain(&root, &project)?;
        let manifest_path = fs::canonicalize(project.join("entangle.toml"))
            .context("source checkout has no entangle.toml next to Cargo.toml")?;
        ensure!(
            manifest_path.starts_with(&root),
            "entangle.toml points outside the source checkout"
        );
        let manifest_text = fs::read_to_string(manifest_path)?;
        let manifest: entangle_manifest::Manifest = toml::from_str(&manifest_text)?;
        ensure!(
            manifest.plugin.runtime == entangle_manifest::Runtime::Wasm,
            "only WASI component plugins can be packaged"
        );
        check_wit(&project, &manifest)?;
        Ok(Self {
            temp,
            root,
            project,
            manifest_text,
            rust_toolchain,
            lock_sha256,
        })
    }

    pub fn build(&self, epoch: u64) -> Result<Vec<u8>> {
        let rustc = Command::new("rustc")
            .current_dir(&self.project)
            .arg("--version")
            .output()
            .context("checking the pinned Rust toolchain")?;
        let version = String::from_utf8(checked(rustc, "rustc --version")?)?;
        ensure!(
            version.split_whitespace().nth(1) == Some(self.rust_toolchain.as_str()),
            "source requires Rust {}, but {version} is active",
            self.rust_toolchain
        );
        check_path_dependencies(&self.root, &self.project)?;
        let target = fs::canonicalize(self.temp.path())?.join("target");
        let sysroot = Command::new("rustc")
            .current_dir(&self.project)
            .args(["--print", "sysroot"])
            .output()
            .context("checking the compiler sysroot")?;
        let sysroot = String::from_utf8(checked(sysroot, "rustc --print sysroot")?)?;
        let mut flags = vec![
            format!("--remap-path-prefix={}=/source", self.root.display()),
            format!("--remap-path-prefix={}=/target", target.display()),
            format!(
                "--remap-path-prefix={}=/toolchain",
                sysroot.trim_end_matches(['\r', '\n'])
            ),
            "-C".into(),
            "debuginfo=0".into(),
        ];
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
        if let Some(home) = cargo_home {
            flags.push(format!("--remap-path-prefix={}=/cargo", home.display()));
        }
        let mut cmd = cargo();
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("CARGO_PROFILE_") {
                cmd.env_remove(name);
            }
        }
        cmd.current_dir(&self.project)
            .env_remove("RUSTFLAGS")
            .env_remove("RUSTC")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env("RUSTC_WRAPPER", std::env::current_exe()?)
            .env(crate::rustc::SOURCE_ROOT_ENV, &self.root)
            .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\x1f"))
            .env("CARGO_INCREMENTAL", "0")
            .env("SOURCE_DATE_EPOCH", epoch.to_string())
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .args([
                "build",
                "--locked",
                "--release",
                "--target",
                TARGET,
                "--message-format=json-render-diagnostics",
                "--target-dir",
            ])
            .arg(&target)
            .stderr(std::process::Stdio::inherit());
        let output = cmd.output().context("building the locked WASI source")?;
        let manifest = self.project.join("Cargo.toml");
        let mut artifact = None;
        for line in output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let event: Value =
                serde_json::from_slice(line).context("reading Cargo build output")?;
            if event["reason"] == "compiler-message" {
                if let Some(message) = event["message"]["rendered"].as_str() {
                    eprint!("{message}");
                }
            } else if event["reason"] == "compiler-artifact"
                && event["manifest_path"]
                    .as_str()
                    .is_some_and(|path| Path::new(path) == manifest)
                && event["target"]["crate_types"]
                    .as_array()
                    .is_some_and(|types| types.iter().any(|t| t == "cdylib"))
            {
                let files = event["filenames"]
                    .as_array()
                    .context("Cargo omitted artifact filenames")?;
                for path in files
                    .iter()
                    .filter_map(Value::as_str)
                    .map(Path::new)
                    .filter(|file| file.extension().is_some_and(|ext| ext == "wasm"))
                {
                    ensure!(
                        artifact.replace(path.to_path_buf()).is_none(),
                        "Cargo produced multiple WASI cdylib artifacts"
                    );
                }
            }
        }
        ensure!(
            output.status.success(),
            "cargo build --locked failed for the source commit"
        );
        let component = fs::read(artifact.context("Cargo produced no WASI cdylib artifact")?)?;
        ensure!(
            component.starts_with(b"\0asm\x0d\0\x01\0"),
            "build output is not a WebAssembly component"
        );
        Ok(component)
    }
}

pub(crate) fn package_source(
    dir: &Path,
    url: Option<String>,
    epoch: Option<u64>,
    threads: u32,
) -> Result<(Snapshot, Provenance)> {
    let project = fs::canonicalize(dir).with_context(|| format!("opening {}", dir.display()))?;
    let lock = cargo_lock(&project)?;
    let root = PathBuf::from(git_text(&project, &["rev-parse", "--show-toplevel"])?);
    let root = fs::canonicalize(root)?;
    let relative = display_relative(&root, &project)?;
    let lock_rel = display_relative(&root, &lock)?;
    git_text(&root, &["ls-files", "--error-unmatch", "--", &lock_rel])
        .context("Cargo.lock must be committed")?;
    let dirty = git_text(&root, &["status", "--porcelain", "--untracked-files=no"])?;
    ensure!(
        dirty.is_empty(),
        "tracked source has uncommitted changes; commit them before packaging"
    );
    let head = git_text(&root, &["rev-parse", "HEAD"])?;
    let url = match url {
        Some(url) => url,
        None => git_text(&root, &["remote", "get-url", "origin"])
            .context("no Git origin URL; pass --source-url with the HTTPS repository")?,
    };
    https_url(&url)?;
    let epoch = match epoch {
        Some(epoch) => epoch,
        None => git_text(&root, &["show", "-s", "--format=%ct", &head])?.parse()?,
    };
    let snapshot = Snapshot::clone(root.as_os_str(), &head, &relative)?;
    let record = Provenance {
        version: 1,
        source_url: url,
        source_commit: head,
        project: relative,
        source_date_epoch: epoch,
        rust_toolchain: snapshot.rust_toolchain.clone(),
        lock_sha256: snapshot.lock_sha256.clone(),
        zstd_version: zstd::zstd_safe::version_string().to_owned(),
        zstd_threads: threads,
    };
    Ok((snapshot, record))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toolchain_requires_a_stable_patch_version() {
        assert!(exact_toolchain("1.91.1").is_ok());
        for floating in ["stable", "1.91", "1.91.1-nightly"] {
            assert!(exact_toolchain(floating).is_err());
        }
    }

    #[test]
    fn external_wit_imports_require_pinned_versions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("world.wit");
        fs::write(
            &file,
            "package test:plugin@1.0.0; world plugin { import vendor:api/example@1.2.3; }",
        )
        .unwrap();
        pinned_wit(&file).unwrap();
        fs::write(
            &file,
            "package test:plugin@1.0.0; world plugin { import vendor:api/example; }",
        )
        .unwrap();
        let error = pinned_wit(&file).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires a pinned @x.y.z version"),
            "{error:#}"
        );
    }
}
