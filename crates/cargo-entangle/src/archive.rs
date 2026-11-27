use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use entangle_manifest::render::render_dist_manifest;
use entangle_oci::{read_file, PackageFiles, ARCHIVE_LIMIT};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, SignatureBundle, TrustEntry};
use sha2::{Digest, Sha256};

use crate::source::{package_source, Provenance, Snapshot};

const ZSTD_LEVEL: i32 = 19;

fn state_file(explicit: Option<&Path>, name: &str) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    let home =
        std::env::var_os("HOME").context("HOME is unset; provide the key path explicitly")?;
    Ok(PathBuf::from(home).join(".entangle").join(name))
}

fn publisher_key(explicit: Option<&Path>) -> Result<IdentityKeyPair> {
    let path = state_file(explicit, "identity.key")?;
    let pem = fs::read_to_string(&path)
        .with_context(|| format!("reading publisher key {}", path.display()))?;
    IdentityKeyPair::from_pem(&pem).context("invalid publisher identity PEM")
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn sibling_signature(archive: &Path) -> PathBuf {
    let mut path = archive.as_os_str().to_os_string();
    path.push(".sig");
    path.into()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.persist(path)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn encode(
    manifest: &[u8],
    component: &[u8],
    signature: &[u8],
    provenance: &[u8],
    threads: u32,
) -> Result<Vec<u8>> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), ZSTD_LEVEL)?;
    if threads > 1 {
        encoder.multithread(threads)?;
    }
    let mut tar = tar::Builder::new(encoder);
    tar.mode(tar::HeaderMode::Deterministic);
    for (name, data) in [
        ("entangle.toml", manifest),
        ("plugin.wasm", component),
        ("plugin.wasm.sig", signature),
        ("rebuild.json", provenance),
    ] {
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(data.len() as u64);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_mode(0o644);
        tar.append_data(&mut header, name, data)?;
    }
    let bytes = tar.into_inner()?.finish()?;
    ensure!(
        bytes.len() <= ARCHIVE_LIMIT,
        "compressed package exceeds the package size limit"
    );
    Ok(bytes)
}

pub(crate) fn package(
    dir: &Path,
    out: Option<&Path>,
    key: Option<&Path>,
    url: Option<String>,
    epoch: Option<u64>,
    threads: u32,
) -> Result<()> {
    let (source, record) = package_source(dir, url, epoch, threads)?;
    let key = publisher_key(key)?;
    let rendered = render_dist_manifest(&source.manifest_text, &key.fingerprint_hex())?;
    let component = source.build(record.source_date_epoch)?;
    let mut signature = sign_artifact(&component, rendered.toml.as_bytes(), &key);
    signature.created_at = record.source_date_epoch;
    let signature = toml::to_string(&signature)?;
    let provenance = serde_json::to_vec(&record)?;
    if threads > 1 {
        eprintln!("warning: archives built with different zstd thread counts may differ");
    }
    let archive = encode(
        rendered.toml.as_bytes(),
        &component,
        signature.as_bytes(),
        &provenance,
        threads,
    )?;
    let filename = rendered
        .plugin_id
        .split_once('/')
        .context("package manifest is missing its plugin name")?
        .1
        .replace('@', "-");
    let default = dir
        .join("target")
        .join("entangle")
        .join(format!("{filename}.tar.zst"));
    let path = out.unwrap_or(&default);
    write_atomic(path, &archive)?;
    println!("Package: {}", path.display());
    println!("SHA-256: {}", hex::encode(digest(&archive)));
    Ok(())
}

pub(crate) fn sign(archive: &Path, key: Option<&Path>) -> Result<()> {
    let key = publisher_key(key)?;
    let bytes = read_file(archive, ARCHIVE_LIMIT)?;
    let signature = key.sign(&digest(&bytes));
    let mut keyring = Keyring::new();
    keyring.add(TrustEntry {
        fingerprint: key.fingerprint(),
        public_key: *key.public().as_bytes(),
        publisher_name: "package publisher".into(),
        added_at: 0,
        note: String::new(),
    });
    PackageFiles::from_signed_archive(&bytes, signature.as_bytes(), &keyring)
        .context("archive was not packaged by the selected publisher")?;
    let path = sibling_signature(archive);
    write_atomic(&path, signature.as_bytes())?;
    println!("Signed: {} (64 bytes)", path.display());
    println!("Publisher key: {}", hex::encode(key.public().as_bytes()));
    Ok(())
}

pub(crate) fn verify(
    archive: &Path,
    source_path: Option<&Path>,
    keyring: Option<&Path>,
) -> Result<()> {
    let keyring = Keyring::load(&state_file(keyring, "keyring.toml")?)?;
    let bytes = read_file(archive, ARCHIVE_LIMIT)?;
    let signature = read_file(&sibling_signature(archive), 64)?;
    let package = PackageFiles::from_signed_archive(&bytes, &signature, &keyring)
        .context("authenticating the package before rebuilding")?;
    let provenance = package.provenance.context("archive has no rebuild.json")?;
    let record: Provenance =
        serde_json::from_slice(&provenance).context("reading the signed rebuild metadata")?;
    record.validate()?;
    let signature: SignatureBundle = toml::from_str(std::str::from_utf8(&package.signature)?)?;
    ensure!(
        signature.created_at == record.source_date_epoch,
        "artifact signature timestamp differs from the signed build epoch"
    );

    let local = source_path
        .map(fs::canonicalize)
        .transpose()
        .context("opening the local source repository")?;
    let origin = local
        .as_deref()
        .map(Path::as_os_str)
        .unwrap_or_else(|| OsStr::new(&record.source_url));
    let source = Snapshot::clone(origin, &record.source_commit, &record.project)?;
    ensure!(
        source.rust_toolchain == record.rust_toolchain,
        "the source toolchain differs from the signed metadata"
    );
    ensure!(
        source.lock_sha256 == record.lock_sha256,
        "the committed Cargo.lock SHA-256 differs from the signed metadata"
    );
    let rendered = render_dist_manifest(&source.manifest_text, &package.plugin_id.publisher)?;
    ensure!(
        rendered.toml.as_bytes() == package.manifest,
        "the committed plugin manifest differs from the signed manifest"
    );
    let component = source.build(record.source_date_epoch)?;
    ensure!(
        component == package.component,
        "the rebuilt component differs from the signed component"
    );

    // Reuse the verified Ed25519 signature after reproducing its signed
    // component and manifest. Serialize the enclosing metadata canonically.
    let canonical_signature = toml::to_string(&signature)?;
    let canonical_provenance = serde_json::to_vec(&record)?;
    let rebuilt = encode(
        rendered.toml.as_bytes(),
        &component,
        canonical_signature.as_bytes(),
        &canonical_provenance,
        record.zstd_threads,
    )?;
    let expected = digest(&bytes);
    let actual = digest(&rebuilt);
    ensure!(
        actual == expected,
        "archive SHA-256 mismatch (expected {}, rebuilt {})",
        hex::encode(expected),
        hex::encode(actual)
    );
    println!(
        "PASS: reproduced SHA-256 {} from {}",
        hex::encode(actual),
        record.source_commit
    );
    Ok(())
}
