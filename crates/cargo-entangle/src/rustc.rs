//! Preserve stable Wasm crate identities when checkout paths change.

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

pub(crate) const SOURCE_ROOT_ENV: &str = "ENTANGLE_REPRO_SOURCE_ROOT";

pub(crate) fn forward(args: &[OsString]) -> Option<Result<ExitStatus>> {
    let root = std::env::var_os(SOURCE_ROOT_ENV)?;
    let rustc = args.get(1)?;
    if !matches!(
        Path::new(rustc).file_name()?.to_str()?,
        "rustc" | "rustc.exe"
    ) {
        return None;
    }
    Some(invoke(rustc, &args[2..], Path::new(&root)))
}

fn invoke(rustc: &OsString, args: &[OsString], root: &Path) -> Result<ExitStatus> {
    let mut args = args.to_vec();
    let project = std::env::var_os("CARGO_MANIFEST_DIR");
    if let Some(relative) = project
        .as_deref()
        .and_then(|path| Path::new(path).strip_prefix(root).ok())
    {
        let is_guest = args
            .windows(2)
            .any(|args| args[0] == "--target" && args[1] == crate::source::TARGET);
        if is_guest {
            normalize_metadata(&mut args, relative)?;
        }
    }
    Command::new(rustc)
        .args(args)
        .status()
        .context("forwarding Cargo's compiler invocation")
}

fn normalize_metadata(args: &mut [OsString], relative: &Path) -> Result<()> {
    // Cargo hashes an absolute source URL into -C metadata for path dependencies
    // outside the plugin's Cargo workspace. Keep Cargo's output filenames and
    // normalize the compiler's symbol disambiguator to the signed Git tree.
    let mut hash = Sha256::new();
    for component in relative.components() {
        let component = component
            .as_os_str()
            .to_str()
            .context("package path is not UTF-8")?;
        hash.update(component.as_bytes());
        hash.update([0]);
    }
    if let Ok(version) = std::env::var("CARGO_PKG_VERSION") {
        hash.update(version.as_bytes());
        hash.update([0]);
    }
    for pair in args.windows(2) {
        let option = pair[0].to_str().unwrap_or_default();
        let value = pair[1].to_str().unwrap_or_default();
        if matches!(option, "--crate-name" | "--crate-type" | "--target")
            || (option == "--cfg" && value.starts_with("feature="))
        {
            hash.update(option.as_bytes());
            hash.update([0]);
            hash.update(value.as_bytes());
            hash.update([0]);
        }
    }
    let hash = hex::encode(hash.finalize());
    if let Some(pos) = args.windows(2).position(|pair| {
        pair[0] == "-C"
            && pair[1]
                .to_str()
                .is_some_and(|value| value.starts_with("metadata="))
    }) {
        args[pos + 1] = format!("metadata={}", &hash[..16]).into();
    }
    Ok(())
}
