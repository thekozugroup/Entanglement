//! `entangle mirror set|get|unset` — the registry kill-switch (spec §12.1).
//!
//! A mirror is another OCI registry that holds the same repositories as the
//! one a reference names. When one is configured, `plugins install oci://…`
//! and `plugins tags` ask **the mirror first and the origin second**
//! (`crate::cmd::oci`), so plugins stay installable when the origin registry
//! is gone, slow or blocked.
//!
//! * The setting is one URL in `~/.entangle/mirror.toml`. It is read by the
//!   CLI each time it pulls, so a change applies to the next command; the
//!   daemon never pulls from registries and needs no restart or reload.
//! * **No mirror is built in.** The spec names a project-run fallback host;
//!   no such host is operated, so nothing is hard-coded and the only mirror
//!   ever contacted is the one the operator sets here.
//! * A mirror is a CDN, not an authority. Packages it serves must carry the
//!   same publisher signature as from anywhere else, and its tag listings are
//!   checked against the mirror keyring (`~/.entangle/mirror-keys.toml`) and
//!   the rollback record like any other.
//! * The URL must be `https://` (plain `http://` only for a loopback host)
//!   with no credentials, query or fragment; a path prefix is allowed
//!   (`https://mirror.example.org/oci` serves `…/oci/v2/<repository>/…`).
//!   Credentials for a private mirror go in `~/.entangle/oci-auth.toml` under
//!   the mirror's host, exactly as for a registry.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use entangle_oci::{ClientConfig, OciClient};
use serde::{Deserialize, Serialize};

use crate::config;

/// `entangle mirror` arguments.
#[derive(Args)]
pub struct MirrorArgs {
    #[command(subcommand)]
    pub cmd: MirrorCmd,
}

/// `entangle mirror` subcommands.
#[derive(Subcommand)]
pub enum MirrorCmd {
    /// Pull from this mirror first, and from the origin registry only if the
    /// mirror cannot supply what was asked for.
    Set {
        /// `https://host[:port][/prefix]` of an OCI registry mirroring the
        /// repositories you install from.
        url: String,
    },
    /// Print the configured mirror, if any.
    Get {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove the mirror: pulls go to the origin registry only.
    Unset,
}

/// `~/.entangle/mirror.toml`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MirrorFile {
    /// The mirror's base URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url: Option<String>,
}

/// `~/.entangle/mirror.toml`.
pub fn mirror_path() -> PathBuf {
    config::entangle_dir().join("mirror.toml")
}

/// The configured mirror URL, if any (`ENTANGLE-E0944` if the file is damaged).
pub fn configured() -> Result<Option<String>> {
    let path = mirror_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => bail!("ENTANGLE-E0944: reading {}: {e}", path.display()),
    };
    let file: MirrorFile = toml::from_str(&text).map_err(|e| {
        anyhow::anyhow!(
            "ENTANGLE-E0944: {} is not a valid mirror setting: {e}. Rewrite it with `entangle \
             mirror set <URL>` or remove it with `entangle mirror unset`",
            path.display()
        )
    })?;
    Ok(file.url.filter(|u| !u.trim().is_empty()))
}

/// Normalise and vet a mirror URL exactly as the pull path will use it.
fn vet(url: &str) -> Result<String> {
    let client = OciClient::with_base_url(url.trim(), ClientConfig::default())?;
    Ok(client.base_url().as_str().trim_end_matches('/').to_owned())
}

/// `entangle mirror …`.
pub async fn run(args: MirrorArgs) -> Result<()> {
    let path = mirror_path();
    match args.cmd {
        MirrorCmd::Set { url } => {
            let url = vet(&url)?;
            let text = toml::to_string(&MirrorFile {
                url: Some(url.clone()),
            })?;
            crate::fsutil::atomic_write(&path, text.as_bytes(), 0o600)
                .with_context(|| format!("writing {}", path.display()))?;
            println!("mirror set to {url}");
            println!(
                "  `entangle plugins install oci://…` and `plugins tags` now ask it first and \
                 the origin registry second."
            );
            println!(
                "  This applies to the next command; the daemon needs no restart. Packages \
                 from the mirror must still be signed by a publisher in your keyring."
            );
            Ok(())
        }
        MirrorCmd::Get { json } => {
            let url = configured()?;
            if json {
                println!("{}", serde_json::json!({ "mirror": url }));
            } else {
                match url {
                    Some(u) => println!("{u}"),
                    None => println!(
                        "no mirror configured (pulls go to the registry each reference names)"
                    ),
                }
            }
            Ok(())
        }
        MirrorCmd::Unset => {
            match std::fs::remove_file(&path) {
                Ok(()) => println!("mirror removed; pulls go to the origin registry only"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    println!("no mirror was configured")
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("removing {}", path.display()));
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_urls_are_normalised_and_bad_ones_refused() {
        assert_eq!(
            vet("https://mirror.example.org/").unwrap(),
            "https://mirror.example.org"
        );
        assert_eq!(
            vet(" https://mirror.example.org/oci/ ").unwrap(),
            "https://mirror.example.org/oci"
        );
        assert_eq!(
            vet("http://127.0.0.1:5000").unwrap(),
            "http://127.0.0.1:5000"
        );
        for bad in [
            "http://mirror.example.org",
            "mirror.example.org",
            "https://user:pw@mirror.example.org",
            "https://mirror.example.org/?a=1",
            "ftp://mirror.example.org",
        ] {
            let e = vet(bad).unwrap_err().to_string();
            assert!(e.starts_with("ENTANGLE-E0825"), "{bad}: {e}");
            assert!(!e.contains("--insecure-registry"), "{bad}: {e}");
        }
    }

    /// The kill-switch must not be pre-armed: no host name is compiled in,
    /// in any crate's sources (comments aside).
    #[test]
    fn no_mirror_host_is_hard_coded() {
        fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    rust_files(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut files = Vec::new();
        for c in std::fs::read_dir(&crates).unwrap().flatten() {
            rust_files(&c.path().join("src"), &mut files);
        }
        assert!(files.len() > 50, "found only {} source files", files.len());
        let needles = ["mirror.entanglement", "entanglement.dev"];
        for f in files {
            let text = std::fs::read_to_string(&f).unwrap();
            for (n, line) in text.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") || line.contains("let needles = [") {
                    continue;
                }
                for needle in needles {
                    assert!(
                        !line.contains(needle),
                        "{needle} in {}:{}",
                        f.display(),
                        n + 1
                    );
                }
            }
        }
    }
}
