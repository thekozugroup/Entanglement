//! Verify a release archive with independent publisher and release-workflow signatures.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context};
use clap::{Args, Subcommand};
use entangle_signing::{IdentityPublicKey, Signature};
use serde::Deserialize;

const WORKFLOW_IDENTITY_PREFIX: &str =
    "https://github.com/thekozugroup/Entanglement/.github/workflows/release.yml@refs/tags/";
const ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
const BUNDLE_MEDIA_TYPES: &[&str] = &[
    "application/vnd.dev.sigstore.bundle.v0.3+json",
    "application/vnd.dev.sigstore.bundle+json;version=0.3",
];
const RELEASE_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
];

#[derive(Args)]
pub struct ReleaseArgs {
    #[command(subcommand)]
    command: ReleaseCommand,
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// Verify the adjacent publisher signature and Sigstore bundle.
    Verify {
        /// Downloaded release archive with its original filename.
        artifact: PathBuf,
        /// Independently trusted Ed25519 public key in PEM format.
        /// Defaults to ~/.entangle/release.pub.
        #[arg(long)]
        publisher_key: Option<PathBuf>,
    },
}

pub fn run(args: ReleaseArgs) -> anyhow::Result<()> {
    let ReleaseCommand::Verify {
        artifact,
        publisher_key,
    } = args.command;
    let identity = release_workflow_identity(&artifact)?;
    let key_path =
        publisher_key.unwrap_or_else(|| crate::config::entangle_dir().join("release.pub"));
    let pem = fs::read_to_string(&key_path).with_context(|| {
        format!(
            "reading trusted release publisher key {}",
            key_path.display()
        )
    })?;
    let publisher = IdentityPublicKey::from_pem(&pem).context("invalid Ed25519 publisher key")?;
    let signature_path = sidecar(&artifact, ".sig");
    let signature =
        Signature::from_bytes(&fs::read(&signature_path).with_context(|| {
            format!("reading publisher signature {}", signature_path.display())
        })?)
        .context("malformed Ed25519 publisher signature")?;
    let bundle_path = sidecar(&artifact, ".sigstore");
    let bundle = fs::read(&bundle_path)
        .with_context(|| format!("reading Sigstore bundle {}", bundle_path.display()))?;
    // Both verifiers receive these bytes even if the download path changes.
    let bytes = fs::read(&artifact)
        .with_context(|| format!("reading release artifact {}", artifact.display()))?;
    let mut cosign = cosign_command(&identity, ACTIONS_ISSUER);
    verify_both(&bytes, &signature, &publisher, &bundle, &mut cosign)?;
    println!(
        "Verified {} with publisher {} and the tagged workflow's Sigstore/Rekor proof",
        artifact.display(),
        publisher.fingerprint_hex()
    );
    Ok(())
}

fn release_workflow_identity(artifact: &Path) -> anyhow::Result<String> {
    let name = artifact.file_name().and_then(|name| name.to_str());
    let tag = name
        .and_then(|name| name.strip_prefix("entanglement-"))
        .and_then(|name| name.strip_suffix(".tar.gz"))
        .and_then(|stem| {
            RELEASE_TARGETS.iter().find_map(|target| {
                stem.strip_suffix(target)
                    .and_then(|prefix| prefix.strip_suffix('-'))
            })
        })
        .filter(|tag| is_release_tag(tag))
        .context("expected the original release filename entanglement-vX.Y.Z-<target>.tar.gz")?;
    Ok(format!("{WORKFLOW_IDENTITY_PREFIX}{tag}"))
}

fn is_release_tag(tag: &str) -> bool {
    let Some(version) = tag.strip_prefix('v') else {
        return false;
    };
    let (core, suffix) = version.split_once('-').unwrap_or((version, ""));
    let mut numbers = core.split('.');
    numbers.clone().count() == 3
        && numbers.all(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
        && (core == version
            || (!suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.')))
}

fn sidecar(artifact: &Path, suffix: &str) -> PathBuf {
    let mut path = artifact.as_os_str().to_owned();
    path.push(suffix);
    path.into()
}

fn cosign_command(identity: &str, issuer: &str) -> Command {
    let mut command = Command::new("cosign");
    command.args([
        "verify-blob",
        "--new-bundle-format",
        "--offline",
        "--certificate-identity",
        identity,
        "--certificate-oidc-issuer",
        issuer,
    ]);
    command
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlobBundleHeader {
    media_type: String,
    message_signature: serde_json::Value,
}

fn verify_both(
    artifact: &[u8],
    signature: &Signature,
    publisher: &IdentityPublicKey,
    bundle: &[u8],
    cosign: &mut Command,
) -> anyhow::Result<()> {
    publisher
        .verify(artifact, signature)
        .context("Ed25519 release publisher verification failed")?;

    let header: BlobBundleHeader =
        serde_json::from_slice(bundle).context("invalid Sigstore blob bundle")?;
    // With a v0.3 bundle, Cosign requires and verifies a Rekor inclusion
    // proof. Older formats can carry only an inclusion promise.
    if !BUNDLE_MEDIA_TYPES.contains(&header.media_type.as_str())
        || !header.message_signature.is_object()
    {
        bail!("expected a v0.3 Sigstore blob signature bundle");
    }
    let mut staged_bundle = tempfile::NamedTempFile::new().context("staging Sigstore bundle")?;
    staged_bundle
        .write_all(bundle)
        .context("staging Sigstore bundle")?;
    let mut verifier = cosign
        .arg("--bundle")
        .arg(staged_bundle.path())
        .args(["--", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .context("starting cosign (install Cosign with v0.3 bundle support and put it on PATH)")?;
    let sent = verifier
        .stdin
        .take()
        .expect("Cosign stdin is piped")
        .write_all(artifact);
    let status = verifier.wait().context("waiting for Cosign")?;
    if !status.success() {
        bail!("Sigstore/Rekor release verification failed ({status})");
    }
    sent.context("sending release artifact to Cosign")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_signing::IdentityKeyPair;

    #[test]
    fn artifact_name_pins_the_exact_workflow_tag() {
        for target in RELEASE_TARGETS {
            let artifact = format!("dir/entanglement-v1.0.0-rc.2-{target}.tar.gz");
            assert_eq!(
                release_workflow_identity(Path::new(&artifact)).unwrap(),
                format!("{WORKFLOW_IDENTITY_PREFIX}v1.0.0-rc.2")
            );
        }
        for name in [
            "downloaded.tar.gz",
            "entanglement-main-x86_64-unknown-linux-gnu.tar.gz",
            "entanglement-v1.1-x86_64-unknown-linux-gnu.tar.gz",
            "entanglement-v1.1.1-x86_64-pc-windows-gnu.tar.gz",
        ] {
            assert!(
                release_workflow_identity(Path::new(name)).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn publisher_pem_round_trips_and_rejects_another_key() {
        let signer = IdentityKeyPair::generate();
        let publisher = IdentityPublicKey::from_pem(&signer.public().to_pem()).unwrap();
        let message = b"release archive bytes";
        let signature = signer.sign(message);
        publisher.verify(message, &signature).unwrap();
        assert!(publisher
            .verify(b"other archive bytes", &signature)
            .is_err());
        assert!(IdentityKeyPair::generate()
            .public()
            .verify(message, &signature)
            .is_err());
    }

    #[test]
    #[ignore = "run scripts/tests/release-verify.sh with a verified Cosign executable on PATH"]
    fn dual_sig_pass() {
        const HISTORICAL_IDENTITY: &str = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main";
        let fixture = PathBuf::from(std::env::var_os("ENTANGLE_RELEASE_TEST_FIXTURES").unwrap());
        let artifact = fs::read(fixture.join("artifact")).unwrap();
        let historical_bundle = fs::read(fixture.join("bundle.sigstore.json")).unwrap();
        let trusted_root = fixture.join("trusted-root.json");
        let signer = IdentityKeyPair::generate();
        let publisher = IdentityPublicKey::from_pem(&signer.public().to_pem()).unwrap();
        let sig = signer.sign(&artifact);

        let command = |identity| {
            let mut command = cosign_command(identity, ACTIONS_ISSUER);
            command.arg("--trusted-root").arg(&trusted_root);
            command
        };
        verify_both(
            &artifact,
            &sig,
            &publisher,
            &historical_bundle,
            &mut command(HISTORICAL_IDENTITY),
        )
        .unwrap();

        // Cosign v2.5.3 sign-blob emits the other v0.3 media type spelling.
        let mut signing_format: serde_json::Value =
            serde_json::from_slice(&historical_bundle).unwrap();
        signing_format["mediaType"] = BUNDLE_MEDIA_TYPES[1].into();
        verify_both(
            &artifact,
            &sig,
            &publisher,
            &serde_json::to_vec(&signing_format).unwrap(),
            &mut command(HISTORICAL_IDENTITY),
        )
        .unwrap();

        let wrong_key = IdentityKeyPair::generate().public();
        let error = verify_both(
            &artifact,
            &sig,
            &wrong_key,
            &historical_bundle,
            &mut command(HISTORICAL_IDENTITY),
        )
        .unwrap_err();
        assert!(error.to_string().contains("Ed25519 release publisher"));

        // A matching publisher signature for a different payload must not
        // stand in for a Sigstore signature over the same artifact bytes.
        let another_artifact = b"another archive";
        let error = verify_both(
            another_artifact,
            &signer.sign(another_artifact),
            &publisher,
            &historical_bundle,
            &mut command(HISTORICAL_IDENTITY),
        )
        .unwrap_err();
        assert!(error.to_string().contains("Sigstore/Rekor"));

        let official_identity = release_workflow_identity(Path::new(
            "entanglement-v1.0.0-x86_64-unknown-linux-gnu.tar.gz",
        ))
        .unwrap();
        let error = verify_both(
            &artifact,
            &sig,
            &publisher,
            &historical_bundle,
            &mut command(&official_identity),
        )
        .unwrap_err();
        assert!(error.to_string().contains("Sigstore/Rekor"));

        let mut missing_proof: serde_json::Value =
            serde_json::from_slice(&historical_bundle).unwrap();
        missing_proof["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .unwrap()
            .remove("inclusionProof")
            .unwrap();
        let error = verify_both(
            &artifact,
            &sig,
            &publisher,
            &serde_json::to_vec(&missing_proof).unwrap(),
            &mut command(HISTORICAL_IDENTITY),
        )
        .unwrap_err();
        assert!(error.to_string().contains("Sigstore/Rekor"));
    }
}
