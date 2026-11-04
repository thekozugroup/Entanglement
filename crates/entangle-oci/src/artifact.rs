//! Pull and push of Entanglement plugin artifacts.
//!
//! Pulling returns *bytes*. Whether those bytes may be installed is decided by
//! [`crate::verify_package`] alone; nothing returned from here carries a trust
//! claim.

use crate::client::OciClient;
use crate::error::{OciError, Result};
use crate::reference::{Digest, Reference, Selector};
use crate::types::*;

/// A pulled, digest-verified (but not publisher-verified) plugin artifact.
#[derive(Clone, Debug)]
pub struct PulledArtifact {
    /// Digest of the manifest that was resolved.
    pub manifest_digest: Digest,
    /// Digest of the package layer.
    pub layer_digest: Digest,
    /// The package bytes (zstd-compressed tar); feed to [`crate::verify_package`].
    pub package: Vec<u8>,
}

/// Result of a publish.
#[derive(Clone, Debug)]
pub struct PushedArtifact {
    /// Digest of the pushed manifest.
    pub manifest_digest: Digest,
    /// Digest of the package layer.
    pub layer_digest: Digest,
    /// Reference to the pushed manifest by digest.
    pub by_digest: Reference,
}

/// Check that a manifest is an artifact of type `artifact_type`.
///
/// Registries that predate `artifactType` (OCI 1.0) are handled the way the
/// 1.1 spec prescribes: the config descriptor's media type stands in for it.
pub(crate) fn check_artifact_type(m: &ImageManifest, artifact_type: &str) -> Result<()> {
    let actual = m.artifact_type.as_deref().unwrap_or(&m.config.media_type);
    if actual != artifact_type {
        return Err(OciError::WrongMediaType {
            what: "artifactType".into(),
            expected: artifact_type.to_owned(),
            actual: actual.to_owned(),
        });
    }
    if !m.media_type.is_empty() && m.media_type != MEDIA_TYPE_MANIFEST {
        return Err(OciError::WrongMediaType {
            what: "manifest mediaType".into(),
            expected: MEDIA_TYPE_MANIFEST.into(),
            actual: m.media_type.clone(),
        });
    }
    Ok(())
}

/// Pull a plugin artifact.
pub async fn pull_artifact(client: &OciClient, reference: &Reference) -> Result<PulledArtifact> {
    let fetched = client.get_manifest(reference, ARTIFACT_TYPE_PLUGIN).await?;
    check_artifact_type(&fetched.manifest, ARTIFACT_TYPE_PLUGIN)?;
    let [layer] = fetched.manifest.layers.as_slice() else {
        return Err(OciError::InvalidManifest(format!(
            "a plugin artifact has exactly one layer, this one has {}",
            fetched.manifest.layers.len()
        )));
    };
    if layer.media_type != LAYER_TYPE_PLUGIN {
        return Err(OciError::WrongMediaType {
            what: "plugin layer".into(),
            expected: LAYER_TYPE_PLUGIN.into(),
            actual: layer.media_type.clone(),
        });
    }
    let package = client.get_blob(&reference.repository, layer).await?;
    Ok(PulledArtifact {
        manifest_digest: fetched.digest,
        layer_digest: layer.digest.clone(),
        package,
    })
}

/// Build the manifest bytes for an artifact with the given layers.
pub(crate) fn build_manifest(artifact_type: &str, layers: Vec<Descriptor>) -> Result<Vec<u8>> {
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: MEDIA_TYPE_MANIFEST.to_owned(),
        artifact_type: Some(artifact_type.to_owned()),
        config: Descriptor::for_bytes(MEDIA_TYPE_EMPTY, EMPTY_JSON),
        layers,
        annotations: None,
    };
    serde_json::to_vec(&manifest).map_err(|e| OciError::InvalidManifest(e.to_string()))
}

/// Push `layers` (media type, bytes) as an artifact under `reference` (a tag).
pub(crate) async fn push_layers(
    client: &OciClient,
    reference: &Reference,
    artifact_type: &str,
    layers: &[(&str, &[u8])],
) -> Result<(Digest, Vec<Digest>)> {
    if !matches!(reference.selector, Selector::Tag(_)) {
        return Err(OciError::Unsupported(
            "publishing needs a tag (oci://registry/repo:tag), not a digest".into(),
        ));
    }
    let repo = &reference.repository;
    client.push_blob(repo, EMPTY_JSON).await?;
    let mut descs = Vec::new();
    let mut digests = Vec::new();
    for (mt, data) in layers {
        digests.push(client.push_blob(repo, data).await?);
        descs.push(Descriptor::for_bytes(mt, data));
    }
    let manifest = build_manifest(artifact_type, descs)?;
    let digest = client
        .put_manifest(repo, &reference.selector, &manifest, MEDIA_TYPE_MANIFEST)
        .await?;
    Ok((digest, digests))
}

/// Publish package bytes (see [`crate::pack_dir`]) as a plugin artifact.
pub async fn push_artifact(
    client: &OciClient,
    reference: &Reference,
    package: &[u8],
) -> Result<PushedArtifact> {
    // Refuse to publish something no consumer could unpack.
    crate::package::unpack(package)?;
    let (manifest_digest, layers) = push_layers(
        client,
        reference,
        ARTIFACT_TYPE_PLUGIN,
        &[(LAYER_TYPE_PLUGIN, package)],
    )
    .await?;
    Ok(PushedArtifact {
        by_digest: reference.with_selector(Selector::Digest(manifest_digest.clone())),
        manifest_digest,
        layer_digest: layers
            .into_iter()
            .next()
            .ok_or_else(|| OciError::Upload("internal: push produced no layer digest".into()))?,
    })
}
