//! OCI wire types and the Entanglement media types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::reference::Digest;

/// OCI image manifest media type.
pub const MEDIA_TYPE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// OCI image index media type.
pub const MEDIA_TYPE_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// OCI 1.1 "empty" descriptor media type, used for the config of artifacts.
pub const MEDIA_TYPE_EMPTY: &str = "application/vnd.oci.empty.v1+json";

/// `artifactType` of an Entanglement plugin artifact.
pub const ARTIFACT_TYPE_PLUGIN: &str = "application/vnd.entangle.plugin.v1";
/// Media type of the single layer of a plugin artifact: a tar archive,
/// zstd-compressed, holding the signed package files.
pub const LAYER_TYPE_PLUGIN: &str = "application/vnd.entangle.plugin.layer.v1.tar+zstd";

/// `artifactType` of a mirror-listing artifact.
pub const ARTIFACT_TYPE_LISTING: &str = "application/vnd.entangle.mirror-listing.v1";
/// Layer holding the listing JSON (the exact bytes that are signed).
pub const LAYER_TYPE_LISTING: &str = "application/vnd.entangle.mirror-listing.v1+json";
/// Layer holding the detached listing signature (JSON).
pub const LAYER_TYPE_LISTING_SIG: &str = "application/vnd.entangle.mirror-listing.sig.v1+json";

/// Well-known tag under which a repository's signed listing is published.
pub const LISTING_TAG: &str = "_entangle-listing";

/// The 2-byte `{}` body of the empty config blob.
pub(crate) const EMPTY_JSON: &[u8] = b"{}";

/// An OCI content descriptor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    /// Media type of the referenced content.
    pub media_type: String,
    /// SHA-256 digest of the referenced content.
    pub digest: Digest,
    /// Size in bytes of the referenced content.
    pub size: u64,
    /// Artifact type (index entries only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    /// Free-form annotations. **Never** consulted for trust decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

impl Descriptor {
    /// Descriptor for `bytes` with `media_type`.
    pub fn for_bytes(media_type: &str, bytes: &[u8]) -> Self {
        Self {
            media_type: media_type.to_owned(),
            digest: Digest::of(bytes),
            size: bytes.len() as u64,
            artifact_type: None,
            annotations: None,
        }
    }
}

/// An OCI image manifest (used here as an artifact manifest).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImageManifest {
    /// Always 2.
    pub schema_version: u32,
    /// Manifest media type.
    #[serde(default)]
    pub media_type: String,
    /// Artifact type, when the registry/pusher set one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    /// Config descriptor (the empty descriptor for our artifacts).
    pub config: Descriptor,
    /// Layers.
    #[serde(default)]
    pub layers: Vec<Descriptor>,
    /// Annotations. Informational only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// An OCI image index.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImageIndex {
    #[serde(default)]
    pub manifests: Vec<Descriptor>,
}
