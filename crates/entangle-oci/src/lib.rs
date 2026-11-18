//! OCI registry distribution for Entanglement plugins (spec §3.6 path A,
//! §12.1 mirror-as-CDN, ATC-MIR-1 / ATC-MIR-2).
//!
//! * [`OciClient`] — OCI Distribution v1.1 client (anonymous, Bearer-token and
//!   Basic auth; digest- and size-verified blob streaming; CDN redirects that
//!   never carry credentials; retry on 429/5xx; HTTPS unless loopback or
//!   explicitly insecure).
//! * [`pull_artifact`] / [`push_artifact`] — the plugin artifact format
//!   ([`ARTIFACT_TYPE_PLUGIN`], [`LAYER_TYPE_PLUGIN`]).
//! * [`verify_package`] — the *only* trust decision for pulled bytes:
//!   `(bytes, publisher keyring)` in, verified package out. Registry identity
//!   is not an input.
//! * [`list_tags`] — tags plus the recorded verification of the mirror's signed
//!   listing against a [`MirrorKeyring`] kept separate from publisher keys.
//!
//! * [`fetch_url`] + [`verify_archive_signature`] — the plain-HTTPS path
//!   (spec §3.6 path B): a `.tar.zst` and its detached `.sig` from any web
//!   server, the signature checked before the archive is opened.
//! * [`write_pack`] / [`read_pack`] — the `.entanglepack` offline bundle.
//! * [`ListingState`] — remembers the newest listing seen per repository so
//!   an older, still validly signed listing is refused (rollback protection).
//!
//! Error codes: `ENTANGLE-E0800`..`E0829` ([`OciError`]).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod artifact;
pub mod auth;
pub mod client;
pub mod detached;
pub mod error;
pub mod fetch;
mod http;
pub mod listing;
pub mod listing_state;
pub mod offline;
pub mod package;
pub mod reference;
#[cfg(feature = "testing")]
pub mod testing;
pub mod types;

pub use artifact::{pull_artifact, push_artifact, PulledArtifact, PushedArtifact};
pub use auth::{Credential, Secret};
pub use client::{ClientConfig, FetchedManifest, OciClient, RetryPolicy};
pub use detached::{
    archive_signature_signer, sign_archive, verify_archive_signature, ArchiveSignature,
    MAX_ARCHIVE_SIGNATURE_BYTES,
};
pub use error::{OciError, Result};
pub use fetch::{fetch_url, parse_download_url, signature_url, FetchOptions};
pub use listing::{
    build_listing, list_tags, publish_listing, sign_listing, verify_listing, ListOptions,
    ListingSignature, ListingVerification, MirrorKeyring, MirrorListing, TagListing,
};
pub use listing_state::{ListingState, SeenListing};
pub use offline::{
    read_pack, write_pack, OfflinePack, PackIndex, PackIndexEntry, PackKey, PackedPackage,
    MAX_PACK_BYTES, PACK_EXTENSION,
};
pub use package::{
    pack, pack_dir, pack_with_threads, unpack, verify_package, PackageFiles, VerifiedPackage,
    FILE_MANIFEST, FILE_PROVENANCE, FILE_SIGNATURE, FILE_WASM,
};
pub use reference::{Digest, Reference, Selector};
pub use types::*;

/// Returns the crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
