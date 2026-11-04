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
//! Error codes: `ENTANGLE-E0800`..`E0829` ([`OciError`]).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod artifact;
pub mod auth;
pub mod client;
pub mod error;
mod http;
pub mod listing;
pub mod package;
pub mod reference;
#[cfg(feature = "testing")]
pub mod testing;
pub mod types;

pub use artifact::{pull_artifact, push_artifact, PulledArtifact, PushedArtifact};
pub use auth::{Credential, Secret};
pub use client::{ClientConfig, FetchedManifest, OciClient, RetryPolicy};
pub use error::{OciError, Result};
pub use listing::{
    build_listing, list_tags, publish_listing, sign_listing, verify_listing, ListOptions,
    ListingSignature, ListingVerification, MirrorKeyring, MirrorListing, TagListing,
};
pub use package::{
    pack, pack_dir, unpack, verify_package, PackageFiles, VerifiedPackage, FILE_MANIFEST,
    FILE_PROVENANCE, FILE_SIGNATURE, FILE_WASM,
};
pub use reference::{Digest, Reference, Selector};
pub use types::*;

/// Returns the crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
