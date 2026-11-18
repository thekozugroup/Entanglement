//! Signed mirror listings (ATC-MIR-2) and the mirror keyring.
//!
//! A mirror (or any registry operator) may publish, under the well-known tag
//! [`LISTING_TAG`], an artifact of type [`ARTIFACT_TYPE_LISTING`] with two
//! layers: the listing JSON ([`MirrorListing`]) and a detached Ed25519
//! signature over *exactly those bytes* ([`ListingSignature`]).
//!
//! # Keys
//! Listings are verified against a [`MirrorKeyring`]. It is a different type,
//! loaded from a different file, from the publisher [`entangle_signing::Keyring`]
//! that gates artifacts, and the two never cross:
//!
//! * [`crate::verify_package`] takes a publisher keyring, so a key that exists
//!   only in the mirror keyring cannot validate an artifact;
//! * [`verify_listing`] takes a mirror keyring, so a publisher key is not
//!   accepted as a listing signer;
//! * listing signatures are over a domain-separated message, so even a key
//!   present in both rings cannot have a listing signature replayed as an
//!   artifact signature (artifact signatures are over a BLAKE3 digest with a
//!   different domain).
//!
//! A listing says which tags exist and what they pointed at; it never makes an
//! artifact trusted.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use entangle_signing::{
    IdentityKeyPair, IdentityPublicKey, Keyring, KeyringError, Signature, TrustEntry,
};
use serde::{Deserialize, Serialize};

use crate::artifact::{check_artifact_type, push_layers};
use crate::client::OciClient;
use crate::error::{OciError, Result};
use crate::listing_state::{ListingState, Observation};
use crate::reference::{Digest, Reference, Selector};
use crate::types::*;

/// Domain prefix of the signed message.
const LISTING_DOMAIN: &[u8] = b"entangle-oci mirror listing v1\0";
/// Largest listing/signature layer accepted.
const MAX_LISTING_BYTES: u64 = 4 * 1024 * 1024;

/// How far in the future a listing's `generated_at` may lie (clock skew
/// between the mirror and this machine). A listing dated later is
/// `Invalid` and never recorded: otherwise one signed listing from the
/// future would make every real listing look like a rollback.
pub const MAX_LISTING_CLOCK_SKEW_SECS: u64 = 300;

/// Longest lifetime (`expires_at - generated_at`) a listing may claim: 366
/// days. A longer one is `Invalid`; `plugins mirror-sign` refuses to sign it.
pub const MAX_LISTING_LIFETIME_SECS: u64 = 366 * 86_400;

/// The signed listing document.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MirrorListing {
    /// Format version, currently 1.
    pub version: u32,
    /// Repository the listing describes (e.g. `entangle/hash-it`).
    pub repository: String,
    /// Tag to manifest digest.
    pub tags: BTreeMap<String, Digest>,
    /// Unix seconds when the listing was generated.
    pub generated_at: u64,
    /// Unix seconds after which the listing must not be relied on.
    pub expires_at: u64,
}

/// Detached signature over the listing bytes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListingSignature {
    /// Format version, currently 1.
    pub version: u32,
    /// Always `ed25519`.
    pub algorithm: String,
    /// Fingerprint (32 hex) of the signing mirror key.
    pub key_fingerprint: String,
    /// Signature (128 hex) over `LISTING_DOMAIN || listing bytes`.
    pub signature: String,
}

/// The recorded outcome of checking a listing's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListingVerification {
    /// Signed by a configured mirror key, repository matches, not expired.
    Verified {
        /// Fingerprint (hex) of the mirror key that signed.
        key_fingerprint: String,
    },
    /// The mirror published no listing, or a listing with no signature.
    Unsigned,
    /// A listing exists but must not be trusted.
    Invalid {
        /// Why (unknown key, bad signature, wrong repository, malformed, ...).
        reason: String,
    },
    /// Correctly signed, but past `expires_at`.
    Expired,
    /// Correctly signed and not expired, but **older** than a listing already
    /// seen for this repository (`ENTANGLE-E0820`; see
    /// [`crate::listing_state`]). Treated like an invalid listing: its tags
    /// and digests are not used.
    RolledBack {
        /// `generated_at` (unix seconds) of the newest listing recorded.
        newest_seen: u64,
        /// `generated_at` (unix seconds) of the listing just offered.
        offered: u64,
    },
}

impl std::fmt::Display for ListingVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verified { key_fingerprint } => {
                write!(f, "verified (mirror key {key_fingerprint})")
            }
            Self::Unsigned => f.write_str("unsigned"),
            Self::Invalid { reason } => write!(f, "INVALID: {reason}"),
            Self::Expired => f.write_str("EXPIRED"),
            Self::RolledBack {
                newest_seen,
                offered,
            } => write!(
                f,
                "ROLLED BACK (ENTANGLE-E0820): this listing was generated at {offered}, but a \
                 newer one (generated at {newest_seen}) was already seen for this repository"
            ),
        }
    }
}

/// Trusted mirror (listing) keys. Distinct from the publisher keyring.
#[derive(Clone, Debug, Default)]
pub struct MirrorKeyring(Keyring);

impl MirrorKeyring {
    /// An empty mirror keyring (every listing will be `Invalid` or `Unsigned`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `entry` for listings only.
    pub fn add(&mut self, entry: TrustEntry) {
        self.0.add(entry);
    }

    /// Trust a raw public key for listings.
    pub fn add_public_key(&mut self, key: &IdentityPublicKey, name: &str) {
        self.0.add(TrustEntry {
            fingerprint: key.fingerprint(),
            public_key: *key.as_bytes(),
            publisher_name: name.to_owned(),
            added_at: now_secs(),
            note: "mirror listing key".to_owned(),
        });
    }

    /// Look up a key by fingerprint.
    pub fn lookup(&self, fp: &[u8; 16]) -> Option<&TrustEntry> {
        self.0.lookup(fp)
    }

    /// All entries.
    pub fn entries(&self) -> impl Iterator<Item = &TrustEntry> {
        self.0.entries()
    }

    /// Load from a TOML file (same `[[entries]]` schema as `keyring.toml`).
    /// A missing file is an empty keyring.
    pub fn load(path: &Path) -> Result<Self> {
        Keyring::load(path)
            .map(Self)
            .map_err(|e: KeyringError| OciError::MirrorKeys(format!("{}: {e}", path.display())))
    }

    /// Save to a TOML file (mode 0600 on Unix).
    pub fn save(&self, path: &Path) -> Result<()> {
        self.0
            .save(path)
            .map_err(|e| OciError::MirrorKeys(format!("{}: {e}", path.display())))
    }

    /// Fingerprints that are in both this ring and `publishers`. A key that is
    /// trusted for both roles weakens the separation; operators should be told.
    pub fn overlap_with(&self, publishers: &Keyring) -> Vec<String> {
        self.entries()
            .filter(|e| publishers.lookup(&e.fingerprint).is_some())
            .map(|e| hex::encode(e.fingerprint))
            .collect()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn signed_message(listing_bytes: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(LISTING_DOMAIN.len() + listing_bytes.len());
    m.extend_from_slice(LISTING_DOMAIN);
    m.extend_from_slice(listing_bytes);
    m
}

/// Serialize and sign a listing. Returns `(listing_json, signature_json)`.
pub fn sign_listing(listing: &MirrorListing, key: &IdentityKeyPair) -> Result<(Vec<u8>, Vec<u8>)> {
    let listing_bytes =
        serde_json::to_vec(listing).map_err(|e| OciError::Listing(e.to_string()))?;
    let sig = key.sign(&signed_message(&listing_bytes));
    let sig_bytes = serde_json::to_vec(&ListingSignature {
        version: 1,
        algorithm: "ed25519".into(),
        key_fingerprint: key.fingerprint_hex(),
        signature: sig.to_hex(),
    })
    .map_err(|e| OciError::Listing(e.to_string()))?;
    Ok((listing_bytes, sig_bytes))
}

/// Check a listing and its detached signature. Pure; `now` is unix seconds.
///
/// Order matters: the signature is checked before expiry so a tampered,
/// expired listing is `Invalid`, not `Expired`.
pub fn verify_listing(
    listing_bytes: &[u8],
    signature_bytes: Option<&[u8]>,
    expected_repository: &str,
    keys: &MirrorKeyring,
    now: u64,
) -> (ListingVerification, Option<MirrorListing>) {
    let invalid = |r: String| (ListingVerification::Invalid { reason: r }, None);
    let Some(sig_bytes) = signature_bytes else {
        return (ListingVerification::Unsigned, None);
    };
    let sig: ListingSignature = match serde_json::from_slice(sig_bytes) {
        Ok(s) => s,
        Err(e) => return invalid(format!("malformed signature document: {e}")),
    };
    if sig.version != 1 || sig.algorithm != "ed25519" {
        return invalid(format!(
            "unsupported signature version {} / algorithm {:?}",
            sig.version, sig.algorithm
        ));
    }
    let Some(fp) = hex::decode(&sig.key_fingerprint)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
    else {
        return invalid("signature names a malformed key fingerprint".into());
    };
    let Some(entry) = keys.lookup(&fp) else {
        return invalid(format!(
            "listing signed by key {} which is not in the mirror keyring",
            sig.key_fingerprint
        ));
    };
    let Ok(pk) = IdentityPublicKey::from_bytes(&entry.public_key) else {
        return invalid("mirror keyring holds an invalid public key".into());
    };
    let Ok(signature) = Signature::from_hex(&sig.signature) else {
        return invalid("malformed signature bytes".into());
    };
    if pk
        .verify(&signed_message(listing_bytes), &signature)
        .is_err()
    {
        return invalid("signature does not verify".into());
    }
    let listing: MirrorListing = match serde_json::from_slice(listing_bytes) {
        Ok(l) => l,
        Err(e) => return invalid(format!("signed listing is not valid: {e}")),
    };
    if listing.version != 1 {
        return invalid(format!("unsupported listing version {}", listing.version));
    }
    if listing.repository != expected_repository {
        return invalid(format!(
            "listing is for repository {:?}, not {:?}",
            listing.repository, expected_repository
        ));
    }
    if listing.expires_at <= listing.generated_at {
        return invalid("expires_at is not after generated_at".into());
    }
    if listing.generated_at > now.saturating_add(MAX_LISTING_CLOCK_SKEW_SECS) {
        return invalid(format!(
            "generated_at {} is in the future (now {now}, allowance \
             {MAX_LISTING_CLOCK_SKEW_SECS} s); check the mirror's clock and this machine's",
            listing.generated_at
        ));
    }
    if listing.expires_at - listing.generated_at > MAX_LISTING_LIFETIME_SECS {
        return invalid(format!(
            "lifetime of {} s exceeds the maximum of {MAX_LISTING_LIFETIME_SECS} s (366 days)",
            listing.expires_at - listing.generated_at
        ));
    }
    if listing.expires_at <= now {
        return (ListingVerification::Expired, Some(listing));
    }
    (
        ListingVerification::Verified {
            key_fingerprint: hex::encode(fp),
        },
        Some(listing),
    )
}

/// What [`list_tags`] returns.
#[derive(Clone, Debug)]
pub struct TagListing {
    /// Repository that was listed.
    pub repository: String,
    /// Tag names, each with its digest **only when** the listing verified.
    /// When it did not, these are the registry's own (unauthenticated) tag
    /// names with no digests.
    pub tags: BTreeMap<String, Option<Digest>>,
    /// The parsed listing, when its signature verified (`Verified`/`Expired`).
    pub listing: Option<MirrorListing>,
    /// The recorded verification result for the listing signature.
    pub verification: ListingVerification,
    /// The tag names `/tags/list` reported, unauthenticated.
    pub registry_tags: Vec<String>,
}

/// Options for [`list_tags`].
#[derive(Clone, Debug, Default)]
pub struct ListOptions {
    /// Override "now" (unix seconds); `None` uses the system clock.
    pub now: Option<u64>,
    /// Where the newest listing seen per repository is remembered. With it, a
    /// verified listing older than the recorded one is reported as
    /// [`ListingVerification::RolledBack`], and a newer one is recorded.
    /// `None` disables rollback protection (the listing is judged on its
    /// signature and expiry alone).
    pub state: Option<ListingState>,
    /// Accept a verified listing even when it is older than the recorded
    /// one, and record it as the new baseline. The operator's explicit reset
    /// for a mirror that was legitimately rebuilt from an older snapshot.
    pub accept_older: bool,
}

/// List a repository's tags and record whether its listing is trustworthy.
///
/// `reference` supplies registry and repository; its tag is ignored.
pub async fn list_tags(
    client: &OciClient,
    reference: &Reference,
    mirror_keys: &MirrorKeyring,
    opts: &ListOptions,
) -> Result<TagListing> {
    let repo = &reference.repository;
    let now = opts.now.unwrap_or_else(now_secs);
    let registry_tags: Vec<String> = client
        .list_tag_names(repo)
        .await?
        .into_iter()
        .filter(|t| t != LISTING_TAG)
        .collect();

    let mut listing_sha256 = String::new();
    let (mut verification, listing) = match fetch_listing_layers(client, reference).await? {
        Fetched::Absent => (ListingVerification::Unsigned, None),
        Fetched::Bad(reason) => (ListingVerification::Invalid { reason }, None),
        Fetched::Layers { listing, signature } => {
            listing_sha256 = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&listing));
            verify_listing(&listing, signature.as_deref(), repo, mirror_keys, now)
        }
    };

    // Rollback protection: only a listing that verified is compared or
    // recorded, so nobody without a mirror key can move the baseline. The
    // record is keyed on what the signature binds (the listing's repository
    // and the signing key), not on the server that delivered it.
    if let (Some(state), ListingVerification::Verified { key_fingerprint }, Some(l)) =
        (&opts.state, &verification, &listing)
    {
        match state.observe(
            &l.repository,
            key_fingerprint,
            l.generated_at,
            &listing_sha256,
            opts.accept_older,
        )? {
            Observation::Recorded | Observation::Same => {}
            Observation::Older { newest_seen } => {
                verification = ListingVerification::RolledBack {
                    newest_seen,
                    offered: l.generated_at,
                };
            }
            Observation::Equivocation { recorded_sha256 } => {
                verification = ListingVerification::Invalid {
                    reason: format!(
                        "equivocation: a different listing (sha256 {recorded_sha256}) with the \
                         same generated_at {} was already seen for this repository and key; \
                         the mirror key signed two listings for one instant",
                        l.generated_at
                    ),
                };
            }
        }
    }

    let tags = match (&verification, &listing) {
        (ListingVerification::Verified { .. }, Some(l)) => l
            .tags
            .iter()
            .map(|(t, d)| (t.clone(), Some(d.clone())))
            .collect(),
        _ => registry_tags.iter().map(|t| (t.clone(), None)).collect(),
    };
    Ok(TagListing {
        repository: repo.clone(),
        tags,
        listing,
        verification,
        registry_tags,
    })
}

enum Fetched {
    Absent,
    Bad(String),
    Layers {
        listing: Vec<u8>,
        signature: Option<Vec<u8>>,
    },
}

async fn fetch_listing_layers(client: &OciClient, reference: &Reference) -> Result<Fetched> {
    let lref = reference.with_selector(Selector::Tag(LISTING_TAG.to_owned()));
    let fetched = match client.get_manifest(&lref, ARTIFACT_TYPE_LISTING).await {
        Ok(f) => f,
        Err(OciError::Status { status: 404, .. }) => return Ok(Fetched::Absent),
        Err(
            e @ (OciError::WrongMediaType { .. }
            | OciError::InvalidManifest(_)
            | OciError::DigestMismatch { .. }
            | OciError::Unsupported(_)),
        ) => return Ok(Fetched::Bad(e.to_string())),
        Err(e) => return Err(e),
    };
    if let Err(e) = check_artifact_type(&fetched.manifest, ARTIFACT_TYPE_LISTING) {
        return Ok(Fetched::Bad(e.to_string()));
    }
    let find = |mt: &str| fetched.manifest.layers.iter().find(|l| l.media_type == mt);
    let Some(ldesc) = find(LAYER_TYPE_LISTING) else {
        return Ok(Fetched::Bad("listing artifact has no listing layer".into()));
    };
    if ldesc.size > MAX_LISTING_BYTES {
        return Ok(Fetched::Bad("listing layer is too large".into()));
    }
    let listing = client.get_blob(&reference.repository, ldesc).await?;
    let signature = match find(LAYER_TYPE_LISTING_SIG) {
        Some(sd) if sd.size <= MAX_LISTING_BYTES => {
            Some(client.get_blob(&reference.repository, sd).await?)
        }
        Some(_) => return Ok(Fetched::Bad("signature layer is too large".into())),
        None => None,
    };
    Ok(Fetched::Layers { listing, signature })
}

/// Build a listing for a repository from the registry's current tags.
pub async fn build_listing(
    client: &OciClient,
    reference: &Reference,
    ttl_secs: u64,
    now: Option<u64>,
) -> Result<MirrorListing> {
    let now = now.unwrap_or_else(now_secs);
    let mut tags = BTreeMap::new();
    for t in client.list_tag_names(&reference.repository).await? {
        if t == LISTING_TAG {
            continue;
        }
        let r = reference.with_selector(Selector::Tag(t.clone()));
        tags.insert(t, client.manifest_digest(&r).await?);
    }
    Ok(MirrorListing {
        version: 1,
        repository: reference.repository.clone(),
        tags,
        generated_at: now,
        expires_at: now.saturating_add(ttl_secs.max(1)),
    })
}

/// Sign `listing` with `key` and publish it at [`LISTING_TAG`].
pub async fn publish_listing(
    client: &OciClient,
    reference: &Reference,
    listing: &MirrorListing,
    key: &IdentityKeyPair,
) -> Result<Digest> {
    let (lb, sb) = sign_listing(listing, key)?;
    let target = reference.with_selector(Selector::Tag(LISTING_TAG.to_owned()));
    let (digest, _) = push_layers(
        client,
        &target,
        ARTIFACT_TYPE_LISTING,
        &[(LAYER_TYPE_LISTING, &lb), (LAYER_TYPE_LISTING_SIG, &sb)],
    )
    .await?;
    Ok(digest)
}

/// Publish a listing document with no signature (for tests and for operators
/// who want to see the `Unsigned` status).
#[doc(hidden)]
pub async fn publish_unsigned_listing(
    client: &OciClient,
    reference: &Reference,
    listing: &MirrorListing,
) -> Result<Digest> {
    let lb = serde_json::to_vec(listing).map_err(|e| OciError::Listing(e.to_string()))?;
    let target = reference.with_selector(Selector::Tag(LISTING_TAG.to_owned()));
    let (digest, _) = push_layers(
        client,
        &target,
        ARTIFACT_TYPE_LISTING,
        &[(LAYER_TYPE_LISTING, &lb)],
    )
    .await?;
    Ok(digest)
}
