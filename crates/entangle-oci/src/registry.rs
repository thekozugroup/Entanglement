//! OCI Distribution pull and authenticated mirror tag enumeration.
use anyhow::{bail, ensure, Context, Result};
use entangle_signing::{IdentityPublicKey, Keyring, Signature};
use reqwest::{header, redirect, Client, Response, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::{PackageFiles, ARCHIVE_LIMIT, COMPONENT_LIMIT, MANIFEST_LIMIT, SIGNATURE_LIMIT};

const IMAGE: &str = "application/vnd.oci.image.manifest.v1+json";
const LAYERS: [(&str, usize); 3] = [
    ("application/vnd.entangle.manifest.+toml", MANIFEST_LIMIT),
    ("application/wasm", COMPONENT_LIMIT),
    (
        "application/vnd.entangle.signature.+ed25519",
        SIGNATURE_LIMIT,
    ),
];
/// Header carrying a hex-encoded signature over the tag listing.
pub const LISTING_SIGNATURE: &str = "entangle-listing-signature";
/// Prepend these bytes to the exact JSON response when signing mirror listings.
pub const LISTING_DOMAIN: &[u8] = b"entangle/oci-tags/v1\0";

fn loopback(url: &Url) -> bool {
    matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback())
}

fn allowed(url: &Url) -> bool {
    url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https" || (url.scheme() == "http" && loopback(url)))
}

fn client(local_http: bool) -> Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let builder = if local_http {
        Client::builder().no_proxy()
    } else {
        Client::builder()
    };
    Ok(builder
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(10))
        .redirect(redirect::Policy::custom(move |attempt| {
            let next = attempt.url();
            let previous = attempt.previous();
            let same_origin = previous
                .first()
                .is_some_and(|first| first.origin() == next.origin());
            let allowed_transport = if local_http {
                same_origin
            } else {
                next.scheme() == "https"
            };
            if previous.len() < 5 && allowed(next) && allowed_transport {
                attempt.follow()
            } else {
                attempt.error("unsupported package redirect")
            }
        }))
        .build()?)
}

async fn body(response: Response, limit: usize) -> Result<Vec<u8>> {
    let mut response = response.error_for_status()?;
    ensure!(
        response.status().is_success(),
        "unexpected response status {}",
        response.status()
    );
    ensure!(
        response.content_length().unwrap_or(0) <= limit as u64,
        "response exceeds size limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= limit - bytes.len(),
            "response exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Fetch a signed archive and its adjacent detached signature over HTTPS.
pub async fn fetch_archive(
    reference: &str,
    http_loopback: bool,
    keyring: &Keyring,
) -> Result<PackageFiles> {
    let url = Url::parse(reference)?;
    ensure!(
        allowed(&url)
            && (url.scheme() == "https" || http_loopback)
            && url.path().ends_with(".tar.zst"),
        "expected HTTPS tar.zst URL"
    );
    let mut sig_url = url.clone();
    // Keep the original path percent-encoding and query when appending the suffix.
    sig_url.set_path(&format!("{}.sig", url.path()));
    let http = client(url.scheme() == "http")?;
    let sig = body(http.get(sig_url).send().await?, 64).await?;
    let bytes = body(http.get(url).send().await?, ARCHIVE_LIMIT).await?;
    PackageFiles::from_signed_archive(&bytes, &sig, keyring)
}

fn valid_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn valid_tag(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with(['.', '-'])
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

struct Repository {
    base: Url,
    name: String,
}

impl Repository {
    fn parse(reference: &str, http_loopback: bool) -> Result<Self> {
        let (authority, name) = reference
            .strip_prefix("oci://")
            .context("expected oci://registry/repository")?
            .split_once('/')
            .context("missing repository")?;
        ensure!(
            !authority.is_empty() && !authority.contains(['@', '?', '#', '\\', '%']),
            "invalid registry authority"
        );
        ensure!(
            name.len() <= 255
                && name.split('/').all(|s| !s.is_empty()
                    && s.as_bytes()[0].is_ascii_alphanumeric()
                    && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
                    && s.bytes().all(|b| b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || b"._-".contains(&b))),
            "invalid repository name"
        );
        let scheme = if http_loopback { "http" } else { "https" };
        let base = Url::parse(&format!("{scheme}://{authority}/v2/{name}/"))?;
        ensure!(
            allowed(&base),
            "HTTP registries require a loopback IP address"
        );
        Ok(Self {
            base,
            name: name.into(),
        })
    }
}

/// A fully authenticated listing and the independently configured mirror fingerprint.
#[derive(Debug, serde::Serialize)]
pub struct VerifiedTags {
    /// Repository that the mirror signed.
    pub name: String,
    /// Tags authenticated by the mirror.
    pub tags: Vec<String>,
    /// Fingerprint of the key that verified the response.
    pub mirror_fingerprint: String,
}

/// Fetch one complete signed listing. Refuse paginated responses to avoid exposing a partial catalog.
pub async fn list_tags(
    repository: &str,
    http_loopback: bool,
    mirror: &IdentityPublicKey,
) -> Result<VerifiedTags> {
    let repo = Repository::parse(repository, http_loopback)?;
    let response = client(repo.base.scheme() == "http")?
        .get(repo.base.join("tags/list")?)
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        !response.headers().contains_key(header::LINK),
        "paginated mirror listings are unsupported"
    );
    let sig = response
        .headers()
        .get(LISTING_SIGNATURE)
        .context("missing listing signature")?
        .to_str()?;
    let sig = Signature::from_bytes(&hex::decode(sig)?)?;
    let bytes = body(response, MANIFEST_LIMIT).await?;
    mirror.verify(&[LISTING_DOMAIN, &bytes].concat(), &sig)?;
    #[derive(Deserialize)]
    struct Listing {
        name: String,
        tags: Option<Vec<String>>,
    }
    let listing: Listing = serde_json::from_slice(&bytes)?;
    ensure!(
        listing.name == repo.name,
        "signed listing names another repository"
    );
    let tags = listing.tags.unwrap_or_default();
    ensure!(
        tags.iter().all(|tag| valid_tag(tag)),
        "invalid tag in listing"
    );
    let mirror_fingerprint = mirror.fingerprint_hex();
    tracing::info!(repository = %listing.name, %mirror_fingerprint, "verified mirror tag listing");
    Ok(VerifiedTags {
        name: listing.name,
        tags,
        mirror_fingerprint,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Image {
    schema_version: u32,
    media_type: Option<String>,
    config: Descriptor,
    layers: Vec<Descriptor>,
}

fn check_digest(bytes: &[u8], digest: &str) -> Result<()> {
    ensure!(
        valid_digest(digest) && hex::encode(Sha256::digest(bytes)) == digest[7..],
        "OCI digest mismatch"
    );
    Ok(())
}

async fn get(http: &Client, url: Url, token: Option<&str>) -> Result<Response> {
    let mut req = http.get(url).header(header::ACCEPT, IMAGE);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    Ok(req.send().await?)
}

// Public Distribution registries issue anonymous, repository-scoped pull tokens.
async fn anonymous_token(http: &Client, response: &Response, repo: &Repository) -> Result<String> {
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .context("missing registry authentication challenge")?
        .to_str()?;
    let (scheme, params) = challenge
        .split_once(' ')
        .context("invalid authentication challenge")?;
    ensure!(
        scheme.eq_ignore_ascii_case("bearer"),
        "registry requires a non-anonymous credential"
    );
    let mut fields = std::collections::BTreeMap::new();
    for part in params.split(',') {
        let (key, quoted) = part
            .trim()
            .split_once('=')
            .context("invalid bearer challenge")?;
        let val = quoted
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .context("invalid bearer parameter")?;
        ensure!(
            !val.contains(['"', '\\']) && fields.insert(key, val).is_none(),
            "ambiguous bearer challenge"
        );
    }
    let mut url = Url::parse(
        fields
            .get("realm")
            .context("missing registry token realm")?,
    )?;
    ensure!(
        allowed(&url)
            && (if repo.base.scheme() == "http" {
                url.origin() == repo.base.origin()
            } else {
                url.scheme() == "https"
            })
            && url.query().is_none(),
        "invalid registry token realm"
    );
    let scope = format!("repository:{}:pull", repo.name);
    if let Some(claimed) = fields.get("scope") {
        ensure!(**claimed == scope, "unexpected registry token scope");
    }
    if let Some(service) = fields.get("service") {
        url.query_pairs_mut().append_pair("service", service);
    }
    url.query_pairs_mut().append_pair("scope", &scope);
    #[derive(Deserialize)]
    struct Token {
        token: Option<String>,
        access_token: Option<String>,
    }
    let token: Token =
        serde_json::from_slice(&body(http.get(url).send().await?, SIGNATURE_LIMIT).await?)?;
    token
        .token
        .or(token.access_token)
        .filter(|v| !v.is_empty())
        .context("registry returned no token")
}

/// Pull and authenticate a three-layer OCI image by tag or pinned manifest digest.
/// HTTP is available only with explicit opt-in and a loopback IP.
pub async fn pull(reference: &str, http_loopback: bool, keyring: &Keyring) -> Result<PackageFiles> {
    let (repo, target) = if let Some((repo, digest)) = reference.rsplit_once('@') {
        ensure!(valid_digest(digest), "invalid pinned manifest digest");
        (repo, digest)
    } else {
        let (repo, tag) = reference.rsplit_once(':').context("missing OCI tag")?;
        ensure!(valid_tag(tag), "invalid or missing OCI tag");
        (repo, tag)
    };
    let repo = Repository::parse(repo, http_loopback)?;
    let url = repo.base.join(&format!("manifests/{target}"))?;
    let http = client(url.scheme() == "http")?;
    let mut response = get(&http, url.clone(), None).await?;
    let mut token = None;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        token = Some(anonymous_token(&http, &response, &repo).await?);
        response = get(&http, url, token.as_deref()).await?;
    }
    let digest = response
        .headers()
        .get("docker-content-digest")
        .map(|s| s.to_str().map(str::to_owned))
        .transpose()?;
    let bytes = body(response, MANIFEST_LIMIT).await?;
    if valid_digest(target) {
        check_digest(&bytes, target)?;
    }
    if let Some(digest) = digest {
        check_digest(&bytes, &digest)?;
    }
    let image: Image = serde_json::from_slice(&bytes)?;
    ensure!(
        image.schema_version == 2
            && image.media_type.as_deref().is_none_or(|s| s == IMAGE)
            && image.layers.len() == 3,
        "expected OCI v1 three-layer image manifest"
    );
    ensure!(
        valid_digest(&image.config.digest) && !image.config.media_type.is_empty(),
        "invalid OCI config descriptor"
    );
    let mut files: [Option<Vec<u8>>; 3] = Default::default();
    for layer in &image.layers {
        let i = LAYERS
            .iter()
            .position(|(name, _)| *name == layer.media_type)
            .context("unknown OCI layer type")?;
        let limit = LAYERS[i].1;
        ensure!(
            files[i].is_none() && valid_digest(&layer.digest) && layer.size <= limit as u64,
            "invalid or duplicate OCI descriptor"
        );
        let url = repo.base.join(&format!("blobs/{}", layer.digest))?;
        let bytes = body(
            get(&http, url, token.as_deref()).await?,
            layer.size as usize,
        )
        .await?;
        ensure!(
            bytes.len() as u64 == layer.size,
            "OCI descriptor size mismatch"
        );
        check_digest(&bytes, &layer.digest)?;
        files[i] = Some(bytes);
    }
    let [Some(manifest), Some(component), Some(signature)] = files else {
        bail!("missing OCI layer")
    };
    PackageFiles::verify(manifest, component, signature, None, keyring)
}
