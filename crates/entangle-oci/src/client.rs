//! The OCI Distribution v1.1 client: auth, redirects, retries, verified blobs.
//!
//! Invariants enforced here (each has a test in `tests/registry.rs`):
//! * `Authorization` is only ever sent to the registry's own `host:port`; a
//!   redirect to any other authority (a CDN) is followed without it.
//! * Only HTTP 429 and 5xx are retried, with capped exponential backoff.
//! * Blob bytes are hashed while streaming and rejected on any digest or size
//!   difference from the descriptor; the descriptor size is also checked
//!   against the configured cap before a single byte is requested.
//! * Nothing here knows about publisher trust: it returns bytes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::{HeaderMap, Method, Response};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::auth::{Credential, Secret};
use crate::error::{OciError, Result};
use crate::http::{authority, is_loopback_host, Transport};
use crate::reference::{Digest, Reference, Selector};
use crate::types::*;

/// Retry behaviour for HTTP 429 and 5xx responses.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    /// Total attempts including the first.
    pub max_attempts: u32,
    /// Delay before the second attempt; doubles each time.
    pub base_delay: Duration,
    /// Upper bound for any single delay (also caps `Retry-After`).
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(8),
        }
    }
}

/// Client configuration.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Speak plain HTTP to this registry even if it is not loopback
    /// (`--insecure-registry`). Loopback registries always use plain HTTP.
    pub insecure_registry: bool,
    /// Credential for the registry, if any.
    pub credential: Option<Credential>,
    /// Largest blob accepted (descriptor size is checked against this).
    pub max_blob_bytes: u64,
    /// Largest manifest/index/token/tag-list body accepted.
    pub max_manifest_bytes: u64,
    /// Retry policy.
    pub retry: RetryPolicy,
    /// Per-request connect/header timeout and per-read idle timeout.
    pub timeout: Duration,
    /// Upload chunk size; blobs at most this large are uploaded monolithically.
    pub chunk_size: usize,
    /// Maximum redirects followed per request.
    pub max_redirects: u8,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            insecure_registry: false,
            credential: None,
            max_blob_bytes: 512 * 1024 * 1024,
            max_manifest_bytes: 4 * 1024 * 1024,
            retry: RetryPolicy::default(),
            timeout: Duration::from_secs(30),
            chunk_size: 4 * 1024 * 1024,
            max_redirects: 5,
        }
    }
}

/// A manifest as fetched, with the digest of its exact bytes.
#[derive(Clone, Debug)]
pub struct FetchedManifest {
    /// SHA-256 of `raw`.
    pub digest: Digest,
    /// Parsed manifest.
    pub manifest: ImageManifest,
    /// The exact bytes the registry served.
    pub raw: Bytes,
}

/// A client bound to one registry.
pub struct OciClient {
    registry: String,
    base: Url,
    cfg: ClientConfig,
    transport: Transport,
    tokens: Mutex<HashMap<String, Secret>>,
    basic_challenged: AtomicBool,
}

struct Req {
    method: Method,
    url: Url,
    headers: Vec<(String, String)>,
    body: Bytes,
    /// Token scope; `None` means "send no registry credentials" (token fetches).
    scope: Option<String>,
    /// Explicit `Authorization` value, only sent to the original authority.
    explicit_auth: Option<String>,
    what: String,
}

impl Req {
    fn new(method: Method, url: Url, scope: Option<String>, what: impl Into<String>) -> Self {
        Self {
            method,
            url,
            headers: Vec::new(),
            body: Bytes::new(),
            scope,
            explicit_auth: None,
            what: what.into(),
        }
    }
    fn header(mut self, k: &str, v: impl Into<String>) -> Self {
        self.headers.push((k.to_owned(), v.into()));
        self
    }
    fn body(mut self, b: Bytes) -> Self {
        self.body = b;
        self
    }
}

impl OciClient {
    /// Create a client for `registry` (`host[:port]`).
    pub fn new(registry: &str, cfg: ClientConfig) -> Result<Self> {
        let plain = cfg.insecure_registry || is_loopback_host(registry);
        let scheme = if plain { "http" } else { "https" };
        let base = Url::parse(&format!("{scheme}://{registry}/")).map_err(|e| {
            OciError::InvalidReference {
                reference: registry.to_owned(),
                reason: e.to_string(),
            }
        })?;
        let transport = Transport::new(cfg.insecure_registry, cfg.timeout);
        Ok(Self {
            registry: authority(&base),
            base,
            cfg,
            transport,
            tokens: Mutex::new(HashMap::new()),
            basic_challenged: AtomicBool::new(false),
        })
    }

    /// Create a client for the registry named by `reference`.
    pub fn for_reference(reference: &Reference, cfg: ClientConfig) -> Result<Self> {
        Self::new(&reference.registry, cfg)
    }

    /// The registry's `host:port`.
    pub fn registry(&self) -> &str {
        &self.registry
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.base.join(path).map_err(|e| OciError::Transport {
            host: self.registry.clone(),
            detail: format!("bad URL path {path:?}: {e}"),
        })
    }

    fn auth_err(&self, detail: impl Into<String>) -> OciError {
        OciError::Auth {
            host: self.registry.clone(),
            detail: detail.into(),
        }
    }

    fn lock_tokens(&self) -> std::sync::MutexGuard<'_, HashMap<String, Secret>> {
        // A poisoned lock only means another thread panicked mid-insert of a
        // String->Secret pair; the map is still structurally valid.
        self.tokens.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The `Authorization` value for a registry-bound request, if we have one.
    fn registry_auth(&self, scope: &str) -> Option<String> {
        if let Some(t) = self.lock_tokens().get(scope) {
            return Some(format!("Bearer {}", t.expose()));
        }
        match &self.cfg.credential {
            Some(Credential::Bearer(t)) => Some(format!("Bearer {}", t.expose())),
            Some(Credential::Basic { username, password })
                if self.basic_challenged.load(Ordering::Relaxed) =>
            {
                Some(basic_header(username, password))
            }
            _ => None,
        }
    }

    // -----------------------------------------------------------------
    // Core request loop
    // -----------------------------------------------------------------

    async fn execute(&self, req: &Req) -> Result<Response<Incoming>> {
        let origin = authority(&req.url);
        let mut url = req.url.clone();
        let mut method = req.method.clone();
        let mut body = req.body.clone();
        let mut redirects = 0u8;
        let mut attempts = 0u32;
        let mut challenged = false;

        loop {
            let here = authority(&url);
            let mut headers = req.headers.clone();
            // The one place Authorization is decided.
            let auth = match (&req.scope, &req.explicit_auth) {
                (Some(scope), _) if here == self.registry => self.registry_auth(scope),
                (None, Some(v)) if here == origin => Some(v.clone()),
                _ => None,
            };
            if let Some(v) = auth {
                headers.push(("authorization".into(), v));
            }

            let resp = self
                .transport
                .send(&method, &url, &headers, body.clone())
                .await?;
            let status = resp.status().as_u16();

            match status {
                401 if req.scope.is_some() && here == self.registry => {
                    if challenged {
                        return Err(self.auth_err(format!(
                            "registry rejected the credentials for {}",
                            req.what
                        )));
                    }
                    challenged = true;
                    let www = www_authenticate(resp.headers());
                    drop(resp);
                    self.answer_challenge(www, req.scope.as_deref().unwrap_or_default())
                        .await?;
                }
                301 | 302 | 303 | 307 | 308 => {
                    let loc = resp
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    drop(resp);
                    let loc = loc.ok_or_else(|| {
                        OciError::Redirect(format!("{status} without Location from {here}"))
                    })?;
                    redirects += 1;
                    if redirects > self.cfg.max_redirects {
                        return Err(OciError::Redirect(format!(
                            "more than {} redirects",
                            self.cfg.max_redirects
                        )));
                    }
                    url = url.join(&loc).map_err(|e| {
                        OciError::Redirect(format!("unparseable Location {loc:?}: {e}"))
                    })?;
                    if status == 303 || (matches!(status, 301 | 302) && method == Method::POST) {
                        method = Method::GET;
                        body = Bytes::new();
                    }
                }
                429 | 500..=599 => {
                    attempts += 1;
                    let retry_after = retry_after(resp.headers());
                    drop(resp);
                    if attempts >= self.cfg.retry.max_attempts {
                        return Err(OciError::RetriesExhausted {
                            host: here,
                            attempts,
                            status,
                        });
                    }
                    let backoff = self
                        .cfg
                        .retry
                        .base_delay
                        .saturating_mul(1u32 << (attempts - 1).min(16));
                    let delay = retry_after.unwrap_or(backoff).min(self.cfg.retry.max_delay);
                    tracing::debug!(host = %here, status, attempt = attempts, ?delay, "retrying");
                    tokio::time::sleep(delay).await;
                }
                _ => return Ok(resp),
            }
        }
    }

    async fn answer_challenge(&self, www: Vec<Challenge>, scope: &str) -> Result<()> {
        if matches!(self.cfg.credential, Some(Credential::Bearer(_))) {
            return Err(self.auth_err("registry rejected the configured bearer token"));
        }
        self.lock_tokens().remove(scope);
        if let Some(c) = www.iter().find(|c| c.scheme.eq_ignore_ascii_case("bearer")) {
            let realm = c
                .param("realm")
                .ok_or_else(|| self.auth_err("Bearer challenge without realm"))?;
            let service = c.param("service");
            // The registry may widen/narrow the scope it wants; use its words.
            let want_scope = c.param("scope").unwrap_or(scope);
            let token = self.fetch_token(realm, service, want_scope).await?;
            self.lock_tokens().insert(scope.to_owned(), token);
            return Ok(());
        }
        if www.iter().any(|c| c.scheme.eq_ignore_ascii_case("basic")) {
            return match self.cfg.credential {
                Some(Credential::Basic { .. }) => {
                    self.basic_challenged.store(true, Ordering::Relaxed);
                    Ok(())
                }
                _ => Err(self.auth_err(
                    "registry requires Basic authentication but no credential is configured \
                     (set ENTANGLE_OCI_USERNAME/ENTANGLE_OCI_PASSWORD or ~/.entangle/oci-auth.toml)",
                )),
            };
        }
        Err(self.auth_err(if self.cfg.credential.is_none() {
            "registry requires authentication and offered no usable scheme; no credential configured"
        } else {
            "registry offered no supported authentication scheme"
        }))
    }

    async fn fetch_token(&self, realm: &str, service: Option<&str>, scope: &str) -> Result<Secret> {
        let mut url = Url::parse(realm)
            .or_else(|_| self.base.join(realm))
            .map_err(|e| self.auth_err(format!("bad token realm {realm:?}: {e}")))?;
        {
            let mut q = url.query_pairs_mut();
            if let Some(s) = service {
                q.append_pair("service", s);
            }
            if !scope.is_empty() {
                q.append_pair("scope", scope);
            }
        }
        let mut req =
            Req::new(Method::GET, url, None, "token request").header("accept", "application/json");
        if let Some(Credential::Basic { username, password }) = &self.cfg.credential {
            req.explicit_auth = Some(basic_header(username, password));
        }
        // Boxed: execute -> answer_challenge -> fetch_token -> execute.
        let resp = Box::pin(self.execute(&req)).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(self.auth_err(format!("token endpoint answered HTTP {}", status.as_u16())));
        }
        let body = read_limited(
            resp.into_body(),
            self.cfg.max_manifest_bytes,
            "token response",
            self.transport.timeout(),
        )
        .await?;
        #[derive(serde::Deserialize)]
        struct Tok {
            token: Option<String>,
            access_token: Option<String>,
        }
        let t: Tok = serde_json::from_slice(&body)
            .map_err(|_| self.auth_err("token endpoint returned malformed JSON"))?;
        t.token
            .or(t.access_token)
            .filter(|s| !s.is_empty())
            .map(Secret::new)
            .ok_or_else(|| self.auth_err("token endpoint returned no token"))
    }

    async fn expect(
        &self,
        resp: Response<Incoming>,
        ok: &[u16],
        what: &str,
    ) -> Result<Response<Incoming>> {
        let status = resp.status().as_u16();
        if ok.contains(&status) {
            return Ok(resp);
        }
        let detail = match read_limited(
            resp.into_body(),
            4096,
            "error body",
            self.transport.timeout(),
        )
        .await
        {
            Ok(b) => registry_error_text(&b),
            Err(_) => String::new(),
        };
        Err(OciError::Status {
            host: self.registry.clone(),
            status,
            what: what.to_owned(),
            detail,
        })
    }

    fn pull_scope(repo: &str) -> String {
        format!("repository:{repo}:pull")
    }

    fn push_scope(repo: &str) -> String {
        format!("repository:{repo}:pull,push")
    }

    // -----------------------------------------------------------------
    // Pull side
    // -----------------------------------------------------------------

    /// Fetch and validate a manifest. An image index is resolved to the single
    /// child whose `artifactType` is `want_artifact_type`.
    pub async fn get_manifest(
        &self,
        reference: &Reference,
        want_artifact_type: &str,
    ) -> Result<FetchedManifest> {
        let first = self
            .get_manifest_raw(&reference.repository, &reference.selector)
            .await?;
        match first {
            Raw::Manifest(m) => Ok(m),
            Raw::Index(idx, index_digest) => {
                let mut hits = idx.manifests.iter().filter(|d| {
                    d.media_type == MEDIA_TYPE_MANIFEST
                        && d.artifact_type.as_deref() == Some(want_artifact_type)
                });
                let (Some(child), None) = (hits.next(), hits.next()) else {
                    return Err(OciError::Unsupported(format!(
                        "image index {index_digest} must contain exactly one manifest with \
                         artifactType {want_artifact_type}"
                    )));
                };
                match self
                    .get_manifest_raw(
                        &reference.repository,
                        &Selector::Digest(child.digest.clone()),
                    )
                    .await?
                {
                    Raw::Manifest(m) => Ok(m),
                    Raw::Index(..) => Err(OciError::Unsupported("nested image index".into())),
                }
            }
        }
    }

    /// Digest of the manifest (or index) a reference currently points at,
    /// without resolving indexes. Used to build mirror listings.
    pub async fn manifest_digest(&self, reference: &Reference) -> Result<Digest> {
        Ok(
            match self
                .get_manifest_raw(&reference.repository, &reference.selector)
                .await?
            {
                Raw::Manifest(m) => m.digest,
                Raw::Index(_, d) => d,
            },
        )
    }

    async fn get_manifest_raw(&self, repo: &str, sel: &Selector) -> Result<Raw> {
        let url = self.url(&format!("v2/{repo}/manifests/{}", sel.as_path()))?;
        let req = Req::new(
            Method::GET,
            url,
            Some(Self::pull_scope(repo)),
            "GET manifest",
        )
        .header(
            "accept",
            format!("{MEDIA_TYPE_MANIFEST}, {MEDIA_TYPE_INDEX}"),
        );
        let resp = self.execute(&req).await?;
        let resp = self.expect(resp, &[200], "GET manifest").await?;
        let ctype = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            });
        let header_digest = resp
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let raw = read_limited(
            resp.into_body(),
            self.cfg.max_manifest_bytes,
            "manifest",
            self.transport.timeout(),
        )
        .await?;
        let digest = Digest::of(&raw);
        if let Selector::Digest(want) = sel {
            if *want != digest {
                return Err(OciError::DigestMismatch {
                    what: "manifest".into(),
                    expected: want.to_string(),
                    actual: digest.to_string(),
                });
            }
        }
        if let Some(h) = header_digest {
            if h != digest.as_str() {
                return Err(OciError::DigestMismatch {
                    what: "manifest (Docker-Content-Digest header)".into(),
                    expected: h,
                    actual: digest.to_string(),
                });
            }
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Peek {
            #[serde(default)]
            media_type: String,
        }
        let peek: Peek = serde_json::from_slice(&raw)
            .map_err(|e| OciError::InvalidManifest(format!("not JSON: {e}")))?;
        let effective = match (ctype.as_deref(), peek.media_type.as_str()) {
            (Some(c), b) if !b.is_empty() && c != b => {
                return Err(OciError::WrongMediaType {
                    what: "manifest (Content-Type vs body mediaType)".into(),
                    expected: c.to_owned(),
                    actual: b.to_owned(),
                })
            }
            (Some(c), _) => c.to_owned(),
            (None, b) => b.to_owned(),
        };
        match effective.as_str() {
            MEDIA_TYPE_MANIFEST => {
                let manifest: ImageManifest = serde_json::from_slice(&raw)
                    .map_err(|e| OciError::InvalidManifest(e.to_string()))?;
                if manifest.schema_version != 2 {
                    return Err(OciError::InvalidManifest(format!(
                        "schemaVersion {} (expected 2)",
                        manifest.schema_version
                    )));
                }
                Ok(Raw::Manifest(FetchedManifest {
                    digest,
                    manifest,
                    raw: Bytes::from(raw),
                }))
            }
            MEDIA_TYPE_INDEX => {
                let idx: ImageIndex = serde_json::from_slice(&raw)
                    .map_err(|e| OciError::InvalidManifest(e.to_string()))?;
                Ok(Raw::Index(idx, digest))
            }
            other => Err(OciError::WrongMediaType {
                what: "manifest".into(),
                expected: format!("{MEDIA_TYPE_MANIFEST} or {MEDIA_TYPE_INDEX}"),
                actual: other.to_owned(),
            }),
        }
    }

    /// Fetch a blob, verifying size and SHA-256 against `desc` while streaming.
    pub async fn get_blob(&self, repo: &str, desc: &Descriptor) -> Result<Vec<u8>> {
        if desc.size > self.cfg.max_blob_bytes {
            return Err(OciError::TooLarge {
                what: format!("blob {}", desc.digest),
                size: desc.size,
                limit: self.cfg.max_blob_bytes,
            });
        }
        let url = self.url(&format!("v2/{repo}/blobs/{}", desc.digest))?;
        let req = Req::new(Method::GET, url, Some(Self::pull_scope(repo)), "GET blob");
        let resp = self.execute(&req).await?;
        let resp = self.expect(resp, &[200], "GET blob").await?;
        if let Some(len) = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        {
            if len != desc.size {
                return Err(OciError::SizeMismatch {
                    what: format!("blob {}", desc.digest),
                    expected: desc.size,
                    actual: len,
                });
            }
        }
        let what = format!("blob {}", desc.digest);
        let mut body = resp.into_body();
        let mut hasher = Sha256::new();
        let mut buf = Vec::with_capacity(desc.size.min(16 * 1024 * 1024) as usize);
        loop {
            let frame = tokio::time::timeout(self.transport.timeout(), body.frame())
                .await
                .map_err(|_| OciError::Timeout(format!("reading {what}")))?;
            let Some(frame) = frame else { break };
            let frame = frame.map_err(|e| OciError::Transport {
                host: self.registry.clone(),
                detail: format!("reading {what}: {e}"),
            })?;
            if let Ok(data) = frame.into_data() {
                // Checked per chunk, so a hostile stream is cut off as soon as
                // it exceeds the descriptor, not after it finished.
                if buf.len() as u64 + data.len() as u64 > desc.size {
                    return Err(OciError::SizeMismatch {
                        what,
                        expected: desc.size,
                        actual: buf.len() as u64 + data.len() as u64,
                    });
                }
                hasher.update(&data);
                buf.extend_from_slice(&data);
            }
        }
        if buf.len() as u64 != desc.size {
            return Err(OciError::SizeMismatch {
                what,
                expected: desc.size,
                actual: buf.len() as u64,
            });
        }
        let actual = Digest::from_raw(hasher.finalize().into());
        if actual != desc.digest {
            return Err(OciError::DigestMismatch {
                what,
                expected: desc.digest.to_string(),
                actual: actual.to_string(),
            });
        }
        Ok(buf)
    }

    /// List the repository's tag names (follows `Link: rel="next"` pagination).
    pub async fn list_tag_names(&self, repo: &str) -> Result<Vec<String>> {
        #[derive(serde::Deserialize)]
        struct Tags {
            #[serde(default)]
            tags: Option<Vec<String>>,
        }
        let mut out = Vec::new();
        let mut url = self.url(&format!("v2/{repo}/tags/list?n=100"))?;
        for _ in 0..100 {
            let req = Req::new(
                Method::GET,
                url.clone(),
                Some(Self::pull_scope(repo)),
                "GET tags/list",
            );
            let resp = self.execute(&req).await?;
            let resp = self.expect(resp, &[200], "GET tags/list").await?;
            let next = resp
                .headers()
                .get("link")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_link_next);
            let body = read_limited(
                resp.into_body(),
                self.cfg.max_manifest_bytes,
                "tag list",
                self.transport.timeout(),
            )
            .await?;
            let t: Tags = serde_json::from_slice(&body)
                .map_err(|e| OciError::InvalidManifest(format!("tag list: {e}")))?;
            out.extend(t.tags.unwrap_or_default());
            match next {
                Some(n) => {
                    url = url
                        .join(&n)
                        .map_err(|e| OciError::InvalidManifest(format!("Link header: {e}")))?
                }
                None => return Ok(out),
            }
        }
        Err(OciError::Unsupported(
            "tag list has more than 100 pages".into(),
        ))
    }

    // -----------------------------------------------------------------
    // Push side
    // -----------------------------------------------------------------

    /// Does the registry already hold this blob?
    pub async fn blob_exists(&self, repo: &str, digest: &Digest) -> Result<bool> {
        let url = self.url(&format!("v2/{repo}/blobs/{digest}"))?;
        let req = Req::new(Method::HEAD, url, Some(Self::push_scope(repo)), "HEAD blob");
        let resp = self.execute(&req).await?;
        match resp.status().as_u16() {
            200 => Ok(true),
            404 => Ok(false),
            _ => {
                self.expect(resp, &[200, 404], "HEAD blob").await?;
                Ok(false)
            }
        }
    }

    /// Upload a blob (monolithic if it fits one chunk, chunked otherwise).
    pub async fn push_blob(&self, repo: &str, data: &[u8]) -> Result<Digest> {
        let digest = Digest::of(data);
        if self.blob_exists(repo, &digest).await? {
            return Ok(digest);
        }
        let scope = Self::push_scope(repo);
        let start = self.url(&format!("v2/{repo}/blobs/uploads/"))?;
        let req = Req::new(Method::POST, start, Some(scope.clone()), "POST blob upload");
        let resp = self.execute(&req).await?;
        let resp = self.expect(resp, &[202], "POST blob upload").await?;
        let mut location = self.location(&req.url, resp.headers())?;
        drop(resp);

        let chunk = self.cfg.chunk_size.max(1);
        if data.len() > chunk {
            let mut offset = 0usize;
            while offset < data.len() {
                let end = (offset + chunk).min(data.len());
                let req = Req::new(
                    Method::PATCH,
                    location.clone(),
                    Some(scope.clone()),
                    "PATCH blob chunk",
                )
                .header("content-type", "application/octet-stream")
                .header("content-range", format!("{offset}-{}", end - 1))
                .body(Bytes::copy_from_slice(&data[offset..end]));
                let resp = self.execute(&req).await?;
                let resp = self.expect(resp, &[202], "PATCH blob chunk").await?;
                location = self.location(&req.url, resp.headers())?;
                offset = end;
            }
            location
                .query_pairs_mut()
                .append_pair("digest", digest.as_str());
            let req = Req::new(Method::PUT, location, Some(scope), "PUT blob finalize");
            let resp = self.execute(&req).await?;
            self.expect(resp, &[201], "PUT blob finalize").await?;
        } else {
            location
                .query_pairs_mut()
                .append_pair("digest", digest.as_str());
            let req = Req::new(Method::PUT, location, Some(scope), "PUT blob")
                .header("content-type", "application/octet-stream")
                .body(Bytes::copy_from_slice(data));
            let resp = self.execute(&req).await?;
            self.expect(resp, &[201], "PUT blob").await?;
        }
        Ok(digest)
    }

    fn location(&self, current: &Url, headers: &HeaderMap) -> Result<Url> {
        let loc = headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| OciError::Upload("registry did not return an upload Location".into()))?;
        current
            .join(loc)
            .map_err(|e| OciError::Upload(format!("bad upload Location {loc:?}: {e}")))
    }

    /// `PUT` a manifest under `selector`; returns its digest.
    pub async fn put_manifest(
        &self,
        repo: &str,
        selector: &Selector,
        manifest_bytes: &[u8],
        media_type: &str,
    ) -> Result<Digest> {
        let digest = Digest::of(manifest_bytes);
        if let Selector::Digest(d) = selector {
            if *d != digest {
                return Err(OciError::DigestMismatch {
                    what: "manifest to push".into(),
                    expected: d.to_string(),
                    actual: digest.to_string(),
                });
            }
        }
        let url = self.url(&format!("v2/{repo}/manifests/{}", selector.as_path()))?;
        let req = Req::new(
            Method::PUT,
            url,
            Some(Self::push_scope(repo)),
            "PUT manifest",
        )
        .header("content-type", media_type)
        .body(Bytes::copy_from_slice(manifest_bytes));
        let resp = self.execute(&req).await?;
        let resp = self.expect(resp, &[200, 201], "PUT manifest").await?;
        if let Some(h) = resp
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
        {
            if h != digest.as_str() {
                return Err(OciError::DigestMismatch {
                    what: "pushed manifest (registry-reported digest)".into(),
                    expected: digest.to_string(),
                    actual: h.to_owned(),
                });
            }
        }
        Ok(digest)
    }
}

enum Raw {
    Manifest(FetchedManifest),
    Index(ImageIndex, Digest),
}

fn basic_header(username: &str, password: &Secret) -> String {
    use base64::Engine as _;
    let raw = format!("{username}:{}", password.expose());
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

/// Read a body fully but never more than `limit` bytes, with an idle timeout.
async fn read_limited(
    mut body: Incoming,
    limit: u64,
    what: &str,
    idle: Duration,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        let frame = tokio::time::timeout(idle, body.frame())
            .await
            .map_err(|_| OciError::Timeout(format!("reading {what}")))?;
        let Some(frame) = frame else { return Ok(buf) };
        let frame = frame.map_err(|e| OciError::Transport {
            host: String::new(),
            detail: format!("reading {what}: {e}"),
        })?;
        if let Ok(data) = frame.into_data() {
            if buf.len() as u64 + data.len() as u64 > limit {
                return Err(OciError::TooLarge {
                    what: what.to_owned(),
                    size: buf.len() as u64 + data.len() as u64,
                    limit,
                });
            }
            buf.extend_from_slice(&data);
        }
    }
}

fn retry_after(h: &HeaderMap) -> Option<Duration> {
    h.get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn registry_error_text(body: &[u8]) -> String {
    #[derive(serde::Deserialize)]
    struct E {
        code: Option<String>,
        message: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Es {
        errors: Vec<E>,
    }
    let Ok(es) = serde_json::from_slice::<Es>(body) else {
        return String::new();
    };
    let text: Vec<String> = es
        .errors
        .iter()
        .take(3)
        .map(|e| {
            format!(
                "{} {}",
                e.code.as_deref().unwrap_or(""),
                e.message.as_deref().unwrap_or("")
            )
            .trim()
            .to_owned()
        })
        .collect();
    let joined: String = text
        .join("; ")
        .chars()
        .filter(|c| !c.is_control())
        .take(240)
        .collect();
    if joined.is_empty() {
        String::new()
    } else {
        format!(": {joined}")
    }
}

fn parse_link_next(v: &str) -> Option<String> {
    v.split(',').find_map(|part| {
        let part = part.trim();
        if !part.contains("rel=\"next\"") && !part.contains("rel=next") {
            return None;
        }
        let start = part.find('<')? + 1;
        let end = part.find('>')?;
        Some(part[start..end].to_owned())
    })
}

// -------------------------------------------------------------------------
// WWW-Authenticate parsing
// -------------------------------------------------------------------------

struct Challenge {
    scheme: String,
    params: Vec<(String, String)>,
}

impl Challenge {
    fn param(&self, k: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.as_str())
    }
}

fn www_authenticate(h: &HeaderMap) -> Vec<Challenge> {
    h.get_all("www-authenticate")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(parse_challenges)
        .collect()
}

/// Parse one header value into challenges (`Bearer realm="x",service="y"`).
fn parse_challenges(v: &str) -> Vec<Challenge> {
    let mut out: Vec<Challenge> = Vec::new();
    let b = v.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i] == b' ' || b[i] == b',') {
            i += 1;
        }
        let start = i;
        while i < b.len() && !matches!(b[i], b' ' | b',' | b'=') {
            i += 1;
        }
        let token = &v[start..i];
        if token.is_empty() {
            break;
        }
        if i < b.len() && b[i] == b'=' {
            // name=value belonging to the current challenge
            i += 1;
            let val = if i < b.len() && b[i] == b'"' {
                i += 1;
                let mut s = String::new();
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        i += 1;
                    }
                    s.push(b[i] as char);
                    i += 1;
                }
                i += 1;
                s
            } else {
                let st = i;
                while i < b.len() && b[i] != b',' {
                    i += 1;
                }
                v[st..i].trim().to_owned()
            };
            if let Some(c) = out.last_mut() {
                c.params.push((token.to_owned(), val));
            }
        } else {
            out.push(Challenge {
                scheme: token.to_owned(),
                params: Vec::new(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_challenge_with_commas_in_quotes() {
        let c = parse_challenges(
            r#"Bearer realm="https://auth.example/token",service="reg",scope="repository:a/b:pull,push""#,
        );
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].scheme, "Bearer");
        assert_eq!(c[0].param("realm"), Some("https://auth.example/token"));
        assert_eq!(c[0].param("scope"), Some("repository:a/b:pull,push"));
    }

    #[test]
    fn link_next_is_extracted() {
        assert_eq!(
            parse_link_next(r#"</v2/x/tags/list?last=b&n=2>; rel="next""#).as_deref(),
            Some("/v2/x/tags/list?last=b&n=2")
        );
    }
}
