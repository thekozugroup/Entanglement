//! In-process mock OCI registry for tests (feature `testing`).
//!
//! Implements just enough of the Distribution spec to exercise the client:
//! Bearer-token and Basic challenges, manifests by tag and digest, blobs
//! (optionally redirected to a second "CDN" listener on another port),
//! monolithic and chunked uploads, tag listing with pagination, and fault
//! injection. Every request is logged, including the `Authorization` header it
//! carried, so tests can assert credentials never reached the CDN.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;

/// How the mock registry authenticates clients.
#[derive(Clone, Debug)]
pub enum MockAuth {
    /// No authentication.
    None,
    /// `Bearer` challenge pointing at `/token` on the same listener. When
    /// `token_requires_basic` is set, the token endpoint demands those Basic
    /// credentials (as private registries do).
    Bearer {
        /// `(username, password)` the token endpoint requires, if any.
        token_requires_basic: Option<(String, String)>,
    },
    /// `Basic` challenge with these credentials.
    Basic {
        /// Expected username.
        username: String,
        /// Expected password.
        password: String,
    },
}

/// Mock registry options.
#[derive(Clone, Debug)]
pub struct MockOptions {
    /// Authentication mode.
    pub auth: MockAuth,
    /// Redirect blob downloads to a second listener (different port).
    pub cdn: bool,
    /// Page size for `tags/list` (enables `Link: rel="next"`).
    pub tag_page_size: Option<usize>,
}

impl Default for MockOptions {
    fn default() -> Self {
        Self {
            auth: MockAuth::None,
            cdn: false,
            tag_page_size: None,
        }
    }
}

/// One request the mock saw.
#[derive(Clone, Debug)]
pub struct LoggedRequest {
    /// `"registry"` or `"cdn"`.
    pub server: &'static str,
    /// HTTP method.
    pub method: String,
    /// Path and query.
    pub path: String,
    /// The `Authorization` header value, if any.
    pub authorization: Option<String>,
}

/// `(content-type, bytes)`
type StoredManifest = (String, Vec<u8>);

#[derive(Default)]
struct State {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    /// `(repo, digest)` -> `(content-type, bytes)`
    manifests: Mutex<HashMap<(String, String), StoredManifest>>,
    /// `(repo, tag)` -> digest
    tags: Mutex<BTreeMap<(String, String), String>>,
    uploads: Mutex<HashMap<String, Vec<u8>>>,
    log: Mutex<Vec<LoggedRequest>>,
    faults: Mutex<Vec<(String, VecDeque<u16>)>>,
    tampered: Mutex<HashMap<String, Vec<u8>>>,
    endless: Mutex<HashMap<String, u64>>,
    streamed: AtomicU64,
    next_upload: AtomicU64,
    cdn_addr: Mutex<Option<SocketAddr>>,
    registry_addr: Mutex<Option<SocketAddr>>,
    opts: Mutex<MockOptions>,
    content_type_override: Mutex<HashMap<String, String>>,
}

/// A running mock registry (and optional CDN listener).
pub struct MockRegistry {
    state: Arc<State>,
    addr: SocketAddr,
    cdn_addr: Option<SocketAddr>,
}

type Body_ = BoxBody<Bytes, Infallible>;

fn full(b: impl Into<Bytes>) -> Body_ {
    Full::new(b.into()).boxed()
}

/// A body of `remaining` bytes sent in 64 KiB chunks with no known length.
struct Endless {
    remaining: u64,
    state: Arc<State>,
}

impl Body for Endless {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let n = self.remaining.min(64 * 1024);
        self.remaining -= n;
        self.state.streamed.fetch_add(n, Ordering::Relaxed);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![0xAB; n as usize])))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl MockRegistry {
    /// Start a mock on `127.0.0.1` with ephemeral ports.
    pub async fn start(opts: MockOptions) -> Self {
        let state = Arc::new(State::default());
        let cdn = opts.cdn;
        *lock(&state.opts) = opts;

        let reg_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock registry");
        let addr = reg_listener.local_addr().expect("mock addr");
        *lock(&state.registry_addr) = Some(addr);
        let mut cdn_addr = None;
        if cdn {
            let l = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind mock cdn");
            cdn_addr = Some(l.local_addr().expect("cdn addr"));
            *lock(&state.cdn_addr) = cdn_addr;
            spawn_server(l, state.clone(), "cdn");
        }
        spawn_server(reg_listener, state.clone(), "registry");
        Self {
            state,
            addr,
            cdn_addr,
        }
    }

    /// `127.0.0.1:<port>` of the registry.
    pub fn registry(&self) -> String {
        self.addr.to_string()
    }

    /// `127.0.0.1:<port>` of the CDN listener, if enabled.
    pub fn cdn(&self) -> Option<String> {
        self.cdn_addr.map(|a| a.to_string())
    }

    /// All requests seen so far.
    pub fn requests(&self) -> Vec<LoggedRequest> {
        lock(&self.state.log).clone()
    }

    /// Requests seen by one listener (`"registry"` or `"cdn"`).
    pub fn requests_to(&self, server: &str) -> Vec<LoggedRequest> {
        self.requests()
            .into_iter()
            .filter(|r| r.server == server)
            .collect()
    }

    /// Answer the next requests whose path contains `needle` with `statuses`
    /// in order (e.g. `[503, 429]`), then behave normally.
    pub fn fail_next(&self, needle: &str, statuses: &[u16]) {
        lock(&self.state.faults).push((needle.to_owned(), statuses.iter().copied().collect()));
    }

    /// Serve `bytes` instead of the stored content for blob `digest` (the
    /// digest and, unless the length matches, the size will be wrong).
    pub fn tamper_blob(&self, digest: &str, bytes: Vec<u8>) {
        lock(&self.state.tampered).insert(digest.to_owned(), bytes);
    }

    /// Stream `total` bytes (chunked, no `Content-Length`) for blob `digest`.
    pub fn serve_endless(&self, digest: &str, total: u64) {
        lock(&self.state.endless).insert(digest.to_owned(), total);
    }

    /// Bytes the mock has pushed out via [`MockRegistry::serve_endless`].
    pub fn bytes_streamed(&self) -> u64 {
        self.state.streamed.load(Ordering::Relaxed)
    }

    /// Force the `Content-Type` header returned for manifests of `repo`.
    pub fn override_manifest_content_type(&self, repo: &str, content_type: &str) {
        lock(&self.state.content_type_override).insert(repo.to_owned(), content_type.to_owned());
    }

    /// Store a blob directly; returns `sha256:<hex>`.
    pub fn put_blob(&self, bytes: &[u8]) -> String {
        let d = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        lock(&self.state.blobs).insert(d.clone(), bytes.to_vec());
        d
    }

    /// Store a manifest directly under `tag`; returns its digest.
    pub fn put_manifest(&self, repo: &str, tag: &str, content_type: &str, bytes: &[u8]) -> String {
        let d = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        lock(&self.state.manifests).insert(
            (repo.to_owned(), d.clone()),
            (content_type.to_owned(), bytes.to_vec()),
        );
        lock(&self.state.tags).insert((repo.to_owned(), tag.to_owned()), d.clone());
        d
    }

    /// Replace the bytes stored for manifest `digest` (so the registry serves
    /// content that does not hash to the digest it is addressed by).
    pub fn corrupt_manifest(&self, repo: &str, digest: &str, content_type: &str, bytes: &[u8]) {
        lock(&self.state.manifests).insert(
            (repo.to_owned(), digest.to_owned()),
            (content_type.to_owned(), bytes.to_vec()),
        );
    }

    /// The bytes of the manifest `reference` (tag or digest) resolves to.
    pub fn manifest_bytes(&self, repo: &str, reference: &str) -> Option<Vec<u8>> {
        let d = resolve(&self.state, repo, reference)?;
        lock(&self.state.manifests)
            .get(&(repo.to_owned(), d))
            .map(|(_, b)| b.clone())
    }

    /// A stored blob.
    pub fn blob(&self, digest: &str) -> Option<Vec<u8>> {
        lock(&self.state.blobs).get(digest).cloned()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn resolve(state: &State, repo: &str, reference: &str) -> Option<String> {
    if reference.starts_with("sha256:") {
        return lock(&state.manifests)
            .contains_key(&(repo.to_owned(), reference.to_owned()))
            .then(|| reference.to_owned());
    }
    lock(&state.tags)
        .get(&(repo.to_owned(), reference.to_owned()))
        .cloned()
}

fn spawn_server(listener: TcpListener, state: Arc<State>, role: &'static str) {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| handle(state.clone(), role, req));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
}

fn status(code: u16) -> hyper::http::response::Builder {
    Response::builder().status(code)
}

async fn handle(
    state: Arc<State>,
    role: &'static str,
    req: Request<Incoming>,
) -> Result<Response<Body_>, Infallible> {
    let (parts, body) = req.into_parts();
    let path_q = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_default();
    let authz = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    lock(&state.log).push(LoggedRequest {
        server: role,
        method: parts.method.to_string(),
        path: path_q.clone(),
        authorization: authz.clone(),
    });
    let body = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => Bytes::new(),
    };
    Ok(route(&state, role, &parts, &path_q, authz.as_deref(), body))
}

fn route(
    state: &Arc<State>,
    role: &'static str,
    parts: &hyper::http::request::Parts,
    path_q: &str,
    authz: Option<&str>,
    body: Bytes,
) -> Response<Body_> {
    let path = parts.uri.path();
    let method = &parts.method;
    let query: HashMap<String, String> = parts
        .uri
        .query()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .unwrap_or_default();

    // Fault injection (registry listener only).
    if role == "registry" {
        let mut faults = lock(&state.faults);
        for (needle, q) in faults.iter_mut() {
            if path_q.contains(needle.as_str()) {
                if let Some(code) = q.pop_front() {
                    return status(code)
                        .header("retry-after", "0")
                        .body(full("injected fault"))
                        .expect("response");
                }
            }
        }
    }

    // CDN: only /blob/<digest>.
    if role == "cdn" {
        let Some(d) = path.strip_prefix("/blob/") else {
            return status(404).body(full("")).expect("response");
        };
        return serve_blob(state, d, method == Method::HEAD);
    }

    let opts = lock(&state.opts).clone();
    let reg_addr = lock(&state.registry_addr).expect("registry addr set before serving");

    // Token endpoint.
    if path == "/token" {
        if let MockAuth::Bearer {
            token_requires_basic,
        } = &opts.auth
        {
            if let Some((u, p)) = token_requires_basic {
                if authz != Some(&basic(u, p)) {
                    return status(401)
                        .body(full("token endpoint needs basic"))
                        .expect("response");
                }
            }
            let scope = query.get("scope").cloned().unwrap_or_default();
            let tok = format!("tok-{}", scope.replace([':', ',', '/'], "_"));
            return status(200)
                .header("content-type", "application/json")
                .body(full(format!("{{\"token\":\"{tok}\",\"expires_in\":300}}")))
                .expect("response");
        }
        return status(404).body(full("")).expect("response");
    }

    // Auth gate for /v2/.
    let scope = scope_for(path, method);
    match &opts.auth {
        MockAuth::None => {}
        MockAuth::Bearer { .. } => {
            let want = format!("Bearer tok-{}", scope.replace([':', ',', '/'], "_"));
            if authz != Some(want.as_str()) {
                return status(401)
                    .header(
                        "www-authenticate",
                        format!(
                            "Bearer realm=\"http://{reg_addr}/token\",service=\"mock\",scope=\"{scope}\""
                        ),
                    )
                    .body(full("{\"errors\":[{\"code\":\"UNAUTHORIZED\",\"message\":\"authentication required\"}]}"))
                    .expect("response");
            }
        }
        MockAuth::Basic { username, password } => {
            if authz != Some(basic(username, password).as_str()) {
                return status(401)
                    .header("www-authenticate", "Basic realm=\"mock\"")
                    .body(full(""))
                    .expect("response");
            }
        }
    }

    let Some(rest) = path.strip_prefix("/v2/") else {
        return status(404).body(full("")).expect("response");
    };

    // Longest-suffix matching on the repo-qualified paths.
    if let Some((repo, tail)) = split_repo(rest, "/manifests/") {
        return manifests(state, method, repo, tail, body, parts);
    }
    if let Some((repo, tail)) = split_repo(rest, "/blobs/uploads/") {
        return uploads(state, method, repo, tail, &query, &body, parts);
    }
    if let Some((repo, digest)) = split_repo(rest, "/blobs/") {
        if *method == Method::GET || *method == Method::HEAD {
            if *method == Method::GET {
                if let Some(cdn) = *lock(&state.cdn_addr) {
                    if lock(&state.blobs).contains_key(digest) {
                        return status(307)
                            .header("location", format!("http://{cdn}/blob/{digest}"))
                            .body(full(""))
                            .expect("response");
                    }
                }
                let _ = repo;
            }
            return serve_blob(state, digest, *method == Method::HEAD);
        }
    }
    if let Some(repo) = rest.strip_suffix("/tags/list") {
        return tags_list(state, repo, &query, opts.tag_page_size);
    }
    status(404).body(full("")).expect("response")
}

fn scope_for(path: &str, method: &Method) -> String {
    let rest = path.strip_prefix("/v2/").unwrap_or("");
    let repo = ["/manifests/", "/blobs/", "/tags/"]
        .iter()
        .find_map(|m| rest.find(m).map(|i| &rest[..i]))
        .unwrap_or(rest);
    let actions = if *method == Method::GET || *method == Method::HEAD {
        // HEAD blob during publish also uses push scope on the client side,
        // but the mock only requires the token's scope to match what it
        // challenged with, so pull is fine.
        "pull"
    } else {
        "pull,push"
    };
    format!("repository:{repo}:{actions}")
}

fn basic(u: &str, p: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
    )
}

fn split_repo<'a>(rest: &'a str, marker: &str) -> Option<(&'a str, &'a str)> {
    let i = rest.find(marker)?;
    Some((&rest[..i], &rest[i + marker.len()..]))
}

fn serve_blob(state: &Arc<State>, digest: &str, head: bool) -> Response<Body_> {
    if let Some(total) = lock(&state.endless).get(digest).copied() {
        return status(200)
            .body(
                Endless {
                    remaining: total,
                    state: state.clone(),
                }
                .boxed(),
            )
            .expect("response");
    }
    let data = lock(&state.tampered)
        .get(digest)
        .cloned()
        .or_else(|| lock(&state.blobs).get(digest).cloned());
    match data {
        None => status(404).body(full("")).expect("response"),
        Some(d) if head => status(200)
            .header("content-length", d.len().to_string())
            .header("docker-content-digest", digest)
            .body(full(""))
            .expect("response"),
        Some(d) => status(200)
            .header("docker-content-digest", digest)
            .body(full(d))
            .expect("response"),
    }
}

fn manifests(
    state: &Arc<State>,
    method: &Method,
    repo: &str,
    reference: &str,
    body: Bytes,
    parts: &hyper::http::request::Parts,
) -> Response<Body_> {
    match *method {
        Method::GET | Method::HEAD => {
            let Some(d) = resolve(state, repo, reference) else {
                return status(404)
                    .header("content-type", "application/json")
                    .body(full("{\"errors\":[{\"code\":\"MANIFEST_UNKNOWN\",\"message\":\"manifest unknown\"}]}"))
                    .expect("response");
            };
            let (ct, bytes) = lock(&state.manifests)
                .get(&(repo.to_owned(), d.clone()))
                .cloned()
                .expect("resolved manifest exists");
            let ct = lock(&state.content_type_override)
                .get(repo)
                .cloned()
                .unwrap_or(ct);
            status(200)
                .header("content-type", ct)
                .header("docker-content-digest", d)
                .body(if *method == Method::HEAD {
                    full("")
                } else {
                    full(bytes)
                })
                .expect("response")
        }
        Method::PUT => {
            let d = format!("sha256:{}", hex::encode(Sha256::digest(&body)));
            let ct = parts
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            lock(&state.manifests).insert((repo.to_owned(), d.clone()), (ct, body.to_vec()));
            if !reference.starts_with("sha256:") {
                lock(&state.tags).insert((repo.to_owned(), reference.to_owned()), d.clone());
            }
            status(201)
                .header("docker-content-digest", d)
                .body(full(""))
                .expect("response")
        }
        _ => status(405).body(full("")).expect("response"),
    }
}

fn uploads(
    state: &Arc<State>,
    method: &Method,
    repo: &str,
    id: &str,
    query: &HashMap<String, String>,
    body: &Bytes,
    parts: &hyper::http::request::Parts,
) -> Response<Body_> {
    let loc = |id: &str| format!("/v2/{repo}/blobs/uploads/{id}");
    match *method {
        Method::POST if id.is_empty() => {
            let id = format!("up{}", state.next_upload.fetch_add(1, Ordering::Relaxed));
            lock(&state.uploads).insert(id.clone(), Vec::new());
            status(202)
                .header("location", loc(&id))
                .body(full(""))
                .expect("response")
        }
        Method::PATCH => {
            let mut ups = lock(&state.uploads);
            let Some(buf) = ups.get_mut(id) else {
                return status(404).body(full("")).expect("response");
            };
            let want = parts
                .headers
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split('-').next())
                .and_then(|v| v.parse::<usize>().ok());
            if want != Some(buf.len()) {
                return status(416).body(full("bad range")).expect("response");
            }
            buf.extend_from_slice(body);
            status(202)
                .header("location", loc(id))
                .header("range", format!("0-{}", buf.len().saturating_sub(1)))
                .body(full(""))
                .expect("response")
        }
        Method::PUT => {
            let mut ups = lock(&state.uploads);
            let Some(mut buf) = ups.remove(id) else {
                return status(404).body(full("")).expect("response");
            };
            buf.extend_from_slice(body);
            let actual = format!("sha256:{}", hex::encode(Sha256::digest(&buf)));
            if query.get("digest") != Some(&actual) {
                return status(400)
                    .body(full("{\"errors\":[{\"code\":\"DIGEST_INVALID\",\"message\":\"digest mismatch\"}]}"))
                    .expect("response");
            }
            lock(&state.blobs).insert(actual.clone(), buf);
            status(201)
                .header("docker-content-digest", actual)
                .body(full(""))
                .expect("response")
        }
        _ => status(405).body(full("")).expect("response"),
    }
}

fn tags_list(
    state: &Arc<State>,
    repo: &str,
    query: &HashMap<String, String>,
    page: Option<usize>,
) -> Response<Body_> {
    let all: Vec<String> = lock(&state.tags)
        .keys()
        .filter(|(r, _)| r == repo)
        .map(|(_, t)| t.clone())
        .collect();
    if all.is_empty() && !lock(&state.manifests).keys().any(|(r, _)| r == repo) {
        return status(404)
            .body(full(
                "{\"errors\":[{\"code\":\"NAME_UNKNOWN\",\"message\":\"repository unknown\"}]}",
            ))
            .expect("response");
    }
    let mut sorted = all;
    sorted.sort();
    if let Some(last) = query.get("last") {
        sorted.retain(|t| t.as_str() > last.as_str());
    }
    let mut link = None;
    if let Some(n) = page {
        if sorted.len() > n {
            sorted.truncate(n);
            link = Some(format!(
                "</v2/{repo}/tags/list?last={}&n={n}>; rel=\"next\"",
                sorted.last().cloned().unwrap_or_default()
            ));
        }
    }
    let json = format!(
        "{{\"name\":\"{repo}\",\"tags\":[{}]}}",
        sorted
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut b = status(200).header("content-type", "application/json");
    if let Some(l) = link {
        b = b.header("link", l);
    }
    b.body(full(json)).expect("response")
}
