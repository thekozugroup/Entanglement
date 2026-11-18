//! Plain HTTPS downloads (spec §3.6 path B): a package archive and its
//! detached signature fetched from an ordinary web server.
//!
//! This reuses the registry client's transport (the private `http` module): the same
//! TLS configuration, connect/idle timeouts and loopback rule. On top of it:
//!
//! * the URL must be `https://`; `http://` is accepted for a loopback host
//!   only (local test servers), and the transport re-checks that the peer
//!   address really is loopback after connecting;
//! * a URL with embedded credentials or a fragment is refused;
//! * redirects are followed up to a limit, but never to a different scheme
//!   (neither an HTTPS download handed down to HTTP, nor the reverse);
//! * no credentials are ever sent;
//! * the body is cut off at `max_bytes`: a `Content-Length` over the cap is
//!   refused before a byte is read, and a body without one is stopped at the
//!   first byte past it.
//!
//! Nothing here judges the bytes. Trust is decided afterwards, by
//! [`crate::verify_archive_signature`] and [`crate::verify_package`].

use std::time::Duration;

use bytes::Bytes;
use hyper::Method;
use url::Url;

use crate::client::{read_limited, redact_url};
use crate::error::{OciError, Result};
use crate::http::{authority, url_is_loopback, Transport};

/// Options for [`fetch_url`].
#[derive(Clone, Debug)]
pub struct FetchOptions {
    /// Largest body accepted, in bytes.
    pub max_bytes: u64,
    /// Connect / TLS-handshake / idle timeout.
    pub timeout: Duration,
    /// Maximum redirects followed.
    pub max_redirects: u8,
    /// Extra TLS trust anchors for tests (feature `testing` only; see
    /// [`crate::ClientConfig::test_roots`]).
    #[cfg(feature = "testing")]
    pub test_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            max_bytes: 512 * 1024 * 1024,
            timeout: Duration::from_secs(30),
            max_redirects: 5,
            #[cfg(feature = "testing")]
            test_roots: Vec::new(),
        }
    }
}

/// Parse and vet a download URL (see the module docs for the rules).
pub fn parse_download_url(text: &str) -> Result<Url> {
    let refused = |reason: &str| OciError::UrlRefused {
        url: redact_url(text),
        reason: reason.to_owned(),
    };
    let url = Url::parse(text).map_err(|e| refused(&e.to_string()))?;
    if url.host().is_none() {
        return Err(refused("no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refused("credentials in a download URL are not supported"));
    }
    if url.fragment().is_some() {
        return Err(refused("a #fragment is not allowed"));
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if url_is_loopback(&url) => Ok(url),
        "http" => Err(refused(
            "plain http is only accepted for a loopback host; use https",
        )),
        other => Err(refused(&format!("unsupported scheme {other:?}; use https"))),
    }
}

/// The URL of the detached signature for `url`: the same URL with `.sig`
/// appended to its path (a query string, if any, is kept as it is).
pub fn signature_url(url: &Url) -> Url {
    let mut sig = url.clone();
    let path = format!("{}.sig", url.path());
    sig.set_path(&path);
    sig
}

/// Download `url` into memory, at most `opts.max_bytes` bytes.
///
/// `what` names the object in error messages (`package archive`,
/// `detached signature`).
pub async fn fetch_url(url: &Url, what: &str, opts: &FetchOptions) -> Result<Vec<u8>> {
    // Re-vet: callers may have built the URL themselves.
    let mut url = parse_download_url(url.as_str())?;
    let scheme = url.scheme().to_owned();
    let transport = Transport::new(false, opts.timeout);
    #[cfg(feature = "testing")]
    let transport = transport.with_test_roots(opts.test_roots.clone());
    debug_assert!(!transport.allows_plain_http());

    let headers = [("accept".to_owned(), "*/*".to_owned())];
    let mut redirects = 0u8;
    loop {
        let here = authority(&url);
        let resp = transport
            .send(&Method::GET, &url, &headers, Bytes::new())
            .await?;
        let status = resp.status().as_u16();
        match status {
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
                if redirects > opts.max_redirects {
                    return Err(OciError::Redirect(format!(
                        "more than {} redirects fetching the {what}",
                        opts.max_redirects
                    )));
                }
                let next = url.join(&loc).map_err(|e| {
                    OciError::Redirect(format!("unparseable Location {loc:?}: {e}"))
                })?;
                if next.scheme() != scheme {
                    return Err(OciError::Redirect(format!(
                        "{here} redirected the {scheme} download of the {what} to a {} URL \
                         ({}); a redirect may not change the scheme",
                        next.scheme(),
                        authority(&next)
                    )));
                }
                if !next.username().is_empty() || next.password().is_some() {
                    return Err(OciError::Redirect(format!(
                        "{here} redirected the {what} to a URL with embedded credentials"
                    )));
                }
                url = next;
            }
            200 => {
                if let Some(len) = resp
                    .headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok())
                {
                    if len > opts.max_bytes {
                        return Err(OciError::TooLarge {
                            what: what.to_owned(),
                            size: len,
                            limit: opts.max_bytes,
                        });
                    }
                }
                return read_limited(resp.into_body(), opts.max_bytes, what, opts.timeout)
                    .await
                    .map_err(|e| match e {
                        OciError::Transport { detail, .. } => OciError::Transport {
                            host: here.clone(),
                            detail,
                        },
                        other => other,
                    });
            }
            _ => {
                return Err(OciError::Status {
                    host: here,
                    status,
                    what: format!("GET {what}"),
                    detail: String::new(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_http_urls_are_accepted() {
        for ok in [
            "https://example.org/a/tool-0.1.0.tar.zst",
            "https://example.org:8443/x.tar.zst?token=1",
            "http://127.0.0.1:8080/x.tar.zst",
            "http://localhost/x.tar.zst",
            "http://[::1]:9/x.tar.zst",
        ] {
            parse_download_url(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for (bad, why) in [
            ("http://example.org/x.tar.zst", "loopback"),
            ("http://10.0.0.7/x.tar.zst", "loopback"),
            ("http://localhost.evil.example/x.tar.zst", "loopback"),
            ("ftp://example.org/x.tar.zst", "unsupported scheme"),
            ("file:///etc/passwd", "no host"),
            ("https://user:pw@example.org/x.tar.zst", "credentials"),
            ("https://example.org/x.tar.zst#frag", "fragment"),
            ("not a url", "relative URL"),
        ] {
            let e = parse_download_url(bad).unwrap_err().to_string();
            assert!(e.starts_with("ENTANGLE-E0822"), "{bad}: {e}");
            assert!(e.contains(why), "{bad}: {e}");
            assert!(!e.contains("pw@"), "credentials leaked: {e}");
        }
    }

    #[test]
    fn signature_url_appends_to_the_path_and_keeps_the_query() {
        let u = Url::parse("https://example.org/r/tool-0.1.0.tar.zst").unwrap();
        assert_eq!(
            signature_url(&u).as_str(),
            "https://example.org/r/tool-0.1.0.tar.zst.sig"
        );
        let q = Url::parse("https://example.org/dl/tool.tar.zst?sv=1&sig=abc").unwrap();
        assert_eq!(
            signature_url(&q).as_str(),
            "https://example.org/dl/tool.tar.zst.sig?sv=1&sig=abc"
        );
    }
}
