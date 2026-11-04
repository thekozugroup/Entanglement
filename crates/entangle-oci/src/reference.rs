//! `oci://registry[:port]/repo[:tag|@sha256:<hex>]` references and digests.

use std::fmt;
use std::str::FromStr;

use sha2::{Digest as _, Sha256};

use crate::error::{OciError, Result};

/// A content digest, always `sha256:<64 lowercase hex>`.
///
/// Other algorithms are rejected at parse time rather than silently skipped,
/// so a descriptor can never be "verified" by an algorithm we do not run.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(String);

impl Digest {
    /// Digest of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self::from_raw(Sha256::digest(bytes).into())
    }

    /// Wrap a finished SHA-256 output.
    pub(crate) fn from_raw(raw: [u8; 32]) -> Self {
        Self(format!("sha256:{}", hex::encode(raw)))
    }

    /// The canonical `sha256:<hex>` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Just the hex part.
    pub fn hex(&self) -> &str {
        &self.0["sha256:".len()..]
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Digest {
    type Err = OciError;

    fn from_str(s: &str) -> Result<Self> {
        let bad = |reason: &str| OciError::InvalidReference {
            reference: s.to_owned(),
            reason: reason.to_owned(),
        };
        let Some(h) = s.strip_prefix("sha256:") else {
            return Err(bad("only sha256 digests are supported"));
        };
        if h.len() != 64 || !h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(bad("digest must be 64 lowercase hex characters"));
        }
        Ok(Self(s.to_owned()))
    }
}

impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// What part of a repository a reference selects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    /// A mutable tag.
    Tag(String),
    /// An immutable content digest (the manifest's digest).
    Digest(Digest),
}

impl Selector {
    /// The string used in `/v2/<repo>/manifests/<reference>`.
    pub fn as_path(&self) -> String {
        match self {
            Selector::Tag(t) => t.clone(),
            Selector::Digest(d) => d.to_string(),
        }
    }
}

/// A parsed `oci://` reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    /// `host` or `host:port` (IPv6 hosts keep their brackets).
    pub registry: String,
    /// Repository path, e.g. `entangle/hash-it`.
    pub repository: String,
    /// Tag or digest. A reference with neither selects the tag `latest`.
    pub selector: Selector,
}

impl Reference {
    /// Parse an `oci://` reference.
    pub fn parse(text: &str) -> Result<Self> {
        let bad = |reason: &str| OciError::InvalidReference {
            reference: text.to_owned(),
            reason: reason.to_owned(),
        };
        let rest = text
            .strip_prefix("oci://")
            .ok_or_else(|| bad("must start with oci://"))?;
        let (registry, path) = rest
            .split_once('/')
            .ok_or_else(|| bad("expected oci://<registry>/<repository>"))?;
        validate_registry(registry).map_err(|r| bad(&r))?;

        // `@sha256:...` first (a digest contains ':'), then a tag after the
        // last ':' of the final path segment.
        let (name_part, digest) = match path.split_once('@') {
            Some((n, d)) => (n, Some(d.parse::<Digest>().map_err(|_| bad("bad digest"))?)),
            None => (path, None),
        };
        let last_slash = name_part.rfind('/').map_or(0, |i| i + 1);
        let (repository, tag) = match name_part[last_slash..].rfind(':') {
            Some(i) => {
                let split = last_slash + i;
                (&name_part[..split], Some(&name_part[split + 1..]))
            }
            None => (name_part, None),
        };
        validate_repository(repository).map_err(|r| bad(&r))?;
        if let Some(t) = tag {
            validate_tag(t).map_err(|r| bad(&r))?;
        }
        let selector = match (digest, tag) {
            (Some(d), _) => Selector::Digest(d),
            (None, Some(t)) => Selector::Tag(t.to_owned()),
            (None, None) => Selector::Tag("latest".to_owned()),
        };
        Ok(Self {
            registry: registry.to_owned(),
            repository: repository.to_owned(),
            selector,
        })
    }

    /// The same repository, selecting a different tag or digest.
    pub fn with_selector(&self, selector: Selector) -> Self {
        Self {
            selector,
            ..self.clone()
        }
    }
}

impl FromStr for Reference {
    type Err = OciError;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.selector {
            Selector::Tag(t) => write!(f, "oci://{}/{}:{}", self.registry, self.repository, t),
            Selector::Digest(d) => write!(f, "oci://{}/{}@{}", self.registry, self.repository, d),
        }
    }
}

fn validate_registry(r: &str) -> std::result::Result<(), String> {
    if r.is_empty() {
        return Err("empty registry host".into());
    }
    let (host, port) = if let Some(rest) = r.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or("unterminated [ in IPv6 host")?;
        (h, after.strip_prefix(':'))
    } else {
        match r.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (r, None),
        }
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        return Err("registry host contains invalid characters".into());
    }
    if let Some(p) = port {
        if p.parse::<u16>().is_err() {
            return Err("registry port is not a number".into());
        }
    }
    Ok(())
}

fn validate_repository(repo: &str) -> std::result::Result<(), String> {
    if repo.is_empty() {
        return Err("empty repository".into());
    }
    for comp in repo.split('/') {
        let ok = !comp.is_empty()
            && comp
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
            && comp.starts_with(|c: char| c.is_ascii_alphanumeric())
            && comp.ends_with(|c: char| c.is_ascii_alphanumeric());
        if !ok || comp.contains("..") {
            return Err(format!(
                "repository component {comp:?} must be lowercase alphanumerics separated by . _ -"
            ));
        }
    }
    Ok(())
}

/// OCI tag grammar: `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`.
pub(crate) fn validate_tag(t: &str) -> std::result::Result<(), String> {
    let ok = !t.is_empty()
        && t.len() <= 128
        && t.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(format!("invalid tag {t:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tag_digest_port_and_default() {
        let r = Reference::parse("oci://ghcr.io/acme/tools/hash-it:1.2.3").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "acme/tools/hash-it");
        assert_eq!(r.selector, Selector::Tag("1.2.3".into()));

        let hex = "a".repeat(64);
        let r = Reference::parse(&format!("oci://localhost:5000/x@sha256:{hex}")).unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(
            r.selector,
            Selector::Digest(format!("sha256:{hex}").parse().unwrap())
        );

        let r = Reference::parse("oci://[::1]:5000/x").unwrap();
        assert_eq!(r.registry, "[::1]:5000");
        assert_eq!(r.selector, Selector::Tag("latest".into()));
    }

    #[test]
    fn rejects_bad_references() {
        for bad in [
            "https://ghcr.io/x:1",
            "oci://ghcr.io",
            "oci:///x",
            "oci://h/UPPER:1",
            "oci://h/x:",
            "oci://h/x@sha256:abc",
            "oci://h/x@sha512:00",
            "oci://h/../x:1",
            "oci://h:99999/x",
            "oci://h/x:-bad",
        ] {
            let e = Reference::parse(bad).unwrap_err();
            assert!(e.to_string().starts_with("ENTANGLE-E0800"), "{bad}: {e}");
        }
    }

    #[test]
    fn display_round_trips() {
        let r = Reference::parse("oci://r.example:443/a/b:v1").unwrap();
        assert_eq!(Reference::parse(&r.to_string()).unwrap(), r);
    }
}
