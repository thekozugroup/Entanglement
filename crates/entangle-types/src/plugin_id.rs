//! [`PluginId`] — the canonical three-part identifier for an Entanglement plugin.
//!
//! Format: `<publisher>/<name>@<version>`
//!
//! - `publisher` — lowercase hex of the publisher's Ed25519 key fingerprint (BLAKE3-16, 32 hex chars).
//! - `name` — DNS-label-style string matching `^[a-z][a-z0-9-]{0,62}$`.
//! - `version` — a valid SemVer 2.0 version string.

use std::fmt;
use std::str::FromStr;

use crate::errors::EntangleError;

/// Canonical three-part identifier for an Entanglement plugin.
///
/// # Display / parse format
/// `<publisher>/<name>@<version>`
///
/// ```
/// use entangle_types::plugin_id::PluginId;
/// let id: PluginId = "aabbccddeeff00112233445566778899/my-plugin@1.2.3".parse().unwrap();
/// assert_eq!(id.to_string(), "aabbccddeeff00112233445566778899/my-plugin@1.2.3");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PluginId {
    /// Hex of the publisher Ed25519 key fingerprint (BLAKE3-16, 32 lowercase hex chars).
    pub publisher: String,
    /// DNS-label-style plugin name: `^[a-z][a-z0-9-]{0,62}$`.
    pub name: String,
    /// SemVer 2.0 version.
    pub version: semver::Version,
}

/// Returns `true` if `s` is a valid plugin name (`^[a-z][a-z0-9-]{0,62}$`).
///
/// Deliberately avoids the `regex` crate to keep this crate pure.
pub fn is_valid_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

impl PluginId {
    /// Construct a `PluginId`, validating all components.
    pub fn new(
        publisher: impl Into<String>,
        name: impl Into<String>,
        version: semver::Version,
    ) -> Result<Self, EntangleError> {
        let publisher = publisher.into();
        let name = name.into();
        // publisher must be 32 lowercase hex chars (BLAKE3-16 = 16 bytes = 32 hex)
        if publisher.len() != 32 || !publisher.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(EntangleError::PluginIdInvalid(format!(
                "publisher must be 32 hex chars, got {:?}",
                publisher
            )));
        }
        if !is_valid_name(&name) {
            return Err(EntangleError::PluginIdInvalid(format!(
                "name {:?} does not match ^[a-z][a-z0-9-]{{0,62}}$",
                name
            )));
        }
        Ok(Self {
            publisher,
            name,
            version,
        })
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}@{}", self.publisher, self.name, self.version)
    }
}

impl FromStr for PluginId {
    type Err = EntangleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split on '/' then '@'
        let slash = s
            .find('/')
            .ok_or_else(|| EntangleError::PluginIdInvalid(format!("missing '/' in {:?}", s)))?;
        let publisher = &s[..slash];
        let rest = &s[slash + 1..];

        let at = rest
            .rfind('@')
            .ok_or_else(|| EntangleError::PluginIdInvalid(format!("missing '@' in {:?}", s)))?;
        let name = &rest[..at];
        let ver_str = &rest[at + 1..];

        let version = semver::Version::parse(ver_str).map_err(|e| {
            EntangleError::PluginIdInvalid(format!("bad semver {:?}: {}", ver_str, e))
        })?;

        PluginId::new(publisher, name, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publisher() -> &'static str {
        "aabbccddeeff00112233445566778899"
    }

    #[test]
    fn round_trip() {
        let raw = format!("{}/foo@1.2.3", publisher());
        let id: PluginId = raw.parse().unwrap();
        assert_eq!(id.to_string(), raw);
    }

    #[test]
    fn parse_from_str() {
        let id: PluginId = format!("{}/my-plugin@0.1.0", publisher()).parse().unwrap();
        assert_eq!(id.name, "my-plugin");
        assert_eq!(id.version.major, 0);
    }

    #[test]
    fn invalid_name_uppercase() {
        let result: Result<PluginId, _> = format!("{}/MyPlugin@1.0.0", publisher()).parse();
        assert!(result.is_err());
    }

    #[test]
    fn invalid_publisher_short() {
        let result: Result<PluginId, _> = "abc/foo@1.0.0".parse();
        assert!(result.is_err());
    }

    #[test]
    fn is_valid_name_checks() {
        assert!(is_valid_name("foo"));
        assert!(is_valid_name("my-plugin"));
        assert!(is_valid_name("a"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("Foo"));
        assert!(!is_valid_name("-foo"));
        assert!(!is_valid_name(&"a".repeat(64)));
    }
}
