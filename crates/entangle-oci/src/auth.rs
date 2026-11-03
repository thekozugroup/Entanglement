//! Registry credentials: explicit sources only, never logged.
//!
//! Resolution order for a registry (`host[:port]`):
//! 1. environment: `ENTANGLE_OCI_TOKEN` (bearer), or
//!    `ENTANGLE_OCI_USERNAME` + `ENTANGLE_OCI_PASSWORD` (basic);
//! 2. `~/.entangle/oci-auth.toml`, section `[registries."<host[:port]>"]` with
//!    `username`+`password`, or `token`.
//! 3. none: anonymous.
//!
//! The file must not be readable by group/other on Unix (like `~/.ssh`).

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{OciError, Result};

/// A secret string whose `Debug` output is redacted.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// Wrap a secret value.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Reveal the value. Callers must not log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// How to authenticate to a registry.
#[derive(Clone, Debug)]
pub enum Credential {
    /// HTTP Basic (also used against token endpoints in the Bearer flow).
    Basic {
        /// Account name.
        username: String,
        /// Password or personal access token.
        password: Secret,
    },
    /// A pre-obtained bearer token, sent directly.
    Bearer(Secret),
}

/// Environment variable holding a bearer token.
pub const ENV_TOKEN: &str = "ENTANGLE_OCI_TOKEN";
/// Environment variable holding the basic-auth username.
pub const ENV_USERNAME: &str = "ENTANGLE_OCI_USERNAME";
/// Environment variable holding the basic-auth password.
pub const ENV_PASSWORD: &str = "ENTANGLE_OCI_PASSWORD";

#[derive(serde::Deserialize, Default)]
struct AuthFile {
    #[serde(default)]
    registries: BTreeMap<String, AuthEntry>,
}

#[derive(serde::Deserialize)]
struct AuthEntry {
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
}

impl Credential {
    /// Resolve the credential for `registry`, reading the process environment
    /// and `auth_file` (typically `~/.entangle/oci-auth.toml`).
    pub fn resolve(registry: &str, auth_file: Option<&Path>) -> Result<Option<Self>> {
        Self::resolve_with(registry, auth_file, |k| std::env::var(k).ok())
    }

    /// Like [`Credential::resolve`] with an injectable environment lookup.
    pub fn resolve_with(
        registry: &str,
        auth_file: Option<&Path>,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>> {
        let non_empty = |k: &str| env(k).filter(|v| !v.is_empty());
        if let Some(t) = non_empty(ENV_TOKEN) {
            return Ok(Some(Credential::Bearer(Secret::new(t))));
        }
        match (non_empty(ENV_USERNAME), non_empty(ENV_PASSWORD)) {
            (Some(u), Some(p)) => {
                return Ok(Some(Credential::Basic {
                    username: u,
                    password: Secret::new(p),
                }))
            }
            (None, None) => {}
            _ => {
                return Err(OciError::Credentials(format!(
                    "{ENV_USERNAME} and {ENV_PASSWORD} must be set together"
                )))
            }
        }
        match auth_file {
            Some(p) if p.exists() => Self::from_file(registry, p),
            _ => Ok(None),
        }
    }

    fn from_file(registry: &str, path: &Path) -> Result<Option<Self>> {
        let cred_err = |m: String| OciError::Credentials(format!("{}: {m}", path.display()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(path)
                .map_err(|e| cred_err(e.to_string()))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(cred_err(format!(
                    "file mode is {:04o}; it holds secrets, run `chmod 600`",
                    mode & 0o777
                )));
            }
        }
        let raw = std::fs::read_to_string(path).map_err(|e| cred_err(e.to_string()))?;
        // `toml` error text can quote the offending line, which may be a secret.
        let file: AuthFile = toml::from_str(&raw)
            .map_err(|e| cred_err(format!("not valid TOML at {:?}", e.span())))?;
        let Some(entry) = file.registries.get(registry) else {
            return Ok(None);
        };
        match (&entry.token, &entry.username, &entry.password) {
            (Some(t), None, None) => Ok(Some(Credential::Bearer(Secret::new(t.clone())))),
            (None, Some(u), Some(p)) => Ok(Some(Credential::Basic {
                username: u.clone(),
                password: Secret::new(p.clone()),
            })),
            _ => Err(cred_err(format!(
                "[registries.\"{registry}\"] needs either `token`, or both `username` and `password`"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn env_beats_file_and_debug_is_redacted() {
        let c = Credential::resolve_with("r:1", None, |k| {
            (k == ENV_TOKEN).then(|| "s3cret-token".to_owned())
        })
        .unwrap()
        .unwrap();
        assert!(!format!("{c:?}").contains("s3cret"));
        assert!(matches!(c, Credential::Bearer(_)));
    }

    #[test]
    fn half_set_basic_env_is_an_error() {
        let e = Credential::resolve_with("r", None, |k| (k == ENV_USERNAME).then(|| "u".into()))
            .unwrap_err();
        assert!(e.to_string().starts_with("ENTANGLE-E0815"));
    }

    #[cfg(unix)]
    #[test]
    fn file_credentials_and_permission_check() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("oci-auth.toml");
        std::fs::write(
            &p,
            "[registries.\"reg.example:5000\"]\nusername = \"bob\"\npassword = \"hunter2\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = Credential::resolve_with("reg.example:5000", Some(&p), no_env).unwrap_err();
        assert!(e.to_string().contains("chmod 600"), "{e}");
        assert!(!e.to_string().contains("hunter2"));

        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let c = Credential::resolve_with("reg.example:5000", Some(&p), no_env).unwrap();
        assert!(matches!(c, Some(Credential::Basic { ref username, .. }) if username == "bob"));
        assert!(Credential::resolve_with("other", Some(&p), no_env)
            .unwrap()
            .is_none());
    }
}
