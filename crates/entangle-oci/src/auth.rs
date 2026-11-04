//! Registry credentials: explicit sources only, never logged.
//!
//! Resolution order for a registry (`host[:port]`):
//! 1. environment: `ENTANGLE_OCI_TOKEN` (bearer), or
//!    `ENTANGLE_OCI_USERNAME` + `ENTANGLE_OCI_PASSWORD` (basic), **only** when
//!    `ENTANGLE_OCI_REGISTRY` names this registry. Environment credentials
//!    without `ENTANGLE_OCI_REGISTRY` are refused rather than offered to
//!    whatever registry a reference happens to name;
//! 2. `~/.entangle/oci-auth.toml`, section `[registries."<host[:port]>"]` with
//!    `username`+`password`, or `token`.
//! 3. none: anonymous.
//!
//! Registry names are compared as written in the reference (`host` or
//! `host:port`, IPv6 in brackets), ignoring ASCII case.
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
/// Environment variable naming the one registry (`host[:port]`) the
/// environment credentials belong to.
pub const ENV_REGISTRY: &str = "ENTANGLE_OCI_REGISTRY";

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
        let non_empty = |k: &str| env(k).filter(|v| !v.trim().is_empty());
        let from_env = match (
            non_empty(ENV_TOKEN),
            non_empty(ENV_USERNAME),
            non_empty(ENV_PASSWORD),
        ) {
            (Some(t), _, _) => Some(Credential::Bearer(Secret::new(t))),
            (None, Some(u), Some(p)) => Some(Credential::Basic {
                username: u,
                password: Secret::new(p),
            }),
            (None, None, None) => None,
            (None, _, _) => {
                return Err(OciError::Credentials(format!(
                    "{ENV_USERNAME} and {ENV_PASSWORD} must be set together"
                )))
            }
        };
        if let Some(cred) = from_env {
            // Environment credentials are bound to one named registry: a
            // reference to any other registry must not receive them.
            let Some(bound) = non_empty(ENV_REGISTRY) else {
                return Err(OciError::Credentials(format!(
                    "registry credentials are set in the environment but {ENV_REGISTRY} is not; \
                     set {ENV_REGISTRY} to the host[:port] they belong to (they are never sent \
                     to any other registry), or move them to oci-auth.toml"
                )));
            };
            if bound.trim().eq_ignore_ascii_case(registry) {
                return Ok(Some(cred));
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
        let c = Credential::resolve_with(
            "r:1",
            None,
            env_of(&[(ENV_TOKEN, "s3cret-token"), (ENV_REGISTRY, "r:1")]),
        )
        .unwrap()
        .unwrap();
        assert!(!format!("{c:?}").contains("s3cret"));
        assert!(matches!(c, Credential::Bearer(_)));
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    }

    #[test]
    fn env_credentials_apply_only_to_the_registry_they_name() {
        let env = env_of(&[
            (ENV_TOKEN, "internal-token"),
            (ENV_REGISTRY, "registry.internal:5000"),
        ]);
        for other in [
            "ghcr.io",
            "attacker.example",
            "registry.internal",
            "registry.internal:5001",
        ] {
            assert!(
                Credential::resolve_with(other, None, &env)
                    .unwrap()
                    .is_none(),
                "the env token must not be offered to {other}"
            );
        }
        let c = Credential::resolve_with("Registry.Internal:5000", None, &env)
            .unwrap()
            .unwrap();
        assert!(matches!(c, Credential::Bearer(ref t) if t.expose() == "internal-token"));

        let env = env_of(&[
            (ENV_USERNAME, "ci"),
            (ENV_PASSWORD, "pw"),
            (ENV_REGISTRY, "registry.internal:5000"),
        ]);
        assert!(Credential::resolve_with("attacker.example", None, &env)
            .unwrap()
            .is_none());
        assert!(matches!(
            Credential::resolve_with("registry.internal:5000", None, &env).unwrap(),
            Some(Credential::Basic { ref username, .. }) if username == "ci"
        ));
    }

    #[test]
    fn env_credentials_without_a_named_registry_are_refused() {
        for env in [
            env_of(&[(ENV_TOKEN, "s3cret-token")]),
            env_of(&[(ENV_USERNAME, "ci"), (ENV_PASSWORD, "s3cret-pw")]),
            env_of(&[(ENV_TOKEN, "s3cret-token"), (ENV_REGISTRY, "")]),
        ] {
            let e = Credential::resolve_with("ghcr.io", None, &env).unwrap_err();
            let text = e.to_string();
            assert!(text.starts_with("ENTANGLE-E0815"), "{text}");
            assert!(text.contains(ENV_REGISTRY), "{text}");
            assert!(!text.contains("s3cret"), "{text}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn env_credentials_for_another_registry_fall_back_to_the_auth_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("oci-auth.toml");
        std::fs::write(&p, "[registries.\"ghcr.io\"]\ntoken = \"file-token\"\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let env = env_of(&[
            (ENV_TOKEN, "internal-token"),
            (ENV_REGISTRY, "registry.internal:5000"),
        ]);
        let c = Credential::resolve_with("ghcr.io", Some(&p), &env)
            .unwrap()
            .unwrap();
        assert!(matches!(c, Credential::Bearer(ref t) if t.expose() == "file-token"));
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
