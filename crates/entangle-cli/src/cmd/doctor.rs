//! `entangle doctor` — run health checks and print status per check.

use crate::config::{self, entangle_dir};
use entangle_signing::IdentityKeyPair;

struct Check {
    label: &'static str,
    status: Status,
    detail: String,
}

enum Status {
    Ok,
    Warn,
    Fail,
    Skip,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Ok => write!(f, "[ok]  "),
            Status::Warn => write!(f, "[warn]"),
            Status::Fail => write!(f, "[fail]"),
            Status::Skip => write!(f, "[skip]"),
        }
    }
}

pub async fn run() -> anyhow::Result<()> {
    let mut checks: Vec<Check> = Vec::new();
    let mut any_fail = false;

    // 1. entangle dir exists
    let dir = entangle_dir();
    if dir.exists() {
        checks.push(Check {
            label: "~/.entangle/ exists",
            status: Status::Ok,
            detail: dir.display().to_string(),
        });
    } else {
        checks.push(Check {
            label: "~/.entangle/ exists",
            status: Status::Warn,
            detail: format!("{} not found — run `entangle init`", dir.display()),
        });
    }

    // 2. identity.key — exists and valid PEM
    let id_path = config::identity_path();
    if id_path.exists() {
        match std::fs::read_to_string(&id_path) {
            Ok(pem) => match IdentityKeyPair::from_pem(&pem) {
                Ok(kp) => {
                    checks.push(Check {
                        label: "identity.key valid",
                        status: Status::Ok,
                        detail: format!("fingerprint {}", kp.fingerprint_hex()),
                    });
                }
                Err(e) => {
                    any_fail = true;
                    checks.push(Check {
                        label: "identity.key valid",
                        status: Status::Fail,
                        detail: format!("PEM parse error: {e}"),
                    });
                }
            },
            Err(e) => {
                any_fail = true;
                checks.push(Check {
                    label: "identity.key valid",
                    status: Status::Fail,
                    detail: format!("read error: {e}"),
                });
            }
        }
    } else {
        checks.push(Check {
            label: "identity.key valid",
            status: Status::Warn,
            detail: "not found — run `entangle init`".into(),
        });
    }

    // 3. config.toml parses
    let cfg_path = config::config_path();
    if cfg_path.exists() {
        match config::load(&cfg_path) {
            Ok(_) => checks.push(Check {
                label: "config.toml parses",
                status: Status::Ok,
                detail: cfg_path.display().to_string(),
            }),
            Err(e) => {
                any_fail = true;
                checks.push(Check {
                    label: "config.toml parses",
                    status: Status::Fail,
                    detail: format!("parse error: {e}"),
                });
            }
        }
    } else {
        checks.push(Check {
            label: "config.toml parses",
            status: Status::Warn,
            detail: "absent — run `entangle init`".into(),
        });
    }

    // 4. keyring.toml parses
    let kr_path = config::keyring_path();
    if kr_path.exists() {
        match entangle_signing::Keyring::load(&kr_path) {
            Ok(_) => checks.push(Check {
                label: "keyring.toml parses",
                status: Status::Ok,
                detail: kr_path.display().to_string(),
            }),
            Err(e) => {
                any_fail = true;
                checks.push(Check {
                    label: "keyring.toml parses",
                    status: Status::Fail,
                    detail: format!("parse error: {e}"),
                });
            }
        }
    } else {
        checks.push(Check {
            label: "keyring.toml parses",
            status: Status::Warn,
            detail: "absent — run `entangle init`".into(),
        });
    }

    // 5. entangle_dir permissions (Unix only — warn if world-readable)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if dir.exists() {
            match std::fs::metadata(&dir) {
                Ok(meta) => {
                    let mode = meta.mode() & 0o777;
                    if mode & 0o077 != 0 {
                        checks.push(Check {
                            label: "~/.entangle/ permissions",
                            status: Status::Warn,
                            detail: format!(
                                "mode {:04o} — consider `chmod 700 {}`",
                                mode,
                                dir.display()
                            ),
                        });
                    } else {
                        checks.push(Check {
                            label: "~/.entangle/ permissions",
                            status: Status::Ok,
                            detail: format!("mode {:04o}", mode),
                        });
                    }
                }
                Err(e) => {
                    checks.push(Check {
                        label: "~/.entangle/ permissions",
                        status: Status::Warn,
                        detail: format!("could not stat dir: {e}"),
                    });
                }
            }
        } else {
            checks.push(Check {
                label: "~/.entangle/ permissions",
                status: Status::Skip,
                detail: "dir absent, skipping".into(),
            });
        }
    }

    // 6. Daemon socket (Phase 2)
    checks.push(Check {
        label: "daemon RPC",
        status: Status::Skip,
        detail: "daemon RPC not implemented yet".into(),
    });

    // Print results
    for c in &checks {
        println!("{} {}  {}", c.status, c.label, c.detail);
    }

    if any_fail {
        std::process::exit(1);
    }

    Ok(())
}
