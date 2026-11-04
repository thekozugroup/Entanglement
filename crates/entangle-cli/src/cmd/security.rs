//! `entangle security set-max-tier` and `entangle config {reload,validate}` —
//! the safe-lowering workflow for `[security] max_tier_allowed`
//! (spec §9.4.1).
//!
//! Lowering the ceiling below the tier of a loaded plugin is never silent:
//! the affected plugins are listed, the operator chooses unload-and-disable
//! (default) or cancel, and every outcome is audited — `ENTANGLE-W0214` per
//! unloaded plugin, `ENTANGLE-I0215` summary, `ENTANGLE-I0216` on cancel.
//! Raising the ceiling never unloads anything and is audited too
//! (`ENTANGLE-I0217`).
//!
//! Audit entries go to two places: the running daemon's broker audit log
//! (recorded by the daemon when it applies the change over RPC) and the
//! durable operator trail `~/.entangle/audit.log` (JSON lines, written here,
//! so the record exists even when the daemon is down or restarts).

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as _, Result};
use clap::{Args, Subcommand};
use entangle_rpc::{methods::AffectedPlugin, Client as RpcClient, RpcError};

use crate::config;
use crate::configedit::ConfigDoc;

// ---------------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------------

/// `entangle security` arguments.
#[derive(Args)]
pub struct SecurityArgs {
    #[command(subcommand)]
    cmd: SecurityCmd,
}

#[derive(Subcommand)]
enum SecurityCmd {
    /// Set `[security] max_tier_allowed`, safely unloading plugins above it.
    #[command(long_about = "\
Set `[security] max_tier_allowed` (1..=5) in ~/.entangle/config.toml and in the
running daemon.

Raising the ceiling never unloads anything. Lowering it below the tier of a
loaded plugin lists the affected plugins and, at a terminal, asks whether to
unload-and-disable them (default) or cancel. `--force-unload` is the
non-interactive path: it unloads and disables them without asking, but is never
silent -- the affected list goes to stderr and one ENTANGLE-W0214 audit entry is
written per plugin. `--yes` answers the prompt with its default, at a terminal
only. Without a terminal and without --force-unload (`--yes` included), lowering
over loaded plugins is refused (ENTANGLE-E0753) and nothing changes.

If the daemon is not running nothing is loaded, so only config.toml changes and
the ceiling applies at the next daemon start.")]
    SetMaxTier {
        /// New ceiling, 1..=5 (4 forbids tier-5 native plugins, 3 forbids all native).
        tier: u8,
        /// Non-interactive: unload and disable affected plugins without asking.
        #[arg(long)]
        force_unload: bool,
        /// At a terminal, accept the default action (unload-and-disable)
        /// without prompting. Without a terminal it is refused like no flag;
        /// use --force-unload there.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// `entangle config` arguments.
#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    cmd: ConfigCmd,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Apply an edited `[security] max_tier_allowed` to the running daemon.
    #[command(long_about = "\
Apply an edited `[security] max_tier_allowed` to the running daemon.

Reads ~/.entangle/config.toml and, if the ceiling there is lower than the
daemon's, shows which loaded plugins it would unload and asks (default:
unload-and-disable; cancel reverts your edit of config.toml and writes audit
entry ENTANGLE-I0216). Raising applies immediately and unloads nothing. Only the
ceiling is applied at runtime; every other setting takes effect when the daemon
restarts. Flags behave as for `entangle security set-max-tier`.")]
    Reload {
        /// Non-interactive: unload and disable affected plugins without asking.
        #[arg(long)]
        force_unload: bool,
        /// At a terminal, accept the default action (unload-and-disable)
        /// without prompting. Without a terminal it is refused like no flag;
        /// use --force-unload there.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Check config.toml and list plugins the ceiling in it would orphan.
    #[command(long_about = "\
Check ~/.entangle/config.toml without applying anything. Exits 1 if the file
is invalid or if its `max_tier_allowed` is below the tier of a loaded plugin
(for CI: fail fast on a config that would orphan plugins).")]
    Validate,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// `entangle security ...`; returns the process exit code.
pub async fn run_security(a: SecurityArgs) -> Result<i32> {
    match a.cmd {
        SecurityCmd::SetMaxTier {
            tier,
            force_unload,
            yes,
        } => {
            check_range(tier, "argument")?;
            lower_or_raise(tier, Mode::SetMaxTier, Flags { force_unload, yes }).await
        }
    }
}

/// `entangle config ...`; returns the process exit code.
pub async fn run_config(a: ConfigArgs) -> Result<i32> {
    match a.cmd {
        ConfigCmd::Reload { force_unload, yes } => {
            let tier = tier_from_config_file()?;
            lower_or_raise(tier, Mode::Reload, Flags { force_unload, yes }).await
        }
        ConfigCmd::Validate => validate().await,
    }
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
enum Mode {
    /// The CLI makes the config edit (after the operator agrees).
    SetMaxTier,
    /// The operator already edited the file; cancel must revert it.
    Reload,
}

#[derive(Copy, Clone)]
struct Flags {
    force_unload: bool,
    yes: bool,
}

fn check_range(n: u8, what: &str) -> Result<()> {
    if (1..=5).contains(&n) {
        Ok(())
    } else {
        bail!("ENTANGLE-E0752: invalid max_tier_allowed {n} ({what}): expected 1..=5")
    }
}

fn tier_from_config_file() -> Result<u8> {
    let path = config::config_path();
    let cfg = config::load(&path)
        .with_context(|| format!("ENTANGLE-E0754: cannot read {}", path.display()))?;
    let n = cfg.security.max_tier_allowed;
    check_range(
        n,
        &format!("{} [security] max_tier_allowed", path.display()),
    )?;
    Ok(n)
}

fn rpc_client() -> RpcClient {
    RpcClient::new(RpcClient::default_socket())
}

fn audit_path() -> std::path::PathBuf {
    config::entangle_dir().join("audit.log")
}

/// Append one JSON line to `~/.entangle/audit.log` (mode 0600).
fn audit(code: &str, message: &str, extra: serde_json::Value) -> Result<()> {
    let mut rec = serde_json::json!({
        "ts_unix": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        "code": code,
        "message": message,
    });
    if let (Some(o), Some(e)) = (rec.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    let path = audit_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&path)
        .with_context(|| format!("opening audit log {}", path.display()))?;
    writeln!(f, "{rec}").with_context(|| format!("writing audit log {}", path.display()))?;
    Ok(())
}

/// Durable audit line for a ceiling change that unloaded nothing: I0215 for
/// a lowering, I0217 for a raise (spec §9.4.1: both are audited).
fn audit_ceiling_change(old: u8, new: u8, applied_to: &str) -> Result<()> {
    let fields = serde_json::json!({
        "old_ceiling": old, "new_ceiling": new, "applied_to": applied_to,
    });
    if new > old {
        audit("ENTANGLE-I0217", "max_tier_allowed raised", fields)
    } else {
        let mut fields = fields;
        fields["unloaded"] = serde_json::json!(0);
        audit(
            "ENTANGLE-I0215",
            "max_tier_allowed lowered; no plugins affected",
            fields,
        )
    }
}

fn fmt_uptime(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s uptime"),
        60..=3599 => format!("{}m uptime", secs / 60),
        _ => {
            let (h, m) = (secs / 3600, (secs % 3600) / 60);
            if m == 0 || h >= 10 {
                format!("{h}h uptime")
            } else {
                format!("{h}h{m:02}m uptime")
            }
        }
    }
}

fn affected_list(affected: &[AffectedPlugin]) -> String {
    let w = affected
        .iter()
        .map(|a| a.plugin_id.len())
        .max()
        .unwrap_or(0);
    affected
        .iter()
        .map(|a| {
            format!(
                "  - {:<w$}   (tier {}, {}, {})\n",
                a.plugin_id,
                a.tier,
                if a.native {
                    "native subprocess"
                } else {
                    "wasm component"
                },
                fmt_uptime(a.uptime_secs),
            )
        })
        .collect()
}

#[derive(PartialEq, Eq)]
enum Decision {
    Unload,
    Cancel,
}

/// Ask on the terminal. EOF or anything unrecognised after three tries is
/// treated as cancel: the safe answer.
fn prompt(current: u8, new: u8, affected: &[AffectedPlugin]) -> Result<Decision> {
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "Lowering [security] max_tier_allowed from {current} to {new} will affect {} running plugin{}:\n",
        affected.len(),
        if affected.len() == 1 { "" } else { "s" }
    )?;
    write!(out, "{}", affected_list(affected))?;
    writeln!(
        out,
        "\nChoose action:\n  [u] unload-and-disable  (default; plugins are stopped, marked disabled in config)\n  [c] cancel              (config reload aborted; max_tier_allowed unchanged)\n"
    )?;
    let stdin = std::io::stdin();
    for _ in 0..3 {
        write!(out, "Decision [u/c]: ")?;
        out.flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            writeln!(out)?;
            return Ok(Decision::Cancel);
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "" | "u" | "unload" => return Ok(Decision::Unload),
            "c" | "cancel" => return Ok(Decision::Cancel),
            other => writeln!(out, "Unrecognised answer {other:?}; type u or c.")?,
        }
    }
    Ok(Decision::Cancel)
}

/// config.toml with the tier and the disabled plugins applied, in memory
/// (format-preserving). Fails, without writing anything, when the file cannot
/// take the edit (unreadable, not valid TOML, a section of the wrong shape).
fn edited_config(mode: Mode, new: u8, disabled: &[String]) -> Result<ConfigDoc> {
    let mut doc = ConfigDoc::load(&config::config_path())?;
    if mode == Mode::SetMaxTier {
        doc.set_int("security", "max_tier_allowed", i64::from(new))?;
    }
    for id in disabled {
        doc.add_to_str_array("plugins", "disabled", id)?;
    }
    Ok(doc)
}

/// Persist the tier and the disabled plugins in config.toml.
fn persist(mode: Mode, new: u8, disabled: &[String]) -> Result<()> {
    edited_config(mode, new, disabled)?.save(&config::config_path())
}

/// [`persist`] after the daemon already applied `new`: on failure, say that
/// the two now disagree and how to reconcile them.
fn persist_applied(mode: Mode, new: u8, disabled: &[String]) -> Result<()> {
    persist(mode, new, disabled).with_context(|| {
        format!(
            "the daemon already runs with max_tier_allowed = {new}, but {} could not be \
             updated to match; fix the file and re-run `entangle security set-max-tier {new}`",
            config::config_path().display()
        )
    })
}

async fn lower_or_raise(new: u8, mode: Mode, flags: Flags) -> Result<i32> {
    let cfg_path = config::config_path();
    let client = rpc_client();
    // Where the daemon stands now. For Reload the file already says `new`, so
    // "current" can only come from the daemon.
    let plan = match client.security_plan_max_tier(new).await {
        Ok(p) => Some(p),
        Err(RpcError::DaemonNotRunning(_)) | Err(RpcError::ConnectTimeout { .. }) => None,
        Err(e) => return Err(e).context("asking the daemon which plugins the new ceiling affects"),
    };

    let Some(plan) = plan else {
        // No daemon: no plugins are loaded (the daemon does not persist or
        // reload them), so there is nothing to unload.
        eprintln!(
            "note: daemon not running at {}; no plugins are loaded, so none are affected.",
            RpcClient::default_socket().display()
        );
        if mode == Mode::SetMaxTier {
            // The file's ceiling is the one the next daemon start applies, so
            // a change of it is audited like a runtime change.
            let old = config::load(&cfg_path)
                .ok()
                .map(|c| c.security.max_tier_allowed);
            persist(mode, new, &[])?;
            println!(
                "max_tier_allowed = {new} written to {}; it applies when the daemon starts.",
                cfg_path.display()
            );
            if let Some(old) = old.filter(|o| *o != new) {
                audit_ceiling_change(old, new, "config.toml (daemon not running)")?;
            }
        } else {
            println!(
                "max_tier_allowed = {new} in {}; nothing to reload (daemon not running).",
                cfg_path.display()
            );
        }
        return Ok(0);
    };

    let current = plan.current;
    let listed: Vec<String> = plan.affected.iter().map(|a| a.plugin_id.clone()).collect();
    // Nothing in the daemon changes before config.toml is known to take the
    // edit; after the daemon applied it, the file is written first and the
    // durable audit lines last, so no later failure can leave the daemon
    // changed while the file still holds the old ceiling (which the next
    // daemon start would restore).
    edited_config(mode, new, &listed)?;
    if plan.affected.is_empty() {
        let applied = client
            .security_apply_max_tier(new, false, None)
            .await
            .context("applying the new ceiling to the daemon")?;
        if mode == Mode::SetMaxTier {
            persist_applied(mode, new, &[])?;
        }
        if applied.old < applied.new {
            println!(
                "max_tier_allowed raised {} -> {}; nothing was unloaded. (ENTANGLE-I0217 audited)",
                applied.old, applied.new
            );
        } else if applied.old == applied.new {
            println!("max_tier_allowed already {new}; no change.");
        } else {
            println!(
                "max_tier_allowed lowered {} -> {}; no loaded plugin is above it.",
                applied.old, applied.new
            );
        }
        if applied.old != applied.new {
            audit_ceiling_change(applied.old, applied.new, "daemon")?;
        }
        return Ok(0);
    }

    // Lowering over loaded plugins: never silent. An answer at the prompt
    // covers exactly the plugins listed there; the daemon refuses
    // (ENTANGLE-E0758) to unload any other one, e.g. one loaded while the
    // prompt waited. `--force-unload` consents in advance to whatever is above
    // the ceiling when it is applied (still listed and audited per plugin).
    // `--yes` only answers a prompt, so it counts only at a terminal; the one
    // non-interactive path is `--force-unload` (spec §9.4.1 step 6).
    let at_terminal = std::io::stdin().is_terminal();
    let unattended = flags.force_unload || (flags.yes && at_terminal);
    let confirmed = (!unattended).then(|| listed.clone());
    let decision = if unattended {
        eprintln!(
            "Lowering [security] max_tier_allowed from {current} to {new}: unloading and disabling {} plugin{} above the new ceiling:\n{}",
            plan.affected.len(),
            if plan.affected.len() == 1 { "" } else { "s" },
            affected_list(&plan.affected)
        );
        Decision::Unload
    } else if at_terminal {
        prompt(current, new, &plan.affected)?
    } else {
        eprintln!(
            "Lowering [security] max_tier_allowed from {current} to {new} would affect {} running plugin{}:\n{}",
            plan.affected.len(),
            if plan.affected.len() == 1 { "" } else { "s" },
            affected_list(&plan.affected)
        );
        bail!(
            "ENTANGLE-E0753: refusing to unload plugins without confirmation (no terminal); \
             re-run with --force-unload to unload and disable them, or run interactively. \
             Nothing was changed."
        );
    };

    match decision {
        Decision::Cancel => {
            if mode == Mode::Reload {
                // The operator's edit is backed out: the daemon keeps `current`.
                let mut doc = ConfigDoc::load(&cfg_path)?;
                doc.set_int("security", "max_tier_allowed", i64::from(current))?;
                doc.save(&cfg_path)?;
            }
            client
                .security_cancel_max_tier(new)
                .await
                .context("recording the cancellation in the daemon audit log")?;
            audit(
                "ENTANGLE-I0216",
                "max_tier_allowed lowering cancelled by operator",
                serde_json::json!({
                    "current_ceiling": current,
                    "requested_ceiling": new,
                    "affected": plan.affected.iter().map(|a| a.plugin_id.clone()).collect::<Vec<_>>(),
                }),
            )?;
            println!(
                "Cancelled: max_tier_allowed stays {current}{}. (ENTANGLE-I0216 audited)",
                if mode == Mode::Reload {
                    format!(" (reverted in {})", cfg_path.display())
                } else {
                    String::new()
                }
            );
            Ok(1)
        }
        Decision::Unload => {
            let applied = client
                .security_apply_max_tier(new, true, confirmed)
                .await
                .context(
                    "applying the new ceiling to the daemon (nothing was changed; re-run to see \
                     the plugins it affects now)",
                )?;
            // Per-plugin W0214 (loud, stderr + durable audit), then I0215.
            let tiers: std::collections::HashMap<_, _> = plan
                .affected
                .iter()
                .map(|a| (a.plugin_id.as_str(), a.tier))
                .collect();
            for id in &applied.unloaded {
                eprintln!(
                    "ENTANGLE-W0214: unloaded and disabled {id}{} (max_tier_allowed {} -> {})",
                    tiers
                        .get(id.as_str())
                        .map(|t| format!(" (tier {t})"))
                        .unwrap_or_default(),
                    applied.old,
                    applied.new
                );
            }
            persist_applied(mode, new, &applied.unloaded)?;
            // Durable trail last. A failure is reported (exit non-zero) after
            // every line was attempted; daemon and config.toml already agree.
            let mut audit_err = None;
            for id in &applied.unloaded {
                let tier = tiers.get(id.as_str()).copied();
                if let Err(e) = audit(
                    "ENTANGLE-W0214",
                    "plugin unloaded and disabled: tier above new max_tier_allowed",
                    serde_json::json!({
                        "plugin": id, "tier": tier,
                        "old_ceiling": applied.old, "new_ceiling": applied.new,
                    }),
                ) {
                    audit_err.get_or_insert(e);
                }
            }
            if let Err(e) = audit(
                "ENTANGLE-I0215",
                "max_tier_allowed lowered",
                serde_json::json!({
                    "old_ceiling": applied.old, "new_ceiling": applied.new,
                    "unloaded": applied.unloaded,
                }),
            ) {
                audit_err.get_or_insert(e);
            }
            println!(
                "max_tier_allowed lowered {} -> {}; unloaded and disabled {} plugin{} (ENTANGLE-I0215). \
                 Loads above tier {} now fail with ENTANGLE-E0043.",
                applied.old,
                applied.new,
                applied.unloaded.len(),
                if applied.unloaded.len() == 1 { "" } else { "s" },
                applied.new
            );
            match audit_err {
                Some(e) => Err(e),
                None => Ok(0),
            }
        }
    }
}

async fn validate() -> Result<i32> {
    let new = tier_from_config_file()?;
    match rpc_client().security_plan_max_tier(new).await {
        Ok(p) if p.affected.is_empty() => {
            println!(
                "config ok: max_tier_allowed = {new}; no loaded plugin is above it (daemon ceiling {}).",
                p.current
            );
            Ok(0)
        }
        Ok(p) => {
            println!(
                "max_tier_allowed = {new} in {} would unload {} plugin(s) (daemon ceiling is {}):\n{}",
                config::config_path().display(),
                p.affected.len(),
                p.current,
                affected_list(&p.affected)
            );
            Ok(1)
        }
        Err(RpcError::DaemonNotRunning(_)) | Err(RpcError::ConnectTimeout { .. }) => {
            println!(
                "config ok: max_tier_allowed = {new}; daemon not running, so no loaded plugins to check."
            );
            Ok(0)
        }
        Err(e) => Err(e).context("asking the daemon which plugins the ceiling affects"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_formats_like_the_spec_example() {
        assert_eq!(fmt_uptime(5), "5s uptime");
        assert_eq!(fmt_uptime(17 * 60), "17m uptime");
        assert_eq!(fmt_uptime(3600 + 17 * 60), "1h17m uptime");
        assert_eq!(fmt_uptime(22 * 3600 + 5), "22h uptime");
    }

    #[test]
    fn tier_range_is_enforced() {
        assert!(check_range(0, "t").is_err());
        assert!(check_range(6, "t")
            .unwrap_err()
            .to_string()
            .contains("E0752"));
        assert!(check_range(3, "t").is_ok());
    }
}
