//! `entangle wrapper {enable,disable,status,repair}` — the opt-in shell shim
//! that warns when an agent host runs outside an Entanglement session
//! (spec §8.3, "Wrapper-bypass UX trap").
//!
//! The shim is a UX guardrail, not a security boundary: `command claude` or
//! `\claude` bypasses it, by design. It is written between marker lines into
//! `~/.bashrc`, `~/.zshrc` and `~/.config/fish/conf.d/entangle.fish`; the
//! choice is recorded in `~/.entangle/config.toml` as `[wrappers] install`
//! so that disabling is never silent and later installs respect it.

use std::path::PathBuf;

use anyhow::{bail, Context as _, Result};
use clap::{Args, Subcommand};

use super::rcblock::{self, BlockState, Dialect, Host};
use crate::configedit::ConfigDoc;
use crate::{config, fsutil};

/// `entangle wrapper` arguments.
#[derive(Args)]
pub struct WrapperArgs {
    #[command(subcommand)]
    cmd: WrapperCmd,
}

#[derive(Subcommand)]
enum WrapperCmd {
    /// Install the warning shim into your shell rc files (idempotent).
    #[command(long_about = "\
Install the warning shim into your shell rc files (idempotent).

Writes one marked block (`# >>> entangle wrapper >>>` ... `# <<< entangle wrapper <<<`)
into ~/.bashrc, ~/.zshrc and ~/.config/fish/conf.d/entangle.fish, defining a
function for every agent host `entangle agent run` supports (see `entangle agent
list`). Outside an Entanglement session (ENTANGLE_SESSION_ID unset) the function
prints a warning to stderr and then runs the real binary with the same arguments
and exit status; inside a session it is silent.

Only the text between the markers is ever touched. Records `[wrappers] install =
true` in ~/.entangle/config.toml. Open a new shell (or `source ~/.bashrc`) to
pick it up. This is a guardrail, not a security boundary: `command claude`
bypasses it.")]
    Enable,
    /// Remove the shim and record the opt-out in config.toml.
    #[command(long_about = "\
Remove the shim and record the opt-out.

Deletes the marked block from every rc file (nothing else in them is touched)
and records `[wrappers] install = false` in ~/.entangle/config.toml. `entangle
wrapper enable` turns it back on.")]
    Disable,
    /// Show, per rc file, whether the shim is installed, outdated or damaged.
    Status,
    /// Rewrite a damaged or duplicated block into exactly one current block.
    Repair,
}

/// One rc file the shim lives in.
#[derive(Clone, Debug)]
pub struct RcFile {
    /// Display name, e.g. `~/.bashrc`.
    pub label: &'static str,
    /// Absolute path.
    pub path: PathBuf,
    /// Syntax to render.
    pub dialect: Dialect,
    /// Interactive shell that reads this file.
    pub shell: &'static str,
}

/// The rc files managed on this machine (`$HOME`-relative; the zsh one is
/// `$ZDOTDIR/.zshrc` when `ZDOTDIR` is set).
pub fn rc_files() -> Result<Vec<RcFile>> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| !h.as_os_str().is_empty())
        .context("ENTANGLE-E0756: $HOME is not set; cannot locate shell rc files")?;
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"));
    // zsh reads $ZDOTDIR/.zshrc instead of ~/.zshrc when ZDOTDIR is set
    // (typically exported from ~/.zshenv, so it is in the environment of
    // every command run from zsh). A relative ZDOTDIR is ignored, as zsh's
    // meaning for it depends on the shell's working directory.
    let (zlabel, zshrc) = match std::env::var_os("ZDOTDIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        Some(z) => ("$ZDOTDIR/.zshrc", z.join(".zshrc")),
        None => ("~/.zshrc", home.join(".zshrc")),
    };
    Ok(vec![
        RcFile {
            label: "~/.bashrc",
            path: home.join(".bashrc"),
            dialect: Dialect::Posix,
            shell: "bash",
        },
        RcFile {
            label: zlabel,
            path: zshrc,
            dialect: Dialect::Posix,
            shell: "zsh",
        },
        RcFile {
            label: "~/.config/fish/conf.d/entangle.fish",
            path: xdg.join("fish/conf.d/entangle.fish"),
            dialect: Dialect::Fish,
            shell: "fish",
        },
    ])
}

/// State of the shim in one rc file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RcStatus {
    /// The file does not exist.
    Missing,
    /// The file exists without a block.
    Absent,
    /// One block, identical to what `enable` would write now.
    Installed,
    /// One block that differs from the current rendering (e.g. a newly
    /// supported agent host); `enable` refreshes it.
    Outdated,
    /// This many blocks (more than one).
    Duplicated(usize),
    /// Stray, nested or unterminated markers.
    Damaged(String),
}

impl RcStatus {
    /// True when the shim is usable (installed or merely outdated).
    pub fn has_block(&self) -> bool {
        matches!(self, RcStatus::Installed | RcStatus::Outdated)
    }
    /// Human-readable one-liner.
    pub fn describe(&self) -> String {
        match self {
            RcStatus::Missing => "file does not exist".into(),
            RcStatus::Absent => "no wrapper block".into(),
            RcStatus::Installed => "installed".into(),
            RcStatus::Outdated => "installed but outdated (run `entangle wrapper enable`)".into(),
            RcStatus::Duplicated(n) => {
                format!("{n} wrapper blocks (run `entangle wrapper repair`)")
            }
            RcStatus::Damaged(why) => {
                format!("damaged block: {why} (run `entangle wrapper repair`)")
            }
        }
    }
}

fn desired(rc: &RcFile, hosts: &[Host]) -> String {
    rcblock::render(rc.dialect, hosts)
}

fn read_rc(rc: &RcFile) -> Result<Option<String>> {
    match std::fs::read(&rc.path) {
        Ok(b) => String::from_utf8(b).map(Some).map_err(|_| {
            anyhow::anyhow!(
                "ENTANGLE-E0756: {} is not valid UTF-8; refusing to edit it",
                rc.label
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("ENTANGLE-E0756: reading {}", rc.label)),
    }
}

/// Inspect one rc file.
pub fn rc_status(rc: &RcFile, hosts: &[Host]) -> Result<RcStatus> {
    let Some(text) = read_rc(rc)? else {
        return Ok(RcStatus::Missing);
    };
    Ok(match rcblock::inspect(&text, &desired(rc, hosts)) {
        BlockState::Absent => RcStatus::Absent,
        BlockState::Present { current: true } => RcStatus::Installed,
        BlockState::Present { current: false } => RcStatus::Outdated,
        BlockState::Duplicated(n) => RcStatus::Duplicated(n),
        BlockState::Damaged(w) => RcStatus::Damaged(w),
    })
}

/// Whether the operator opted in (`[wrappers] install = true`). Absent means
/// "not opted in": the shim is opt-in (spec §8.3 item 2).
pub fn wrappers_enabled() -> bool {
    config::load(&config::config_path())
        .map(|c| c.wrappers.install)
        .unwrap_or(false)
}

/// Whether config.toml explicitly says `[wrappers] install = false`, which
/// the installed shim honours at run time (spec §8.3 item 2): its blocks are
/// then inactive.
pub fn wrappers_off_in_config() -> bool {
    std::fs::read_to_string(config::config_path())
        .ok()
        .and_then(|t| t.parse::<toml::Table>().ok())
        .and_then(|t| t.get("wrappers")?.get("install")?.as_bool())
        == Some(false)
}

fn write_rc(rc: &RcFile, text: &str) -> Result<()> {
    if rc.dialect == Dialect::Fish && text.is_empty() {
        // The conf.d snippet is wholly ours: don't leave an empty file.
        let target = fsutil::resolve_symlink(&rc.path);
        match std::fs::remove_file(&target) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("removing {}", rc.label)),
        }
    }
    fsutil::atomic_write(&rc.path, text.as_bytes(), 0o644)
        .with_context(|| format!("ENTANGLE-E0756: writing {}", rc.label))
}

/// What to do to each rc file.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Op {
    Install,
    Remove,
    Repair,
}

/// Apply `op` to every rc file; prints one line per file. Returns the number
/// of files that failed.
fn apply(op: Op, hosts: &[Host]) -> Result<usize> {
    let mut failed = 0;
    for rc in rc_files()? {
        let want = desired(&rc, hosts);
        let outcome = (|| -> Result<(String, bool)> {
            let current = read_rc(&rc)?;
            let text = current.clone().unwrap_or_default();
            let edit = match op {
                Op::Install => rcblock::install(&text, &want).map_err(|_| {
                    let st = rc_status(&rc, hosts)
                        .map(|s| s.describe())
                        .unwrap_or_default();
                    anyhow::anyhow!("ENTANGLE-E0751: {}: {st}", rc.label)
                })?,
                Op::Remove => {
                    if current.is_none() {
                        return Ok(("not present".into(), false));
                    }
                    rcblock::remove(&text, &want)
                }
                Op::Repair => rcblock::repair(&text, &want),
            };
            if edit.changed || (current.is_none() && op != Op::Remove) {
                write_rc(&rc, &edit.text)?;
                let verb = match op {
                    Op::Install => "installed",
                    Op::Remove => "removed",
                    Op::Repair => "repaired",
                };
                Ok((verb.into(), true))
            } else {
                let verb = match op {
                    Op::Remove => "no block to remove",
                    _ => "already up to date",
                };
                Ok((verb.into(), false))
            }
        })();
        match outcome {
            Ok((msg, _)) => println!("{:<8} {:<38} {msg}", rc.shell, rc.label),
            Err(e) => {
                failed += 1;
                eprintln!("error: {e:#}");
            }
        }
    }
    Ok(failed)
}

fn set_install(on: bool) -> Result<()> {
    let path = config::config_path();
    let mut doc = ConfigDoc::load(&path)?;
    doc.set_bool("wrappers", "install", on)?;
    doc.save(&path)
}

/// `entangle wrapper enable`: record the opt-in and install the shim in
/// every rc file.
pub fn enable() -> Result<()> {
    let hosts = rcblock::hosts_from_adapters();
    set_install(true)?;
    let failed = apply(Op::Install, &hosts)?;
    if failed > 0 {
        bail!("{failed} rc file(s) could not be updated");
    }
    println!(
        "Wrappers enabled for: {}. Open a new shell (or `source` your rc file) to use them.",
        hosts
            .iter()
            .map(|h| h.binary.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("Outside an Entanglement session they warn on stderr, then run the real binary.");
    Ok(())
}

/// `entangle wrapper disable`: record the opt-out, then remove the shim
/// from every rc file (also what `entangle uninstall` runs).
pub fn disable() -> Result<()> {
    let hosts = rcblock::hosts_from_adapters();
    // Record the opt-out first: it must survive a failure below.
    set_install(false)?;
    let failed = apply(Op::Remove, &hosts)?;
    println!(
        "Wrappers DISABLED: recorded [wrappers] install = false in {}.",
        config::config_path().display()
    );
    println!("Agent hosts run outside `entangle agent run` will no longer warn. Re-enable with `entangle wrapper enable`.");
    if failed > 0 {
        bail!("{failed} rc file(s) could not be cleaned; fix them and re-run `entangle wrapper disable`");
    }
    Ok(())
}

/// What config.toml records about the shim: `Some(true)` opted in,
/// `Some(false)` opted out, `None` never asked.
pub fn recorded_choice() -> Option<bool> {
    std::fs::read_to_string(config::config_path())
        .ok()
        .and_then(|t| t.parse::<toml::Table>().ok())
        .and_then(|t| t.get("wrappers")?.get("install")?.as_bool())
}

/// Record the opt-out without touching any rc file (`entangle install
/// --no-wrapper` when no choice was recorded yet).
pub fn record_opt_out() -> Result<()> {
    set_install(false)
}

/// Entry point for `entangle wrapper`.
pub async fn run(a: WrapperArgs) -> Result<()> {
    let hosts = rcblock::hosts_from_adapters();
    match a.cmd {
        WrapperCmd::Enable => enable(),
        WrapperCmd::Disable => disable(),
        WrapperCmd::Status => {
            let enabled = wrappers_enabled();
            println!(
                "wrappers: {} ({})",
                if enabled { "enabled" } else { "disabled" },
                format_args!(
                    "[wrappers] install in {}{}",
                    config::config_path().display(),
                    if enabled {
                        ""
                    } else {
                        "; opt-in, absent or false"
                    }
                )
            );
            println!(
                "hosts:    {}",
                hosts
                    .iter()
                    .map(|h| format!("{} (entangle agent run {})", h.binary, h.agent))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let off = wrappers_off_in_config();
            for rc in rc_files()? {
                let st = match rc_status(&rc, &hosts) {
                    Ok(s) if off && s.has_block() => format!(
                        "{} -- inactive: [wrappers] install = false (`entangle wrapper disable` \
                         removes it)",
                        s.describe()
                    ),
                    Ok(s) => s.describe(),
                    Err(e) => format!("error: {e:#}"),
                };
                println!("{:<8} {:<38} {st}", rc.shell, rc.label);
            }
            Ok(())
        }
        WrapperCmd::Repair => {
            if !wrappers_enabled() {
                bail!(
                    "ENTANGLE-E0757: wrappers are not enabled ([wrappers] install is not true); \
                     run `entangle wrapper enable`. (`entangle wrapper disable` also cleans up \
                     damaged blocks.)"
                );
            }
            let failed = apply(Op::Repair, &hosts)?;
            if failed > 0 {
                bail!("{failed} rc file(s) could not be repaired");
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Shadow detection (used by `entangle doctor`, spec §8.3 item 3)
// ---------------------------------------------------------------------------

/// What the user's shell resolves an agent-host name to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Our shim function is what runs.
    Wrapper,
    /// Some other shell function; `from` is the defining file when the shell
    /// reports it (zsh does).
    OtherFunction {
        /// Where the shell says the function was defined, if it says.
        from: Option<String>,
    },
    /// An alias with this expansion.
    Alias(String),
    /// A file found on `PATH` (no function in the way).
    File(String),
    /// Not found at all.
    NotFound,
    /// Something else (builtin, keyword); the raw `type` line.
    Other(String),
}

const SENTINEL: &str = "__ENTANGLE_PROBE__";

/// Parse the output of the probe script for the names in `bins`.
///
/// The script prints `__ENTANGLE_PROBE__ BEGIN <bin>` ... `__ENTANGLE_PROBE__
/// END <bin>` around `type <bin>` and `typeset -f <bin>`; anything the user's
/// rc files print outside the sentinels is ignored. Handles bash
/// ("claude is a function", "is aliased to `x'", "is /usr/bin/claude", "is
/// hashed (/usr/bin/claude)") and zsh ("is a shell function from F", "is an
/// alias for x", "is /usr/bin/claude").
pub fn parse_probe(output: &str, bins: &[String]) -> Vec<(String, Resolution)> {
    let mut out = Vec::new();
    for bin in bins {
        let begin = format!("{SENTINEL} BEGIN {bin}");
        let end = format!("{SENTINEL} END {bin}");
        let mut body = Vec::new();
        let mut inside = false;
        let mut seen = false;
        for line in output.lines() {
            let line = line.trim_end_matches('\r');
            if line == begin {
                inside = true;
                seen = true;
            } else if line == end {
                inside = false;
            } else if inside {
                body.push(line);
            }
        }
        if !seen {
            continue;
        }
        out.push((bin.clone(), classify(bin, &body)));
    }
    out
}

fn classify(bin: &str, body: &[&str]) -> Resolution {
    let first = body
        .iter()
        .find(|l| !l.trim().is_empty())
        .copied()
        .unwrap_or("");
    let first = first.trim();
    let rest = &first[first.find(" is ").map_or(0, |i| i + 4)..];
    // `typeset -f <bin>` printed our function somewhere in the body.
    let shim_defined = || {
        let all = body.join("\n");
        all.contains("ENTANGLE_SESSION_ID") && all.contains("outside Entanglement session")
    };
    if first.contains(" is a function") || first.contains(" is a shell function") {
        if shim_defined() {
            return Resolution::Wrapper;
        }
        let from = first.split(" from ").nth(1).map(|s| s.trim().to_owned());
        return Resolution::OtherFunction { from };
    }
    let alias = if first.contains(" is aliased to ") {
        let a = first.split(" is aliased to ").nth(1).unwrap_or("");
        Some(a.trim_matches(|c| c == '`' || c == '\'').to_owned())
    } else if first.contains(" is an alias for ") {
        Some(
            first
                .split(" is an alias for ")
                .nth(1)
                .unwrap_or("")
                .to_owned(),
        )
    } else {
        None
    };
    if let Some(a) = alias {
        // `alias claude='claude --flag'` expands to the same name, which the
        // shell then resolves to our function (an alias is not re-expanded
        // inside its own expansion; `\claude` only skips alias lookup).
        let head = a.split_whitespace().next().unwrap_or("");
        if head.trim_start_matches('\\') == bin && shim_defined() {
            return Resolution::Wrapper;
        }
        return Resolution::Alias(a);
    }
    if let Some(p) = rest
        .strip_prefix("hashed (")
        .and_then(|s| s.strip_suffix(')'))
        .or_else(|| rest.starts_with('/').then_some(rest))
    {
        return Resolution::File(p.to_owned());
    }
    if first.is_empty() || first.contains("not found") {
        return Resolution::NotFound;
    }
    Resolution::Other(first.to_owned())
}

/// Run the user's interactive shell with its rc files loaded and report how
/// each name in `bins` resolves.
///
/// Limits (documented in `docs/operations.md`): only bash and zsh are probed
/// (fish is skipped); the shell runs `-i -c` with an empty stdin, in a new
/// session without a controlling terminal (so it cannot stop a doctor run as
/// a background job), so an rc file that behaves differently without a tty,
/// or that blocks, is
/// cut off by `timeout`; rc files that print or exec are tolerated but the
/// result reflects a non-tty shell; shadowing introduced only by a *login*
/// profile (`~/.bash_profile`, `~/.zprofile`) the interactive shell does not
/// re-read is not seen.
pub async fn probe_shell(
    shell: &std::path::Path,
    bins: &[String],
    timeout: std::time::Duration,
) -> Result<Vec<(String, Resolution)>> {
    use std::process::Stdio;
    let safe: Vec<&String> = bins
        .iter()
        .filter(|b| {
            !b.is_empty()
                && b.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        .collect();
    let mut script = String::new();
    for b in &safe {
        script.push_str(&format!(
            "echo {SENTINEL} BEGIN {b}; type {b}; typeset -f {b} 2>/dev/null; echo {SENTINEL} END {b}; "
        ));
    }
    let mut cmd = tokio::process::Command::new(shell);
    cmd.args(["-i", "-c", &script])
        .env("ENTANGLE_DOCTOR_PROBE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // An interactive shell opens /dev/tty for job control even with stdin
    // redirected; when doctor is not in the terminal's foreground process
    // group (`entangle doctor &`) it sends SIGTTIN to its whole process group
    // -- doctor included, so the timeout below could never fire. In a new
    // session the probe has no controlling terminal: it runs without job
    // control and cannot signal doctor's group.
    #[cfg(unix)]
    // SAFETY: the closure runs in the forked child before exec. It only calls
    // setsid(2) through rustix (a raw syscall, async-signal-safe, no
    // allocation, no lock) and converts its result; it touches no state shared
    // with the parent.
    unsafe {
        cmd.pre_exec(|| {
            rustix::process::setsid()
                .map(drop)
                .map_err(std::io::Error::from)
        });
    }
    let child = cmd
        .spawn()
        .with_context(|| format!("starting {}", shell.display()))?;
    let out = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| anyhow::anyhow!("{} did not finish within {timeout:?}", shell.display()))?
        .with_context(|| format!("running {}", shell.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let owned: Vec<String> = safe.into_iter().cloned().collect();
    Ok(parse_probe(&text, &owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(body: &str) -> Resolution {
        let out =
            format!("noise from rc\n{SENTINEL} BEGIN claude\n{body}\n{SENTINEL} END claude\n");
        parse_probe(&out, &["claude".to_owned()]).remove(0).1
    }

    #[test]
    fn bash_and_zsh_type_output_is_classified() {
        let shim = "ENTANGLE_SESSION_ID printf 'claude launched outside Entanglement session.'";
        assert_eq!(
            probe(&format!("claude is a function\nclaude () {{ {shim}; }}")),
            Resolution::Wrapper
        );
        assert_eq!(
            probe("claude is a function\nclaude () { echo hi; }"),
            Resolution::OtherFunction { from: None }
        );
        assert_eq!(
            probe("claude is a shell function from /home/u/.zshrc"),
            Resolution::OtherFunction {
                from: Some("/home/u/.zshrc".into())
            }
        );
        assert_eq!(
            probe("claude is aliased to `/opt/x/claude --fast'"),
            Resolution::Alias("/opt/x/claude --fast".into())
        );
        assert_eq!(
            probe("claude is an alias for /opt/x"),
            Resolution::Alias("/opt/x".into())
        );
        // An alias to the same name reaches the shim function.
        assert_eq!(
            probe(&format!(
                "claude is aliased to `claude --fast'\nclaude () {{ {shim}; }}"
            )),
            Resolution::Wrapper
        );
        assert_eq!(
            probe("claude is aliased to `claude --fast'"),
            Resolution::Alias("claude --fast".into()),
            "no shim function behind it"
        );
        assert_eq!(
            probe("claude is /usr/local/bin/claude"),
            Resolution::File("/usr/local/bin/claude".into())
        );
        assert_eq!(
            probe("claude is hashed (/usr/bin/claude)"),
            Resolution::File("/usr/bin/claude".into())
        );
        assert_eq!(probe("bash: type: claude: not found"), Resolution::NotFound);
        assert_eq!(probe(""), Resolution::NotFound);
    }

    #[test]
    fn output_without_sentinels_yields_nothing() {
        assert!(parse_probe("claude is /x\n", &["claude".into()]).is_empty());
    }
}
