//! Opt-in shell warnings for agent commands outside Entanglement sessions.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};

use crate::config;

const START: &str = "# >>> entangle wrapper >>>";
const END: &str = "# <<< entangle wrapper <<<";

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

#[derive(Args)]
pub struct WrapperArgs {
    #[command(subcommand)]
    command: WrapperCommand,
}

#[derive(Subcommand)]
enum WrapperCommand {
    /// Add the warning function to a shell startup file and opt in.
    Enable {
        /// Shell to configure (defaults to the current SHELL).
        #[arg(long, value_enum)]
        shell: Option<Shell>,
    },
    /// Restore a missing, unmodified managed block.
    Repair {
        /// Shell to configure (defaults to the current SHELL).
        #[arg(long, value_enum)]
        shell: Option<Shell>,
    },
    /// Remove managed warning functions and persist the opt-out.
    Disable,
    /// Show the saved preference and managed startup files.
    Status,
}

pub fn run(args: WrapperArgs) -> Result<()> {
    match args.command {
        WrapperCommand::Enable { shell } | WrapperCommand::Repair { shell } => enable(shell),
        WrapperCommand::Disable => disable(),
        WrapperCommand::Status => status(),
    }
}

fn selected_shell(shell: Option<Shell>) -> Result<Shell> {
    if let Some(shell) = shell {
        return Ok(shell);
    }
    let value =
        std::env::var_os("SHELL").context("set SHELL or pass --shell bash, zsh, or fish")?;
    match Path::new(&value).file_name().and_then(|v| v.to_str()) {
        Some("bash") => Ok(Shell::Bash),
        Some("zsh") => Ok(Shell::Zsh),
        Some("fish") => Ok(Shell::Fish),
        _ => bail!("unsupported SHELL; pass --shell bash, zsh, or fish"),
    }
}

fn shell_file(shell: Shell) -> Result<PathBuf> {
    let home =
        PathBuf::from(std::env::var_os("HOME").context("HOME is required for wrapper setup")?);
    if !home.is_absolute() {
        bail!("HOME must be an absolute path");
    }
    Ok(match shell {
        Shell::Bash => home.join(".bashrc"),
        Shell::Zsh => match std::env::var_os("ZDOTDIR") {
            Some(dir) if Path::new(&dir).is_absolute() => PathBuf::from(dir).join(".zshrc"),
            Some(_) => bail!("ZDOTDIR must be an absolute path"),
            None => home.join(".zshrc"),
        },
        Shell::Fish => match std::env::var_os("XDG_CONFIG_HOME") {
            Some(dir) if Path::new(&dir).is_absolute() => PathBuf::from(dir),
            Some(_) => bail!("XDG_CONFIG_HOME must be an absolute path"),
            None => home.join(".config"),
        }
        .join("fish/conf.d/entangle-wrapper.fish"),
    })
}

fn shell_block(shell: Shell) -> String {
    let mut s = format!("{START}\n# Optional warning only; this is not a sandbox.\n");
    match shell {
        Shell::Bash | Shell::Zsh => s.push_str("export ENTANGLE_WRAPPER_ACTIVE=1\n"),
        Shell::Fish => s.push_str("set -gx ENTANGLE_WRAPPER_ACTIVE 1\n"),
    }
    for name in ["claude-code", "codex", "aider"] {
        match shell {
            Shell::Bash | Shell::Zsh => s.push_str(&format!(
                "{name}() {{\n  if [ ! -e \"$HOME/.entangle/wrapper-disabled\" ] && [ -z \"${{ENTANGLE_SESSION_ID:-}}\" ]; then\n    printf '%s\\n' 'warning: {name} launched outside Entanglement session.' 'Tools are not routed through the Entanglement gateway.' >&2\n  fi\n  command {name} \"$@\"\n}}\n"
            )),
            Shell::Fish => s.push_str(&format!(
                "function {name}\n  if not test -e \"$HOME/.entangle/wrapper-disabled\"\n    if not set -q ENTANGLE_SESSION_ID; or test -z \"$ENTANGLE_SESSION_ID\"\n      printf '%s\\n' 'warning: {name} launched outside Entanglement session.' 'Tools are not routed through the Entanglement gateway.' >&2\n    end\n  end\n  command {name} $argv\nend\n"
            )),
        }
    }
    s.push_str(END);
    s.push('\n');
    s
}

/// Remove only an unmodified block that this version generated. The leading
/// newline is ours, so a missing final newline in the original is preserved.
fn without_block(text: &str, shell: Shell) -> Result<(String, bool)> {
    let starts = text.matches(START).count();
    let ends = text.matches(END).count();
    if starts == 0 && ends == 0 {
        return Ok((text.to_owned(), false));
    }
    if starts != 1 || ends != 1 {
        bail!("malformed or duplicate Entanglement wrapper markers; edit them manually");
    }
    let block = shell_block(shell);
    let marker = format!("\n{block}");
    let Some(start) = text.find(&marker) else {
        bail!("Entanglement wrapper block was modified; preserve it and edit it manually");
    };
    let mut output = text.to_owned();
    output.replace_range(start..start + marker.len(), "");
    Ok((output, true))
}

fn read_regular(path: &Path) -> Result<Option<String>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => {
            bail!("refusing to replace non-regular file {}", path.display())
        }
        Ok(_) => Ok(Some(
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn atomic_write(path: &Path, text: &str) -> Result<()> {
    let parent = path.parent().context("file has no parent")?;
    std::fs::create_dir_all(parent)?;
    let old = std::fs::symlink_metadata(path).ok();
    if old.as_ref().is_some_and(|m| !m.file_type().is_file()) {
        bail!("refusing to replace non-regular file {}", path.display());
    }
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    if let Some(meta) = old {
        tmp.as_file().set_permissions(meta.permissions())?;
    }
    tmp.write_all(text.as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn preference_text(enabled: bool) -> Result<(PathBuf, String)> {
    let path = config::config_path();
    let raw = read_regular(&path)?.unwrap_or_default();
    let mut doc = raw
        .parse::<toml_edit::DocumentMut>()
        .context("parsing config before changing wrapper preference")?;
    if doc
        .get("wrappers")
        .is_some_and(|item| item.as_table_like().is_none())
    {
        bail!("[wrappers] must be a table");
    }
    let preference = &mut doc["wrappers"]["install"];
    let decor = preference.as_value().map(|v| v.decor().clone());
    *preference = toml_edit::value(enabled);
    if let (Some(decor), Some(value)) = (decor, preference.as_value_mut()) {
        *value.decor_mut() = decor;
    }
    // Do not write a file that the daemon would reject.
    toml::from_str::<entangle_runtime::config::Config>(&doc.to_string())?;
    Ok((path, doc.to_string()))
}

fn checked_disabled_marker() -> Result<(PathBuf, bool)> {
    let path = config::entangle_dir().join("wrapper-disabled");
    let previous = read_regular(&path)?;
    if previous.as_deref().is_some_and(|s| s != "disabled\n") {
        bail!("refusing to replace an unfamiliar wrapper opt-out file");
    }
    Ok((path, previous.is_some()))
}

/// Persist the opt-in and add a managed warning block.
pub fn enable(shell: Option<Shell>) -> Result<()> {
    let _writer = entangle_runtime::config::lock_config_writer(&config::config_path())?;
    let shell = selected_shell(shell)?;
    let path = shell_file(shell)?;
    let previous = read_regular(&path)?;
    let original = previous.as_deref().unwrap_or_default();
    let (clean, _) = without_block(original, shell)?;
    let (cfg_path, cfg) = preference_text(true)?;
    let (disabled_marker, was_disabled) = checked_disabled_marker()?;
    let next = format!("{clean}\n{}", shell_block(shell));
    atomic_write(&path, &next)?;
    if let Err(error) = atomic_write(&cfg_path, &cfg) {
        // Keep the startup file as it was if preference persistence fails.
        if previous.is_some() {
            let _ = atomic_write(&path, original);
        } else {
            let _ = std::fs::remove_file(&path);
        }
        return Err(error);
    }
    if was_disabled {
        std::fs::remove_file(disabled_marker).context("removing wrapper opt-out marker")?;
    }
    println!(
        "Wrapper enabled in {}. Start a new shell; the warning is not a sandbox.",
        path.display()
    );
    Ok(())
}

/// Remove only managed blocks and persist an explicit opt-out.
pub fn disable() -> Result<()> {
    let _writer = entangle_runtime::config::lock_config_writer(&config::config_path())?;
    let mut changes = Vec::new();
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
        let path = shell_file(shell)?;
        if let Some(original) = read_regular(&path)? {
            let (clean, found) = without_block(&original, shell)?;
            if found {
                changes.push((path, original, clean));
            }
        }
    }
    let (cfg_path, cfg) = preference_text(false)?;
    let (disabled_marker, was_disabled) = checked_disabled_marker()?;
    // Existing shell functions cannot be removed from a parent process. The
    // marker silences them immediately, even before a new shell is started.
    atomic_write(&disabled_marker, "disabled\n")?;
    let mut written: Vec<(&Path, &str)> = Vec::new();
    for (path, original, clean) in &changes {
        if let Err(error) = atomic_write(path, clean) {
            for (path, contents) in written {
                let _ = atomic_write(path, contents);
            }
            if !was_disabled {
                let _ = std::fs::remove_file(&disabled_marker);
            }
            return Err(error);
        }
        written.push((path, original));
    }
    if let Err(error) = atomic_write(&cfg_path, &cfg) {
        for (path, contents) in written {
            let _ = atomic_write(path, contents);
        }
        if !was_disabled {
            let _ = std::fs::remove_file(&disabled_marker);
        }
        return Err(error);
    }
    println!("Wrapper disabled; the preference is saved in [wrappers] install = false.");
    Ok(())
}

fn status() -> Result<()> {
    let cfg = config::load(&config::config_path())?;
    println!(
        "Wrapper preference: {}",
        match cfg.wrappers.install {
            Some(true) => "enabled",
            Some(false) => "disabled",
            None => "not set",
        }
    );
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
        let path = shell_file(shell)?;
        let present = match read_regular(&path)? {
            Some(contents) => without_block(&contents, shell)?.1,
            None => false,
        };
        println!(
            "{:?}: {} ({})",
            shell,
            if present {
                "installed"
            } else {
                "not installed"
            },
            path.display()
        );
    }
    Ok(())
}

/// Detect a binary in PATH when the opt-in wrapper was not sourced by the
/// launching shell. Parent-shell aliases/functions cannot be inspected from a
/// child process, so this is deliberately a conservative diagnostic.
pub fn shadowed_binary() -> Result<Option<PathBuf>> {
    if config::load(&config::config_path())?.wrappers.install != Some(true)
        || std::env::var_os("ENTANGLE_WRAPPER_ACTIVE").is_some_and(|v| v == "1")
    {
        return Ok(None);
    }
    let Some(path) = std::env::var_os("PATH") else {
        return Ok(None);
    };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("claude-code");
        let Ok(meta) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        return Ok(Some(candidate));
    }
    Ok(None)
}
