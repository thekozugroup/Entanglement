//! The shell-history note of `entangle doctor` (spec §8.3, wrapper item 3):
//! how many recent commands in the user's shell history started an agent
//! binary directly, outside `entangle agent run`.
//!
//! Informational only. The history files are opened read-only, only their
//! tail is read, and nothing of their content leaves this module except
//! counts per agent binary: no command line is ever printed, logged or
//! stored. Set [`OPT_OUT_ENV`] to skip the check entirely (the files are
//! then not opened).

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Set (to anything but `0` or the empty string) to skip the check.
pub const OPT_OUT_ENV: &str = "ENTANGLE_DOCTOR_NO_HISTORY";

/// How many of the most recent history entries of each file are looked at.
pub const RECENT_ENTRIES: usize = 500;

/// At most this much of the end of a history file is read.
const TAIL_BYTES: u64 = 256 * 1024;

/// Whether the user opted out.
pub fn opted_out() -> bool {
    std::env::var_os(OPT_OUT_ENV).is_some_and(|v| !v.is_empty() && v != "0")
}

/// The history files that exist: `$HISTFILE`, then the default bash, zsh
/// and fish locations under `home`.
pub fn history_files(home: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    if let Some(h) = std::env::var_os("HISTFILE").map(PathBuf::from) {
        if h.is_absolute() {
            out.push(h);
        }
    }
    out.push(home.join(".bash_history"));
    out.push(home.join(".zsh_history"));
    out.push(home.join(".local/share/fish/fish_history"));
    let mut seen: Vec<PathBuf> = Vec::new();
    for p in out {
        if p.is_file() && !seen.contains(&p) {
            seen.push(p);
        }
    }
    seen
}

/// The command of one history line, or `None` for a line that is not a
/// command (bash timestamp comments, fish metadata).
///
/// - zsh extended history: `: <start>:<elapsed>;<command>`.
/// - fish: `- cmd: <command>`; `  when:` / `  paths:` lines are metadata.
/// - bash: the line itself; `#<digits>` lines are timestamps.
fn command_of(line: &str) -> Option<&str> {
    let line = line.trim_end();
    if let Some(rest) = line.strip_prefix(": ") {
        if let Some((meta, cmd)) = rest.split_once(';') {
            if meta
                .split(':')
                .all(|p| p.chars().all(|c| c.is_ascii_digit()))
            {
                return Some(cmd);
            }
        }
    }
    if let Some(cmd) = line.strip_prefix("- cmd: ") {
        return Some(cmd);
    }
    if line.starts_with("  when:") || line.starts_with("  paths:") || line.starts_with("    - ") {
        return None;
    }
    if line
        .strip_prefix('#')
        .is_some_and(|r| !r.is_empty() && r.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    (!line.trim().is_empty()).then_some(line)
}

/// Words that precede the program name without being it.
const PREFIX_WORDS: [&str; 6] = ["sudo", "command", "exec", "time", "nohup", "env"];

/// The agent binaries `command` starts directly: for each `&&` / `||` /
/// `;` / `|` segment, the first word that is not an environment assignment
/// or a prefix word such as `sudo` or `command`, by base name. `entangle
/// agent run claude-code` starts `entangle`, so it is not counted.
fn direct_invocations<'a>(command: &str, binaries: &'a [String]) -> Vec<&'a str> {
    let mut found = Vec::new();
    for segment in command.split(['|', ';', '&']) {
        let program = segment.split_whitespace().find(|w| {
            let is_assignment = w.split_once('=').is_some_and(|(k, _)| {
                !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            });
            !is_assignment && !PREFIX_WORDS.contains(w) && !w.starts_with('-')
        });
        let Some(program) = program else { continue };
        // `\claude` bypasses an alias or function; `/usr/bin/claude` a PATH lookup.
        let program = program.trim_start_matches('\\');
        let base = program.rsplit('/').next().unwrap_or(program);
        if let Some(b) = binaries.iter().find(|b| b.as_str() == base) {
            found.push(b.as_str());
        }
    }
    found
}

/// Counts for one or more history files.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryCount {
    /// History entries looked at.
    pub entries: usize,
    /// Direct invocations per agent binary.
    pub direct: BTreeMap<String, usize>,
}

impl HistoryCount {
    /// Total direct invocations.
    pub fn total(&self) -> usize {
        self.direct.values().sum()
    }
}

/// Count direct invocations of `binaries` in the last [`RECENT_ENTRIES`]
/// commands of `text` (the tail of a history file).
pub fn count_in(text: &str, binaries: &[String], into: &mut HistoryCount) {
    let commands: Vec<&str> = text.lines().filter_map(command_of).collect();
    let recent = &commands[commands.len().saturating_sub(RECENT_ENTRIES)..];
    into.entries += recent.len();
    for cmd in recent {
        for b in direct_invocations(cmd, binaries) {
            *into.direct.entry(b.to_owned()).or_insert(0) += 1;
        }
    }
}

/// Read the tail of `path` (read-only) as text. The first, possibly
/// partial, line of a truncated read is dropped.
fn read_tail(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let start = len.saturating_sub(TAIL_BYTES);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.take(TAIL_BYTES).read_to_end(&mut buf)?;
    // zsh writes non-ASCII bytes in its own "metafied" encoding: lossy is fine
    // for matching ASCII program names.
    let text = String::from_utf8_lossy(&buf).into_owned();
    Ok(if start > 0 {
        text.split_once('\n')
            .map(|(_, rest)| rest.to_owned())
            .unwrap_or_default()
    } else {
        text
    })
}

/// Count direct agent invocations across `files`. Unreadable files are
/// skipped (their number is returned second).
pub fn count_files(files: &[PathBuf], binaries: &[String]) -> (HistoryCount, usize) {
    let mut count = HistoryCount::default();
    let mut unreadable = 0;
    for f in files {
        match read_tail(f) {
            Ok(text) => count_in(&text, binaries, &mut count),
            Err(_) => unreadable += 1,
        }
    }
    (count, unreadable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bins() -> Vec<String> {
        ["claude", "codex", "opencode"].map(String::from).to_vec()
    }

    fn count(text: &str) -> HistoryCount {
        let mut c = HistoryCount::default();
        count_in(text, &bins(), &mut c);
        c
    }

    #[test]
    fn counts_direct_invocations_in_bash_zsh_and_fish_formats() {
        let bash = "ls\n#1700000000\nclaude --resume\nentangle agent run claude-code\ncodex\n";
        let c = count(bash);
        assert_eq!(c.entries, 4, "the timestamp line is not an entry");
        assert_eq!(c.direct.get("claude"), Some(&1));
        assert_eq!(c.direct.get("codex"), Some(&1));
        assert_eq!(
            c.total(),
            2,
            "`entangle agent run` is not a direct invocation"
        );

        let zsh = ": 1700000000:0;cd proj && claude\n: 1700000001:12;git status\n";
        let c = count(zsh);
        assert_eq!((c.entries, c.total()), (2, 1));

        let fish = "- cmd: opencode\n  when: 1700000000\n  paths:\n    - foo\n- cmd: echo hi\n";
        let c = count(fish);
        assert_eq!((c.entries, c.total()), (2, 1));
    }

    #[test]
    fn recognises_bypass_forms_and_ignores_mentions() {
        for line in [
            "command claude",
            "\\claude -p hi",
            "/usr/local/bin/claude",
            "ANTHROPIC_LOG=debug claude",
            "sudo -E codex",
            "cat prompt.txt | claude -p",
            "cd x; claude",
        ] {
            assert_eq!(count(line).total(), 1, "{line}");
        }
        for line in [
            "echo claude",
            "which claude",
            "man codex",
            "vim claude.md",
            "claude-wrapper run",
            "entangle agent run claude-code -- --model x",
            "git commit -m 'run codex'",
        ] {
            assert_eq!(count(line).total(), 0, "{line}");
        }
    }

    #[test]
    fn only_the_most_recent_entries_count() {
        let mut text = String::from("claude\n");
        for _ in 0..RECENT_ENTRIES {
            text.push_str("ls\n");
        }
        let c = count(&text);
        assert_eq!(c.entries, RECENT_ENTRIES);
        assert_eq!(c.total(), 0, "the old entry is outside the window");
    }

    #[test]
    fn files_are_read_from_the_tail_and_missing_ones_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join(".bash_history");
        let mut text = "x".repeat(TAIL_BYTES as usize + 10);
        text.push_str("\nclaude\ncodex exec\n");
        std::fs::write(&f, &text).unwrap();
        let before = std::fs::metadata(&f).unwrap().modified().unwrap();
        let (c, unreadable) = count_files(&[f.clone(), dir.path().join("gone")], &bins());
        assert_eq!(unreadable, 1);
        assert_eq!(c.total(), 2);
        // Read-only: the file is untouched.
        assert_eq!(std::fs::read_to_string(&f).unwrap(), text);
        assert_eq!(std::fs::metadata(&f).unwrap().modified().unwrap(), before);
    }
}
