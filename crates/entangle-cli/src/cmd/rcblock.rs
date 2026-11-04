//! Pure text editor for the marked shell-wrapper block in rc files.
//!
//! No I/O here: every function maps `&str -> String`, which keeps the
//! guarantees testable byte-for-byte:
//!
//! * the block is delimited by [`BEGIN`] / [`END`] marker lines and nothing
//!   outside the markers is ever changed (the one exception, a single blank
//!   separator line that [`install`] itself appended at end of file, is
//!   removed again by [`remove`] so enable-then-disable restores the file);
//! * [`install`] is idempotent;
//! * LF and CRLF files keep their line ending;
//! * damaged (unterminated, stray, nested) or duplicated blocks are detected
//!   by [`inspect`] and rewritten by [`repair`].
//!
//! The shim itself is POSIX-shell syntax for bash/zsh and fish syntax for
//! `conf.d/entangle.fish` (spec §8.3 item 1).

/// First marker line of the managed block.
pub const BEGIN: &str = "# >>> entangle wrapper >>>";
/// Last marker line of the managed block.
pub const END: &str = "# <<< entangle wrapper <<<";

/// Which rc-file dialect to render.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Dialect {
    /// bash and zsh (POSIX function syntax).
    Posix,
    /// fish `conf.d` snippet.
    Fish,
}

/// One agent host the shim wraps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    /// Executable name the user types (`Adapter::binary()`), e.g. `claude`.
    pub binary: String,
    /// `entangle agent run` name (`Adapter::name()`), e.g. `claude-code`.
    pub agent: String,
}

/// Hosts to wrap, taken from the agent-host adapter registry so the shim
/// follows whatever `entangle agent run` supports.
pub fn hosts_from_adapters() -> Vec<Host> {
    let mut v: Vec<Host> = entangle_agent_host::registry()
        .iter()
        .map(|a| Host {
            binary: a.binary().to_owned(),
            agent: a.name().to_owned(),
        })
        .collect();
    v.sort_by(|a, b| a.binary.cmp(&b.binary));
    v.dedup_by(|a, b| a.binary == b.binary);
    v
}

/// The warning lines the shim prints to stderr (without the colour escape).
fn warning_lines(h: &Host) -> [String; 4] {
    [
        format!("{} launched outside Entanglement session.", h.binary),
        "         Tools are NOT routed through Entanglement gateway.".to_owned(),
        format!(
            "         For sandboxed mode: entangle agent run {}",
            h.agent
        ),
        "         To silence: entangle wrapper disable".to_owned(),
    ]
}

/// Render the managed block (marker to marker, LF line endings, no trailing
/// newline) for `hosts`.
pub fn render(dialect: Dialect, hosts: &[Host]) -> String {
    let mut out = String::new();
    out.push_str(BEGIN);
    out.push('\n');
    out.push_str(
        "# Managed by `entangle wrapper {enable,disable,status,repair}`. Warns when an agent\n",
    );
    out.push_str("# host runs outside an Entanglement session (a UX guardrail, not a security\n");
    out.push_str(
        "# boundary: `command <bin>` or `\\<bin>` bypasses it). Edits here are overwritten.\n",
    );
    if dialect == Dialect::Posix && !hosts.is_empty() {
        // bash and zsh alias-expand the first word of `name() {`: an earlier
        // `alias claude='claude --flag'` would turn the definition into a
        // syntax error that also stops the rest of the rc file. The alias is
        // set aside while the function is defined and restored after it, so
        // `claude` still expands to the user's alias and then reaches the
        // function. (POSIX syntax on purpose: a `function` keyword would break
        // `sh` sourcing the file.)
        out.push_str(
            "# An alias of the same name is set aside while each function is defined.\n",
        );
    }
    for h in hosts {
        let w = warning_lines(h);
        match dialect {
            Dialect::Posix => {
                // Must stay a separate line before the definition: aliases are
                // expanded when a command is read, not when it runs.
                out.push_str(&format!(
                    "if alias {0} >/dev/null 2>&1; then __entangle_alias=$(alias {0}); unalias {0}; else __entangle_alias=; fi\n",
                    h.binary
                ));
                out.push_str(&format!("{}() {{\n", h.binary));
                out.push_str("  if [ -z \"${ENTANGLE_SESSION_ID:-}\" ]; then\n");
                out.push_str(&format!(
                    "    printf '\\033[33mwarning:\\033[0m {}\\n' >&2\n",
                    w[0]
                ));
                for l in &w[1..] {
                    out.push_str(&format!("    printf '{l}\\n' >&2\n"));
                }
                out.push_str("  fi\n");
                out.push_str(&format!("  command {} \"$@\"\n", h.binary));
                out.push_str("}\n");
                // bash prints `alias name='...'`, zsh and dash `name='...'`.
                out.push_str(
                    "if [ -n \"$__entangle_alias\" ]; then eval \"alias ${__entangle_alias#alias }\"; fi\n",
                );
            }
            Dialect::Fish => {
                out.push_str(&format!(
                    "function {0} --wraps {0} --description 'entangle wrapper'\n",
                    h.binary
                ));
                out.push_str("    if test -z \"$ENTANGLE_SESSION_ID\"\n");
                out.push_str(&format!(
                    "        printf '\\033[33mwarning:\\033[0m {}\\n' >&2\n",
                    w[0]
                ));
                for l in &w[1..] {
                    out.push_str(&format!("        printf '{l}\\n' >&2\n"));
                }
                out.push_str("    end\n");
                out.push_str(&format!("    command {} $argv\n", h.binary));
                out.push_str("end\n");
            }
        }
    }
    if dialect == Dialect::Posix && !hosts.is_empty() {
        out.push_str("unset __entangle_alias\n");
    }
    out.push_str(END);
    out
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// What [`inspect`] found in an rc file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockState {
    /// No marker lines at all.
    Absent,
    /// Exactly one well-formed block.
    Present {
        /// Whether its content equals what [`render`] would write now.
        current: bool,
    },
    /// More than one well-formed block.
    Duplicated(usize),
    /// Stray, nested or unterminated markers.
    Damaged(String),
}

#[derive(Debug)]
struct Line<'a> {
    /// Text without the line terminator.
    text: &'a str,
    /// Full slice including the terminator.
    full: &'a str,
}

fn lines(text: &str) -> Vec<Line<'_>> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let (full, next) = match rest.find('\n') {
            Some(i) => (&rest[..=i], &rest[i + 1..]),
            None => (rest, ""),
        };
        let text = full.strip_suffix('\n').unwrap_or(full);
        let text = text.strip_suffix('\r').unwrap_or(text);
        out.push(Line { text, full });
        rest = next;
    }
    out
}

fn is_begin(l: &Line<'_>) -> bool {
    l.text.trim() == BEGIN
}
fn is_end(l: &Line<'_>) -> bool {
    l.text.trim() == END
}

/// A parsed region: inclusive line range plus whether it was terminated.
#[derive(Debug, Clone, Copy)]
struct Region {
    start: usize,
    end: usize,
}

struct Scan {
    /// Well-formed `BEGIN ... END` regions.
    regions: Vec<Region>,
    /// Marker lines that are not part of a well-formed region, with a reason.
    stray: Vec<(usize, &'static str)>,
}

fn scan(ls: &[Line<'_>]) -> Scan {
    let mut regions = Vec::new();
    let mut stray = Vec::new();
    let mut open: Option<usize> = None;
    for (i, l) in ls.iter().enumerate() {
        if is_begin(l) {
            if let Some(prev) = open {
                stray.push((prev, "begin marker without end marker"));
            }
            open = Some(i);
        } else if is_end(l) {
            match open.take() {
                Some(s) => regions.push(Region { start: s, end: i }),
                None => stray.push((i, "end marker without begin marker")),
            }
        }
    }
    if let Some(s) = open {
        stray.push((s, "begin marker without end marker"));
    }
    stray.sort_by_key(|(i, _)| *i);
    Scan { regions, stray }
}

fn eol_of(text: &str) -> &'static str {
    if text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

fn with_eol(block: &str, eol: &str) -> String {
    if eol == "\n" {
        block.to_owned()
    } else {
        block.replace('\n', eol)
    }
}

fn region_text(ls: &[Line<'_>], r: Region) -> String {
    ls[r.start..=r.end]
        .iter()
        .map(|l| l.text)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Classify the block in `text` against the `desired` rendering.
pub fn inspect(text: &str, desired: &str) -> BlockState {
    let ls = lines(text);
    let s = scan(&ls);
    if let Some((i, why)) = s.stray.first() {
        return BlockState::Damaged(format!("{why} (line {})", i + 1));
    }
    match s.regions.len() {
        0 => BlockState::Absent,
        1 => BlockState::Present {
            current: region_text(&ls, s.regions[0]) == desired,
        },
        n => BlockState::Duplicated(n),
    }
}

// ---------------------------------------------------------------------------
// Editing
// ---------------------------------------------------------------------------

/// Result of an edit.
#[derive(Debug, PartialEq, Eq)]
pub struct Edit {
    /// The new file text.
    pub text: String,
    /// Whether it differs from the input.
    pub changed: bool,
}

/// Why [`install`] declined to edit.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallError {
    /// Damaged or duplicated block: use [`repair`].
    NeedsRepair(BlockState),
}

fn append_block(text: &str, block: &str) -> String {
    let eol = eol_of(text);
    let mut out = String::from(text);
    if !out.is_empty() {
        if !out.ends_with('\n') {
            out.push_str(eol);
        }
        // One blank separator line; `remove` takes it away again.
        out.push_str(eol);
    }
    out.push_str(&with_eol(block, eol));
    out.push_str(eol);
    out
}

/// Install (or refresh) the block, idempotently. A damaged or duplicated
/// block is refused; `entangle wrapper repair` handles those.
pub fn install(text: &str, desired: &str) -> Result<Edit, InstallError> {
    match inspect(text, desired) {
        BlockState::Absent => Ok(Edit {
            text: append_block(text, desired),
            changed: true,
        }),
        BlockState::Present { current: true } => Ok(Edit {
            text: text.to_owned(),
            changed: false,
        }),
        BlockState::Present { current: false } => {
            let ls = lines(text);
            let r = scan(&ls).regions[0];
            let eol = eol_of(text);
            let mut out = String::new();
            for l in &ls[..r.start] {
                out.push_str(l.full);
            }
            out.push_str(&with_eol(desired, eol));
            // Keep the original terminator of the END line (it may be absent
            // at EOF).
            let end_full = ls[r.end].full;
            out.push_str(&end_full[ls[r.end].text.len()..]);
            for l in &ls[r.end + 1..] {
                out.push_str(l.full);
            }
            Ok(Edit {
                changed: out != text,
                text: out,
            })
        }
        other => Err(InstallError::NeedsRepair(other)),
    }
}

/// Lines the shim itself generates, used to clean up the body of a *damaged*
/// block without touching unrelated lines the user put there.
fn is_generated_line(t: &str, desired: &str) -> bool {
    let t = t.trim_end();
    !t.trim().is_empty() && desired.lines().any(|d| d.trim_end() == t)
}

/// Line indices to delete for every block in `ls`, whether well-formed or
/// damaged. Well-formed regions go entirely (markers and body). For a damaged
/// marker only the marker line and the *generated* lines directly after a
/// stray begin (up to the next marker or a line we did not write) are
/// dropped, so unrelated user lines are never lost.
fn removal_set(ls: &[Line<'_>], s: &Scan, desired: &str) -> Vec<usize> {
    let mut del = vec![false; ls.len()];
    for r in &s.regions {
        for d in &mut del[r.start..=r.end] {
            *d = true;
        }
    }
    for (i, _) in &s.stray {
        del[*i] = true;
        if is_begin(&ls[*i]) {
            let mut j = *i + 1;
            while j < ls.len()
                && !is_begin(&ls[j])
                && !is_end(&ls[j])
                && is_generated_line(ls[j].text, desired)
            {
                del[j] = true;
                j += 1;
            }
        }
    }
    del.iter()
        .enumerate()
        .filter_map(|(i, d)| d.then_some(i))
        .collect()
}

fn delete_lines(text: &str, ls: &[Line<'_>], del: &[usize]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut it = del.iter().peekable();
    for (i, l) in ls.iter().enumerate() {
        if it.peek().is_some_and(|&&d| d == i) {
            it.next();
        } else {
            out.push_str(l.full);
        }
    }
    out
}

/// Remove every block (well-formed or damaged). `desired` is only used to
/// recognise the lines the shim generated inside a damaged block.
pub fn remove(text: &str, desired: &str) -> Edit {
    let ls = lines(text);
    let s = scan(&ls);
    let mut del = removal_set(&ls, &s, desired);
    if del.is_empty() {
        return Edit {
            text: text.to_owned(),
            changed: false,
        };
    }
    // If the (last) deleted run reaches the end of the file and a blank line
    // precedes it, that blank is the separator `install` appended.
    let last = ls.len() - 1;
    if del.last() == Some(&last) {
        let first_of_run = {
            let mut k = del.len() - 1;
            while k > 0 && del[k - 1] + 1 == del[k] {
                k -= 1;
            }
            del[k]
        };
        if first_of_run > 0 && ls[first_of_run - 1].text.is_empty() {
            del.push(first_of_run - 1);
            del.sort_unstable();
        }
    }
    let out = delete_lines(text, &ls, &del);
    Edit {
        changed: out != text,
        text: out,
    }
}

/// Rewrite damaged or duplicated blocks into exactly one current block, at
/// the position of the first old one (or at end of file when none is left).
pub fn repair(text: &str, desired: &str) -> Edit {
    let ls = lines(text);
    let s = scan(&ls);
    let del = removal_set(&ls, &s, desired);
    if del.is_empty() {
        return match install(text, desired) {
            Ok(e) => e,
            // Unreachable: no markers means `Absent`, which installs.
            Err(_) => Edit {
                text: text.to_owned(),
                changed: false,
            },
        };
    }
    let eol = eol_of(text);
    let anchor = del[0];
    let mut out = String::new();
    let mut it = del.iter().peekable();
    let mut placed = false;
    for (i, l) in ls.iter().enumerate() {
        if it.peek().is_some_and(|&&d| d == i) {
            it.next();
            if i == anchor && !placed {
                out.push_str(&with_eol(desired, eol));
                // Keep the anchor's terminator (the file may end without one).
                out.push_str(&l.full[l.text.len()..]);
                placed = true;
            }
        } else {
            out.push_str(l.full);
        }
    }
    if !out.ends_with('\n') && out != text {
        // The anchor line had no terminator (last line of the file).
        out.push_str(eol);
    }
    Edit {
        changed: out != text,
        text: out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts() -> Vec<Host> {
        vec![
            Host {
                binary: "claude".into(),
                agent: "claude-code".into(),
            },
            Host {
                binary: "codex".into(),
                agent: "codex".into(),
            },
        ]
    }
    fn posix() -> String {
        render(Dialect::Posix, &hosts())
    }

    #[test]
    fn render_has_markers_one_function_per_host_and_spec_warning() {
        let b = posix();
        assert!(b.starts_with(BEGIN) && b.ends_with(END));
        assert!(b.contains("claude() {") && b.contains("codex() {"));
        assert!(b.contains("claude launched outside Entanglement session."));
        assert!(b.contains("entangle agent run claude-code"));
        assert!(b.contains("command claude \"$@\""));
        let f = render(Dialect::Fish, &hosts());
        assert!(f.contains("function claude --wraps claude"));
        assert!(f.contains("command claude $argv") && f.contains("end\n"));
        assert!(!f.contains("() {"));
    }

    #[test]
    fn install_is_idempotent_and_appends_after_user_content() {
        let b = posix();
        let rc = "export A=1\nalias ll='ls -l'\n";
        let once = install(rc, &b).unwrap();
        assert!(once.changed && once.text.starts_with(rc));
        let twice = install(&once.text, &b).unwrap();
        assert!(!twice.changed);
        assert_eq!(twice.text, once.text);
        assert_eq!(once.text.matches(BEGIN).count(), 1);
    }

    #[test]
    fn missing_empty_and_unterminated_files() {
        let b = posix();
        assert_eq!(install("", &b).unwrap().text, format!("{b}\n"));
        let e = install("export A=1", &b).unwrap();
        assert!(e.text.starts_with("export A=1\n\n# >>>"));
    }

    #[test]
    fn disable_after_enable_restores_the_file_byte_for_byte() {
        let b = posix();
        for rc in ["", "a\n", "a\n\n", "a", "a\r\nb\r\n", "\n\n"] {
            let on = install(rc, &b).unwrap().text;
            let off = remove(&on, &b);
            let expect = if rc.ends_with('\n') || rc.is_empty() {
                rc.to_owned()
            } else {
                format!("{rc}{}", eol_of(rc))
            };
            assert_eq!(off.text, expect, "rc={rc:?}");
        }
    }

    #[test]
    fn remove_never_touches_text_outside_the_markers() {
        let b = posix();
        let rc = format!("before\n# comment\n{b}\nafter\n\nlast\n");
        let off = remove(&rc, &b);
        assert_eq!(off.text, "before\n# comment\nafter\n\nlast\n");
        assert!(!remove("nothing here\n", &b).changed);
    }

    #[test]
    fn stale_block_is_refreshed_in_place() {
        let old = render(Dialect::Posix, &hosts()[..1]);
        let new = posix();
        let rc = format!("x\n\n{old}\ny\n");
        let e = install(&rc, &new).unwrap();
        assert_eq!(e.text, format!("x\n\n{new}\ny\n"));
        assert_eq!(inspect(&rc, &new), BlockState::Present { current: false });
    }

    #[test]
    fn crlf_files_keep_crlf() {
        let b = posix();
        let rc = "export A=1\r\n";
        let on = install(rc, &b).unwrap().text;
        assert!(on.contains("\r\n# >>> entangle wrapper >>>\r\n"));
        assert!(!on.replace("\r\n", "").contains('\r'));
        assert_eq!(on.matches('\n').count(), on.matches("\r\n").count());
        assert!(!install(&on, &b).unwrap().changed, "idempotent under CRLF");
        assert_eq!(remove(&on, &b).text, rc);
    }

    #[test]
    fn duplicates_are_detected_and_repaired_to_one_block() {
        let b = posix();
        let rc = format!("a\n{b}\nmid\n{b}\nz\n");
        assert_eq!(inspect(&rc, &b), BlockState::Duplicated(2));
        assert!(install(&rc, &b).is_err());
        let fixed = repair(&rc, &b);
        assert_eq!(fixed.text, format!("a\n{b}\nmid\nz\n"));
        assert_eq!(
            inspect(&fixed.text, &b),
            BlockState::Present { current: true }
        );
    }

    #[test]
    fn damaged_blocks_are_detected_and_repaired_keeping_user_lines() {
        let b = posix();
        // Unterminated: the END marker line was deleted by hand.
        let cut = b.replace(END, "");
        let rc = format!("pre\n{cut}\nmy-own-line\n");
        assert!(matches!(inspect(&rc, &b), BlockState::Damaged(_)));
        assert!(install(&rc, &b).is_err());
        let fixed = repair(&rc, &b);
        assert!(fixed.text.contains("my-own-line"), "{}", fixed.text);
        assert_eq!(fixed.text.matches(BEGIN).count(), 1);
        assert_eq!(fixed.text.matches(END).count(), 1);
        assert_eq!(
            inspect(&fixed.text, &b),
            BlockState::Present { current: true }
        );
        // Stray END only.
        let rc2 = format!("pre\n{END}\npost\n");
        assert!(matches!(inspect(&rc2, &b), BlockState::Damaged(_)));
        let fixed2 = repair(&rc2, &b);
        assert!(fixed2.text.starts_with("pre\n") && fixed2.text.contains("post"));
        assert_eq!(
            inspect(&fixed2.text, &b),
            BlockState::Present { current: true }
        );
        // remove() cleans damage too.
        assert_eq!(remove(&rc2, &b).text, "pre\npost\n");
    }

    #[test]
    fn repair_on_a_healthy_or_absent_file_behaves_like_install() {
        let b = posix();
        assert!(!repair(&format!("{b}\n"), &b).changed);
        assert!(repair("x\n", &b).changed);
    }

    #[test]
    fn fish_blocks_round_trip_like_posix_ones() {
        let b = render(Dialect::Fish, &hosts());
        let on = install("", &b).unwrap();
        assert_eq!(on.text, format!("{b}\n"));
        assert_eq!(remove(&on.text, &b).text, "");
    }
}
