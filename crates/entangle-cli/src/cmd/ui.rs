//! Terminal conventions for the interactive commands (spec §9.4.2).
//!
//! * **Colour** only when it can be seen and is wanted: never with `NO_COLOR`
//!   set (<https://no-color.org>), never on `TERM=dumb`, otherwise when the
//!   stream is a terminal or `CLICOLOR_FORCE` is set.
//! * **Prompts are plain lines**: the question and its default on one line,
//!   the answer read as one line from stdin. No cursor movement, no
//!   redrawing, no arrow-key menus — the same at a terminal, under a screen
//!   reader, on `TERM=dumb` and with stdin piped (which is also how the tests
//!   drive the wizard).

use std::io::{BufRead as _, IsTerminal as _, Write as _};

use anyhow::{bail, Result};

/// Whether colour may be written to a stream that `is_tty` describes.
pub fn color_allowed(is_tty: bool) -> bool {
    let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    if set("NO_COLOR") {
        return false;
    }
    if std::env::var("TERM").is_ok_and(|t| t == "dumb") {
        return false;
    }
    if std::env::var("CLICOLOR_FORCE").is_ok_and(|v| !v.is_empty() && v != "0") {
        return true;
    }
    is_tty
}

/// Styling for one output stream.
#[derive(Clone, Copy, Debug)]
pub struct Style {
    color: bool,
}

impl Style {
    /// Styling for stdout.
    pub fn stdout() -> Self {
        Self {
            color: color_allowed(std::io::stdout().is_terminal()),
        }
    }

    /// Styling for stderr.
    pub fn stderr() -> Self {
        Self {
            color: color_allowed(std::io::stderr().is_terminal()),
        }
    }

    fn paint(self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    /// Bold (headings).
    pub fn bold(self, text: &str) -> String {
        self.paint("1", text)
    }

    /// `warning:` in yellow.
    pub fn warning(self) -> String {
        self.paint("33", "warning:")
    }

    /// `error:` in red.
    pub fn error(self) -> String {
        self.paint("31", "error:")
    }

    /// `note:` in cyan.
    pub fn note(self) -> String {
        self.paint("36", "note:")
    }
}

/// Whether the terminal can show Unicode block graphics (the pairing QR
/// code): not on `TERM=dumb`.
pub fn unicode_graphics_allowed() -> bool {
    !std::env::var("TERM").is_ok_and(|t| t == "dumb")
}

/// Line-based prompts on stdout, answers from stdin.
pub struct Prompter {
    out: std::io::Stdout,
}

impl Default for Prompter {
    fn default() -> Self {
        Self::new()
    }
}

impl Prompter {
    /// Prompts on stdout.
    pub fn new() -> Self {
        Self {
            out: std::io::stdout(),
        }
    }

    fn read_answer(&mut self) -> Result<String> {
        self.out.flush()?;
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line)? == 0 {
            // Terminate the prompt line so later output starts cleanly.
            writeln!(self.out)?;
            bail!(
                "ENTANGLE-E0783: input ended before the question was answered; run the \
                 non-interactive form instead (e.g. `entangle init --headless ...`)"
            );
        }
        Ok(line.trim().to_owned())
    }

    /// Ask for free text; an empty answer takes `default`.
    pub fn text(&mut self, question: &str, default: &str) -> Result<String> {
        if default.is_empty() {
            write!(self.out, "{question}: ")?;
        } else {
            write!(self.out, "{question} [{default}]: ")?;
        }
        let a = self.read_answer()?;
        Ok(if a.is_empty() { default.to_owned() } else { a })
    }

    /// Ask yes/no; an empty answer takes `default`. Anything else is asked
    /// again (three times, then the default).
    pub fn confirm(&mut self, question: &str, default: bool) -> Result<bool> {
        let hint = if default { "Y/n" } else { "y/N" };
        for _ in 0..3 {
            write!(self.out, "{question} [{hint}]: ")?;
            match self.read_answer()?.to_ascii_lowercase().as_str() {
                "" => return Ok(default),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                other => writeln!(self.out, "  Please answer y or n (got {other:?}).")?,
            }
        }
        Ok(default)
    }

    /// Ask for one of `choices` (matched case-insensitively); an empty
    /// answer takes `default`.
    pub fn choose(&mut self, question: &str, choices: &[&str], default: &str) -> Result<String> {
        for _ in 0..3 {
            write!(self.out, "{question} [{}] ({default}): ", choices.join("/"))?;
            let a = self.read_answer()?.to_ascii_lowercase();
            if a.is_empty() {
                return Ok(default.to_owned());
            }
            if let Some(c) = choices.iter().find(|c| c.eq_ignore_ascii_case(&a)) {
                return Ok((*c).to_owned());
            }
            writeln!(self.out, "  Please answer one of {}.", choices.join(", "))?;
        }
        Ok(default.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn style_without_color_is_plain_text() {
        let s = Style { color: false };
        assert_eq!(s.bold("x"), "x");
        assert_eq!(s.warning(), "warning:");
        let c = Style { color: true };
        assert_eq!(c.bold("x"), "\x1b[1mx\x1b[0m");
    }
}
