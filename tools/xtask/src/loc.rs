//! `cargo xtask loc-budget` — the trust-footprint LOC budget (spec §2.3, §10).
//!
//! The crate list and budget come from `docs/trust-footprint.toml`. A line
//! counts when it is non-blank, is not a pure comment, and is not inside a
//! `#[cfg(test)]` item. Files named `tests.rs` and anything under a `tests/`
//! directory are skipped (only `<crate>/src` is walked in the first place).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Parsed `docs/trust-footprint.toml`.
#[derive(Debug)]
pub struct Config {
    /// Maximum allowed total (exclusive upper bound is the budget itself:
    /// totals `<= budget` pass, matching "stays under a budget").
    pub budget: usize,
    /// Crate directories (relative to the root) that must exist.
    pub crates: Vec<String>,
    /// Crate directories the spec names that do not exist yet.
    pub not_yet_present: Vec<String>,
}

impl Config {
    /// Parse the TOML text.
    pub fn parse(text: &str) -> Result<Self> {
        let v: toml::Table = text.parse().context("parsing trust-footprint config")?;
        let budget = v
            .get("budget")
            .and_then(|b| b.as_integer())
            .filter(|b| *b >= 0)
            .context("`budget` must be a non-negative integer")? as usize;
        let list = |key: &str| -> Result<Vec<String>> {
            match v.get(key) {
                None => Ok(Vec::new()),
                Some(a) => a
                    .as_array()
                    .with_context(|| format!("`{key}` must be an array"))?
                    .iter()
                    .map(|s| {
                        s.as_str()
                            .map(str::to_owned)
                            .with_context(|| format!("`{key}` entries must be strings"))
                    })
                    .collect(),
            }
        };
        let crates = list("crates")?;
        if crates.is_empty() {
            bail!("`crates` must list at least one crate directory");
        }
        Ok(Self {
            budget,
            crates,
            not_yet_present: list("not_yet_present")?,
        })
    }
}

/// Per-crate result.
#[derive(Debug)]
pub struct CrateCount {
    /// Crate directory as written in the config.
    pub dir: String,
    /// Counted lines, or `None` when the crate is listed as not yet present.
    pub lines: Option<usize>,
}

/// Whole-run result.
#[derive(Debug)]
pub struct Report {
    /// One row per configured crate.
    pub crates: Vec<CrateCount>,
    /// Sum of all rows.
    pub total: usize,
    /// Configured budget.
    pub budget: usize,
}

impl Report {
    /// Whether the total is within the budget.
    pub fn within_budget(&self) -> bool {
        self.total <= self.budget
    }

    /// Human-readable breakdown.
    pub fn render(&self) -> String {
        let mut s = String::from("trust footprint (L1+L2, non-blank non-comment non-test Rust lines)\n");
        for c in &self.crates {
            match c.lines {
                Some(n) => s.push_str(&format!("  {:<36} {:>7}\n", c.dir, n)),
                None => s.push_str(&format!("  {:<36} {:>7}\n", c.dir, "absent")),
            }
        }
        s.push_str(&format!(
            "  {:<36} {:>7}  (budget {})\n",
            "TOTAL", self.total, self.budget
        ));
        s
    }
}

/// Count every configured crate under `root`.
pub fn run(root: &Path, cfg: &Config) -> Result<Report> {
    let mut rows = Vec::new();
    let mut total = 0;
    for dir in &cfg.crates {
        let src = root.join(dir).join("src");
        if !src.is_dir() {
            bail!("{} has no src/ directory (listed in `crates`)", root.join(dir).display());
        }
        let n = count_dir(&src)?;
        total += n;
        rows.push(CrateCount {
            dir: dir.clone(),
            lines: Some(n),
        });
    }
    for dir in &cfg.not_yet_present {
        if root.join(dir).join("src").is_dir() {
            bail!("{dir} exists now; move it from `not_yet_present` to `crates`");
        }
        rows.push(CrateCount {
            dir: dir.clone(),
            lines: None,
        });
    }
    Ok(Report {
        crates: rows,
        total,
        budget: cfg.budget,
    })
}

fn count_dir(dir: &Path) -> Result<usize> {
    let mut total = 0;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    entries.sort();
    for p in entries {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            if name != "tests" {
                total += count_dir(&p)?;
            }
        } else if p.extension().and_then(|e| e.to_str()) == Some("rs") && name != "tests.rs" {
            let text = std::fs::read_to_string(&p)
                .with_context(|| format!("reading {}", p.display()))?;
            total += count_source(&text);
        }
    }
    Ok(total)
}

/// Count non-blank, non-comment lines of `src`, excluding `#[cfg(test)]` items.
pub fn count_source(src: &str) -> usize {
    let clean = strip_tests(&sanitize(src));
    clean.lines().filter(|l| !l.trim().is_empty()).count()
}

/// Replace comments with spaces (newlines kept) and neutralise structural
/// characters inside string/char literals so brace matching is reliable.
fn sanitize(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    let defang = |c: char| if matches!(c, '{' | '}' | ';' | '#') { '_' } else { c };
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                out.push(' ');
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < b.len() {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(b[i]));
                    i += 1;
                }
            }
        } else if c == 'r' && matches!(next, Some('"') | Some('#')) && is_raw_start(&b, i) {
            // raw string r#"..."#
            let mut j = i + 1;
            let mut hashes = 0;
            while b.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            out.extend(&b[i..=j]); // r, #s, opening quote
            i = j + 1;
            while i < b.len() {
                if b[i] == '"' && (0..hashes).all(|k| b.get(i + 1 + k) == Some(&'#')) {
                    out.push('"');
                    out.extend(std::iter::repeat('#').take(hashes));
                    i += 1 + hashes;
                    break;
                }
                out.push(defang(b[i]));
                i += 1;
            }
        } else if c == '"' {
            out.push('"');
            i += 1;
            while i < b.len() {
                if b[i] == '\\' {
                    out.push('_');
                    if let Some(&n) = b.get(i + 1) {
                        out.push(if n == '\n' { '\n' } else { '_' });
                    }
                    i += 2;
                } else if b[i] == '"' {
                    out.push('"');
                    i += 1;
                    break;
                } else {
                    out.push(defang(b[i]));
                    i += 1;
                }
            }
        } else if c == '\'' {
            // char literal or lifetime
            let is_char = match (next, b.get(i + 2)) {
                (Some('\\'), _) => true,
                (Some(_), Some('\'')) => true,
                _ => false,
            };
            if is_char {
                out.push('\'');
                i += 1;
                while i < b.len() {
                    if b[i] == '\\' {
                        out.push_str("__");
                        i += 2;
                    } else if b[i] == '\'' {
                        out.push('\'');
                        i += 1;
                        break;
                    } else {
                        out.push(defang(b[i]));
                        i += 1;
                    }
                }
            } else {
                out.push(c);
                i += 1;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// `r` at `i` starts a raw string only if followed by `#*"` and not part of an identifier.
fn is_raw_start(b: &[char], i: usize) -> bool {
    if i > 0 && (b[i - 1].is_alphanumeric() || b[i - 1] == '_') {
        // `br"..."` / identifiers ending in r: allow only a preceding `b`.
        if b[i - 1] != 'b' || (i > 1 && (b[i - 2].is_alphanumeric() || b[i - 2] == '_')) {
            return false;
        }
    }
    let mut j = i + 1;
    while b.get(j) == Some(&'#') {
        j += 1;
    }
    b.get(j) == Some(&'"')
}

/// Remove every `#[cfg(test)]` item (attribute through the end of its item).
fn strip_tests(clean: &str) -> String {
    let b: Vec<char> = clean.chars().collect();
    let mut out = String::with_capacity(clean.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == '#' {
            if let Some((attr_end, is_test, inner)) = parse_attr(&b, i) {
                if is_test && inner {
                    return String::new(); // `#![cfg(test)]`: whole file
                }
                if is_test {
                    let end = item_end(&b, attr_end);
                    // keep newlines so nothing else shifts; they are blank lines
                    for &c in &b[i..end] {
                        if c == '\n' {
                            out.push('\n');
                        }
                    }
                    i = end;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Parse `#[...]` / `#![...]` at `i`; returns (index after `]`, is `cfg(test)`, is inner).
fn parse_attr(b: &[char], i: usize) -> Option<(usize, bool, bool)> {
    let mut j = i + 1;
    let inner = b.get(j) == Some(&'!');
    if inner {
        j += 1;
    }
    if b.get(j) != Some(&'[') {
        return None;
    }
    let start = j + 1;
    let mut depth = 0;
    while j < b.len() {
        match b[j] {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    let body: String = b[start..j].iter().filter(|c| !c.is_whitespace()).collect();
                    return Some((j + 1, body == "cfg(test)", inner));
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

/// End (exclusive) of the item that starts at `i`: after a top-level `;` or
/// after the first balanced `{...}` block.
fn item_end(b: &[char], mut i: usize) -> usize {
    let mut paren = 0i32;
    while i < b.len() {
        match b[i] {
            '(' | '[' => paren += 1,
            ')' | ']' => paren -= 1,
            ';' if paren <= 0 => return i + 1,
            '{' if paren <= 0 => {
                let mut depth = 0;
                while i < b.len() {
                    match b[i] {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                return i + 1;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                return b.len();
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_and_comment_lines_are_not_counted() {
        let src = "//! doc\n\n/// item doc\nfn a() {\n    // note\n    let x = 1; // trailing\n}\n/* block\n   still */\n";
        assert_eq!(count_source(src), 3); // fn a() {, let x, }
    }

    #[test]
    fn cfg_test_module_is_excluded() {
        let src = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() { let s = \"}\"; }\n    #[test]\n    fn u() {}\n}\nfn b() {}\n";
        assert_eq!(count_source(src), 2);
    }

    #[test]
    fn braces_in_strings_and_lifetimes_do_not_confuse_matching() {
        let src = "fn a<'a>(x: &'a str) {}\n#[cfg(test)]\nmod t { const S: &str = r#\"}}\"#; const C: char = '}'; }\nfn b() {}\n";
        assert_eq!(count_source(src), 2);
    }

    #[test]
    fn cfg_test_use_and_inner_attribute() {
        assert_eq!(count_source("#[cfg(test)]\nuse std::fmt;\nfn a() {}\n"), 1);
        assert_eq!(count_source("#![cfg(test)]\nfn a() {}\n"), 0);
    }
}
