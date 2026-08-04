//! Contract test: stable `ENTANGLE-Exxxx` codes identify exactly one variant.
//!
//! The workspace publishes `ENTANGLE-Exxxx` codes as a caller-facing API:
//! operators grep logs for them and downstream tests assert on them. That only
//! works if a code is unambiguous — if two enums both emit `ENTANGLE-E0301`,
//! "the E0301 error" no longer names a single failure mode.
//!
//! This test parses the `#[error("ENTANGLE-Exxxx: …")]` declarations straight
//! out of the error-enum sources (via `std::fs` relative to
//! `CARGO_MANIFEST_DIR`) and fails if any code is claimed twice. Parsing the
//! text rather than the values means new variants are covered the moment they
//! are written, with no registry to keep in sync.
//!
//! Scope: the enums listed in [`ERROR_SOURCES`]. Other crates' error enums are
//! not yet collision-free (several deliberately mirror `EntangleError` codes),
//! so they are excluded until their ownership is settled — add each file here
//! as its domain is de-duplicated.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

/// Error-enum sources covered by this contract, relative to this crate's
/// `CARGO_MANIFEST_DIR` (`crates/entangle-types`).
const ERROR_SOURCES: &[&str] = &[
    "src/errors.rs",
    "../entangle-runtime/src/integrity.rs",
    "../entangle-host/src/errors.rs",
];

/// The `ENTANGLE-` prefix a stable code always carries.
const PREFIX: &str = "ENTANGLE-E";

/// One `#[error("ENTANGLE-Exxxx: …")]` declaration site.
#[derive(Debug)]
struct Site {
    /// Source file, as listed in [`ERROR_SOURCES`].
    file: &'static str,
    /// 1-based line of the `#[error(` attribute.
    line: usize,
    /// The enum variant the attribute is attached to.
    variant: String,
}

/// Read one covered source file, failing loudly if it has moved or is unreadable.
fn read_source(rel: &'static str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "error-code contract test could not read {} (from ERROR_SOURCES entry {rel:?}): {e}. \
             If the file moved, update ERROR_SOURCES — do not drop the coverage.",
            path.display()
        )
    })
}

/// Extract a 4-digit code from an attribute body, e.g. `"E0301"`.
///
/// Returns `None` when the text carries no `ENTANGLE-E` marker at all.
/// Panics when the marker is present but malformed, since a variant whose code
/// is not well-formed silently escapes every collision check.
fn extract_code(file: &str, line: usize, attr: &str) -> Option<String> {
    let start = attr.find(PREFIX)? + PREFIX.len();
    let digits: String = attr[start..].chars().take(4).collect();
    assert!(
        digits.len() == 4 && digits.chars().all(|c| c.is_ascii_digit()),
        "{file}:{line}: malformed error code — expected `{PREFIX}` followed by four digits, \
         found {PREFIX}{digits:?} in: {attr}"
    );
    Some(format!("E{digits}"))
}

/// Name of the variant an attribute is attached to: the first identifier on the
/// next line that is not blank, a comment, or another attribute.
fn variant_after(lines: &[&str], mut idx: usize) -> Option<String> {
    while idx < lines.len() {
        let line = lines[idx].trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with("#[") {
            idx += 1;
            continue;
        }
        let name: String = line
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        return (!name.is_empty()).then_some(name);
    }
    None
}

/// Every `(code, site)` pair declared by `#[error(…)]` attributes in one file.
///
/// Only attributes count. Codes appearing in doc comments, prose, or test
/// assertions are ignored, so this reflects the real variant → code mapping.
fn declarations(file: &'static str, src: &str) -> Vec<(String, Site)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !lines[i].trim_start().starts_with("#[error(") {
            i += 1;
            continue;
        }
        // `#[error(…)]` may wrap over several lines; join until it closes.
        let start = i;
        let mut attr = String::new();
        while i < lines.len() {
            attr.push_str(lines[i].trim());
            if lines[i].trim_end().ends_with(")]") {
                break;
            }
            i += 1;
        }
        assert!(
            i < lines.len(),
            "{file}:{}: unterminated `#[error(` attribute",
            start + 1
        );
        if let Some(code) = extract_code(file, start + 1, &attr) {
            let variant = variant_after(&lines, i + 1).unwrap_or_else(|| {
                panic!(
                    "{file}:{}: could not determine the variant carrying ENTANGLE-{code}",
                    start + 1
                )
            });
            found.push((
                code,
                Site {
                    file,
                    line: start + 1,
                    variant,
                },
            ));
        }
        i += 1;
    }
    found
}

/// Collect every declaration across [`ERROR_SOURCES`], keyed by code.
fn declarations_by_code() -> BTreeMap<String, Vec<Site>> {
    let mut by_code: BTreeMap<String, Vec<Site>> = BTreeMap::new();
    for rel in ERROR_SOURCES {
        let src = read_source(rel);
        let decls = declarations(rel, &src);
        assert!(
            !decls.is_empty(),
            "no ENTANGLE-Exxxx declarations parsed from {rel}: either the file no longer \
             declares error codes or the parser needs updating — a silently empty scan would \
             make this contract test vacuous"
        );
        for (code, site) in decls {
            by_code.entry(code).or_default().push(site);
        }
    }
    by_code
}

/// No stable code may be claimed by two different variants.
#[test]
fn error_codes_are_unique() {
    let by_code = declarations_by_code();

    // Guard against a parser that "passes" by finding almost nothing.
    assert!(
        by_code.len() >= 18,
        "expected at least 18 distinct error codes across {} files, found {}: {:?}",
        ERROR_SOURCES.len(),
        by_code.len(),
        by_code.keys().collect::<Vec<_>>()
    );

    let mut report = String::new();
    for (code, sites) in &by_code {
        if sites.len() > 1 {
            let _ = writeln!(
                report,
                "  ENTANGLE-{code} is claimed by {} variants:",
                sites.len()
            );
            for site in sites {
                let _ = writeln!(report, "    - {}:{} {}", site.file, site.line, site.variant);
            }
        }
    }
    assert!(
        report.is_empty(),
        "stable error-code collisions detected — one ENTANGLE-Exxxx code must name exactly one \
         failure mode. Move one side to a free code in its own domain range and update the range \
         table in crates/entangle-types/src/errors.rs:\n{report}"
    );
}

/// Where a variant's doc comment states a code, it must match the code the
/// variant actually emits — stale docs send callers grepping for the wrong string.
#[test]
fn doc_comments_match_emitted_codes() {
    for rel in ERROR_SOURCES {
        let src = read_source(rel);
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("#[error(") {
                continue;
            }
            let mut attr = String::new();
            let mut j = i;
            while j < lines.len() {
                attr.push_str(lines[j].trim());
                if lines[j].trim_end().ends_with(")]") {
                    break;
                }
                j += 1;
            }
            let Some(emitted) = extract_code(rel, i + 1, &attr) else {
                continue;
            };

            // Collect every code mentioned in the contiguous doc-comment block
            // directly above, then require the emitted code to be among them.
            //
            // We deliberately do NOT require the *nearest* mention to match:
            // the module doc asks maintainers to record superseded codes in
            // the variant's docs (e.g. "Previously ENTANGLE-E0500"), and a
            // nearest-wins rule would turn that good practice into a
            // confusing failure. Membership still catches the drift that
            // matters — a variant whose docs never mention the code it emits.
            let mut documented = Vec::new();
            let mut k = i;
            while k > 0 {
                let above = lines[k - 1].trim();
                if !above.starts_with("///") {
                    break;
                }
                k -= 1;
                if let Some(code) = extract_code(rel, k + 1, above) {
                    documented.push(code);
                }
            }
            if !documented.is_empty() {
                assert!(
                    documented.contains(&emitted),
                    "{rel}:{}: variant emits ENTANGLE-{emitted} but its doc comment only \
                     mentions {}",
                    i + 1,
                    documented
                        .iter()
                        .map(|c| format!("ENTANGLE-{c}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }
}
