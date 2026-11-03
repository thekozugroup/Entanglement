//! Spec ↔ test cross-check for the §16 acceptance criteria.
//!
//! `docs/architecture.md` §16 defines falsifiable propositions named
//! `ATC-<GROUP>-<N>` and states that Phase 1 is done iff all of them pass on
//! CI. A test implements a proposition when its function name starts with
//! `atc_<group>_<n>_` (snake case of the ID, e.g. `atc_int_5_oversized_...`
//! implements ATC-INT-5).
//!
//! This runner scans every `.rs` file under `crates/` and `plugins/` and
//! classifies **each occurrence** of an ID:
//!
//! * **live** — an ordinary test;
//! * **ignored** — carries `#[ignore]` (or a `cfg_attr(.., ignore)`);
//! * **stub** — its body calls `unimplemented!` or `todo!`.
//!
//! An ID counts as covered only if at least one occurrence is live. Ignored or
//! stubbed occurrences do not count: a placeholder that never runs proves
//! nothing.
//!
//! IDs implemented by tests but absent from §16 are reported as extensions
//! when they follow the `ATC-<GROUP>-<N>` shape (numeric tail), and as
//! orphans otherwise (a likely typo).
//!
//! Run with: `cargo test -p entangle-atc-matrix -- --nocapture` to print the
//! matrix.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Path to the spec, relative to the workspace root.
const SPEC_REL: &str = "docs/architecture.md";

/// Directories (relative to the workspace root) that are scanned for tests.
const SCAN_DIRS: &[&str] = &["crates", "plugins"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Live,
    Ignored,
    Stub,
}

#[derive(Clone, Debug)]
struct Occurrence {
    file: String,
    line: usize,
    func: String,
    kind: Kind,
}

fn workspace_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR = <root>/crates/entangle-atc-matrix
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root is two levels above the crate")
        .to_path_buf()
}

/// Collect the IDs defined in §16, mapped to the spec line where each is
/// first defined. Only the §16 block (from the first `### 16.` heading up to
/// `### Acceptance summary`) is scanned, so forward references elsewhere in
/// the spec do not create phantom requirements.
fn spec_ids(spec: &str) -> BTreeMap<String, usize> {
    let id_re = regex::Regex::new(r"\bATC-([A-Z]+(?:-[A-Z]+)?)-(\d+)\b").unwrap();
    let mut in_block = false;
    let mut out = BTreeMap::new();
    for (i, line) in spec.lines().enumerate() {
        if line.starts_with("### 16.") {
            in_block = true;
        } else if line.starts_with("### Acceptance summary") {
            break;
        }
        if !in_block {
            continue;
        }
        // Definition sites are lines that begin with the ID (inside the
        // fenced blocks), not prose mentions.
        let trimmed = line.trim_start();
        if !trimmed.starts_with("ATC-") {
            continue;
        }
        if let Some(cap) = id_re.captures(trimmed) {
            let id = format!("ATC-{}-{}", &cap[1], &cap[2]);
            out.entry(id).or_insert(i + 1);
        }
    }
    out
}

/// Classify the body of the function starting at `lines[start]`.
///
/// The body ends at the first later line that is a closing brace at the
/// function's own indentation. Returns `true` if it contains a stub macro.
fn body_is_stub(lines: &[&str], start: usize) -> bool {
    let indent: String = lines[start]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect();
    let close = format!("{indent}}}");
    for line in &lines[start..] {
        let t = line.trim();
        if t.contains("unimplemented!") || t.contains("todo!") {
            return true;
        }
        if line.trim_end() == close {
            break;
        }
    }
    false
}

/// `true` if the attribute lines directly above `fn_line` include an ignore.
fn has_ignore(lines: &[&str], fn_line: usize) -> bool {
    let mut j = fn_line;
    while j > 0 {
        j -= 1;
        let l = lines[j].trim();
        if l.starts_with("#[ignore") || (l.starts_with("#[cfg_attr") && l.contains("ignore")) {
            return true;
        }
        // Keep walking over attributes, doc comments, and attribute
        // continuation lines; stop at anything else.
        let attribute_ish = l.starts_with("#[")
            || l.starts_with("///")
            || l.starts_with("//")
            || l.ends_with(")]")
            || l.ends_with(',')
            || l.starts_with('"');
        if !attribute_ish {
            return false;
        }
    }
    false
}

fn scan_tests(root: &Path) -> BTreeMap<String, Vec<Occurrence>> {
    let fn_re =
        regex::Regex::new(r"fn\s+(atc_([a-z]+(?:_[a-z]+)*)_([0-9]+)(?:_[a-z0-9_]*)?)\s*[(<]")
            .unwrap();
    let mut found: BTreeMap<String, Vec<Occurrence>> = BTreeMap::new();

    for dir in SCAN_DIRS {
        let base = root.join(dir);
        for entry in walkdir::WalkDir::new(&base)
            .into_iter()
            .filter_entry(|e| e.file_name() != "target")
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if !entry.file_type().is_file()
                || path.extension().and_then(|e| e.to_str()) != Some("rs")
            {
                continue;
            }
            // This file mentions the pattern in its own docs.
            if path.ends_with("entangle-atc-matrix/tests/matrix.rs") {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(path) else {
                continue;
            };
            let lines: Vec<&str> = src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let Some(cap) = fn_re.captures(line) else {
                    continue;
                };
                let group = cap[2].to_uppercase().replace('_', "-");
                let n: u32 = cap[3].parse().expect("regex guarantees digits");
                let id = format!("ATC-{group}-{n}");
                let kind = if body_is_stub(&lines, i) {
                    Kind::Stub
                } else if has_ignore(&lines, i) {
                    Kind::Ignored
                } else {
                    Kind::Live
                };
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .into_owned();
                found.entry(id).or_default().push(Occurrence {
                    file: rel,
                    line: i + 1,
                    func: cap[1].to_string(),
                    kind,
                });
            }
        }
    }
    found
}

/// A spec ID is an extension (not an orphan) if it has the `ATC-<GROUP>-<N>`
/// shape with a numeric tail.
fn is_extension(id: &str) -> bool {
    id.strip_prefix("ATC-")
        .and_then(|s| s.split('-').next_back())
        .is_some_and(|last| last.parse::<u32>().is_ok())
}

#[test]
#[ignore = "gating is switched on once every §16 stream has landed"]
fn atc_matrix_full_coverage() {
    let root = workspace_root();
    let spec_path = root.join(SPEC_REL);
    let spec = std::fs::read_to_string(&spec_path)
        .unwrap_or_else(|e| panic!("could not read spec at {spec_path:?}: {e}"));

    let expected = spec_ids(&spec);
    assert!(
        !expected.is_empty(),
        "no ATC IDs found in §16 of {spec_path:?}; check the section headings"
    );

    let found = scan_tests(&root);

    println!("\n## ATC coverage matrix\n");
    println!("| ATC ID | Spec line | Status | Live tests |");
    println!("|---|---|---|---|");

    let mut covered = Vec::new();
    let mut not_running = Vec::new();
    let mut uncovered = Vec::new();

    for (id, spec_line) in &expected {
        let occ = found.get(id).map(Vec::as_slice).unwrap_or(&[]);
        let live: Vec<&Occurrence> = occ.iter().filter(|o| o.kind == Kind::Live).collect();
        let status = if !live.is_empty() {
            covered.push(id.clone());
            "COVERED"
        } else if !occ.is_empty() {
            not_running.push(id.clone());
            "NOT RUNNING (ignored/stub only)"
        } else {
            uncovered.push(id.clone());
            "UNCOVERED"
        };
        let where_ = if live.is_empty() {
            occ.iter()
                .map(|o| format!("{}:{} ({:?})", o.file, o.line, o.kind))
                .collect::<Vec<_>>()
                .join("; ")
        } else {
            live.iter()
                .map(|o| format!("{}::{}", o.file, o.func))
                .collect::<Vec<_>>()
                .join("; ")
        };
        println!("| {id} | §16 L{spec_line} | {status} | {where_} |");
    }

    let expected_ids: BTreeSet<&String> = expected.keys().collect();
    let mut extensions = Vec::new();
    let mut orphans = Vec::new();
    for id in found.keys().filter(|id| !expected_ids.contains(id)) {
        if is_extension(id) {
            extensions.push(id.clone());
        } else {
            orphans.push(id.clone());
        }
    }

    // Stubs anywhere are dead weight; list them so they get deleted.
    let stubs: Vec<String> = found
        .values()
        .flatten()
        .filter(|o| o.kind == Kind::Stub)
        .map(|o| format!("{}:{} {}", o.file, o.line, o.func))
        .collect();

    println!(
        "\n**Summary**: expected={}, covered={}, not-running={}, uncovered={}, extensions={}, orphans={}, stubs={}",
        expected.len(),
        covered.len(),
        not_running.len(),
        uncovered.len(),
        extensions.len(),
        orphans.len(),
        stubs.len(),
    );
    if !extensions.is_empty() {
        println!("Extensions beyond §16: {}", extensions.join(", "));
    }

    let mut problems = Vec::new();
    if !uncovered.is_empty() {
        problems.push(format!("uncovered §16 IDs: {uncovered:?}"));
    }
    if !not_running.is_empty() {
        problems.push(format!(
            "§16 IDs whose only tests are ignored or stubbed: {not_running:?}"
        ));
    }
    if !orphans.is_empty() {
        problems.push(format!("malformed ATC test names: {orphans:?}"));
    }
    if !stubs.is_empty() {
        problems.push(format!("unimplemented!/todo! ATC stubs: {stubs:?}"));
    }
    assert!(
        problems.is_empty(),
        "§16 acceptance matrix is incomplete:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn spec_ids_reads_only_definition_lines_in_section_16() {
    let spec = "\
## 7. Something
ATC-FOO-9 mentioned early
### 16.1 Group
```
ATC-MAN-1
  GIVEN prose mentioning ATC-BAR-2
ATC-MAN-2
```
### Acceptance summary
ATC-ZZZ-1
";
    let ids = spec_ids(spec);
    let keys: Vec<&str> = ids.keys().map(String::as_str).collect();
    assert_eq!(keys, ["ATC-MAN-1", "ATC-MAN-2"]);
}

#[test]
fn stub_and_ignore_detection() {
    let src = "\
#[test]
#[ignore = \"needs hardware\"]
fn atc_x_1_a() {
    assert!(true);
}

#[test]
fn atc_x_2_b() {
    unimplemented!(\"later\")
}

    #[test]
    fn atc_x_3_c() {
        let x = 1;
        assert_eq!(x, 1);
    }
";
    let lines: Vec<&str> = src.lines().collect();
    let pos = |name: &str| lines.iter().position(|l| l.contains(name)).unwrap();
    assert!(has_ignore(&lines, pos("atc_x_1_a")));
    assert!(!body_is_stub(&lines, pos("atc_x_1_a")));
    assert!(body_is_stub(&lines, pos("atc_x_2_b")));
    assert!(!has_ignore(&lines, pos("atc_x_2_b")));
    assert!(!has_ignore(&lines, pos("atc_x_3_c")));
    assert!(!body_is_stub(&lines, pos("atc_x_3_c")));
}

#[test]
fn extension_shape() {
    assert!(is_extension("ATC-BRG-7"));
    assert!(is_extension("ATC-MAX-TIER-1"));
    assert!(!is_extension("ATC-BRG-X"));
}
