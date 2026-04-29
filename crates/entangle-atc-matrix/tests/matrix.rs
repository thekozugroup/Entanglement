use std::collections::{BTreeMap, BTreeSet};

/// Path to spec relative to this file's manifest dir, walking up to repo root.
const SPEC_REL: &str = "docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md";

/// Phase-1 status: §16 has 35 ATCs; 9 covered + 3 deferred; 23 uncovered
/// (Phase 2-3 work) and 14 orphaned (tests with sub-group IDs not in §16:
/// ATC-CAP-*, ATC-SIG-*, ATC-AUDIT-*, ATC-MAX-TIER-*, ATC-OUT-*, ATC-REP-*).
/// The matrix is a living artifact — it prints the table and tells you which
/// IDs are missing. Hard-fail on uncovered/orphaned will resume in Phase 2.
/// Run with: `cargo test -p entangle-atc-matrix -- --ignored --nocapture`
#[test]
#[ignore = "Phase-1 coverage gap is intentional; matrix is informational, not gating"]
fn atc_matrix_full_coverage() {
    // -----------------------------------------------------------------------
    // Locate the workspace root
    // CARGO_MANIFEST_DIR = .../crates/entangle-atc-matrix
    // parent()           = .../crates
    // parent()           = repo root
    // -----------------------------------------------------------------------
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("crates dir")
        .parent()
        .expect("repo root");

    let spec_path = workspace_root.join(SPEC_REL);
    let spec = std::fs::read_to_string(&spec_path)
        .unwrap_or_else(|e| panic!("Could not read spec at {:?}: {e}", spec_path));

    // -----------------------------------------------------------------------
    // 1. Collect expected ATC IDs from the spec.
    //    §16 uses plain `ATC-XXX-N` (not **bold**).
    //    We scan the whole file and deduplicate — every `ATC-GRP-N` pattern
    //    is a spec-defined ID regardless of the line it appears on.
    //    To narrow to *definitions* only (avoid counting forward-references
    //    in the changelog), we restrict to the §16 block by only reading
    //    lines from "## 16." onward.  If the section header is absent we
    //    fall back to the whole file.
    // -----------------------------------------------------------------------
    let id_re = regex::Regex::new(r"ATC-([A-Z]+(?:-[A-Z]+)?)-(\d+)").unwrap();

    // Find the line where §16 starts so we only count definition-site IDs.
    let section16_start = spec
        .lines()
        .enumerate()
        .find(|(_, l)| l.starts_with("## 16.") || l.starts_with("# 16."))
        .map(|(i, _)| i)
        .unwrap_or(0);

    let mut expected: BTreeMap<String, usize> = BTreeMap::new();
    for (lineno, line) in spec.lines().enumerate().skip(section16_start) {
        for cap in id_re.captures_iter(line) {
            let id = format!("ATC-{}-{}", &cap[1], &cap[2]);
            expected.entry(id).or_insert(lineno + 1);
        }
    }

    assert!(
        !expected.is_empty(),
        "No ATC IDs found in §16 of spec — check the regex or spec path ({:?})",
        spec_path
    );

    // -----------------------------------------------------------------------
    // 2. Collect implemented ATC IDs from all .rs files under crates/.
    //    Pattern: `fn atc_<group_parts>_<N>_<rest>`
    //    where group_parts may be multiple underscore-separated words.
    //    We reconstruct the ATC ID as ATC-<GROUP>-<N> where GROUP is
    //    group_parts uppercased with underscores replaced by hyphens.
    //
    //    e.g.  fn atc_max_tier_1_native_blocked  → ATC-MAX-TIER-1
    //          fn atc_brg_1_valid_bridge_accepted → ATC-BRG-1
    //
    //    Also collect the `#[ignore` state of the surrounding lines.
    // -----------------------------------------------------------------------
    // Regex: captures everything between `fn atc_` and a trailing `_N_` or `_N(` boundary.
    // Group 1: group name parts (e.g. "max_tier")
    // Group 2: number
    let fn_re = regex::Regex::new(r#"fn\s+atc_([a-z]+(?:_[a-z]+)*)_([0-9]+)[_( ]"#).unwrap();

    let crates_dir = workspace_root.join("crates");
    let mut implemented: BTreeMap<String, (String, bool)> = BTreeMap::new();

    for entry in walkdir::WalkDir::new(&crates_dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "rs" {
            continue;
        }

        let src = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some(cap) = fn_re.captures(line) else {
                continue;
            };

            // Reconstruct group: underscore → hyphen, uppercase
            let group = cap[1].to_uppercase().replace('_', "-");
            let n: u32 = cap[2].parse().unwrap();
            let id = format!("ATC-{group}-{n}");

            // Look back up to 8 lines for `#[ignore`
            let ignored = (i.saturating_sub(8)..i).any(|j| {
                let l = lines[j].trim();
                l.starts_with("#[ignore") || (l.starts_with("#[cfg_attr") && l.contains("ignore"))
            });

            let rel_path = path
                .strip_prefix(workspace_root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            // First occurrence wins (stable across runs via BTreeMap iteration order)
            implemented.entry(id).or_insert((rel_path, ignored));
        }
    }

    // -----------------------------------------------------------------------
    // 3. Reconcile
    // -----------------------------------------------------------------------
    let expected_ids: BTreeSet<&String> = expected.keys().collect();
    let impl_ids: BTreeSet<&String> = implemented.keys().collect();

    let mut uncovered: Vec<&String> = expected_ids.difference(&impl_ids).copied().collect();
    uncovered.sort();
    let mut orphaned: Vec<&String> = impl_ids.difference(&expected_ids).copied().collect();
    orphaned.sort();

    // -----------------------------------------------------------------------
    // 4. Print the matrix as a Markdown table (always, for --nocapture view)
    // -----------------------------------------------------------------------
    println!("\n## ATC coverage matrix\n");
    println!("| ATC ID | Spec line | Status | File |");
    println!("|---|---|---|---|");

    for (id, spec_line) in &expected {
        let (file, ignored) = implemented
            .get(id)
            .map(|(f, i)| (f.as_str(), *i))
            .unwrap_or(("(missing)", false));
        let status = if file == "(missing)" {
            "UNCOVERED"
        } else if ignored {
            "IGNORED (deferred)"
        } else {
            "COVERED"
        };
        println!("| {id} | §16 L{spec_line} | {status} | {file} |");
    }

    // Summary counts
    let covered_count = expected_ids
        .iter()
        .filter(|id| {
            implemented
                .get(id.as_str())
                .map(|(_, ig)| !ig)
                .unwrap_or(false)
        })
        .count();
    let ignored_count = expected_ids
        .iter()
        .filter(|id| {
            implemented
                .get(id.as_str())
                .map(|(_, ig)| *ig)
                .unwrap_or(false)
        })
        .count();

    println!();
    println!(
        "**Summary**: expected={}, covered={}, ignored(deferred)={}, uncovered={}, orphaned={}",
        expected.len(),
        covered_count,
        ignored_count,
        uncovered.len(),
        orphaned.len()
    );

    if !uncovered.is_empty() || !orphaned.is_empty() {
        println!();
        if !uncovered.is_empty() {
            println!("### UNCOVERED ({}):", uncovered.len());
            for id in &uncovered {
                println!("  {} (spec line {})", id, expected[*id]);
            }
        }
        if !orphaned.is_empty() {
            println!("### ORPHANED ({}):", orphaned.len());
            for id in &orphaned {
                let (f, _) = &implemented[*id];
                println!("  {id} in {f}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // 5. Assertions
    // -----------------------------------------------------------------------
    assert!(
        uncovered.is_empty(),
        "{} ATC ID(s) from spec §16 have no test (even #[ignore]'d): {:?}",
        uncovered.len(),
        uncovered
    );
    assert!(
        orphaned.is_empty(),
        "{} test fn(s) reference non-existent spec §16 ATC IDs (possible typo or dropped spec entry): {:?}",
        orphaned.len(),
        orphaned
    );
}
