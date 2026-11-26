use std::collections::{BTreeMap, BTreeSet};

/// Path to spec relative to this file's manifest dir, walking up to repo root.
const SPEC_REL: &str = "docs/architecture.md";

/// Name-based inventory only: a matching test name does not prove the test
/// exercises the specified acceptance criterion. Mixed active and ignored
/// matches are shown explicitly for manual review.
///
/// Numeric IDs outside the acceptance definitions are listed separately.
/// Malformed names are not detected by this name-based inventory.
/// Run with: `cargo test -p entangle-atc-matrix -- --ignored --nocapture`
#[test]
#[ignore = "Phase-1.5 coverage gap is intentional; matrix is informational, not gating"]
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
    //    Collect definition lines only, inside the acceptance section.
    // -----------------------------------------------------------------------
    let id_re = regex::Regex::new(r"^\s*ATC-([A-Z]+(?:-[A-Z]+)?)-(\d+)(?:\s|$)").unwrap();

    // Find the acceptance section heading so we only count definition-site IDs.
    let section16_start = spec
        .lines()
        .enumerate()
        .find(|(_, l)| l.starts_with("## ") && l.contains("Acceptance criteria"))
        .map(|(i, _)| i)
        .expect("acceptance criteria heading not found");

    let mut expected: BTreeMap<String, usize> = BTreeMap::new();
    for (lineno, line) in spec.lines().enumerate().skip(section16_start + 1) {
        if line.starts_with("## ") {
            break;
        }
        for cap in id_re.captures_iter(line) {
            let id = format!("ATC-{}-{}", &cap[1], &cap[2]);
            expected.entry(id).or_insert(lineno + 1);
        }
    }

    assert!(
        !expected.is_empty(),
        "No ATC IDs found in the acceptance section — check the regex or spec path ({:?})",
        spec_path
    );

    // -----------------------------------------------------------------------
    // 2. Collect implemented ATC IDs from all .rs files under crates/.
    //    Pattern: `fn atc_<group_parts>_<N>_<rest>`
    //    Group 1: group name parts (e.g. "max_tier")
    //    Group 2: number
    // -----------------------------------------------------------------------
    let fn_re = regex::Regex::new(r#"fn\s+atc_([a-z]+(?:_[a-z]+)*)_([0-9]+)[_( ]"#).unwrap();

    let crates_dir = workspace_root.join("crates");
    let mut implemented: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();

    for entry in walkdir::WalkDir::new(&crates_dir)
        .sort_by_file_name()
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

            implemented
                .entry(id)
                .or_default()
                .push((format!("{rel_path}:{}", i + 1), ignored));
        }
    }

    // -----------------------------------------------------------------------
    // 3. Reconcile names; an extra ID may be an extension or a typo.
    // The regex only finds well-formed names and cannot detect malformed IDs.
    // -----------------------------------------------------------------------
    let expected_ids: BTreeSet<&String> = expected.keys().collect();
    let impl_ids: BTreeSet<&String> = implemented.keys().collect();
    let uncovered: Vec<&String> = expected_ids.difference(&impl_ids).copied().collect();
    let extra_ids: Vec<&String> = impl_ids.difference(&expected_ids).copied().collect();

    // -----------------------------------------------------------------------
    // 4. Print the matrix as a Markdown table (always, for --nocapture view)
    // -----------------------------------------------------------------------
    println!("\n## ATC name inventory\n");
    println!("| ATC ID | Spec line | Status | File |");
    println!("|---|---|---|---|");

    for (id, spec_line) in &expected {
        let matches = implemented.get(id);
        let status = match matches {
            None => "NO MATCH",
            Some(entries) if entries.iter().all(|(_, ignored)| *ignored) => "IGNORED ONLY",
            Some(entries) if entries.iter().any(|(_, ignored)| *ignored) => "MIXED; REVIEW",
            Some(_) => "ACTIVE MATCH; REVIEW",
        };
        let files = matches
            .map(|entries| {
                entries
                    .iter()
                    .map(|(path, ignored)| {
                        format!("{path}{}", if *ignored { " [ignored]" } else { "" })
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "(missing)".to_owned());
        println!("| {id} | L{spec_line} | {status} | {files} |");
    }

    // Summary counts
    let covered_count = expected_ids
        .iter()
        .filter(|id| {
            implemented
                .get(id.as_str())
                .map(|entries| entries.iter().all(|(_, ig)| !ig))
                .unwrap_or(false)
        })
        .count();
    let ignored_count = expected_ids
        .iter()
        .filter(|id| {
            implemented
                .get(id.as_str())
                .map(|entries| entries.iter().all(|(_, ig)| *ig))
                .unwrap_or(false)
        })
        .count();

    println!();
    println!(
        "**Name inventory (not proof of coverage)**: expected={}, active-only={}, ignored-only={}, mixed={}, extra-ids={}, no-match={}",
        expected.len(),
        covered_count,
        ignored_count,
        expected.len() - covered_count - ignored_count - uncovered.len(),
        extra_ids.len(),
        uncovered.len()
    );

    println!(
        "Found {} matching IDs outside the acceptance definitions (not coverage claims)",
        extra_ids.len()
    );

    if !extra_ids.is_empty() {
        println!();
        println!("### EXTRA IDS ({}):", extra_ids.len());
        for id in &extra_ids {
            for (f, ignored) in &implemented[*id] {
                let flag = if *ignored { " [deferred]" } else { "" };
                println!("  {id}{flag} in {f}");
            }
        }
    }

    if !uncovered.is_empty() {
        println!("\n### NO MATCHING TEST NAME ({}):", uncovered.len());
        for id in &uncovered {
            println!("  {} (spec line {})", id, expected[*id]);
        }
    }
}
