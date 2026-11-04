//! `cargo xtask loc-budget` against fixture crates in temp dirs.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn write(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn fixture(budget: usize) -> TempDir {
    let d = TempDir::new().unwrap();
    // a: 3 counted lines; the cfg(test) module, comments, blanks and tests/ are not counted.
    write(
        d.path(),
        "crates/a/src/lib.rs",
        "//! doc\n\nfn one() {\n    let _ = 1;\n}\n\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n",
    );
    write(
        d.path(),
        "crates/a/tests/it.rs",
        "fn big() {}\n".repeat(50).as_str(),
    );
    // b: 2 counted lines (mod decl + nested module file); tests.rs is skipped.
    write(d.path(), "crates/b/src/lib.rs", "pub mod m;\n");
    write(d.path(), "crates/b/src/m.rs", "pub fn f() {}\n");
    write(d.path(), "crates/b/src/tests.rs", "fn x() {}\nfn y() {}\n");
    write(
        d.path(),
        "cfg.toml",
        &format!(
            "budget = {budget}\ncrates = [\"crates/a\", \"crates/b\"]\nnot_yet_present = [\"crates/c\"]\n"
        ),
    );
    d
}

fn run(d: &TempDir) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["loc-budget", "--root"])
        .arg(d.path())
        .arg("--config")
        .arg(d.path().join("cfg.toml"))
        .output()
        .unwrap()
}

#[test]
fn within_budget_passes_and_prints_breakdown() {
    let d = fixture(5);
    let out = run(&d);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("crates/a") && stdout.contains("crates/b"),
        "{stdout}"
    );
    assert!(stdout.contains("absent"), "{stdout}");
    assert!(
        stdout.contains("TOTAL") && stdout.contains(" 5 "),
        "{stdout}"
    );
}

#[test]
fn over_budget_fails_with_the_overage() {
    let d = fixture(4);
    let out = run(&d);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("over the 4 budget by 1"), "{stderr}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("crates/a"));
}

#[test]
fn missing_listed_crate_is_an_error() {
    let d = fixture(100);
    write(
        d.path(),
        "cfg.toml",
        "budget = 100\ncrates = [\"crates/a\", \"crates/zzz\"]\n",
    );
    let out = run(&d);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("crates/zzz"));
}
