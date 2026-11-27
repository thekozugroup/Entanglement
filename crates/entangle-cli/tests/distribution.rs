//! Installer policy is applied before package reads or durable state creation.
use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn install_rejects_above_ceiling_without_mutation() {
    let home = tempfile::tempdir().unwrap();
    let state = home.path().join(".entangle");
    std::fs::create_dir(&state).unwrap();
    let config = "[security]\nmax_tier_allowed=2\n";
    std::fs::write(state.join("config.toml"), config).unwrap();
    let manifest = home.path().join("entangle.toml");
    std::fs::write(&manifest,"[plugin]\nid='aabbccddeeff00112233445566778899/test@1.0.0'\nversion='1.0.0'\ntier=3\nruntime='wasm'\n").unwrap();
    Command::cargo_bin("entangle")
        .unwrap()
        .env("HOME", home.path())
        .arg("install")
        .arg(&manifest)
        .assert()
        .failure()
        .stderr(contains("ENTANGLE-E0043"));
    assert_eq!(
        std::fs::read_to_string(state.join("config.toml")).unwrap(),
        config
    );
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 1);
    let cfg = entangle_runtime::config::load_config(&state.join("config.toml")).unwrap();
    use entangle_types::tier::Tier;
    assert!(matches!(
        cfg.check_install_tier(Tier::Networked),
        Err(entangle_runtime::config::InstallError::TierExceeded {
            plugin_tier: Tier::Networked,
            ceiling: Tier::Sandboxed
        })
    ));
}
