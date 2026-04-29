use wit_parser::Resolve;

#[test]
fn wit_parses_with_wit_parser() {
    let mut resolve = Resolve::default();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("wit");
    resolve.push_dir(&dir).expect("WIT directory parses");
}

#[test]
fn wit_files_returns_all_files() {
    assert_eq!(entangle_wit::wit_files().len(), 5);
    for (_, src) in entangle_wit::wit_files() {
        assert!(src.contains("package entangle:plugin@0.1.0"));
    }
}

#[test]
fn package_constant_matches_world_files() {
    let (_, world_src) = entangle_wit::wit_files()
        .iter()
        .find(|(n, _)| *n == "world.wit")
        .unwrap();
    assert!(world_src.contains(entangle_wit::WIT_PACKAGE));
}

#[test]
fn worlds_resolve() {
    assert_eq!(entangle_wit::world("plugin"), Some("plugin"));
    assert_eq!(entangle_wit::world("stream_plugin"), Some("stream-plugin"));
    assert_eq!(entangle_wit::world("nonexistent"), None);
}
