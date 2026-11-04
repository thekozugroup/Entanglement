use wit_parser::Resolve;

#[test]
fn wit_parses_with_wit_parser() {
    let mut resolve = Resolve::default();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("wit");
    resolve.push_dir(&dir).expect("WIT directory parses");
}

/// The integrity package parses on its own and exposes exactly the shape the
/// host and the stdlib metrics bind to: interface `metric` with
/// `compare(list<u8>, list<u8>) -> f64`, exported by world `metric-plugin`.
#[test]
fn integrity_wit_parses_and_has_the_metric_shape() {
    use wit_parser::{Type, WorldItem, WorldKey};

    let mut resolve = Resolve::default();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("wit-integrity");
    let (pkg, _) = resolve
        .push_dir(&dir)
        .expect("integrity WIT directory parses");
    let package = &resolve.packages[pkg];
    assert_eq!(
        package.name.to_string(),
        entangle_wit::INTEGRITY_WIT_PACKAGE
    );

    let iface_id = package.interfaces["metric"];
    let iface = &resolve.interfaces[iface_id];
    assert_eq!(
        iface.functions.keys().collect::<Vec<_>>(),
        ["compare"],
        "the metric interface must export exactly `compare`"
    );
    let compare = &iface.functions["compare"];
    assert_eq!(compare.params.len(), 2);
    assert_eq!(compare.result, Some(Type::F64));
    assert_eq!(
        resolve.id_of(iface_id).as_deref(),
        Some(entangle_wit::METRIC_INTERFACE)
    );

    let world_id = package.worlds[entangle_wit::METRIC_WORLD];
    let world = &resolve.worlds[world_id];
    assert!(
        world.imports.is_empty(),
        "a metric world imports nothing from Entanglement: {:?}",
        world.imports.keys().collect::<Vec<_>>()
    );
    assert_eq!(world.exports.len(), 1);
    assert!(matches!(
        world.exports.iter().next(),
        Some((WorldKey::Interface(id), WorldItem::Interface { .. })) if *id == iface_id
    ));
}

#[test]
fn wit_files_returns_all_files() {
    // The plugin package: five files, all `entangle:plugin@0.1.0`.
    assert_eq!(entangle_wit::wit_files().len(), 5);
    for (_, src) in entangle_wit::wit_files() {
        assert!(src.contains("package entangle:plugin@0.1.0"));
    }
    // The integrity package: one file, `entangle:integrity@0.1.0`.
    assert_eq!(entangle_wit::integrity_wit_files().len(), 1);
    for (_, src) in entangle_wit::integrity_wit_files() {
        assert!(src.contains("package entangle:integrity@0.1.0"));
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
    assert_eq!(entangle_wit::world("metric_plugin"), Some("metric-plugin"));
    assert_eq!(
        entangle_wit::world("migratable_plugin"),
        Some("migratable-plugin")
    );
    assert_eq!(entangle_wit::world("migrate-hook"), Some("migrate-hook"));
    assert_eq!(entangle_wit::world("nonexistent"), None);
}

/// The optional hot-reload hook: `migrate(from-version: string) ->
/// result<_, string>`, alone in `migrate-hook` (which imports nothing), and
/// added to both plugin worlds by the `migratable-*` worlds.
#[test]
fn migrate_hook_world_has_the_hook_shape() {
    use wit_parser::{Type, WorldItem};
    let mut resolve = Resolve::default();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("wit");
    let (pkg, _) = resolve.push_dir(&dir).expect("wit parses");
    let worlds = &resolve.packages[pkg].worlds;
    let hook = &resolve.worlds[worlds[entangle_wit::MIGRATE_HOOK_WORLD]];
    assert!(hook.imports.is_empty(), "the hook world imports nothing");
    assert_eq!(hook.exports.len(), 1);
    let Some((_, WorldItem::Function(f))) = hook.exports.iter().next() else {
        panic!("migrate is a function export");
    };
    assert_eq!(f.name, "migrate");
    assert_eq!(f.params.len(), 1);
    assert!(matches!(f.params[0].ty, Type::String));
    assert!(f.result.is_some());
    for name in entangle_wit::MIGRATABLE_WORLDS {
        let w = &resolve.worlds[worlds[*name]];
        let exports: Vec<String> = w
            .exports
            .keys()
            .map(|k| resolve.name_world_key(k))
            .collect();
        assert!(
            exports.iter().any(|e| e == "migrate"),
            "{name}: {exports:?}"
        );
        assert_eq!(exports.len(), 2, "{name}: {exports:?}");
    }
}
