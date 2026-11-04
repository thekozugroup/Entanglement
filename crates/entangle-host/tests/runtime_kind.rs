//! ATC-MAN-3 (spec §16.1, §4.4.1 case C): a plugin that lies about its
//! runtime kind is rejected when `entangle-host` instantiates it.

use entangle_host::{
    check_runtime_kind, runtime_kind::HOST_NATIVE_FORMAT, ArtifactKind, CompiledPlugin,
    DeclaredRuntime, HostEngine, HostError, LoadedPlugin, LoadedStreamPlugin,
};
use entangle_types::{plugin_id::PluginId, tier::Tier};

fn plugin_id() -> PluginId {
    "aabbccddeeff00112233445566778899/liar@0.1.0"
        .parse()
        .unwrap()
}

/// The bytes of a real native executable for this host: the running test
/// binary itself.
fn real_native_executable() -> Vec<u8> {
    std::fs::read(std::env::current_exe().unwrap()).unwrap()
}

fn hello_pong_component() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/hello-pong.wasm"
    ))
    .unwrap()
}

/// §16 ATC-MAN-3 — GIVEN a manifest declaring a wasm component whose artifact
/// is actually a native executable, WHEN entangle-host instantiates it, THEN
/// it fails with `RuntimeKindMismatch { declared, observed }`.
#[test]
fn atc_man_3_lie_at_instantiation_rejected() {
    let engine = HostEngine::new().unwrap();
    let elf = real_native_executable();
    let err = match LoadedPlugin::from_bytes(&engine, &elf, plugin_id(), Tier::Pure) {
        Err(e) => e,
        Ok(_) => panic!("a native executable was instantiated as a wasm component"),
    };
    match err {
        HostError::RuntimeKindMismatch { declared, observed } => {
            assert_eq!(declared, DeclaredRuntime::Wasm);
            assert_eq!(observed, HOST_NATIVE_FORMAT);
            assert!(observed.is_native_executable());
        }
        other => panic!("expected RuntimeKindMismatch, got {other}"),
    }

    // Every native format is caught, not just this host's: an ELF shipped to
    // a Mac or a PE shipped to Linux is just as much a lie.
    for (bytes, kind) in [
        (
            &b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00"[..],
            ArtifactKind::Elf,
        ),
        (
            &[0xCF, 0xFA, 0xED, 0xFE, 0x07, 0, 0, 0x01][..],
            ArtifactKind::MachO,
        ),
        (&b"MZ\x90\x00\x03\x00\x00\x00"[..], ArtifactKind::Pe),
    ] {
        let err = match LoadedPlugin::from_bytes(&engine, bytes, plugin_id(), Tier::Pure) {
            Err(e) => e,
            Ok(_) => panic!("{kind} accepted as wasm"),
        };
        assert!(
            matches!(err, HostError::RuntimeKindMismatch { declared: DeclaredRuntime::Wasm, observed } if observed == kind),
            "{err}"
        );
        assert!(err.to_string().starts_with("ENTANGLE-E0507"), "{err}");
    }
}

/// The reverse lie: `runtime = "native"` shipping a wasm component.
#[test]
fn declared_native_but_artifact_is_wasm_is_rejected() {
    let err = check_runtime_kind(DeclaredRuntime::Native, &hello_pong_component()).unwrap_err();
    match err {
        HostError::RuntimeKindMismatch { declared, observed } => {
            assert_eq!(declared, DeclaredRuntime::Native);
            assert_eq!(observed, ArtifactKind::WasmComponent);
        }
        other => panic!("expected RuntimeKindMismatch, got {other}"),
    }
}

/// Honest artifacts pass in both directions.
#[test]
fn honest_artifacts_pass() {
    assert_eq!(
        check_runtime_kind(DeclaredRuntime::Wasm, &hello_pong_component()).unwrap(),
        ArtifactKind::WasmComponent
    );
    assert_eq!(
        check_runtime_kind(DeclaredRuntime::Native, &real_native_executable()).unwrap(),
        HOST_NATIVE_FORMAT
    );
    let engine = HostEngine::new().unwrap();
    LoadedPlugin::from_bytes(&engine, &hello_pong_component(), plugin_id(), Tier::Pure)
        .expect("the real component still loads");
}

/// The world-classifying loader the kernel uses ([`CompiledPlugin`]) and the
/// stream-plugin loader refuse a native executable exactly as
/// [`LoadedPlugin::from_bytes`] does, and still classify the real component.
#[test]
fn compiled_and_stream_loaders_reject_native_executable() {
    let engine = HostEngine::new().unwrap();
    let elf = real_native_executable();
    let expect_mismatch = |err: HostError| match err {
        HostError::RuntimeKindMismatch { declared, observed } => {
            assert_eq!(declared, DeclaredRuntime::Wasm);
            assert_eq!(observed, HOST_NATIVE_FORMAT);
        }
        other => panic!("expected RuntimeKindMismatch, got {other}"),
    };
    match CompiledPlugin::from_bytes(&engine, &elf, plugin_id(), Tier::Pure) {
        Err(e) => expect_mismatch(e),
        Ok(_) => panic!("CompiledPlugin accepted a native executable"),
    }
    match LoadedStreamPlugin::from_bytes(&engine, &elf, plugin_id(), Tier::Pure) {
        Err(e) => expect_mismatch(e),
        Ok(_) => panic!("LoadedStreamPlugin accepted a native executable"),
    }
    let honest =
        CompiledPlugin::from_bytes(&engine, &hello_pong_component(), plugin_id(), Tier::Pure)
            .expect("the real component still loads");
    assert_eq!(honest.world(), "plugin");
}
