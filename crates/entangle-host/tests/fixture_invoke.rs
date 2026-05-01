//! Integration test: load the hello-pong fixture and call run.
//! Verifies wit-bindgen host wiring is correct end-to-end.
//!
//! The `hello-pong.wasm` binary is a pre-built artifact committed to
//! `tests/fixtures/`.  To rebuild it run:
//!   bash crates/entangle-host/fixtures-src/hello-pong/build.sh
//!
//! Source is in `crates/entangle-host/fixtures-src/hello-pong/`.
//!
use entangle_host::{HostEngine, LoadedPlugin};
use entangle_types::{plugin_id::PluginId, tier::Tier};

#[tokio::test(flavor = "multi_thread")]
async fn hello_pong_fixture_returns_pong_on_empty_input() {
    let bytes = include_bytes!("fixtures/hello-pong.wasm");
    let engine = HostEngine::new().expect("engine");
    let plugin_id: PluginId = "aabbccddeeff00112233445566778899/hello-pong@0.1.0"
        .parse()
        .unwrap();
    let plugin = LoadedPlugin::from_bytes(&engine, bytes, plugin_id, Tier::Pure).expect("compile");
    let result = plugin
        .run_one_shot(&engine, b"", 30_000)
        .await
        .expect("run");
    assert_eq!(result.output, b"pong");
}

#[tokio::test(flavor = "multi_thread")]
async fn hello_pong_fixture_returns_greeting_on_input() {
    let bytes = include_bytes!("fixtures/hello-pong.wasm");
    let engine = HostEngine::new().expect("engine");
    let plugin_id: PluginId = "aabbccddeeff00112233445566778899/hello-pong@0.1.0"
        .parse()
        .unwrap();
    let plugin = LoadedPlugin::from_bytes(&engine, bytes, plugin_id, Tier::Pure).expect("compile");
    let result = plugin
        .run_one_shot(&engine, b"world", 30_000)
        .await
        .expect("run");
    assert_eq!(result.output, b"Hello, world!");
}
