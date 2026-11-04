//! Test fixture for plugin lifecycle and hot reload: a `plugin`-world
//! component that also exports the optional `migrate` hook
//! (`migratable-plugin` world, spec §3.3).
//!
//! `run(input)`:
//!
//! | input         | output                                                 |
//! |---------------|--------------------------------------------------------|
//! | `id`          | the plugin id the host runs it as (`host-info.get`)    |
//! | `spin:<ms>`   | busy-waits `<ms>` ms, then `<plugin-id> spun`          |
//! | `read <path>` | the file's contents, or `err:<message>`                |
//! | anything else | `<plugin-id>\|<input>`                                 |
//!
//! `migrate(from-version)`: fails (`err`) when the running version has a
//! pre-release tag containing `fail` (e.g. `0.3.0-fail`); otherwise records
//! `<from>-><to>` in `/data/migrated` (when the plugin has storage) and
//! succeeds.

#![allow(unsafe_code, missing_docs)]

wit_bindgen::generate!({
    world: "migratable-plugin",
    path: "../../../entangle-wit/wit",
});

use entangle::plugin::host_info;

struct LifecycleProbe;

fn plugin_id() -> String {
    host_info::get().plugin_id
}

impl Guest for LifecycleProbe {
    fn run(input: Vec<u8>) -> Result<Vec<u8>, PluginError> {
        let text = String::from_utf8(input).map_err(|e| PluginError::InvalidInput(e.to_string()))?;
        let id = plugin_id();
        let out = if text == "id" {
            id
        } else if let Some(ms) = text.strip_prefix("spin:") {
            let ms: u64 = ms
                .trim()
                .parse()
                .map_err(|e: std::num::ParseIntError| PluginError::InvalidInput(e.to_string()))?;
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_millis(ms) {
                std::hint::spin_loop();
            }
            format!("{id} spun")
        } else if let Some(path) = text.strip_prefix("read ") {
            match std::fs::read_to_string(path.trim()) {
                Ok(s) => s,
                Err(e) => format!("err:{e}"),
            }
        } else {
            format!("{id}|{text}")
        };
        Ok(out.into_bytes())
    }

    fn migrate(from_version: String) -> Result<(), String> {
        let id = plugin_id();
        let version = id.rsplit('@').next().unwrap_or_default().to_owned();
        if version.contains("fail") {
            return Err(format!(
                "lifecycle-probe {version} refuses to migrate from {from_version}"
            ));
        }
        // Without a storage grant there is no /data to migrate: nothing to do.
        let _ = std::fs::write("/data/migrated", format!("{from_version}->{version}"));
        Ok(())
    }
}

export!(LifecycleProbe);
