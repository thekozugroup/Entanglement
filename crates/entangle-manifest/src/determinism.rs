//! What a manifest declares about determinism (spec §7.5).
//!
//! A `Deterministic` (hash-quorum) task is "rejected at submit if the task's
//! component manifest declares `pure: false` or uses non-deterministic host
//! functions". Two optional `[plugin]` keys carry that declaration:
//!
//! ```toml
//! [plugin]
//! pure = false                              # two runs on one input may differ
//! nondeterministic = ["clock", "entropy"]   # host functions it relies on
//! ```
//!
//! `nondeterministic` names `"clock"` (sub-second wall-clock time),
//! `"entropy"` (randomness), `"network"` (answers from other hosts) or
//! `"gpu-float"` (GPU floating-point kernels that are not bit-stable); any
//! entry counts. A network capability (`net.lan`, `net.wan`) counts too:
//! what another host answers is not a function of the task's input — and
//! for the same reason so do `agent.invoke` (an agent or LLM call) and
//! `mesh.peer` (answers from other peers).
//!
//! Both keys are read here, from the manifest text, rather than added to
//! [`crate::schema::PluginSection`]: that struct already ignores keys it does
//! not know, so manifests carrying them load on every node, old or new.

use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Deserialize)]
struct View {
    plugin: PluginView,
    #[serde(default)]
    capabilities: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize)]
struct PluginView {
    #[serde(default)]
    pure: Option<bool>,
    #[serde(default)]
    nondeterministic: Vec<String>,
}

/// Why runs of the plugin described by `manifest_text` may not agree byte
/// for byte: `pure = false`, each declared `nondeterministic` host function
/// and each network, agent or mesh capability, in that order. Empty when the manifest
/// declares no non-determinism; `Err` when the text is not a manifest
/// (missing `[plugin]`, or `pure` / `nondeterministic` of the wrong type).
pub fn nondeterminism(manifest_text: &str) -> Result<Vec<String>, toml::de::Error> {
    let view: View = toml::from_str(manifest_text)?;
    let mut reasons = Vec::new();
    if view.plugin.pure == Some(false) {
        reasons.push("pure = false".to_owned());
    }
    for f in &view.plugin.nondeterministic {
        let entry = format!("nondeterministic host function {f:?}");
        if !reasons.contains(&entry) {
            reasons.push(entry);
        }
    }
    for key in view.capabilities.keys() {
        match key.as_str() {
            "net.lan" | "net.wan" => reasons.push(format!("network capability {key}")),
            "agent.invoke" => reasons.push(format!("agent capability {key}")),
            "mesh.peer" => reasons.push(format!("mesh capability {key}")),
            _ => {}
        }
    }
    Ok(reasons)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(extra: &str, caps: &str) -> String {
        format!(
            "[plugin]\nid = \"p/x\"\nversion = \"0.1.0\"\ntier = 3\nruntime = \"wasm\"\n{extra}\n\
             [capabilities]\n{caps}\n"
        )
    }

    #[test]
    fn nondeterminism_comes_from_pure_declared_functions_and_network() {
        assert!(nondeterminism(&manifest("", "")).unwrap().is_empty());
        assert!(nondeterminism(&manifest("pure = true", ""))
            .unwrap()
            .is_empty());
        assert_eq!(
            nondeterminism(&manifest("pure = false", "")).unwrap(),
            vec!["pure = false"]
        );
        let declared = nondeterminism(&manifest(
            "nondeterministic = [\"clock\", \"entropy\", \"clock\"]",
            "",
        ))
        .unwrap();
        assert_eq!(declared.len(), 2, "{declared:?}");
        let net = nondeterminism(&manifest(
            "",
            "\"net.wan\" = { hosts = [\"api.example.com:443\"] }",
        ))
        .unwrap();
        assert_eq!(net, vec!["network capability net.wan"]);
        let local = nondeterminism(&manifest(
            "",
            "\"storage.local\" = { scope = \"plugin\", mode = \"ro\" }",
        ))
        .unwrap();
        assert!(local.is_empty());
        assert!(nondeterminism("pure = 3").is_err());
        assert!(nondeterminism(&manifest("pure = \"no\"", "")).is_err());
    }

    /// An agent call (an LLM) and answers from other peers are no more a
    /// function of the task's input than a network answer is.
    #[test]
    fn agent_and_peer_capabilities_imply_nondeterminism() {
        let agent = nondeterminism(&manifest("", "\"agent.invoke\" = {}")).unwrap();
        assert_eq!(agent, vec!["agent capability agent.invoke"]);
        let peer = nondeterminism(&manifest("", "\"mesh.peer\" = {}")).unwrap();
        assert_eq!(peer, vec!["mesh capability mesh.peer"]);
    }

    /// The keys do not disturb the regular loader.
    #[test]
    fn the_keys_load_with_the_regular_schema() {
        let text = manifest("pure = false\nnondeterministic = [\"entropy\"]", "");
        let raw: crate::schema::Manifest = toml::from_str(&text).expect("still a manifest");
        assert_eq!(raw.plugin.tier, 3);
    }
}
