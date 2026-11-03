//! WIT contract definitions for Entanglement's component-model packages.
//!
//! See spec §4.4 (`wit_world` field), §9.3 (hello-world uses these interfaces) in
//! `docs/architecture.md`.
//!
//! **Phase**: 1 (all wasm plugins target these interfaces).
//!
//! Two packages ship here, each in its own directory because a WIT directory
//! holds exactly one package:
//!
//! | Package | Directory | Worlds | Used by |
//! |---|---|---|---|
//! | `entangle:plugin@0.1.0` | `wit/` | `plugin`, `stream-plugin` | every wasm plugin |
//! | `entangle:integrity@0.1.0` | `wit-integrity/` | `metric-plugin` | `SemanticEquivalent` metric components (§7.5) |
//!
//! The WIT sources are exposed at compile time via `include_str!`.
//! `entangle-host` (bindgen + linker) and `entangle-sdk` / the stdlib metric
//! plugins (wit-bindgen consumers) read the directories directly.
//!
//! # Key items
//! - [`WIT_PACKAGE`] / [`INTEGRITY_WIT_PACKAGE`] — canonical package ids.
//! - [`wit_files`] / [`integrity_wit_files`] — each package's WIT sources.
//! - [`packages`] — every shipped package, for exhaustive enumeration.
//! - [`world`] — maps a world name to its canonical form.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Canonical package identifier per spec §4.4 `wit_world`.
pub const WIT_PACKAGE: &str = "entangle:plugin@0.1.0";

/// Canonical package identifier of the integrity-metric package (§7.5).
pub const INTEGRITY_WIT_PACKAGE: &str = "entangle:integrity@0.1.0";

/// Fully-qualified interface a `SemanticEquivalent` metric component exports.
pub const METRIC_INTERFACE: &str = "entangle:integrity/metric@0.1.0";

/// World a metric component targets (in [`INTEGRITY_WIT_PACKAGE`]).
pub const METRIC_WORLD: &str = "metric-plugin";

/// Available world names components can target, across both packages.
pub const WORLDS: &[&str] = &["plugin", "stream-plugin", METRIC_WORLD];

/// Default world for the §9.3 hello-world walkthrough.
pub const DEFAULT_WORLD: &str = "plugin";

/// Returns the bytes of every WIT file of the `entangle:plugin@0.1.0`
/// package (directory `wit/`), in deterministic order.
pub fn wit_files() -> &'static [(&'static str, &'static str)] {
    &[
        ("world.wit", include_str!("../wit/world.wit")),
        ("logging.wit", include_str!("../wit/logging.wit")),
        ("capability.wit", include_str!("../wit/capability.wit")),
        ("host-info.wit", include_str!("../wit/host-info.wit")),
        ("stream.wit", include_str!("../wit/stream.wit")),
    ]
}

/// Returns the bytes of every WIT file of the `entangle:integrity@0.1.0`
/// package (directory `wit-integrity/`), in deterministic order.
pub fn integrity_wit_files() -> &'static [(&'static str, &'static str)] {
    &[("metric.wit", include_str!("../wit-integrity/metric.wit"))]
}

/// One WIT package shipped by this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitPackage {
    /// Canonical package id, e.g. `entangle:plugin@0.1.0`.
    pub id: &'static str,
    /// Directory holding the package, relative to this crate's root.
    pub dir: &'static str,
    /// The package's WIT files.
    pub files: &'static [(&'static str, &'static str)],
}

/// Every WIT package this crate ships, in deterministic order.
pub fn packages() -> [WitPackage; 2] {
    [
        WitPackage {
            id: WIT_PACKAGE,
            dir: "wit",
            files: wit_files(),
        },
        WitPackage {
            id: INTEGRITY_WIT_PACKAGE,
            dir: "wit-integrity",
            files: integrity_wit_files(),
        },
    ]
}

/// Returns the canonical world name for a given world keyword.
pub fn world(name: &str) -> Option<&'static str> {
    match name {
        "plugin" => Some("plugin"),
        "stream-plugin" | "stream_plugin" => Some("stream-plugin"),
        "metric-plugin" | "metric_plugin" => Some(METRIC_WORLD),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wit_files_returns_five_named_interfaces() {
        let files = wit_files();
        assert_eq!(files.len(), 5, "expected 5 WIT files; got {}", files.len());
        let names: Vec<&str> = files.iter().map(|(n, _)| *n).collect();
        for required in [
            "world.wit",
            "logging.wit",
            "capability.wit",
            "host-info.wit",
            "stream.wit",
        ] {
            assert!(
                names.contains(&required),
                "missing required interface file {required} (got {names:?})"
            );
        }
    }

    /// The integrity package is deliberately separate and holds exactly the
    /// metric interface + world.
    #[test]
    fn integrity_wit_files_hold_only_the_metric_package() {
        let files = integrity_wit_files();
        assert_eq!(
            files.len(),
            1,
            "expected 1 integrity WIT file; got {files:?}"
        );
        let (name, src) = files[0];
        assert_eq!(name, "metric.wit");
        assert!(src.contains("package entangle:integrity@0.1.0;"));
        assert!(src.contains("interface metric"));
        assert!(src.contains("compare: func(a: list<u8>, b: list<u8>) -> f64;"));
        assert!(src.contains("world metric-plugin"));
    }

    /// Exhaustive enumeration: two packages, six files, every file in the
    /// package its directory claims.
    #[test]
    fn packages_enumerate_every_shipped_file() {
        let pkgs = packages();
        let ids: Vec<&str> = pkgs.iter().map(|p| p.id).collect();
        assert_eq!(ids, [WIT_PACKAGE, INTEGRITY_WIT_PACKAGE]);
        let total: usize = pkgs.iter().map(|p| p.files.len()).sum();
        assert_eq!(total, 6, "5 plugin files + 1 integrity file");
        for p in pkgs {
            for (name, src) in p.files {
                assert!(
                    src.contains(&format!("package {};", p.id)),
                    "{}/{name} must declare package {}",
                    p.dir,
                    p.id
                );
            }
        }
    }

    #[test]
    fn world_resolver_accepts_canonical_and_underscore_form() {
        assert_eq!(world("plugin"), Some("plugin"));
        assert_eq!(world("stream-plugin"), Some("stream-plugin"));
        assert_eq!(world("stream_plugin"), Some("stream-plugin"));
        assert_eq!(world("metric-plugin"), Some("metric-plugin"));
        assert_eq!(world("metric_plugin"), Some("metric-plugin"));
        assert_eq!(world("bogus"), None);
    }

    #[test]
    fn wit_package_identifier_is_stable() {
        assert_eq!(WIT_PACKAGE, "entangle:plugin@0.1.0");
        assert_eq!(INTEGRITY_WIT_PACKAGE, "entangle:integrity@0.1.0");
        assert_eq!(METRIC_INTERFACE, "entangle:integrity/metric@0.1.0");
        assert_eq!(DEFAULT_WORLD, "plugin");
        assert!(WORLDS.contains(&"plugin"));
        assert!(WORLDS.contains(&METRIC_WORLD));
    }
}
