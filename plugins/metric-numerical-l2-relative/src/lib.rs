//! `metric-numerical-l2-relative` — a `SemanticEquivalent` metric (spec §7.5)
//! for numerical workloads: the relative L2 distance between two vectors.
//!
//! The component implements `entangle:integrity/metric@0.1.0`:
//! `compare(a, b) -> f64`. It runs only on the submitter, at tier 2, once per
//! replica pair. See `README.md` and [`l2`] for the input encoding and the
//! exact definition.
//!
//! Layout: the math lives in [`l2`], free of wasm-only types, so it is
//! exercised with `cargo test` on the host target.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod l2;

pub use l2::{distance, parse_vector, relative_l2};

/// wasm entry point: generated bindings for the `metric-plugin` world plus the
/// export. Generated code needs `unsafe` (canonical ABI glue), allowed here
/// only.
#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code, missing_docs)]
mod component {
    wit_bindgen::generate!({
        world: "metric-plugin",
        path: "../../crates/entangle-wit/wit-integrity",
    });

    struct RelativeL2;

    impl exports::entangle::integrity::metric::Guest for RelativeL2 {
        fn compare(a: Vec<u8>, b: Vec<u8>) -> f64 {
            crate::l2::distance(&a, &b)
        }
    }

    export!(RelativeL2);
}
