//! `metric-bleu-4` — a `SemanticEquivalent` metric (spec §7.5): the distance
//! between two text outputs is `1 - BLEU-4`.
//!
//! The component implements `entangle:integrity/metric@0.1.0`:
//! `compare(a, b) -> f64`. It runs only on the submitter, at tier 2, once per
//! replica pair. See `README.md` and [`bleu`] for the exact definition.
//!
//! Layout: the math lives in [`bleu`], free of wasm-only types, so it is
//! exercised with `cargo test` on the host target.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod bleu;

pub use bleu::{bleu4, distance, tokens};

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

    struct Bleu4;

    impl exports::entangle::integrity::metric::Guest for Bleu4 {
        fn compare(a: Vec<u8>, b: Vec<u8>) -> f64 {
            crate::bleu::distance(&a, &b)
        }
    }

    export!(Bleu4);
}
