//! `metric-embedding-cosine` — a `SemanticEquivalent` metric (spec §7.5) for
//! free-text outputs: one minus the cosine similarity of the two outputs'
//! embeddings.
//!
//! The component implements `entangle:integrity/metric@0.1.0`:
//! `compare(a, b) -> f64`. It runs only on the submitter, at tier 2, once per
//! replica pair. See `README.md` and [`cosine`] for the embedding (pinned:
//! the same bytes always embed to the same vector, on every node) and the
//! exact definition.
//!
//! Layout: the math lives in [`cosine`], free of wasm-only types, so it is
//! exercised with `cargo test` on the host target.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod cosine;

pub use cosine::{cosine_similarity, distance, embed_text, Embedding, DIMENSIONS};

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

    struct EmbeddingCosine;

    impl exports::entangle::integrity::metric::Guest for EmbeddingCosine {
        fn compare(a: Vec<u8>, b: Vec<u8>) -> f64 {
            crate::cosine::distance(&a, &b)
        }
    }

    export!(EmbeddingCosine);
}
