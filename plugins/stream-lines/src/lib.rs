//! `stream-lines` — a streaming-task plugin (spec §7.1): it emits its text
//! input one line per chunk, then reads the task's inbound stream and emits
//! each line of every inbound chunk, until the submitter finishes its input.
//!
//! The component implements the `entangle:plugin@0.1.0` `stream-plugin`
//! world: export `start-stream(input)`, imports `yield-chunk` (output stream,
//! handle 0) and `next-chunk` (input stream, handle 1). Every `yield-chunk`
//! blocks until the submitter has granted credit, so the plugin produces no
//! faster than the submitter consumes.
//!
//! Errors: input (or an inbound chunk) that is not UTF-8 is
//! `invalid-input`; a `yield-chunk` or `next-chunk` failure (the stream was
//! cancelled, lost, stalled or hit a size cap) ends the plugin with
//! `internal`.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod lines;

/// The output stream's handle (`yield-chunk`).
pub const OUTPUT: u64 = 0;
/// The input stream's handle (`next-chunk`).
pub const INPUT: u64 = 1;

/// wasm entry point: generated bindings for the `stream-plugin` world plus
/// the export. Generated code needs `unsafe` (canonical ABI glue), allowed
/// here only.
#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code, missing_docs)]
mod component {
    wit_bindgen::generate!({
        world: "stream-plugin",
        path: "../../crates/entangle-wit/wit",
    });

    use entangle::plugin::stream::{next_chunk, yield_chunk, ChunkResult};

    struct StreamLines;

    fn emit(text: &str) -> Result<(), PluginError> {
        for line in crate::lines::split(text) {
            yield_chunk(crate::OUTPUT, line.as_bytes()).map_err(PluginError::Internal)?;
        }
        Ok(())
    }

    impl Guest for StreamLines {
        fn start_stream(input: Vec<u8>) -> Result<u64, PluginError> {
            let text = crate::lines::decode(&input, "input").map_err(PluginError::InvalidInput)?;
            emit(&text)?;
            let mut n = 0u64;
            loop {
                match next_chunk(crate::INPUT) {
                    ChunkResult::Ok(bytes) => {
                        let text = crate::lines::decode(&bytes, &format!("input chunk {n}"))
                            .map_err(PluginError::InvalidInput)?;
                        emit(&text)?;
                        n += 1;
                    }
                    ChunkResult::End => return Ok(crate::OUTPUT),
                    ChunkResult::Error(e) => return Err(PluginError::Internal(e)),
                }
            }
        }
    }

    export!(StreamLines);
}
