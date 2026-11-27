//! Produce one output chunk per input line. Each yield waits for downstream credit.
wit_bindgen::generate!({ world: "stream-plugin", path: "../../crates/entangle-wit/wit" });

struct Lines;
impl Guest for Lines {
    fn start_stream(input: Vec<u8>) -> Result<u64, PluginError> {
        let handle = 1;
        for line in input.split_inclusive(|byte| *byte == b'\n') {
            entangle::plugin::stream::yield_chunk(handle, line)
                .map_err(PluginError::ResourceExhausted)?;
        }
        Ok(handle)
    }
}
export!(Lines);
