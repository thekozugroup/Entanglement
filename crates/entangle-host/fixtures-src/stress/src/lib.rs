//! Test fixture exercising host resource limits and timeouts.
//!
//! Behavior is selected by the input bytes:
//! - `grow`      — allocate 1 MiB chunks forever, until the host's memory
//!   limiter denies `memory.grow` (must surface as ResourceExhausted).
//! - `spin:<ms>` — busy-loop for `<ms>` wall-clock milliseconds (interruptible
//!   only via the epoch deadline), then return `spun`.
//! - other       — echo the input back.

use entangle_sdk::entangle_plugin;

fn run(input: Vec<u8>) -> Result<Vec<u8>, entangle_sdk::PluginError> {
    if input == b"grow" {
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        loop {
            // Touch every byte so the allocation is real; keep chunks alive so
            // the guest heap grows without bound until the host limiter trips.
            chunks.push(vec![0xAB; 1 << 20]);
            std::hint::black_box(&chunks);
        }
    }
    if let Some(rest) = input.strip_prefix(b"spin:") {
        let ms: u64 = std::str::from_utf8(rest)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| entangle_sdk::PluginError::InvalidInput("bad spin:<ms> arg".into()))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(ms);
        while std::time::Instant::now() < deadline {
            std::hint::spin_loop();
        }
        return Ok(b"spun".to_vec());
    }
    Ok(input)
}

entangle_plugin!(run);
