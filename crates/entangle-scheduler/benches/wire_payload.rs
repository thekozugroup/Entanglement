//! Optimized one-shot wire round trip, including both request and response payloads.
use entangle_scheduler::wire::{
    decode_request, decode_response, encode_request, encode_response, RemoteOutcome,
    RemoteTaskRequest, RemoteTaskResponse,
};
use std::{hint::black_box, time::Instant};

fn measure(bytes: usize, iterations: usize) {
    let request = RemoteTaskRequest {
        v: entangle_scheduler::wire::WIRE_VERSION,
        task_id: [7; 16],
        plugin: "0123456789abcdef0123456789abcdef/benchmark@1.0.0".into(),
        input: (0..bytes).map(|i| i as u8).collect(),
        timeout_ms: 5_000,
        max_input_bytes: bytes as u64,
        max_output_bytes: bytes as u64,
    };
    let mut trials = Vec::new();
    for sample in 0..11 {
        let start = Instant::now();
        for _ in 0..iterations {
            let frame = encode_request(black_box(&request)).unwrap();
            let decoded = decode_request(&frame).unwrap();
            let response = encode_response(&RemoteTaskResponse::ok(decoded.input)).unwrap();
            let RemoteOutcome::Ok { output } =
                decode_response(&response, bytes as u64).unwrap().outcome
            else {
                panic!("expected echoed payload")
            };
            assert_eq!(black_box(&output), &request.input);
        }
        if sample >= 2 {
            trials.push(start.elapsed().as_secs_f64() * 1e6 / iterations as f64);
        }
    }
    trials.sort_by(f64::total_cmp);
    println!(
        "bytes={bytes} iterations={iterations} trials={} median_us={:.3} range_us={:.3}..{:.3}",
        trials.len(),
        trials[4],
        trials[0],
        trials[8]
    );
}

fn main() {
    measure(64, 50_000);
    measure(256 * 1024, 64);
}
