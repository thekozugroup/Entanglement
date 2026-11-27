use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn marker() -> &'static str {
    if cfg!(build_b) { "B" } else { "A" }
}

fn utc_ns() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

#[test]
fn arithmetic_case() {
    let x = std::hint::black_box(18_u64);
    assert_eq!((x ^ 7) ^ 7, 18);
    println!("observed_component={}", marker());
}

#[test]
fn controlled_first_failure() {
    let attempt: u32 = std::env::var("ENTANGLE_LIBTEST_ATTEMPT").unwrap().parse().unwrap();
    println!("observed_component={} attempt={}", marker(), attempt);
    assert!(attempt > 1, "controlled first-attempt check");
}

#[test]
fn selected_during_reload() {
    let first = utc_ns();
    let start = Instant::now();
    let mut x = 0x13579bdf_u32;
    while start.elapsed() < Duration::from_millis(1350) {
        for _ in 0..10000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
        }
        std::hint::black_box(x);
    }
    assert_ne!(x, 0);
    println!("observed_component={} guest_utc_ns={} {}", marker(), first, utc_ns());
}
