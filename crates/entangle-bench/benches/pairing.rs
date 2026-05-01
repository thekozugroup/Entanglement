use criterion::{criterion_group, criterion_main, Criterion};
use entangle_pairing::PairingCode;

fn bench_pairing_code_generate(c: &mut Criterion) {
    let mut group = c.benchmark_group("pairing");
    group.bench_function("code_generate_100k", |b| {
        b.iter(|| {
            for _ in 0..100_000u32 {
                let _ = std::hint::black_box(PairingCode::generate());
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_pairing_code_generate);
criterion_main!(benches);
