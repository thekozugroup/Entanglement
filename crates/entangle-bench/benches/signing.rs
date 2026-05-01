use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use entangle_signing::{sign_artifact, verify_artifact, IdentityKeyPair, Keyring, TrustEntry};

fn bench_verify(c: &mut Criterion) {
    let kp = IdentityKeyPair::generate();
    let pub_key = kp.public();
    let mut keyring = Keyring::new();
    keyring.add(TrustEntry {
        fingerprint: pub_key.fingerprint(),
        public_key: *pub_key.as_bytes(),
        publisher_name: "bench".into(),
        added_at: 0,
        note: String::new(),
    });

    for size in [1024usize, 1024 * 1024, 16 * 1024 * 1024] {
        let bytes = vec![0u8; size];
        let bundle = sign_artifact(&bytes, &kp);
        let mut group = c.benchmark_group("signing");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("verify_{size}"), |b| {
            b.iter(|| {
                verify_artifact(&bytes, &bundle, &keyring).unwrap();
            });
        });
        group.finish();
    }
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
