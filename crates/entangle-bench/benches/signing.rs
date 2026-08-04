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

    // A representative manifest is signed alongside the artifact (the bundle
    // now covers both, so verification re-hashes the manifest too).
    let manifest = b"[plugin]\nid = \"bench/artifact@0.1.0\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n";
    for size in [1024usize, 1024 * 1024, 16 * 1024 * 1024] {
        let bytes = vec![0u8; size];
        let bundle = sign_artifact(&bytes, manifest, &kp);
        let mut group = c.benchmark_group("signing");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("verify_{size}"), |b| {
            b.iter(|| {
                verify_artifact(&bytes, manifest, &bundle, &keyring).unwrap();
            });
        });
        group.finish();
    }
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
