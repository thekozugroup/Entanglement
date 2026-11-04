//! [`MetricRegistry`]: loading, verifying and running signed metric
//! components (spec §7.5 Rules 1–2).
//!
//! The metric components here are hand-written WAT components implementing
//! `entangle:integrity/metric@0.1.0`, so the tests need no wasm toolchain and
//! the guest's behaviour is visible in the source.

use std::sync::Arc;

use entangle_runtime::{IntegrityError, MetricRegistry};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use parking_lot::RwLock;

/// A metric component whose `compare` body is `body` (a core-wasm expression
/// over `$la` / `$lb`, the two list lengths, producing an `f64`).
fn wat_metric(body: &str) -> Vec<u8> {
    let wat = format!(
        r#"(component
  (core module $m
    (memory (export "memory") 1)
    (global $bump (mut i32) (i32.const 1024))
    (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
      (local $p i32) (local $end i32)
      (local.set $p
        (i32.and
          (i32.add (global.get $bump) (i32.sub (local.get 2) (i32.const 1)))
          (i32.sub (i32.const 0) (local.get 2))))
      (local.set $end (i32.add (local.get $p) (local.get 3)))
      (if (i32.gt_u (local.get $end) (i32.mul (memory.size) (i32.const 65536)))
        (then
          (if (i32.lt_s
                (memory.grow
                  (i32.add
                    (i32.div_u
                      (i32.sub (local.get $end) (i32.mul (memory.size) (i32.const 65536)))
                      (i32.const 65536))
                    (i32.const 1)))
                (i32.const 0))
            (then unreachable))))
      (global.set $bump (local.get $end))
      (local.get $p))
    (func (export "compare") (param $pa i32) (param $la i32) (param $pb i32) (param $lb i32) (result f64)
      {body}))
  (core instance $i (instantiate $m))
  (func $compare (param "a" (list u8)) (param "b" (list u8)) (result f64)
    (canon lift (core func $i "compare") (memory $i "memory") (realloc (func $i "cabi_realloc"))))
  (instance $metric (export "compare" (func $compare)))
  (export "entangle:integrity/metric@0.1.0" (instance $metric)))"#
    );
    wat::parse_str(wat).expect("metric WAT must assemble")
}

/// `|len(a) - len(b)|`.
const LEN_DIFF: &str =
    "(f64.abs (f64.sub (f64.convert_i32_u (local.get $la)) (f64.convert_i32_u (local.get $lb))))";

fn trust(kp: &IdentityKeyPair) -> TrustEntry {
    TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "metric-publisher".into(),
        added_at: 0,
        note: String::new(),
    }
}

fn registry_trusting(kp: &IdentityKeyPair) -> (MetricRegistry, Arc<RwLock<Keyring>>) {
    let mut kr = Keyring::new();
    kr.add(trust(kp));
    let kr = Arc::new(RwLock::new(kr));
    (MetricRegistry::new(Arc::clone(&kr), "submitter"), kr)
}

fn manifest(kp: &IdentityKeyPair, name: &str, tier: u8, extra: &str) -> String {
    format!(
        "[plugin]\nid = \"{}/{name}@0.1.0\"\nversion = \"0.1.0\"\ntier = {tier}\nruntime = \"wasm\"\n{extra}",
        kp.fingerprint_hex()
    )
}

/// Write a signed package into a fresh tempdir.
fn package(kp: &IdentityKeyPair, wasm: &[u8], manifest: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("entangle.toml"), manifest).unwrap();
    std::fs::write(dir.path().join("plugin.wasm"), wasm).unwrap();
    let bundle = sign_artifact(wasm, manifest.as_bytes(), kp);
    std::fs::write(
        dir.path().join("plugin.wasm.sig"),
        toml::to_string(&bundle).unwrap(),
    )
    .unwrap();
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_metric_loads_pins_its_identity_and_compares() {
    let kp = IdentityKeyPair::generate();
    let (registry, _) = registry_trusting(&kp);
    let wasm = wat_metric(LEN_DIFF);
    let dir = package(&kp, &wasm, &manifest(&kp, "len-diff", 2, ""));

    let r = registry
        .load_from_dir(dir.path())
        .expect("signed metric loads");
    assert_eq!(r.plugin.name, "len-diff");
    assert_eq!(r.plugin.publisher, kp.fingerprint_hex());
    assert_eq!(r.publisher_key, *kp.public().as_bytes());
    assert_eq!(r.artifact_blake3, *blake3::hash(&wasm).as_bytes());
    assert!(r.is_self_consistent());
    assert!(registry.contains(&r));
    assert_eq!(registry.find_by_plugin(&r.plugin), Some(r.clone()));
    assert_eq!(registry.list(), vec![r.clone()]);

    // Loading is not instantiating.
    assert_eq!(registry.instantiations(&r), 0);

    let d = registry.compare(&r, b"abcdef", b"abc").await.unwrap();
    assert_eq!(d, 3.0);
    assert_eq!(registry.instantiations(&r), 1);
    assert_eq!(registry.total_instantiations(), 1);

    // Idempotent reload.
    assert_eq!(registry.load_from_dir(dir.path()).unwrap(), r);
    assert_eq!(registry.list().len(), 1);
}

/// §7.5 Rule 2: a metric signed by a key the submitter does not trust is
/// refused at load, and a reference to one is refused by the trust check.
#[tokio::test(flavor = "multi_thread")]
async fn a_metric_from_an_untrusted_publisher_is_refused() {
    let trusted = IdentityKeyPair::generate();
    let stranger = IdentityKeyPair::generate();
    let (registry, _) = registry_trusting(&trusted);
    let wasm = wat_metric(LEN_DIFF);
    let dir = package(&stranger, &wasm, &manifest(&stranger, "len-diff", 2, ""));

    let err = registry.load_from_dir(dir.path()).unwrap_err();
    assert!(
        matches!(err, IntegrityError::MetricNotInKeyring { ref fingerprint, .. }
            if *fingerprint == stranger.fingerprint_hex()),
        "{err}"
    );
    assert!(err.to_string().contains("ENTANGLE-E0307"), "{err}");

    let forged = entangle_types::task::MetricRef {
        plugin: format!("{}/len-diff@0.1.0", stranger.fingerprint_hex())
            .parse()
            .unwrap(),
        publisher_key: *stranger.public().as_bytes(),
        artifact_blake3: *blake3::hash(&wasm).as_bytes(),
    };
    assert!(matches!(
        registry.check_trusted(&forged),
        Err(IntegrityError::MetricNotInKeyring { .. })
    ));
    assert!(matches!(
        registry.compare(&forged, b"a", b"b").await,
        Err(IntegrityError::MetricNotInKeyring { .. })
    ));
    assert_eq!(registry.total_instantiations(), 0);
}

/// A reference that names a trusted publisher in its id but carries another
/// key is inconsistent — the keyring check never even gets consulted.
#[test]
fn an_inconsistent_reference_is_refused() {
    let kp = IdentityKeyPair::generate();
    let other = IdentityKeyPair::generate();
    let (registry, _) = registry_trusting(&kp);
    let r = entangle_types::task::MetricRef {
        plugin: format!("{}/m@0.1.0", kp.fingerprint_hex()).parse().unwrap(),
        publisher_key: *other.public().as_bytes(),
        artifact_blake3: [0; 32],
    };
    let err = registry.check_trusted(&r).unwrap_err();
    assert!(
        matches!(err, IntegrityError::MetricRefInconsistent { .. }),
        "{err}"
    );
}

/// Removing the publisher key after load stops the metric being used.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_the_publisher_key_disables_a_loaded_metric() {
    let kp = IdentityKeyPair::generate();
    let (registry, keyring) = registry_trusting(&kp);
    let dir = package(
        &kp,
        &wat_metric(LEN_DIFF),
        &manifest(&kp, "len-diff", 2, ""),
    );
    let r = registry.load_from_dir(dir.path()).unwrap();

    keyring.write().remove(&kp.fingerprint());
    assert!(matches!(
        registry.compare(&r, b"a", b"b").await,
        Err(IntegrityError::MetricNotInKeyring { .. })
    ));
    assert_eq!(
        registry.instantiations(&r),
        0,
        "refused before instantiation"
    );
}

/// Metrics run at tier 2 with no capabilities; a package asking for more is
/// refused before it is compiled.
#[test]
fn a_metric_asking_for_more_than_tier_2_is_refused() {
    let kp = IdentityKeyPair::generate();
    let (registry, _) = registry_trusting(&kp);
    let wasm = wat_metric(LEN_DIFF);

    let tier3 = package(&kp, &wasm, &manifest(&kp, "greedy", 3, ""));
    let err = registry.load_from_dir(tier3.path()).unwrap_err();
    assert!(matches!(err, IntegrityError::MetricLoad { .. }), "{err}");
    assert!(err.to_string().contains("tier 2"), "{err}");

    let with_caps = package(
        &kp,
        &wasm,
        &manifest(
            &kp,
            "greedy",
            3,
            "\n[capabilities]\n\"net.wan\" = { hosts = [\"api.example.com:443\"] }\n",
        ),
    );
    assert!(matches!(
        registry.load_from_dir(with_caps.path()),
        Err(IntegrityError::MetricLoad { .. })
    ));
    assert!(registry.list().is_empty());
}

/// Editing the manifest after signing breaks the signature (it covers the
/// manifest bytes), so the load fails.
#[test]
fn a_tampered_metric_package_is_refused() {
    let kp = IdentityKeyPair::generate();
    let (registry, _) = registry_trusting(&kp);
    let dir = package(
        &kp,
        &wat_metric(LEN_DIFF),
        &manifest(&kp, "len-diff", 1, ""),
    );
    std::fs::write(
        dir.path().join("entangle.toml"),
        manifest(&kp, "len-diff", 2, "description = \"edited\"\n"),
    )
    .unwrap();
    let err = registry.load_from_dir(dir.path()).unwrap_err();
    assert!(matches!(err, IntegrityError::MetricLoad { .. }), "{err}");
    assert!(err.to_string().contains("E0104"), "{err}");
}

/// An ordinary `run` plugin is not a metric component.
#[test]
fn a_plugin_component_is_not_a_metric() {
    let kp = IdentityKeyPair::generate();
    let (registry, _) = registry_trusting(&kp);
    let hello = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-host/tests/fixtures/hello-pong.wasm"
    ))
    .unwrap();
    let dir = package(&kp, &hello, &manifest(&kp, "hello", 1, ""));
    let err = registry.load_from_dir(dir.path()).unwrap_err();
    assert!(
        err.to_string()
            .contains("not an entangle:integrity/metric component"),
        "{err}"
    );
}

/// The metric contract: NaN and negative distances are violations, `+inf` is
/// a legitimate "incomparable".
#[tokio::test(flavor = "multi_thread")]
async fn the_metric_contract_is_enforced_on_the_result() {
    let kp = IdentityKeyPair::generate();
    let (registry, _) = registry_trusting(&kp);

    let cases: [(&str, &str, Option<f64>); 3] = [
        ("nan", "(f64.div (f64.const 0) (f64.const 0))", None),
        ("negative", "(f64.const -0.5)", None),
        ("infinite", "(f64.const inf)", Some(f64::INFINITY)),
    ];
    for (name, body, want) in cases {
        let dir = package(&kp, &wat_metric(body), &manifest(&kp, name, 2, ""));
        let r = registry.load_from_dir(dir.path()).unwrap();
        let got = registry.compare(&r, b"a", b"b").await;
        match want {
            Some(v) => assert_eq!(got.unwrap(), v, "{name}"),
            None => {
                let err = got.unwrap_err();
                assert!(
                    matches!(err, IntegrityError::MetricContractViolation { .. }),
                    "{name}: {err}"
                );
                assert!(err.to_string().contains("ENTANGLE-E0312"), "{err}");
            }
        }
    }
}

/// A guest that traps surfaces as a typed metric failure, not a panic.
#[tokio::test(flavor = "multi_thread")]
async fn a_trapping_metric_is_a_typed_failure() {
    let kp = IdentityKeyPair::generate();
    let (registry, _) = registry_trusting(&kp);
    let dir = package(
        &kp,
        &wat_metric("unreachable"),
        &manifest(&kp, "trap", 2, ""),
    );
    let r = registry.load_from_dir(dir.path()).unwrap();
    let err = registry.compare(&r, b"a", b"b").await.unwrap_err();
    assert!(matches!(err, IntegrityError::MetricFailed { .. }), "{err}");
    assert_eq!(registry.instantiations(&r), 1);
}
