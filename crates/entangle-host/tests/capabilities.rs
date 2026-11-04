//! Capability grants realised for wasm plugins, driven through the
//! `caps-probe` fixture (source: `fixtures-src/caps-probe/`).
//!
//! Every test registers a manifest with a real [`Broker`], resolves its
//! standing grants the way the kernel does at load
//! ([`Broker::grant_declared`]), and runs the probe with a script of
//! filesystem, socket, DNS and `capability.fetch` steps. The probe answers
//! one line per step: `ok[:detail]` or `err:<kind>:<message>`.
//!
//! # Loopback listeners
//! The production rules never let a network grant reach loopback (see
//! `entangle_host::net`). Tests that need a reachable "LAN" or "public" host
//! therefore install the documented test hook
//! [`CapabilityContext::with_address_classifier`], which only re-labels
//! specific loopback addresses (`127.0.0.1` as LAN, `127.0.0.2` as public);
//! the grant rules themselves are the production ones, and
//! [`loopback_is_never_reachable_under_production_rules`] checks that without
//! the hook the same grant reaches nothing on loopback.

use entangle_broker::{AuditEvent, Broker, BrokerPolicy, CapabilityPattern};
use entangle_host::net::{classify, AddrClass, NetRules, Via, WanTarget};
use entangle_host::{CapabilityContext, HostEngine, HostError, LoadedPlugin};
use entangle_manifest::{schema::Manifest, validate::validate, ValidatedManifest};
use entangle_observability::catalog::names;
use entangle_observability::Registry;
use entangle_types::capability::{CapabilityKind, ShareMode};
use entangle_types::plugin_id::PluginId;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

const PROBE: &[u8] = include_bytes!("fixtures/caps-probe.wasm");
const PUB: &str = "aabbccddeeff00112233445566778899";
const SECRET: &str = "top-secret-outside-the-sandbox";

/// Test classifier: `127.0.0.1` stands in for a LAN host, `127.0.0.2` for a
/// public one; every other address is classified as in production.
fn lan_and_public_on_loopback(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) if v4 == Ipv4Addr::new(127, 0, 0, 1) => AddrClass::Lan,
        IpAddr::V4(v4) if v4 == Ipv4Addr::new(127, 0, 0, 2) => AddrClass::Wan,
        other => classify(other),
    }
}

/// Test classifier: `127.0.0.1` stands in for a public host (so the name
/// `localhost` can be an allowlisted WAN host).
fn public_on_loopback(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) if v4.is_loopback() => AddrClass::Wan,
        other => classify(other),
    }
}

/// Test classifier: every address is a LAN address — loopback included, so
/// a `127.0.0.1` listener stands in for a LAN host.
fn lan_everywhere(_: IpAddr) -> AddrClass {
    AddrClass::Lan
}

/// One of this host's own non-loopback addresses, if it has one: the source
/// address the kernel picks to reach a public address (a UDP `connect` sends
/// nothing).
fn own_address() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:53").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// A name no real resolver answers (`.test` is reserved, RFC 2606).
const SVC: &str = "svc.entangle.test";

/// Test resolver: [`SVC`] is `127.0.0.1` (a stand-in public host under
/// [`public_on_loopback`]); every other name is unknown. The system
/// resolver used by the guest's own lookups knows nothing of [`SVC`].
fn svc_on_loopback(
    name: String,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<IpAddr>>> + Send>> {
    Box::pin(async move {
        if name == SVC {
            Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, name))
        }
    })
}

fn manifest(name: &str, tier: u8, caps: &str) -> ValidatedManifest {
    let text = format!(
        r#"
[plugin]
id = "{PUB}/{name}@0.1.0"
version = "0.1.0"
tier = {tier}
runtime = "wasm"

[capabilities]
{caps}
"#
    );
    let raw: Manifest = toml::from_str(&text).expect("toml");
    validate(raw).expect("valid manifest")
}

struct Harness {
    engine: HostEngine,
    broker: Arc<Broker>,
    registry: Registry,
    tmp: tempfile::TempDir,
    id: PluginId,
    plugin: LoadedPlugin,
}

struct Setup<'a> {
    name: &'a str,
    tier: u8,
    caps: &'a str,
    deny: &'a [&'a str],
    classify: Option<fn(IpAddr) -> AddrClass>,
    resolver: Option<entangle_host::capability::Resolver>,
    /// Extra (already validated) capabilities appended to the manifest, for
    /// kinds a wasm manifest cannot declare (tier-4 `storage.share`). The
    /// manifest's tiers are raised to what they imply, as the broker
    /// refuses a capability above the manifest's tier (§4.3).
    extra: Vec<CapabilityKind>,
    storage_root: bool,
}

impl<'a> Setup<'a> {
    fn new(name: &'a str, caps: &'a str) -> Self {
        Self {
            name,
            tier: 3,
            caps,
            deny: &[],
            classify: None,
            resolver: None,
            extra: Vec::new(),
            storage_root: true,
        }
    }

    fn harness(self) -> Harness {
        let registry = Registry::new();
        let policy = BrokerPolicy {
            denied_capabilities: self
                .deny
                .iter()
                .map(|p| p.parse::<CapabilityPattern>().expect("pattern"))
                .collect(),
            ..Default::default()
        };
        let broker = Arc::new(Broker::new(policy).with_metrics(registry.clone()));
        let mut m = manifest(self.name, self.tier, self.caps);
        m.capabilities.extend(self.extra);
        let implied = m.capabilities.iter().map(|c| c.min_tier()).max();
        if let Some(t) = implied.filter(|t| *t > m.declared_tier) {
            m.declared_tier = t;
            m.implied_tier = t;
            m.effective_tier = t;
        }
        let id = m.plugin_id.clone();
        let tier = m.effective_tier;
        broker.register_plugin(m).expect("register");
        // What the kernel does at load: resolve the standing grants.
        broker.grant_declared(&id).expect("resolve");

        let tmp = tempfile::tempdir().expect("tempdir");
        let mut ctx = CapabilityContext::new(Arc::clone(&broker));
        if self.storage_root {
            ctx = ctx.with_storage_root(tmp.path().join("data"));
        }
        if let Some(c) = self.classify {
            ctx = ctx.with_address_classifier(c);
        }
        if let Some(r) = self.resolver {
            ctx = ctx.with_resolver(r);
        }
        let engine = HostEngine::new().expect("engine");
        let plugin = LoadedPlugin::from_bytes(&engine, PROBE, id.clone(), tier)
            .expect("compile")
            .with_capabilities(ctx);
        Harness {
            engine,
            broker,
            registry,
            tmp,
            id,
            plugin,
        }
    }
}

impl Harness {
    /// Run the probe with one command per line; one result per command.
    async fn run(&self, script: &str) -> Vec<String> {
        run_plugin(&self.engine, &self.plugin, script).await
    }

    /// The plugin's private data directory on the host.
    fn data_dir(&self) -> PathBuf {
        canonical_root(self.tmp.path())
            .join("data/plugins")
            .join(PUB)
            .join(&self.id.name)
    }

    fn grants(&self, family: &str) -> Option<f64> {
        self.registry
            .value(names::CAPABILITY_GRANTS, &[("capability", family)])
    }

    fn denials(&self, family: &str, reason: &str) -> Option<f64> {
        self.registry.value(
            names::CAPABILITY_DENIALS,
            &[("capability", family), ("reason", reason)],
        )
    }
}

fn canonical_root(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).expect("canonical tempdir")
}

async fn run_plugin(engine: &HostEngine, plugin: &LoadedPlugin, script: &str) -> Vec<String> {
    let out = plugin
        .run_one_shot(engine, script.as_bytes(), 30_000)
        .await
        .expect("probe runs");
    let text = String::from_utf8(out.output).expect("utf-8 output");
    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
    // Shown by the test harness only when a test fails (or with --nocapture).
    for (step, result) in script.lines().filter(|l| !l.trim().is_empty()).zip(&lines) {
        eprintln!("  {step}  →  {result}");
    }
    let steps = script.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(
        lines.len(),
        steps,
        "one result per step:\n{script}\n---\n{text}"
    );
    lines
}

/// Assert each result against a prefix, with the whole transcript on failure.
fn expect(script: &str, got: &[String], want: &[&str]) {
    assert_eq!(got.len(), want.len());
    let steps: Vec<&str> = script.lines().filter(|l| !l.trim().is_empty()).collect();
    for ((step, g), w) in steps.iter().zip(got).zip(want) {
        assert!(
            g.starts_with(w),
            "step `{step}`: expected `{w}…`, got `{g}`\nfull transcript:\n{}",
            steps
                .iter()
                .zip(got)
                .map(|(s, g)| format!("  {s}  →  {g}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// A TCP listener that greets every connection with `greeting` and counts
/// accepted connections.
struct Listener {
    addr: std::net::SocketAddr,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
}

async fn listener(ip: &str, greeting: &'static str) -> Listener {
    let l = tokio::net::TcpListener::bind((ip, 0)).await.expect("bind");
    let addr = l.local_addr().unwrap();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = s.write_all(greeting.as_bytes()).await;
            let _ = s.shutdown().await;
        }
    });
    Listener { addr, accepted }
}

impl Listener {
    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// ── no grants ──────────────────────────────────────────────────────────────

/// Without grants there is no filesystem, no socket, no DNS and every fetch
/// is refused — both with no broker at all and with a broker for a plugin
/// that declares nothing.
#[tokio::test(flavor = "multi_thread")]
async fn without_grants_everything_is_denied() {
    let lan = listener("127.0.0.1", "lan").await;
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let script = format!(
        "write /data/x hello\n\
         read /etc/passwd\n\
         ls /\n\
         connect {lan}\n\
         connect 8.8.8.8:53\n\
         udp {udp}\n\
         resolve localhost\n\
         listen 0.0.0.0:0\n\
         fetch compute-cpu\n\
         fetch storage-local\n",
        lan = lan.addr,
        udp = udp.local_addr().unwrap(),
    );
    let want = [
        "err:",
        "err:",
        "err:",
        "err:",
        "err:",
        "err:",
        "err:",
        "err:",
        "err:not-granted:",
        "err:not-granted:",
    ];

    // No capability context at all.
    let engine = HostEngine::new().unwrap();
    let id: PluginId = format!("{PUB}/bare@0.1.0").parse().unwrap();
    let bare = LoadedPlugin::from_bytes(&engine, PROBE, id, entangle_types::tier::Tier::Networked)
        .unwrap();
    let got = run_plugin(&engine, &bare, &script).await;
    expect(&script, &got, &want);

    // A broker, a storage root and a test classifier that would make the
    // listener a LAN host — but nothing declared, so nothing granted.
    let h = Setup {
        classify: Some(lan_and_public_on_loopback),
        ..Setup::new("nothing", "")
    }
    .harness();
    let got = h.run(&script).await;
    expect(&script, &got, &want);
    assert!(
        got[8].contains("ENTANGLE-E0120") || got[8].contains("not declared"),
        "{}",
        got[8]
    );

    assert_eq!(lan.accepted(), 0, "no connection may reach the listener");
    let mut buf = [0u8; 16];
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            udp.recv_from(&mut buf)
        )
        .await
        .is_err(),
        "no datagram may reach the UDP socket"
    );
    assert!(
        !h.data_dir().exists(),
        "no storage grant, no data directory"
    );
    // The refused fetches were broker decisions: audited and counted.
    assert_eq!(h.denials("compute.cpu", "not_declared"), Some(1.0));
    assert_eq!(h.denials("storage.local", "not_declared"), Some(1.0));
}

// ── storage ────────────────────────────────────────────────────────────────

/// `storage.local` (rw): `/data` is the plugin's private 0700 directory,
/// and no path — absolute, `..`, or a symlink planted by the guest or the
/// host — leaves it.
#[tokio::test(flavor = "multi_thread")]
async fn storage_local_rw_works_and_every_escape_fails() {
    let h = Setup {
        tier: 1,
        ..Setup::new("storage-rw", r#""storage.local" = { mode = "rw" }"#)
    }
    .harness();

    // Secrets next to and above the data directory, and a directory outside.
    let root = canonical_root(h.tmp.path());
    std::fs::write(root.join("secret.txt"), SECRET).unwrap();
    let outside = root.join("outside");
    std::fs::create_dir(&outside).unwrap();

    let script = "write /data/note.txt hello wasm\n\
                  read /data/note.txt\n\
                  mkdir /data/sub\n\
                  write /data/sub/a.txt nested\n\
                  ls /data\n\
                  symlink note.txt /data/alias\n\
                  read /data/alias\n";
    let got = h.run(script).await;
    expect(
        script,
        &got,
        &[
            "ok",
            "ok:hello wasm",
            "ok",
            "ok",
            "ok:note.txt,sub",
            "ok",
            "ok:hello wasm",
        ],
    );

    let data = h.data_dir();
    assert_eq!(
        std::fs::read_to_string(data.join("note.txt")).unwrap(),
        "hello wasm"
    );
    assert_eq!(
        std::fs::read_to_string(data.join("sub/a.txt")).unwrap(),
        "nested"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for d in [&data, &data.parent().unwrap().to_path_buf()] {
            let mode = std::fs::metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", d.display());
        }
    }

    // Symlinks planted by the host, pointing outside.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.join("secret.txt"), data.join("host-abs")).unwrap();
        std::os::unix::fs::symlink("../../../../secret.txt", data.join("host-rel")).unwrap();
        std::os::unix::fs::symlink(&outside, data.join("host-dir")).unwrap();
    }

    let secret = root.join("secret.txt");
    let script = format!(
        "read {secret}\n\
         read /data/../secret.txt\n\
         read /data/../../../../secret.txt\n\
         read ../secret.txt\n\
         read secret.txt\n\
         ls /data/..\n\
         ls /\n\
         symlink {secret} /data/guest-abs\n\
         read /data/guest-abs\n\
         symlink ../../../../secret.txt /data/guest-rel\n\
         read /data/guest-rel\n\
         read /data/host-abs\n\
         read /data/host-rel\n\
         ls /data/host-dir\n\
         write /data/host-dir/pwned x\n\
         write /data/host-rel clobber\n\
         write {outside}/pwned x\n",
        secret = secret.display(),
        outside = outside.display(),
    );
    let got = h.run(&script).await;
    // Creating a symlink is allowed or refused depending on its target;
    // what matters is that nothing outside `/data` is ever read or written.
    let steps: Vec<&str> = script.lines().collect();
    for (step, result) in steps.iter().zip(&got) {
        if step.starts_with("symlink ") {
            continue;
        }
        assert!(
            result.starts_with("err:"),
            "`{step}` must fail, got `{result}`"
        );
        assert!(
            !result.contains(SECRET),
            "`{step}` leaked the secret: {result}"
        );
    }
    assert!(!outside.join("pwned").exists());
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), SECRET);
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}

/// `storage.local { mode = "ro" }`: the directory is readable, nothing in it
/// can be created, changed or removed.
#[tokio::test(flavor = "multi_thread")]
async fn storage_local_ro_rejects_writes() {
    let h = Setup::new("storage-ro", r#""storage.local" = { mode = "ro" }"#).harness();
    // Realising creates the directory; seed it from the host.
    let grants = h.plugin.realise_capabilities().await.unwrap();
    assert_eq!(grants.preopens.len(), 1);
    assert!(!grants.preopens[0].writable);
    std::fs::write(h.data_dir().join("seed.txt"), "seeded").unwrap();

    let script = "read /data/seed.txt\n\
                  ls /data\n\
                  write /data/seed.txt overwritten\n\
                  write /data/new.txt x\n\
                  mkdir /data/d\n\
                  symlink seed.txt /data/alias\n";
    let got = h.run(script).await;
    expect(
        script,
        &got,
        &["ok:seeded", "ok:seed.txt", "err:", "err:", "err:", "err:"],
    );
    assert_eq!(
        std::fs::read_to_string(h.data_dir().join("seed.txt")).unwrap(),
        "seeded"
    );
    let names: Vec<_> = std::fs::read_dir(h.data_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["seed.txt"]);
}

/// `storage.share.<n>` realises `/shares/<n>` (read-only for `ro`), and
/// `rw-scoped` maps to the plugin's own subdirectory of the share. Wasm
/// manifests cannot declare shares (tier 4); the grants are injected here to
/// exercise the host mapping the native runtime shares.
#[tokio::test(flavor = "multi_thread")]
async fn storage_share_grants_preopen_the_named_share() {
    let h = Setup {
        extra: vec![
            CapabilityKind::StorageShare {
                name: "photos".into(),
                mode: ShareMode::Ro,
            },
            CapabilityKind::StorageShare {
                name: "inbox".into(),
                mode: ShareMode::RwScoped,
            },
        ],
        ..Setup::new("sharer", "")
    }
    .harness();
    let grants = h.plugin.realise_capabilities().await.unwrap();
    let root = canonical_root(h.tmp.path()).join("data");
    let mut pre: Vec<_> = grants
        .preopens
        .iter()
        .map(|p| (p.guest.clone(), p.host.clone(), p.writable))
        .collect();
    pre.sort();
    assert_eq!(
        pre,
        vec![
            (
                "/shares/inbox".to_owned(),
                root.join("shares/inbox").join(PUB).join("sharer"),
                true
            ),
            (
                "/shares/photos".to_owned(),
                root.join("shares/photos"),
                false
            ),
        ]
    );
    std::fs::write(root.join("shares/photos/pic.txt"), "pixels").unwrap();

    let script = "read /shares/photos/pic.txt\n\
                  write /shares/photos/new.txt x\n\
                  write /shares/inbox/mine.txt mine\n\
                  read /shares/inbox/../../photos/pic.txt\n\
                  ls /shares\n";
    let got = h.run(script).await;
    expect(script, &got, &["ok:pixels", "err:", "ok", "err:", "err:"]);
    assert_eq!(
        std::fs::read_to_string(root.join("shares/inbox").join(PUB).join("sharer/mine.txt"))
            .unwrap(),
        "mine"
    );
}

/// A storage grant with no storage root, or whose directory is a symlink
/// planted on the host, is refused when realised instead of preopening
/// something else.
#[tokio::test(flavor = "multi_thread")]
async fn unrealisable_storage_grants_fail_closed() {
    let h = Setup {
        storage_root: false,
        ..Setup::new("no-root", r#""storage.local" = {}"#)
    }
    .harness();
    let err = h.plugin.realise_capabilities().await.unwrap_err();
    assert!(matches!(err, HostError::NoStorageRoot { .. }), "{err}");
    assert!(err.to_string().starts_with("ENTANGLE-E0508"), "{err}");
    // An invocation fails the same way rather than running without it.
    let err = h
        .plugin
        .run_one_shot(&h.engine, b"info\n", 30_000)
        .await
        .unwrap_err();
    assert!(err.to_string().starts_with("ENTANGLE-E0508"), "{err}");

    #[cfg(unix)]
    {
        let h = Setup::new("linked", r#""storage.local" = {}"#).harness();
        let root = canonical_root(h.tmp.path());
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(h.data_dir().parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, h.data_dir()).unwrap();
        let err = h.plugin.realise_capabilities().await.unwrap_err();
        assert!(matches!(err, HostError::StorageScope { .. }), "{err}");
        assert!(err.to_string().contains("symbolic link"), "{err}");
    }
}

// ── network ────────────────────────────────────────────────────────────────

/// `net.lan` reaches a LAN host (TCP and UDP), but not a public address;
/// it resolves no names (LAN hosts are reached by address, see
/// `name_lookups_answer_only_allowlisted_names_from_the_pin`); plugins never
/// listen.
#[tokio::test(flavor = "multi_thread")]
async fn net_lan_allows_lan_hosts_but_not_public_ones() {
    let lan = listener("127.0.0.1", "hello-lan").await;
    let public = listener("127.0.0.2", "hello-public").await;
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let h = Setup {
        classify: Some(lan_and_public_on_loopback),
        ..Setup::new("lan", r#""net.lan" = {}"#)
    }
    .harness();

    let script = format!(
        "connect {lan}\n\
         connect {public}\n\
         connect 8.8.8.8:53\n\
         connect [::1]:{lan_port}\n\
         udp {udp}\n\
         udp 127.0.0.2:{udp_port}\n\
         resolve localhost\n\
         listen 127.0.0.1:0\n\
         listen 0.0.0.0:0\n",
        lan = lan.addr,
        public = public.addr,
        lan_port = lan.addr.port(),
        udp = udp.local_addr().unwrap(),
        udp_port = udp.local_addr().unwrap().port(),
    );
    let got = h.run(&script).await;
    expect(
        &script,
        &got,
        &[
            "ok:hello-lan",
            "err:",
            "err:",
            "err:",
            "ok",
            "err:",
            "err:",
            "err:",
            "err:",
        ],
    );
    assert_eq!(lan.accepted(), 1);
    assert_eq!(public.accepted(), 0);
    let mut buf = [0u8; 16];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), udp.recv_from(&mut buf))
        .await
        .expect("datagram arrives")
        .unwrap();
    assert_eq!(&buf[..n], b"ping");
}

/// Without the test hook, loopback is neither LAN nor WAN: the same grants
/// reach nothing on `127.0.0.0/8` (the daemon's own services).
#[tokio::test(flavor = "multi_thread")]
async fn loopback_is_never_reachable_under_production_rules() {
    let l = listener("127.0.0.1", "daemon").await;
    let caps = format!(
        r#""net.lan" = {{}}
"net.wan" = {{ hosts = ["127.0.0.1:{port}", "localhost"] }}"#,
        port = l.addr.port()
    );
    let h = Setup::new("prod-rules", &caps).harness();
    let script = format!(
        "connect {addr}\n\
         connect localhost:{port}\n\
         connect [::ffff:127.0.0.1]:{port}\n",
        addr = l.addr,
        port = l.addr.port()
    );
    let got = h.run(&script).await;
    expect(&script, &got, &["err:", "err:", "err:"]);
    assert_eq!(l.accepted(), 0);
}

/// Cloud instance-metadata endpoints (which hand out the machine's cloud
/// credentials) sit in link-local and unique-local space but are reachable
/// through no grant; other link-local addresses stay LAN.
#[test]
fn cloud_metadata_endpoints_are_never_reachable() {
    let metadata = [
        "169.254.169.254",
        "169.254.169.253",
        "169.254.169.123",
        "169.254.170.2",
        "169.254.170.23",
        "fd00:ec2::254",
        "fd00:ec2::253",
        "fd00:ec2::123",
        "fd00:ec2::23",
        "::ffff:169.254.169.254",
    ];
    for a in metadata {
        let ip: IpAddr = a.parse().unwrap();
        assert_eq!(classify(ip), AddrClass::Other, "{a}");
        let rules = NetRules {
            lan: true,
            wan: true,
            wan_targets: vec![WanTarget { ip, port: None }],
            ..NetRules::default()
        };
        let to = SocketAddr::new(ip, 80);
        for use_ in [
            wasmtime_wasi::sockets::SocketAddrUse::TcpConnect,
            wasmtime_wasi::sockets::SocketAddrUse::UdpOutgoingDatagram,
        ] {
            assert_eq!(rules.check(to, use_), None, "{a}");
        }
    }
    assert_eq!(classify("169.254.10.10".parse().unwrap()), AddrClass::Lan);
    assert_eq!(classify("fd00:ec2::1:1".parse().unwrap()), AddrClass::Lan);
}

/// A destination that is one of the daemon host's own addresses is
/// reachable through no grant, whatever its address class: a service bound
/// to every interface is not reachable through the host's LAN address any
/// more than through loopback.
#[test]
fn the_hosts_own_addresses_are_never_reachable() {
    let Some(me) = own_address() else {
        eprintln!("skipped: this host has no non-loopback address");
        return;
    };
    let connect = wasmtime_wasi::sockets::SocketAddrUse::TcpConnect;
    let as_lan = NetRules {
        lan: true,
        classify: lan_everywhere,
        ..NetRules::default()
    };
    assert_eq!(
        as_lan.check(SocketAddr::new(me, 8080), connect),
        None,
        "{me}"
    );
    let as_wan = NetRules {
        wan: true,
        wan_targets: vec![WanTarget { ip: me, port: None }],
        classify: |_| AddrClass::Wan,
        ..NetRules::default()
    };
    assert_eq!(
        as_wan.check(SocketAddr::new(me, 8080), connect),
        None,
        "{me}"
    );
    // Another address with the same rules is allowed: only the host's own
    // addresses are refused.
    let other: IpAddr = "198.51.100.7".parse().unwrap();
    assert_ne!(other, me);
    assert_eq!(
        as_lan.check(SocketAddr::new(other, 8080), connect),
        Some(Via::Lan)
    );
}

/// End to end: a `net.lan` plugin cannot reach a service bound to every
/// interface through the host's own address.
#[tokio::test(flavor = "multi_thread")]
async fn net_lan_does_not_reach_the_hosts_own_addresses() {
    let Some(me) = own_address() else {
        eprintln!("skipped: this host has no non-loopback address");
        return;
    };
    let all = listener("0.0.0.0", "hello-all-interfaces").await;
    let h = Setup {
        classify: Some(lan_everywhere),
        ..Setup::new("own-addr", r#""net.lan" = {}"#)
    }
    .harness();
    let port = all.addr.port();
    let script = format!(
        "connect {mine}\n\
         connect 127.0.0.1:{port}\n",
        mine = SocketAddr::new(me, port),
    );
    let got = h.run(&script).await;
    expect(&script, &got, &["err:", "ok:hello-all-interfaces"]);
    assert_eq!(all.accepted(), 1, "only the stand-in LAN host was reached");
}

/// `net.wan` reaches exactly the allowlisted host:port pairs: not another
/// port of the same host, not another public host, not a LAN host.
#[tokio::test(flavor = "multi_thread")]
async fn net_wan_allows_only_the_allowlisted_host_and_port() {
    let allowed = listener("127.0.0.2", "hello-allowed").await;
    let other_port = listener("127.0.0.2", "hello-other-port").await;
    let lan = listener("127.0.0.1", "hello-lan").await;
    let caps = format!(
        r#""net.wan" = {{ hosts = ["127.0.0.2:{}"] }}"#,
        allowed.addr.port()
    );
    let h = Setup {
        classify: Some(lan_and_public_on_loopback),
        ..Setup::new("wan", &caps)
    }
    .harness();
    let script = format!(
        "connect {allowed}\n\
         connect {other}\n\
         connect {lan}\n\
         connect 8.8.8.8:443\n\
         listen 0.0.0.0:0\n",
        allowed = allowed.addr,
        other = other_port.addr,
        lan = lan.addr,
    );
    let got = h.run(&script).await;
    expect(
        &script,
        &got,
        &["ok:hello-allowed", "err:", "err:", "err:", "err:"],
    );
    assert_eq!(allowed.accepted(), 1);
    assert_eq!(other_port.accepted(), 0);
    assert_eq!(lan.accepted(), 0);
}

/// An allowlisted *name* is resolved by the host when the instance is
/// created; the guest may connect to the resulting addresses on the listed
/// port only.
#[tokio::test(flavor = "multi_thread")]
async fn net_wan_hostnames_are_pinned_to_their_resolved_addresses() {
    let allowed = listener("127.0.0.1", "hello-by-name").await;
    let other = listener("127.0.0.1", "hello-other").await;
    let caps = format!(
        r#""net.wan" = {{ hosts = ["localhost:{}"] }}"#,
        allowed.addr.port()
    );
    let h = Setup {
        classify: Some(public_on_loopback),
        ..Setup::new("wan-name", &caps)
    }
    .harness();
    let grants = h.plugin.realise_capabilities().await.unwrap();
    assert!(
        grants
            .net
            .wan_targets
            .iter()
            .any(|t| t.ip == IpAddr::V4(Ipv4Addr::LOCALHOST) && t.port == Some(allowed.addr.port())),
        "{:?}",
        grants.net.wan_targets
    );
    let script = format!(
        "connect localhost:{port}\n\
         connect {other}\n\
         resolve localhost\n",
        port = allowed.addr.port(),
        other = other.addr,
    );
    let got = h.run(&script).await;
    expect(&script, &got, &["ok:hello-by-name", "err:", "ok:"]);
    assert_eq!(other.accepted(), 0);
}

/// The guest's name lookups are answered by the host, from the `net.wan`
/// allowlist pinned when the instance was created: an allowlisted name
/// resolves to exactly the addresses the socket rules accept (even when the
/// system resolver would answer differently, or not at all), and every
/// other name is refused — so no grant lets a guest send arbitrary queries
/// (`<data>.attacker.example`) to upstream resolvers.
#[tokio::test(flavor = "multi_thread")]
async fn name_lookups_answer_only_allowlisted_names_from_the_pin() {
    let svc = listener("127.0.0.1", "hello-svc").await;
    let caps = format!(r#""net.wan" = {{ hosts = ["{SVC}:{}"] }}"#, svc.addr.port());
    let h = Setup {
        classify: Some(public_on_loopback),
        resolver: Some(svc_on_loopback),
        ..Setup::new("wan-dns", &caps)
    }
    .harness();
    let script = format!(
        "resolve {SVC}\n\
         resolve SVC.Entangle.Test.\n\
         connect {SVC}:{port}\n\
         resolve localhost\n\
         resolve exfil-0123abcd.example.com\n",
        port = svc.addr.port()
    );
    let got = h.run(&script).await;
    expect(
        &script,
        &got,
        &[
            "ok:127.0.0.1",
            "ok:127.0.0.1",
            "ok:hello-svc",
            "err:",
            "err:",
        ],
    );
    assert_eq!(got[0], "ok:127.0.0.1", "exactly the pinned address");
    assert_eq!(svc.accepted(), 1);

    // `net.lan` alone resolves no names at all (LAN hosts are reached by
    // address); without the allowlist there is nothing to answer from.
    let h = Setup::new("lan-dns", r#""net.lan" = {}"#).harness();
    let script = format!("resolve localhost\nresolve {SVC}\n");
    let got = h.run(&script).await;
    expect(&script, &got, &["err:", "err:"]);
}

/// Lookups made by [`counting_resolver`].
static COUNTED_LOOKUPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Test resolver: counts its lookups; every name is `127.0.0.1`.
fn counting_resolver(
    _name: String,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<IpAddr>>> + Send>> {
    COUNTED_LOOKUPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Box::pin(async { Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]) })
}

/// Test resolver: every lookup takes 400 ms.
fn slow_resolver(
    _name: String,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<IpAddr>>> + Send>> {
    Box::pin(async {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
    })
}

/// Test resolver: never answers (a stalled upstream resolver).
fn stalled_resolver(
    _name: String,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<IpAddr>>> + Send>> {
    Box::pin(std::future::pending())
}

/// Each distinct allowlisted name is looked up once per instance, however
/// many entries name it (several ports) and however many outstanding
/// `net.wan` grants — standing or fetched by running invocations — the
/// plugin holds.
#[tokio::test(flavor = "multi_thread")]
async fn each_allowlisted_name_is_resolved_once() {
    let h = Setup {
        resolver: Some(counting_resolver),
        ..Setup::new(
            "dedup",
            r#""net.wan" = { hosts = ["a.entangle.test:443", "a.entangle.test:80", "b.entangle.test"] }"#,
        )
    }
    .harness();
    for _ in 0..5 {
        h.broker.grant_by_key(&h.id, "net.wan").unwrap();
    }
    assert_eq!(h.broker.snapshot_grants(&h.id).len(), 6);
    COUNTED_LOOKUPS.store(0, std::sync::atomic::Ordering::SeqCst);
    let grants = h.plugin.realise_capabilities().await.unwrap();
    assert_eq!(
        COUNTED_LOOKUPS.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "one lookup per distinct name"
    );
    let mut names: Vec<_> = grants
        .pinned_names
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["a.entangle.test", "b.entangle.test"]);
    assert_eq!(
        grants.net.wan_targets.len(),
        3,
        "{:?}",
        grants.net.wan_targets
    );
}

/// Allowlisted names are resolved concurrently, and resolution may take at
/// most half the invocation's timeout: a slow resolver delays the guest by
/// one lookup, not one per name, and a stalled one leaves its names
/// unreachable for the invocation instead of using up the whole budget and
/// surfacing as a plugin timeout.
#[tokio::test(flavor = "multi_thread")]
async fn wan_resolution_is_concurrent_and_bounded_by_the_invocation() {
    let caps = r#""net.wan" = { hosts = ["a.entangle.test:443", "b.entangle.test:443", "c.entangle.test:443", "d.entangle.test:443"] }"#;
    let h = Setup {
        resolver: Some(slow_resolver),
        ..Setup::new("slow-dns", caps)
    }
    .harness();
    let started = std::time::Instant::now();
    let out = h
        .plugin
        .run_one_shot(&h.engine, b"resolve a.entangle.test\ninfo\n", 1_000)
        .await
        .expect("four 400 ms lookups fit a 1 s invocation when made together");
    assert!(started.elapsed() < std::time::Duration::from_millis(1_000));
    let text = String::from_utf8(out.output).unwrap();
    assert!(text.starts_with("ok:127.0.0.1\nok:"), "{text}");

    let h = Setup {
        resolver: Some(stalled_resolver),
        ..Setup::new("stalled-dns", caps)
    }
    .harness();
    let started = std::time::Instant::now();
    let out = h
        .plugin
        .run_one_shot(&h.engine, b"resolve a.entangle.test\ninfo\n", 1_000)
        .await
        .expect("a stalled resolver does not time the plugin out");
    assert!(started.elapsed() < std::time::Duration::from_millis(1_000));
    let text = String::from_utf8(out.output).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].starts_with("err:"), "{text}");
    assert!(lines[1].starts_with("ok:"), "{text}");
}

// ── capability.fetch ───────────────────────────────────────────────────────

/// `fetch` returns a handle only for a capability the manifest declares and
/// the broker grants; every decision is audited and counted; handles are
/// released by `release` (idempotently) or when the instance ends. A
/// capability the operator denies is neither fetchable nor realised.
#[tokio::test(flavor = "multi_thread")]
async fn fetch_returns_handles_only_for_granted_capabilities() {
    let lan = listener("127.0.0.1", "hello-lan").await;
    let h = Setup {
        deny: &["net.lan"],
        classify: Some(lan_and_public_on_loopback),
        ..Setup::new(
            "fetcher",
            r#""compute.cpu" = {}
"storage.local" = {}
"net.lan" = {}
"custom.telemetry" = {}"#,
        )
    }
    .harness();
    let standing = h.broker.snapshot_grants(&h.id).len();
    assert_eq!(standing, 3, "net.lan is denied by policy at load");

    let script = format!(
        "fetch compute-cpu\n\
         fetch storage-local\n\
         fetch custom telemetry\n\
         fetch net-lan\n\
         fetch net-wan\n\
         fetch compute-gpu\n\
         fetch storage-share\n\
         fetch storage-share ../etc\n\
         fetch custom\n\
         release 1\n\
         release 1\n\
         release 999\n\
         connect {lan}\n\
         write /data/ok.txt fine\n",
        lan = lan.addr
    );
    let got = h.run(&script).await;
    expect(
        &script,
        &got,
        &[
            "ok:1",
            "ok:2",
            "ok:3",
            "err:not-granted:ENTANGLE-E0124",
            "err:not-granted:ENTANGLE-E0120",
            "err:not-granted:ENTANGLE-E0120",
            "err:invalid-kind:",
            "err:invalid-kind:",
            "err:invalid-kind:",
            "ok",
            "ok",
            "ok",
            "err:",
            "ok",
        ],
    );
    assert_eq!(
        lan.accepted(),
        0,
        "a policy-denied net.lan realises nothing"
    );

    // Handles 2 and 3 were never released: the instance's end released them.
    assert_eq!(h.broker.snapshot_grants(&h.id).len(), standing);

    // Metrics: one standing grant per granted capability, plus one per fetch.
    assert_eq!(h.grants("compute.cpu"), Some(2.0));
    assert_eq!(h.grants("storage.local"), Some(2.0));
    assert_eq!(h.grants("custom"), Some(2.0));
    assert_eq!(h.grants("net.lan"), None);
    assert_eq!(h.denials("net.lan", "operator_policy"), Some(2.0));
    assert_eq!(h.denials("net.wan", "not_declared"), Some(1.0));
    assert_eq!(h.denials("compute.gpu", "not_declared"), Some(1.0));

    // Audit: the fetched grants, the refusals, and exactly one release each.
    let audit = h.broker.audit_log().snapshot();
    let denied: Vec<String> = audit
        .iter()
        .filter_map(|e| match e {
            AuditEvent::CapabilityDenied { capability, .. } => Some(capability.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(denied, ["net.lan", "net.lan", "net.wan", "compute.gpu"]);
    let released = audit
        .iter()
        .filter(|e| matches!(e, AuditEvent::CapabilityReleased { .. }))
        .count();
    assert_eq!(released, 3, "handles 1 (released), 2 and 3 (instance end)");
}

/// §4.6: after `revoke`, `fetch` answers `revoked`, the next instance no
/// longer has the capability realised, and other grants are untouched.
#[tokio::test(flavor = "multi_thread")]
async fn revoked_capabilities_are_refused_and_no_longer_realised() {
    let lan = listener("127.0.0.1", "hello-lan").await;
    let h = Setup {
        classify: Some(lan_and_public_on_loopback),
        ..Setup::new(
            "revokee",
            r#""compute.cpu" = {}
"storage.local" = {}
"net.lan" = {}"#,
        )
    }
    .harness();
    let script = format!(
        "fetch net-lan\n\
         connect {lan}\n\
         fetch storage-local\n\
         write /data/before.txt x\n\
         fetch compute-cpu\n",
        lan = lan.addr
    );
    let got = h.run(&script).await;
    expect(&script, &got, &["ok:", "ok:hello-lan", "ok:", "ok", "ok:"]);

    h.broker.revoke(&h.id, "net.lan").unwrap();
    h.broker.revoke(&h.id, "storage.local").unwrap();

    let got = h.run(&script).await;
    expect(
        &script,
        &got,
        &["err:revoked:", "err:", "err:revoked:", "err:", "ok:"],
    );
    assert_eq!(lan.accepted(), 1);
    assert_eq!(h.denials("net.lan", "revoked"), Some(1.0));
    assert_eq!(h.denials("storage.local", "revoked"), Some(1.0));
    let revoked = h
        .broker
        .audit_log()
        .snapshot()
        .iter()
        .filter(|e| matches!(e, AuditEvent::CapabilityRevoked { .. }))
        .count();
    assert_eq!(revoked, 2);
}

/// §4.6: revoking a network capability stops an invocation that is using it
/// at once. A connection the guest opened before the revocation does not
/// outlive the grant: the invocation is stopped (`ENTANGLE-E0511`), which
/// closes its sockets, instead of running on until it ends.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_net_grant_stops_an_invocation_in_flight() {
    let h = Setup {
        classify: Some(lan_everywhere),
        ..Setup::new("in-flight", r#""net.lan" = {}"#)
    }
    .harness();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let broker = Arc::clone(&h.broker);
    let id = h.id.clone();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = l.accept().await {
            // The guest is connected and waiting for a greeting: revoke the
            // grant its connection rests on, then keep talking.
            broker.revoke(&id, "net.lan").unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let _ = s.write_all(b"after-revocation").await;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
    let script = format!("connect {addr}\nresolve 10.0.0.1\n");
    let started = std::time::Instant::now();
    let err = match h
        .plugin
        .run_one_shot(&h.engine, script.as_bytes(), 30_000)
        .await
    {
        Ok(out) => panic!(
            "the connection outlived the revocation:\n{}",
            String::from_utf8_lossy(&out.output)
        ),
        Err(e) => e,
    };
    assert!(
        matches!(err, HostError::CapabilityRevoked { ref capability } if capability == "net.lan"),
        "{err}"
    );
    assert!(err.to_string().starts_with("ENTANGLE-E0511"), "{err}");
    assert!(err.to_string().contains("net.lan"), "{err}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "stopped at the revocation, not at the end: {:?}",
        started.elapsed()
    );
}

/// The same holds for a guest that never waits on the host (busy in wasm
/// code): the per-invocation epoch check stops it, and a networked
/// invocation still times out as before.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_net_grant_stops_a_busy_networked_invocation() {
    const STRESS: &[u8] = include_bytes!("fixtures/stress.wasm");
    let h = Setup::new("busy", r#""net.lan" = {}"#).harness();
    let plugin = LoadedPlugin::from_bytes(
        &h.engine,
        STRESS,
        h.id.clone(),
        entangle_types::tier::Tier::Networked,
    )
    .unwrap()
    .with_capabilities(h.plugin.capabilities().unwrap().clone());

    let broker = Arc::clone(&h.broker);
    let id = h.id.clone();
    let revoker = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        broker.revoke(&id, "net.lan").unwrap();
    });
    let started = std::time::Instant::now();
    let res = plugin.run_one_shot(&h.engine, b"spin:4000", 30_000).await;
    revoker.await.unwrap();
    let err = match res {
        Ok(_) => panic!("the busy invocation outlived the revocation"),
        Err(e) => e,
    };
    assert!(matches!(err, HostError::CapabilityRevoked { .. }), "{err}");
    assert!(err.to_string().starts_with("ENTANGLE-E0511"), "{err}");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(2_000),
        "{:?}",
        started.elapsed()
    );

    // Without a revocation, the same busy networked invocation times out at
    // its deadline as before.
    let h = Setup::new("busy-timeout", r#""net.lan" = {}"#).harness();
    let plugin = LoadedPlugin::from_bytes(
        &h.engine,
        STRESS,
        h.id.clone(),
        entangle_types::tier::Tier::Networked,
    )
    .unwrap()
    .with_capabilities(h.plugin.capabilities().unwrap().clone());
    let started = std::time::Instant::now();
    let err = plugin
        .run_one_shot(&h.engine, b"spin:4000", 300)
        .await
        .unwrap_err();
    assert!(matches!(err, HostError::Timeout(300)), "{err}");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(2_000),
        "{:?}",
        started.elapsed()
    );
}
