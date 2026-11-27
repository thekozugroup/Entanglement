//! Interoperability and trust-boundary checks using real TCP, tar and zstd.
use entangle_oci::{
    registry::{fetch_archive, list_tags, pull, LISTING_DOMAIN, LISTING_SIGNATURE},
    PackageFiles,
};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

fn add(keys: &mut Keyring, key: &IdentityKeyPair) {
    keys.add(TrustEntry {
        public_key: *key.public().as_bytes(),
        fingerprint: key.fingerprint(),
        added_at: 0,
        publisher_name: "fixture".into(),
        note: String::new(),
    });
}

fn package(key: &IdentityKeyPair) -> Vec<(&'static str, Vec<u8>)> {
    let manifest = format!("[plugin]\nid = '{}/example@1.2.3'\nversion = '1.2.3'\ntier = 1\nruntime = 'wasm'\ndescription = 'test'\n[capabilities]\n[build]\nwit_world = 'entangle:plugin/run'\ntarget = 'wasm32-wasip2'\n",key.fingerprint_hex()).into_bytes();
    let wasm = b"sample authenticated bytes".to_vec();
    let sig = toml::to_string(&sign_artifact(&wasm, &manifest, key))
        .unwrap()
        .into_bytes();
    vec![
        ("entangle.toml", manifest),
        ("plugin.wasm", wasm),
        ("plugin.wasm.sig", sig),
        ("rebuild.json", b"{}".to_vec()),
    ]
}
fn archive(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes) in files {
        let mut header = tar::Header::new_ustar();
        header.set_mode(0o644);
        header.set_size(bytes.len() as _);
        header.set_cksum();
        tar.append_data(&mut header, name, &bytes[..]).unwrap();
    }
    zstd::stream::encode_all(&tar.into_inner().unwrap()[..], 1).unwrap()
}

#[test]
fn archive_requires_same_trusted_publisher_on_both_signatures() {
    let author = IdentityKeyPair::generate();
    let mirror = IdentityKeyPair::generate();
    let bytes = archive(&package(&author));
    let mut keys = Keyring::new();
    add(&mut keys, &mirror);
    let check = |key: &IdentityKeyPair, keys: &Keyring| {
        PackageFiles::from_signed_archive(
            &bytes,
            key.sign(&Sha256::digest(&bytes)).as_bytes(),
            keys,
        )
    };
    assert!(check(&author, &keys).is_err());
    assert!(check(&mirror, &keys).is_err());
    add(&mut keys, &author);
    assert!(check(&mirror, &keys).is_err());
    let pkg = check(&author, &keys).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let target = pkg.cache(dir.path()).unwrap();
    assert_eq!(target, pkg.cache(dir.path()).unwrap());
    std::fs::write(target.join("plugin.wasm"), b"changed").unwrap();
    assert!(pkg.cache(dir.path()).is_err());
}

#[test]
fn archive_rejects_duplicates_and_unexpected_files() {
    let key = IdentityKeyPair::generate();
    let mut keys = Keyring::new();
    add(&mut keys, &key);
    for name in ["plugin.wasm", "extra/inert"] {
        let mut files = package(&key);
        files.push((name, vec![]));
        let bytes = archive(&files);
        assert!(PackageFiles::from_signed_archive(
            &bytes,
            key.sign(&Sha256::digest(&bytes)).as_bytes(),
            &keys
        )
        .is_err());
    }
}

type Routes = HashMap<String, (Vec<(String, String)>, Vec<u8>)>;

// Stop accepting requests when the test drops the fixture, including on errors.
struct Server {
    base: String,
    done: std::sync::mpsc::Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn start(routes: Routes) -> Self {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let base = socket.local_addr().unwrap().to_string();
        let (done, rx) = std::sync::mpsc::channel();
        let thread = thread::spawn(move || {
            while rx.try_recv().is_err() {
                let Ok((mut stream, _)) = socket.accept() else {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut line = String::new();
                let mut reader = BufReader::new(&stream);
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                if let Some((headers, bytes)) = routes.get(&path) {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n",
                        bytes.len()
                    )
                    .unwrap();
                    for (k, v) in headers {
                        write!(stream, "{k}: {v}\r\n").unwrap();
                    }
                    stream.write_all(b"\r\n").unwrap();
                    stream.write_all(bytes).unwrap();
                } else {
                    stream
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                        .unwrap();
                }
            }
        });
        Self {
            base,
            done,
            thread: Some(thread),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.done.send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

#[tokio::test]
async fn mirror_listing_verified() {
    let mirror = IdentityKeyPair::generate();
    let body = br#"{"name":"lab/worker","tags":["1.2.3","latest"]}"#.to_vec();
    let signature = mirror.sign(&[LISTING_DOMAIN, &body].concat()).to_hex();
    let mut routes = Routes::new();
    for name in ["lab/worker", "lab/elsewhere"] {
        routes.insert(
            format!("/v2/{name}/tags/list"),
            (
                vec![(LISTING_SIGNATURE.into(), signature.clone())],
                body.clone(),
            ),
        );
    }
    let server = Server::start(routes);
    let repo = format!("oci://{}/lab/worker", server.base);
    let listing = list_tags(&repo, true, &mirror.public()).await.unwrap();
    assert_eq!(listing.tags, ["1.2.3", "latest"]);
    assert_eq!(listing.mirror_fingerprint, mirror.fingerprint_hex());
    assert!(
        list_tags(&repo, true, &IdentityKeyPair::generate().public())
            .await
            .is_err()
    );
    assert!(list_tags(
        &repo.replace("lab/worker", "lab/elsewhere"),
        true,
        &mirror.public()
    )
    .await
    .is_err());
}

#[tokio::test]
async fn oci_and_tarball_yield_same_authenticated_component() {
    let author = IdentityKeyPair::generate();
    let mut keys = Keyring::new();
    add(&mut keys, &author);
    let files = package(&author);
    let mut routes = Routes::new();
    let mut layers = vec![];
    for ((_, bytes), media) in files.iter().zip([
        "application/vnd.entangle.manifest.+toml",
        "application/wasm",
        "application/vnd.entangle.signature.+ed25519",
    ]) {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        layers.push(json!({"mediaType":media,"size":bytes.len(),"digest":digest}));
        routes.insert(format!("/v2/demo/blobs/{digest}"), (vec![], bytes.clone()));
    }
    layers.reverse();
    let config = json!({"mediaType":"application/vnd.oci.empty.v1+json","digest":format!("sha256:{}",hex::encode(Sha256::digest(b"{}"))),"size":2});
    let image = json!({"mediaType":"application/vnd.oci.image.manifest.v1+json","schemaVersion":2,"config":config,"layers":layers});
    let bytes = serde_json::to_vec(&image).unwrap();
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    let wrong_digest = format!("sha256:{}", "0".repeat(64));
    for target in ["stable", &digest, &wrong_digest] {
        routes.insert(
            format!("/v2/demo/manifests/{target}"),
            (vec![], bytes.clone()),
        );
    }
    let mut wrong = image;
    wrong["layers"][0]["size"] = json!(1);
    routes.insert(
        "/v2/demo/manifests/bad-size".into(),
        (vec![], serde_json::to_vec(&wrong).unwrap()),
    );
    let bytes = archive(&files);
    routes.insert(
        "/demo.tar.zst.sig".into(),
        (
            vec![],
            author.sign(&Sha256::digest(&bytes)).as_bytes().to_vec(),
        ),
    );
    routes.insert("/demo.tar.zst".into(), (vec![], bytes));
    let server = Server::start(routes);
    let repo = format!("oci://{}/demo", server.base);
    let tar = fetch_archive(&format!("http://{}/demo.tar.zst", server.base), true, &keys)
        .await
        .unwrap();
    for reference in [format!("{repo}:stable"), format!("{repo}@{digest}")] {
        let pkg = pull(&reference, true, &keys).await.unwrap();
        assert_eq!(
            (pkg.plugin_id, pkg.component),
            (tar.plugin_id.clone(), tar.component.clone())
        );
    }
    assert!(pull(&format!("{repo}@{wrong_digest}"), true, &keys)
        .await
        .is_err());
    assert!(pull(&format!("{repo}:bad-size"), true, &keys)
        .await
        .is_err());
    assert!(pull(&format!("{repo}:stable"), true, &Keyring::new())
        .await
        .is_err());
}

#[cfg(unix)]
#[test]
fn rejects_special_manifest_and_linked_cached_files() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("entangle.toml");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    assert!(PackageFiles::from_directory(dir.path(), &Keyring::new()).is_err());
    let author = IdentityKeyPair::generate();
    let mut keys = Keyring::new();
    add(&mut keys, &author);
    let packed = archive(&package(&author));
    let payload = PackageFiles::from_signed_archive(
        &packed,
        author.sign(&Sha256::digest(&packed)).as_bytes(),
        &keys,
    )
    .unwrap();
    let cache = dir.path().join("cache");
    let path = payload.cache(&cache).unwrap();
    let outside = dir.path().join("external");
    std::fs::rename(&path, &outside).unwrap();
    symlink(&outside, &path).unwrap();
    assert!(payload.cache(&cache).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(outside, &path).unwrap();
    let blob = path.join("plugin.wasm");
    let other = dir.path().join("wasm");
    std::fs::rename(&blob, &other).unwrap();
    symlink(other, blob).unwrap();
    assert!(payload.cache(&cache).is_err());
}

#[test]
fn in_memory_trust_labels_must_match_the_verifying_key() {
    let author = IdentityKeyPair::generate();
    let label = IdentityKeyPair::generate();
    let manifest = b"signed manifest";
    let bytes = b"component";
    let mut bundle = sign_artifact(bytes, manifest, &author);
    bundle.publisher_fingerprint = label.fingerprint();
    let mut keys = Keyring::new();
    keys.add(TrustEntry {
        fingerprint: label.fingerprint(),
        public_key: *author.public().as_bytes(),
        added_at: 0,
        publisher_name: String::new(),
        note: String::new(),
    });
    assert!(entangle_signing::verify_artifact(bytes, manifest, &bundle, &keys).is_err());
}
