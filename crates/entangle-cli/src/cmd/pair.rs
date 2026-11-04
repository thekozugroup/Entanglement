//! `entangle pair` — device pairing.
//!
//! Two channels, one protocol (`entangle-pairing`):
//!
//! * **Over the network (default).** One device runs `entangle pair
//!   --responder`: it binds its own QUIC endpoint, announces itself over mDNS
//!   and shows a 6-digit code. The other runs `entangle pair`, picks the
//!   device from a list (or is given `--peer <long-address>`), types the code,
//!   compares fingerprints, and confirms. No daemon is required on either side.
//! * **Copy-paste (`--manual`).** The original flow: three text blobs —
//!   `ENT-REQ-` / `ENT-ACC-` / `ENT-FIN-` — carried between the machines by
//!   hand. It needs no connectivity at all, which is why it is kept: air-gapped
//!   hosts, and networks where neither mDNS nor QUIC can cross.
//!
//! Both channels end the same way: each side stores the other's public key via
//! [`TrustedPeer::new_validated`], which re-derives the peer id from the key
//! and refuses a record where the two do not correspond.
//!
//! Both channels also exchange `mesh.peer` capability tokens (spec §6.3 step
//! 4, [`entangle_pairing::grant`]): each side mints one rooted at its own
//! identity key for the other, sends it inside the exchange, checks the one
//! it receives, and stores it with the peer record (`peers.toml`, mode
//! 0600) next to the revocation ids of the one it issued. Remote tasks and
//! streams to that peer carry an attenuation of the stored token. A token
//! that went out for a pairing that then fails or is not confirmed is
//! revoked locally (`revoked-tokens.toml`), so it stays dead even if that
//! device is put on the allowlist by hand later.
//!
//! # Blob format (manual channel)
//! `ENT-{REQ,ACC,FIN}-<base64url>`, where the payload is the JSON
//! serialisation of the envelope struct. JSON keeps the blobs inspectable.

use std::io::{self, BufRead, IsTerminal, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::Args;
use entangle_pairing::grant;
use entangle_pairing::mesh::{
    dial_and_pair_with_grant, discover_pairing_hosts, parse_node_addr, start_pairing_transport,
    IrohPeer, PairingCandidate, PairingListener, PairingMeshError, PairingTransportExt as _,
    DEFAULT_PAIRING_BIND,
};
use entangle_pairing::net::{HostConfig, PairingNetError, RejectReason};
use entangle_pairing::{
    fingerprint_from_hex, make_code_commit, signing_payload, PairingAccept, PairingFinalize,
    PairingRequest,
};
use entangle_pairing::{PairedPeer, PairingCode, ShortFingerprint, DEFAULT_MAX_ATTEMPTS};
use entangle_peers::{PeerStore, RevocationStore, TrustedPeer, REVOCATIONS_FILE};
use entangle_signing::{IdentityPublicKey, Signature};
use entangle_types::peer_id::PeerId;

use crate::cmd::pairlog::Tried;
use crate::config::entangle_dir;
use crate::identity::ensure_identity;

// ── Expiry ────────────────────────────────────────────────────────────────────

const EXPIRY_SECS: u64 = 5 * 60; // 5 minutes

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── CLI args ──────────────────────────────────────────────────────────────────

/// Pair this device with another using a short-code + fingerprint exchange.
///
/// Run `entangle pair --responder` on one device and `entangle pair` on the
/// other. The responder shows a 6-digit code; type it on the initiator.
#[derive(Args, Debug)]
pub struct PairArgs {
    /// Act as the responder: show a pairing code and wait for the other device.
    #[arg(long)]
    pub responder: bool,

    /// Show a pairing code on this device and wait for the other device to
    /// type it (`entangle pair <code>` there). Same as --responder.
    #[arg(long, conflicts_with = "responder")]
    pub print_code: bool,

    /// Human-readable display name for this device (default: hostname).
    #[arg(long)]
    pub display_name: Option<String>,

    /// Use the copy-paste blob channel instead of the network.
    ///
    /// For air-gapped machines, or networks where mDNS/QUIC cannot cross.
    /// Implied by any of the `--*-file` blob options.
    #[arg(long)]
    pub manual: bool,

    /// (Initiator) Pair with this device instead of browsing: either a
    /// `<pubkey-hex>@<host>:<port>` long address, or a peer id / name prefix
    /// matching one discovered device.
    #[arg(long, value_name = "PEER")]
    pub peer: Option<String>,

    /// The 6-digit code shown on the other device (skips the prompt).
    ///
    /// Spec §6.3 spells the initiator's invocation `entangle pair 734-291`, so
    /// the code is also accepted as a positional argument.
    #[arg(long, value_name = "CODE")]
    pub code: Option<String>,

    /// The 6-digit code, positionally: `entangle pair 734-291`.
    #[arg(value_name = "CODE")]
    pub code_arg: Option<String>,

    /// Do not ask for confirmation before storing the peer.
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// (Responder) Seconds to wait for a device before giving up.
    #[arg(long, value_name = "SECS", default_value_t = 300)]
    pub timeout: u64,

    /// (Responder) Wrong codes tolerated before the session is destroyed.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_ATTEMPTS)]
    pub max_attempts: u32,

    /// (Initiator) Seconds to browse for devices in pairing mode.
    #[arg(long, value_name = "SECS", default_value_t = 4)]
    pub discover_secs: u64,

    /// (Initiator) Write the REQUEST blob to this file instead of stdout.
    #[arg(long, value_name = "PATH")]
    pub emit_request_file: Option<PathBuf>,

    /// (Initiator) Read the ACCEPT blob from this file instead of stdin.
    #[arg(long, value_name = "PATH")]
    pub consume_accept_file: Option<PathBuf>,

    /// (Initiator) Write the FINALIZE blob to this file instead of stdout.
    #[arg(long, value_name = "PATH")]
    pub emit_finalize_file: Option<PathBuf>,

    /// (Responder) Read the REQUEST blob from this file instead of stdin.
    #[arg(long, value_name = "PATH")]
    pub request_file: Option<PathBuf>,

    /// (Responder) Write the ACCEPT blob to this file instead of stdout.
    #[arg(long, value_name = "PATH")]
    pub emit_accept_file: Option<PathBuf>,

    /// (Responder) Read the FINALIZE blob from this file instead of stdin.
    #[arg(long, value_name = "PATH")]
    pub consume_finalize_file: Option<PathBuf>,

    /// Override the peers.toml path (useful in tests).
    #[arg(long, value_name = "PATH", hide = true)]
    pub peers_file: Option<PathBuf>,

    /// Override the identity.key path (useful in tests).
    #[arg(long, value_name = "PATH", hide = true)]
    pub identity_file: Option<PathBuf>,

    /// Bind the pairing endpoint here (default 0.0.0.0:0, a random UDP
    /// port). Fix the port to allow it through a firewall.
    #[arg(long, value_name = "ADDR")]
    pub bind: Option<String>,

    /// Skip mDNS entirely (useful in tests and on locked-down networks).
    #[arg(long, hide = true)]
    pub no_mdns: bool,

    /// Do not draw the QR code next to the pairing code.
    #[arg(long)]
    pub no_qr: bool,
}

impl PairArgs {
    /// True when any copy-paste blob option was given: those only make sense
    /// on the manual channel, so they select it without a redundant `--manual`
    /// (and keep existing scripts working).
    fn uses_blob_files(&self) -> bool {
        self.emit_request_file.is_some()
            || self.consume_accept_file.is_some()
            || self.emit_finalize_file.is_some()
            || self.request_file.is_some()
            || self.emit_accept_file.is_some()
            || self.consume_finalize_file.is_some()
    }

    fn is_manual(&self) -> bool {
        self.manual || self.uses_blob_files()
    }

    /// This device shows the code (`--responder` / `--print-code`).
    fn shows_code(&self) -> bool {
        self.responder || self.print_code
    }

    /// The code the user supplied, from either spelling.
    fn supplied_code(&self) -> Option<&str> {
        self.code.as_deref().or(self.code_arg.as_deref())
    }

    fn bind_addr(&self) -> anyhow::Result<SocketAddr> {
        let raw = self.bind.as_deref().unwrap_or(DEFAULT_PAIRING_BIND);
        raw.parse()
            .with_context(|| format!("--bind must be host:port, got {raw}"))
    }
}

// ── Blob encoding/decoding ────────────────────────────────────────────────────

const PREFIX_REQ: &str = "ENT-REQ-";
const PREFIX_ACC: &str = "ENT-ACC-";
const PREFIX_FIN: &str = "ENT-FIN-";

fn encode_blob<T: serde::Serialize>(prefix: &str, value: &T) -> anyhow::Result<String> {
    let json = serde_json::to_vec(value).context("serialise blob")?;
    Ok(format!("{}{}", prefix, URL_SAFE_NO_PAD.encode(&json)))
}

fn decode_blob<T: serde::de::DeserializeOwned>(prefix: &str, blob: &str) -> anyhow::Result<T> {
    let blob = blob.trim();
    let rest = blob
        .strip_prefix(prefix)
        .with_context(|| format!("blob must start with `{prefix}`"))?;
    let json = URL_SAFE_NO_PAD
        .decode(rest.as_bytes())
        .context("base64 decode failed — is the blob intact?")?;
    serde_json::from_slice(&json).context("JSON decode failed")
}

// ── I/O helpers ───────────────────────────────────────────────────────────────

/// Read a single non-empty line from either a file or stdin.
fn read_blob_line(file: Option<&Path>, prompt: &str) -> anyhow::Result<String> {
    if let Some(path) = file {
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("read blob file {}", path.display()))?;
        return Ok(s.trim().to_string());
    }
    // Interactive stdin.
    print!("{}", prompt);
    io::stdout().flush()?;
    let stdin = io::stdin();
    // Read lines until we get one that starts with ENT- (skip blank lines)
    for line in stdin.lock().lines() {
        let line = line.context("stdin read")?;
        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    bail!("EOF reached without receiving a blob")
}

/// Write a blob to a file, or print it to stdout.
fn write_blob(file: Option<&Path>, blob: &str) -> anyhow::Result<()> {
    if let Some(path) = file {
        std::fs::write(path, blob).with_context(|| format!("write blob to {}", path.display()))?;
    } else {
        println!("{}", blob);
    }
    Ok(())
}

/// Prompt on stderr and read one trimmed line from stdin.
fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    let read = io::stdin().lock().read_line(&mut line)?;
    if read == 0 {
        bail!("stdin closed before an answer was given");
    }
    Ok(line.trim().to_string())
}

// ── Peer-store path ───────────────────────────────────────────────────────────

fn peers_path(args: &PairArgs) -> PathBuf {
    args.peers_file
        .clone()
        .unwrap_or_else(|| entangle_dir().join("peers.toml"))
}

fn identity_path(args: &PairArgs) -> PathBuf {
    args.identity_file
        .clone()
        .unwrap_or_else(|| entangle_dir().join("identity.key"))
}

/// The capability-token revocation set next to the peer list (where the
/// daemon reads both).
fn revocations(args: &PairArgs) -> anyhow::Result<RevocationStore> {
    crate::cmd::peers::revocations_at(&peers_path(args).with_file_name(REVOCATIONS_FILE))
}

/// Store a paired peer, validating that the recorded id really is the
/// fingerprint of the recorded key, together with the token it issued this
/// device (`received`) and the revocation ids of the token this device
/// issued it (`issued`). A token this device issued to it in an earlier
/// pairing is revoked (`PeerStore::add_paired`).
fn persist(
    args: &PairArgs,
    peer_id: PeerId,
    pubkey_hex: &str,
    name: &str,
    received: Option<&[u8]>,
    issued: &[Vec<u8>],
) -> anyhow::Result<()> {
    let peer = TrustedPeer::new_validated(peer_id, pubkey_hex.to_string(), name.to_string())
        .context("refusing to store a peer whose id does not match its public key")?
        .with_tokens(received, issued);
    let path = peers_path(args);
    let store = PeerStore::open(&path)?;
    store.add_paired(peer, &revocations(args)?)?;
    eprintln!("✓ added to {}", path.display());
    if received.is_some() {
        eprintln!("✓ capability tokens exchanged (remote tasks and streams to it are authorised)");
    } else {
        eprintln!(
            "warning: the other device sent no capability token (it runs an older version). \
             It is paired, but this device's remote requests carry no token there; re-pair \
             after upgrading it."
        );
    }
    Ok(())
}

/// Revoke the token this device issued in a pairing that did not complete:
/// it may already be in the other device's hands.
fn revoke_issued(args: &PairArgs, peer_id: PeerId, issued: &[Vec<u8>], why: &str) {
    if issued.is_empty() {
        return;
    }
    let result = revocations(args).and_then(|r| Ok(r.revoke(issued, &peer_id, why)?));
    if let Err(e) = result {
        eprintln!(
            "warning: could not revoke the capability token sent to {} ({e:#}); remove that \
             peer with `entangle peers remove` if it is ever added",
            peer_id.to_hex()
        );
    }
}

/// Persist a pairing produced by `entangle-pairing` (the network channel).
fn persist_paired(args: &PairArgs, paired: &PairedPeer) -> anyhow::Result<()> {
    persist(
        args,
        paired.peer_id,
        &paired.pubkey_hex,
        &paired.display_name,
        paired.capability_token.as_deref(),
        &paired.issued_revocation_ids,
    )
}

// ── Display name ──────────────────────────────────────────────────────────────

/// `--display-name`, else `[node] label` from config.toml, else the host
/// name: the human-readable label the other device shows next to this one's
/// fingerprint (spec §6.3 step 2).
fn resolve_display_name(args: &PairArgs) -> String {
    args.display_name
        .clone()
        .unwrap_or_else(crate::config::device_label)
}

// ── Public entry point ────────────────────────────────────────────────────────

/// `entangle init`'s "pair now": show a code on this device and wait for the
/// other one (`entangle pair <code>` there), exactly as `entangle pair
/// --print-code` does, with `label` as this device's name.
pub async fn pair_from_wizard(label: &str) -> anyhow::Result<()> {
    run(PairArgs {
        responder: true,
        print_code: false,
        display_name: Some(label.to_owned()),
        manual: false,
        peer: None,
        code: None,
        code_arg: None,
        yes: false,
        timeout: 300,
        max_attempts: DEFAULT_MAX_ATTEMPTS,
        discover_secs: 4,
        emit_request_file: None,
        consume_accept_file: None,
        emit_finalize_file: None,
        request_file: None,
        emit_accept_file: None,
        consume_finalize_file: None,
        peers_file: None,
        identity_file: None,
        bind: None,
        no_mdns: false,
        no_qr: false,
    })
    .await
}

pub async fn run(args: PairArgs) -> anyhow::Result<()> {
    match (args.is_manual(), args.shows_code()) {
        (true, true) => run_manual_responder(args),
        (true, false) => run_manual_initiator(args),
        (false, true) => run_responder(args).await,
        (false, false) => run_initiator(args).await,
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// NETWORK RESPONDER — shows the code, waits for a dial
// ═════════════════════════════════════════════════════════════════════════════

/// Where the spec §6.3 "what this means" page for a fingerprint mismatch is.
pub const FINGERPRINT_MISMATCH_DOCS: &str =
    "https://github.com/thekozugroup/Entanglement/blob/main/docs/operations.md#fingerprint-mismatch \
     (docs/operations.md, \"Fingerprint mismatch\")";

/// `SHA256:<hex>` of a raw public key: the full fingerprint shown next to
/// the short one and the QR code (spec §6.3, §9.4.2).
pub fn sha256_fingerprint(public_key: &[u8; 32]) -> String {
    use sha2::Digest as _;
    format!("SHA256:{}", hex::encode(sha2::Sha256::digest(public_key)))
}

/// The text the pairing QR code carries: the code and the full fingerprint.
pub fn qr_payload(code: PairingCode, public_key: &[u8; 32]) -> String {
    let sha = sha256_fingerprint(public_key);
    let hex = sha.trim_start_matches("SHA256:");
    format!(
        "entangle:pair?code={}&sha256={hex}",
        code.display_grouped().replace('-', "")
    )
}

/// The QR code as lines (empty with `--no-qr` or on `TERM=dumb`).
fn qr_lines(args: &PairArgs, payload: &str) -> Vec<String> {
    if args.no_qr || !crate::cmd::ui::unicode_graphics_allowed() {
        return Vec::new();
    }
    crate::cmd::qr::QrCode::encode(payload.as_bytes())
        .map(|q| q.to_half_blocks())
        .unwrap_or_default()
}

fn attempts_path(args: &PairArgs) -> PathBuf {
    crate::cmd::pairlog::path_next_to(&peers_path(args))
}

fn record_attempt(
    args: &PairArgs,
    role: &str,
    outcome: &str,
    peer: Option<String>,
    error: Option<String>,
    tried: Vec<Tried>,
) {
    crate::cmd::pairlog::record(
        &attempts_path(args),
        crate::cmd::pairlog::Attempt {
            at_unix: crate::cmd::pairlog::now(),
            role: role.into(),
            outcome: outcome.into(),
            peer,
            error,
            tried,
        },
    );
}

async fn run_responder(args: PairArgs) -> anyhow::Result<()> {
    let kp = ensure_identity(&identity_path(&args))?;
    let public_key = *kp.public().as_bytes();
    let display_name = resolve_display_name(&args);
    let ttl = Duration::from_secs(args.timeout.clamp(10, 3600));
    let mdns = !args.no_mdns;

    let listener = PairingListener::start(
        kp,
        HostConfig {
            display_name: display_name.clone(),
            ttl,
            max_attempts: args.max_attempts.max(1),
        },
        args.bind_addr()?,
        mdns,
    )
    .await;
    let listener = match listener {
        Ok(l) => l,
        Err(e) => {
            let tried = vec![Tried::new(
                "mesh.iroh (QUIC)",
                format!("bind {}", args.bind_addr()?),
                format!("failed: {e}"),
            )];
            record_attempt(
                &args,
                "show-code",
                "failed",
                None,
                Some(e.to_string()),
                tried,
            );
            return Err(anyhow::anyhow!(e)).context(
                "could not start the pairing listener (run `entangle diag pair` to see what \
                 pairing can use on this host)",
            );
        }
    };

    let code = listener.code();
    eprintln!("Waiting for another device to pair.\n");
    eprintln!(
        "  Pairing code:  {}   (expires in {}s)",
        code.display_grouped(),
        ttl.as_secs()
    );
    eprintln!("  Fingerprint:   {}", listener.local_fingerprint());
    eprintln!("  SHA-256:       {}", sha256_fingerprint(&public_key));
    eprintln!("  This device:   {display_name}");
    let payload = qr_payload(code, &public_key);
    let qr = qr_lines(&args, &payload);
    if !qr.is_empty() {
        eprintln!(
            "\n  Scan (the 6-digit code above is canonical; the QR carries it and the SHA-256):"
        );
        for line in &qr {
            eprintln!("  {line}");
        }
    }
    if listener.is_announcing() {
        eprintln!(
            "\nOn the other device run:  entangle pair {}",
            code.display_grouped()
        );
    } else {
        eprintln!("\n(no mDNS beacon — the other device needs --peer)");
    }
    for addr in listener.node_addrs() {
        eprintln!("  Direct address: entangle pair --peer {addr}");
    }
    eprintln!();

    let mut tried = vec![
        Tried::new(
            "mesh.iroh (QUIC)",
            listener.node_addrs().join(", "),
            "listening",
        ),
        Tried::new(
            "mesh.local (mDNS)",
            "pairing beacon",
            if listener.is_announcing() {
                "announcing"
            } else if mdns {
                "could not announce"
            } else {
                "off (--no-mdns)"
            },
        ),
    ];
    let result = listener.wait().await;
    let paired = match result {
        Ok(p) => p,
        Err(e) => {
            listener.shutdown().await;
            let err = match &e {
                PairingMeshError::Timeout(after) => anyhow::anyhow!(
                    "ENTANGLE-E0786: code expired: no device paired within {}s. Run `entangle \
                     pair --print-code` again for a new code (and `entangle pair <code>` on the \
                     other device); `entangle diag pair` shows what pairing can use here.",
                    after.as_secs()
                ),
                PairingMeshError::Net(PairingNetError::Identity(why)) => fingerprint_mismatch(why),
                _ => anyhow::anyhow!(e.to_string()).context("pairing did not complete"),
            };
            tried.push(Tried::new("wait", "other device", format!("{err:#}")));
            record_attempt(
                &args,
                "show-code",
                "failed",
                None,
                Some(format!("{err:#}")),
                tried,
            );
            return Err(err);
        }
    };

    // "Their SHA-256" is the other device's key, as the exchange
    // authenticated it — never this device's own.
    let their_key = match their_key(&paired) {
        Ok(k) => k,
        Err(e) => {
            listener.shutdown().await;
            revoke_issued(
                &args,
                paired.peer_id,
                &paired.issued_revocation_ids,
                "pairing failed",
            );
            record_attempt(
                &args,
                "show-code",
                "failed",
                None,
                Some(format!("{e:#}")),
                tried,
            );
            return Err(e);
        }
    };
    report_pairing(&paired, listener.local_fingerprint(), &their_key);
    listener.shutdown().await;
    let peer = Some(format!(
        "{} ({})",
        paired.display_name,
        paired.peer_id.to_hex()
    ));
    if let Err(e) = confirm_or_abort(&args, &paired, "initiator") {
        revoke_issued(
            &args,
            paired.peer_id,
            &paired.issued_revocation_ids,
            "pairing not confirmed",
        );
        record_attempt(
            &args,
            "show-code",
            "not-confirmed",
            peer,
            Some(format!("{e:#}")),
            tried,
        );
        return Err(e);
    }

    persist_paired(&args, &paired)?;
    record_attempt(&args, "show-code", "paired", peer, None, tried);
    Ok(())
}

/// Spec §6.3: a hard error, with a link to what it means.
fn fingerprint_mismatch(detail: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "ENTANGLE-E0787: fingerprint mismatch: {detail}. Nothing was stored. This can mean \
         someone on the network is impersonating the other device (a man-in-the-middle on the \
         rendezvous); do not retry blindly. What it means and what to do: {FINGERPRINT_MISMATCH_DOCS}"
    )
}

// ═════════════════════════════════════════════════════════════════════════════
// NETWORK INITIATOR — finds the device, types the code
// ═════════════════════════════════════════════════════════════════════════════

/// Spec §6.3 "No reachability": which transports were tried and why each
/// failed, what was not tried, and `entangle diag pair`.
fn unreachable(tried: &[Tried], why: &str) -> anyhow::Error {
    let mut msg = format!("ENTANGLE-E0788: {why}\nTransports tried:\n");
    for t in tried {
        msg.push_str(&format!(
            "  - {}: {} -> {}\n",
            t.transport, t.target, t.result
        ));
    }
    msg.push_str(
        "Not tried:\n  - mesh.tailscale: pairing does not search the tailnet; if both devices \
         are on one, run `entangle pair --peer <address>` with the tailnet address that \
         `entangle pair --print-code` prints on the other device\n",
    );
    msg.push_str("Run `entangle diag pair` on both devices to see what pairing can use on each.");
    anyhow::anyhow!(msg)
}

async fn run_initiator(args: PairArgs) -> anyhow::Result<()> {
    let kp = ensure_identity(&identity_path(&args))?;
    let display_name = resolve_display_name(&args);
    let local_peer_id = PeerId::from_public_key_bytes(kp.public().as_bytes());
    let local_fingerprint = ShortFingerprint::from_public_key(kp.public().as_bytes());

    let mut tried = Vec::new();
    let (target, target_name) = match resolve_target(&args, local_peer_id, &mut tried).await {
        Ok(t) => t,
        Err(e) => {
            record_attempt(
                &args,
                "enter-code",
                "failed",
                None,
                Some(format!("{e:#}")),
                tried,
            );
            return Err(e);
        }
    };
    let code = read_code(&args, &target_name)?;

    eprintln!("\nPairing with {target_name}…");
    // This device's token for the target, minted up front so it can be
    // revoked if the exchange fails after it was sent.
    let target_id = PeerId::from_public_key_bytes(&target.public_key);
    let issued = grant::issue(&kp, target_id).context("minting the capability token")?;
    let issued_ids = issued.revocation_ids.clone();
    let bind = args.bind_addr()?;
    let transport = match start_pairing_transport(&kp, bind).await {
        Ok(t) => t,
        Err(e) => {
            tried.push(Tried::new(
                "mesh.iroh (QUIC)",
                format!("bind {bind}"),
                format!("failed: {e}"),
            ));
            let err = unreachable(&tried, "could not bind a local QUIC endpoint for pairing.");
            record_attempt(
                &args,
                "enter-code",
                "failed",
                Some(target_name),
                Some(format!("{err:#}")),
                tried,
            );
            return Err(err);
        }
    };
    let relay = transport.config().allow_derp_relay;
    let paired =
        dial_and_pair_with_grant(&transport, &target, &kp, &display_name, code, issued).await;
    transport.shutdown().await;
    let dial_target = format!(
        "{} ({})",
        target
            .addrs()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        if relay {
            "direct UDP, relay fallback on"
        } else {
            "direct UDP only"
        }
    );
    let paired = match paired {
        Ok(p) => {
            tried.push(Tried::new("mesh.iroh (QUIC)", dial_target, "ok"));
            p
        }
        Err(e) => {
            revoke_issued(&args, target_id, &issued_ids, "pairing failed");
            let err = dial_error(&e, &target_name, dial_target, &mut tried);
            record_attempt(
                &args,
                "enter-code",
                "failed",
                Some(target_name),
                Some(format!("{err:#}")),
                tried,
            );
            return Err(err);
        }
    };

    let their_key = match their_key(&paired) {
        Ok(k) => k,
        Err(e) => {
            revoke_issued(&args, target_id, &issued_ids, "pairing failed");
            record_attempt(
                &args,
                "enter-code",
                "failed",
                Some(target_name),
                Some(format!("{e:#}")),
                tried,
            );
            return Err(e);
        }
    };
    report_pairing(&paired, local_fingerprint, &their_key);
    let peer = Some(format!(
        "{} ({})",
        paired.display_name,
        paired.peer_id.to_hex()
    ));
    if let Err(e) = confirm_or_abort(&args, &paired, "other device") {
        revoke_issued(&args, target_id, &issued_ids, "pairing not confirmed");
        record_attempt(
            &args,
            "enter-code",
            "not-confirmed",
            peer,
            Some(format!("{e:#}")),
            tried,
        );
        return Err(e);
    }

    persist_paired(&args, &paired)?;
    record_attempt(&args, "enter-code", "paired", peer, None, tried);
    Ok(())
}

/// What a failed dial means for the user (spec §6.3 failure modes), with
/// the step recorded in `tried`.
fn dial_error(
    e: &PairingMeshError,
    target_name: &str,
    dial_target: String,
    tried: &mut Vec<Tried>,
) -> anyhow::Error {
    const QUIC: &str = "mesh.iroh (QUIC)";
    match e {
        PairingMeshError::Transport(t) => {
            tried.push(Tried::new(QUIC, dial_target, format!("failed: {t}")));
            unreachable(tried, &format!("could not reach {target_name}."))
        }
        PairingMeshError::Net(PairingNetError::Rejected(RejectReason::Expired)) => {
            tried.push(Tried::new(QUIC, dial_target, "reached; code expired"));
            anyhow::anyhow!(
                "ENTANGLE-E0786: code expired; ask {target_name} to run `entangle pair \
                 --print-code` again, then enter the new code"
            )
        }
        PairingMeshError::Net(PairingNetError::Identity(why)) => {
            tried.push(Tried::new(QUIC, dial_target, "reached; identity mismatch"));
            fingerprint_mismatch(why)
        }
        other => {
            tried.push(Tried::new(QUIC, dial_target, format!("reached; {other}")));
            anyhow::anyhow!(other.to_string()).context(
                "pairing failed — check the code, and that the other device is still showing it",
            )
        }
    }
}

fn decode_pubkey(hex_key: &str) -> Option<[u8; 32]> {
    hex::decode(hex_key).ok()?.try_into().ok()
}

/// The other device's raw public key from a completed exchange. An
/// undecodable key is an error, never a placeholder: the SHA-256 shown from
/// it is what the user compares (spec §6.3).
fn their_key(paired: &PairedPeer) -> anyhow::Result<[u8; 32]> {
    decode_pubkey(&paired.pubkey_hex).ok_or_else(|| {
        anyhow::anyhow!(
            "the other device's public key is not 32 bytes of hex ({:?}); nothing was stored",
            paired.pubkey_hex
        )
    })
}

/// Print both fingerprints. The user compares them against the other screen —
/// this is the step that catches a device that learned the code some other way.
fn report_pairing(paired: &PairedPeer, local: ShortFingerprint, their_key: &[u8; 32]) {
    eprintln!("\n✓ Exchange complete with '{}'", paired.display_name);
    eprintln!("  Their fingerprint: {}", paired.fingerprint);
    eprintln!("  Their SHA-256:     {}", sha256_fingerprint(their_key));
    eprintln!("  Your fingerprint:  {local}");
    eprintln!("  Verify BOTH lines appear, swapped, on the other device.");
}

/// Mutual TOFU means *both* sides confirm before storing anything (spec §6.3).
///
/// Without a terminal there is nobody to ask, and silently storing the peer
/// would turn the confirmation into a no-op — so that case is an error that
/// names `--yes` rather than an implicit accept. A "no" is a fingerprint
/// mismatch: a hard error that links to what it means.
fn confirm_or_abort(args: &PairArgs, paired: &PairedPeer, side: &str) -> anyhow::Result<()> {
    if args.yes {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        bail!(
            "no terminal to confirm the fingerprints on — re-run with --yes if you have \
             already compared them (nothing was stored)"
        );
    }
    let answer = prompt_line("Do both fingerprints match the other device's screen? [y/N] ")?;
    if matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes") {
        return Ok(());
    }
    eprintln!(
        "Note: the {side} already recorded this pairing; remove it there with\n\
         `entangle peers remove {}`.",
        paired.peer_id.to_hex()
    );
    Err(fingerprint_mismatch(
        "the fingerprints shown here do not match the other device's screen",
    ))
}

/// Work out which device to dial: an explicit `--peer`, or a chooser over what
/// mDNS found. Each discovery step is added to `tried`.
async fn resolve_target(
    args: &PairArgs,
    local_peer_id: PeerId,
    tried: &mut Vec<Tried>,
) -> anyhow::Result<(IrohPeer, String)> {
    if let Some(spec) = args.peer.as_deref() {
        if spec.contains('@') {
            let peer = parse_node_addr(spec)
                .map_err(|e| anyhow::anyhow!("invalid --peer address: {e}"))?;
            let name = format!("{} ({})", peer.addr, peer.peer_id.to_hex());
            return Ok((peer, name));
        }
        if args.no_mdns {
            bail!("--peer must be a <pubkey-hex>@<host>:<port> long address when mDNS is off");
        }
        let candidates = browse(args, local_peer_id, tried).await?;
        let matched: Vec<&PairingCandidate> = candidates
            .iter()
            .filter(|c| {
                c.peer_id.to_hex().starts_with(spec)
                    || c.display_name.eq_ignore_ascii_case(spec)
                    || c.display_name.starts_with(spec)
            })
            .collect();
        return match matched.as_slice() {
            [one] => Ok((one.to_peer()?, describe(one))),
            [] => Err(unreachable(
                tried,
                &format!("no device in pairing mode matches '{spec}'."),
            )),
            many => bail!(
                "'{spec}' matches {} devices — use the full peer id or a long address",
                many.len()
            ),
        };
    }

    if args.no_mdns {
        bail!("mDNS is disabled: pass --peer <pubkey-hex>@<host>:<port>");
    }

    let candidates = browse(args, local_peer_id, tried).await?;
    match candidates.len() {
        0 => Err(unreachable(
            tried,
            "no devices are waiting to pair. Run `entangle pair --print-code` on the other \
             device, or pass its `--peer <pubkey-hex>@<host>:<port>` address if it is on \
             another network.",
        )),
        1 => {
            let only = &candidates[0];
            eprintln!("Found one device: {}", describe(only));
            Ok((only.to_peer()?, describe(only)))
        }
        _ => {
            eprintln!("Devices waiting to pair:");
            for (i, c) in candidates.iter().enumerate() {
                eprintln!("  {}) {}", i + 1, describe(c));
            }
            let pick = prompt_line(&format!("Select device [1-{}]: ", candidates.len()))?;
            let index: usize = pick
                .parse()
                .ok()
                .filter(|n| (1..=candidates.len()).contains(n))
                .with_context(|| format!("'{pick}' is not one of the listed devices"))?;
            let chosen = &candidates[index - 1];
            Ok((chosen.to_peer()?, describe(chosen)))
        }
    }
}

async fn browse(
    args: &PairArgs,
    local_peer_id: PeerId,
    tried: &mut Vec<Tried>,
) -> anyhow::Result<Vec<PairingCandidate>> {
    let window = Duration::from_secs(args.discover_secs.clamp(1, 60));
    eprintln!(
        "Searching for devices in pairing mode ({}s)…",
        window.as_secs()
    );
    let target = format!("devices in pairing mode on the LAN ({}s)", window.as_secs());
    match discover_pairing_hosts(local_peer_id, window).await {
        Ok(found) => {
            tried.push(Tried::new(
                "mesh.local (mDNS)",
                target,
                if found.is_empty() {
                    "none answered".to_owned()
                } else {
                    format!("found {}", found.len())
                },
            ));
            Ok(found)
        }
        Err(e) => {
            tried.push(Tried::new(
                "mesh.local (mDNS)",
                target,
                format!("failed: {e}"),
            ));
            Err(unreachable(tried, "mDNS discovery failed."))
        }
    }
}

/// One chooser line. The fingerprint is shown *before* dialing so the user can
/// already tell the devices apart.
fn describe(c: &PairingCandidate) -> String {
    let name = if c.display_name.is_empty() {
        "(unnamed)"
    } else {
        &c.display_name
    };
    let addr = c
        .addrs
        .first()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "?".into());
    format!("{name}  {}  {addr}", c.fingerprint())
}

/// Read the 6-digit code from the command line or the terminal.
fn read_code(args: &PairArgs, target_name: &str) -> anyhow::Result<PairingCode> {
    let raw = match args.supplied_code() {
        Some(c) => c.to_string(),
        None => {
            if !io::stdin().is_terminal() {
                bail!("no terminal to prompt on — pass --code <6-digit code>");
            }
            prompt_line(&format!("Enter the 6-digit code shown on {target_name}: "))?
        }
    };
    raw.parse()
        .map_err(|_| anyhow::anyhow!("could not parse code '{raw}' as 6 digits"))
}

// ═════════════════════════════════════════════════════════════════════════════
// MANUAL INITIATOR (copy-paste channel)
// ═════════════════════════════════════════════════════════════════════════════

fn run_manual_initiator(args: PairArgs) -> anyhow::Result<()> {
    let id_path = identity_path(&args);
    let kp = ensure_identity(&id_path)?;
    let pubkey_bytes = *kp.public().as_bytes();
    let peer_id = PeerId::from_public_key_bytes(&pubkey_bytes);
    let fp = ShortFingerprint::from_public_key(&pubkey_bytes);
    let display_name = resolve_display_name(&args);

    // Generate pairing material.
    let code = PairingCode::generate();
    let mut nonce = [0u8; 32];
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(&mut nonce);
    let code_commit = make_code_commit(code, &pubkey_bytes);

    eprintln!("Generating pairing material...");
    eprintln!(
        "Code:         {}  (read aloud — expires in 5 minutes)",
        code.display_grouped()
    );
    eprintln!("Fingerprint:  {}", fp);
    eprintln!("Display name: {}", display_name);

    // Build and emit REQUEST blob.
    let request = PairingRequest {
        initiator_peer_id: peer_id,
        initiator_pubkey_hex: hex::encode(pubkey_bytes),
        initiator_display_name: display_name.clone(),
        code_commit,
        nonce,
        created_at_secs: now_secs(),
    };
    let req_blob = encode_blob(PREFIX_REQ, &request)?;

    if args.emit_request_file.is_none() {
        eprintln!("\nPaste this REQUEST blob to the other device's `entangle pair --responder --manual`:\n");
    }
    write_blob(args.emit_request_file.as_deref(), &req_blob)?;

    // Read ACCEPT blob.
    let acc_raw = if args.consume_accept_file.is_some() {
        read_blob_line(args.consume_accept_file.as_deref(), "")?
    } else {
        eprintln!("\nWaiting for ACCEPT blob (paste below, then press Enter):");
        read_blob_line(None, "> ")?
    };

    let accept: PairingAccept =
        decode_blob(PREFIX_ACC, &acc_raw).context("failed to decode ACCEPT blob")?;

    // Verify their signature over signing_payload(code, nonce).
    let their_pubkey_bytes =
        hex::decode(&accept.responder_pubkey_hex).context("responder pubkey_hex not valid hex")?;
    if their_pubkey_bytes.len() != 32 {
        bail!("responder pubkey must be 32 bytes");
    }
    let their_pubkey_arr: [u8; 32] = their_pubkey_bytes.try_into().unwrap();
    let their_pubkey = IdentityPublicKey::from_bytes(&their_pubkey_arr)
        .map_err(|e| anyhow::anyhow!("invalid responder pubkey: {e}"))?;

    let their_fp = ShortFingerprint::from_public_key(&their_pubkey_arr);
    let payload = signing_payload(code, &nonce);
    let sig = Signature::from_hex(&accept.signature_hex)
        .map_err(|_| anyhow::anyhow!("signature mismatch: malformed hex in ACCEPT"))?;
    their_pubkey
        .verify(&payload, &sig)
        .map_err(|_| anyhow::anyhow!("signature verification failed — pairing aborted"))?;

    // The responder's capability token (if it sent one) must be a mesh.peer
    // grant from its key to this device; then mint ours for it.
    let their_peer_id = PeerId::from_public_key_bytes(&their_pubkey_arr);
    let received = grant::check_optional(
        accept.capability_token_hex.as_deref(),
        &their_pubkey_arr,
        peer_id,
    )
    .map_err(|e| anyhow::anyhow!("pairing aborted: {e}"))?;
    let issued = grant::issue(&kp, their_peer_id).context("minting the capability token")?;

    eprintln!(
        "\n✓ Paired with peer '{}' ({})",
        accept.responder_display_name, their_fp
    );

    // Build and emit FINALIZE blob (initiator signs too).
    let my_sig = kp.sign(&payload);
    let finalize = PairingFinalize {
        signature_hex: my_sig.to_hex(),
        created_at_secs: now_secs(),
        capability_token_hex: Some(grant::to_hex(&issued)),
    };
    let fin_blob = encode_blob(PREFIX_FIN, &finalize)?;

    if args.emit_finalize_file.is_none() {
        eprintln!("\nPaste this FINALIZE blob to the other device:\n");
    }
    if let Err(e) = write_blob(args.emit_finalize_file.as_deref(), &fin_blob) {
        revoke_issued(
            &args,
            their_peer_id,
            &issued.revocation_ids,
            "pairing failed",
        );
        return Err(e);
    }

    // Persist their peer.
    persist(
        &args,
        their_peer_id,
        &accept.responder_pubkey_hex,
        &accept.responder_display_name,
        received.as_deref(),
        &issued.revocation_ids,
    )
}

// ═════════════════════════════════════════════════════════════════════════════
// MANUAL RESPONDER (copy-paste channel)
// ═════════════════════════════════════════════════════════════════════════════

fn run_manual_responder(args: PairArgs) -> anyhow::Result<()> {
    let id_path = identity_path(&args);
    let kp = ensure_identity(&id_path)?;
    let pubkey_bytes = *kp.public().as_bytes();
    let my_fp = ShortFingerprint::from_public_key(&pubkey_bytes);
    let display_name = resolve_display_name(&args);

    // Read REQUEST blob.
    let req_raw = if args.request_file.is_some() {
        read_blob_line(args.request_file.as_deref(), "")?
    } else {
        eprintln!("Paste REQUEST blob (then press Enter):");
        read_blob_line(None, "> ")?
    };

    let request: PairingRequest = decode_blob(PREFIX_REQ, &req_raw)
        .context("failed to decode REQUEST blob — is the blob intact?")?;

    // Check expiry.
    if now_secs().saturating_sub(request.created_at_secs) > EXPIRY_SECS {
        bail!(
            "ENTANGLE-E0786: code expired (the REQUEST blob is over 5 minutes old); ask the \
             device that showed the code to run `entangle pair --manual` again"
        );
    }

    // Show identities.
    let their_fp = fingerprint_from_hex(&request.initiator_pubkey_hex)
        .map_err(|e| anyhow::anyhow!("bad initiator pubkey: {e}"))?;
    eprintln!(
        "\nInitiator:             '{}'",
        request.initiator_display_name
    );
    eprintln!("Initiator fingerprint: {}", their_fp);
    eprintln!("Your fingerprint:      {}", my_fp);
    eprintln!("\nVerify with the other device that BOTH fingerprints match what it shows.");

    // Read the 6-digit code.
    let code_str = if let Some(c) = args.supplied_code() {
        c.to_string()
    } else {
        print!("Then enter the 6-digit code displayed on the initiator: ");
        io::stdout().flush()?;
        let stdin = io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        line.trim().to_string()
    };

    let code: PairingCode = code_str
        .parse()
        .map_err(|_| anyhow::anyhow!("could not parse code '{}' as 6 digits", code_str))?;

    // Verify the code matches the commitment.
    let their_pubkey_bytes =
        hex::decode(&request.initiator_pubkey_hex).context("initiator pubkey_hex not valid hex")?;
    if their_pubkey_bytes.len() != 32 {
        bail!("initiator pubkey must be 32 bytes");
    }
    let their_pubkey_arr: [u8; 32] = their_pubkey_bytes.try_into().unwrap();
    let expected_commit = make_code_commit(code, &their_pubkey_arr);
    if expected_commit != request.code_commit {
        bail!("code does not match — pairing aborted (no peer added)");
    }
    eprintln!("✓ Code matches");

    // Sign the payload and emit ACCEPT blob, with this device's capability
    // token for the initiator (it proved it knows the code).
    let payload = signing_payload(code, &request.nonce);
    let sig = kp.sign(&payload);
    let peer_id = PeerId::from_public_key_bytes(&pubkey_bytes);
    let their_peer_id = PeerId::from_public_key_bytes(&their_pubkey_arr);
    let issued = grant::issue(&kp, their_peer_id).context("minting the capability token")?;
    let accept = PairingAccept {
        responder_peer_id: peer_id,
        responder_pubkey_hex: hex::encode(pubkey_bytes),
        responder_display_name: display_name.clone(),
        signature_hex: sig.to_hex(),
        created_at_secs: now_secs(),
        capability_token_hex: Some(grant::to_hex(&issued)),
    };
    let acc_blob = encode_blob(PREFIX_ACC, &accept)?;

    if args.emit_accept_file.is_none() {
        eprintln!("\nPaste this ACCEPT blob to the initiator:\n");
    }
    write_blob(args.emit_accept_file.as_deref(), &acc_blob)?;

    // From here on the ACCEPT blob, with this device's token, is out: a
    // pairing that does not complete revokes it.
    let finished = finish_manual_responder(&payload, &their_pubkey_arr, peer_id, &args);
    let received = match finished {
        Ok(received) => received,
        Err(e) => {
            revoke_issued(
                &args,
                their_peer_id,
                &issued.revocation_ids,
                "pairing failed",
            );
            return Err(e);
        }
    };

    eprintln!(
        "\n✓ Paired with peer '{}' ({})",
        request.initiator_display_name, their_fp
    );

    // Persist their peer.
    persist(
        &args,
        their_peer_id,
        &request.initiator_pubkey_hex,
        &request.initiator_display_name,
        received.as_deref(),
        &issued.revocation_ids,
    )
}

/// Read and verify the FINALIZE blob: the initiator's signature over
/// `payload`, and its capability token for this device (`own_id`), if any.
fn finish_manual_responder(
    payload: &[u8; 64],
    their_pubkey_arr: &[u8; 32],
    own_id: PeerId,
    args: &PairArgs,
) -> anyhow::Result<Option<Vec<u8>>> {
    let fin_raw = if args.consume_finalize_file.is_some() {
        read_blob_line(args.consume_finalize_file.as_deref(), "")?
    } else {
        eprintln!("\nWaiting for FINALIZE blob:");
        read_blob_line(None, "> ")?
    };

    let finalize: PairingFinalize =
        decode_blob(PREFIX_FIN, &fin_raw).context("failed to decode FINALIZE blob")?;

    // Verify initiator's signature over the same payload.
    let their_pubkey = IdentityPublicKey::from_bytes(their_pubkey_arr)
        .map_err(|e| anyhow::anyhow!("invalid initiator pubkey: {e}"))?;
    let fin_sig = Signature::from_hex(&finalize.signature_hex)
        .map_err(|_| anyhow::anyhow!("signature mismatch: malformed FINALIZE signature"))?;
    their_pubkey
        .verify(payload, &fin_sig)
        .map_err(|_| anyhow::anyhow!("signature verification failed — pairing aborted"))?;

    grant::check_optional(
        finalize.capability_token_hex.as_deref(),
        their_pubkey_arr,
        own_id,
    )
    .map_err(|e| anyhow::anyhow!("pairing aborted: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dial_failures_say_what_happened_and_what_to_do() {
        let mut tried = vec![Tried::new("mesh.local (mDNS)", "LAN", "found 1")];
        let expired = dial_error(
            &PairingMeshError::Net(PairingNetError::Rejected(RejectReason::Expired)),
            "studio",
            "10.0.0.2:5000".into(),
            &mut tried,
        )
        .to_string();
        assert!(
            expired.starts_with("ENTANGLE-E0786: code expired; ask studio"),
            "{expired}"
        );
        assert!(expired.contains("entangle pair --print-code"), "{expired}");

        let mismatch = format!(
            "{:#}",
            dial_error(
                &PairingMeshError::Net(PairingNetError::Identity("host key differs".into())),
                "studio",
                "10.0.0.2:5000".into(),
                &mut tried,
            )
        );
        assert!(
            mismatch.starts_with("ENTANGLE-E0787: fingerprint mismatch"),
            "{mismatch}"
        );
        assert!(
            mismatch.contains("docs/operations.md#fingerprint-mismatch"),
            "{mismatch}"
        );

        let unreachable = format!(
            "{:#}",
            dial_error(
                &PairingMeshError::Timeout(Duration::from_secs(10)),
                "studio",
                "10.0.0.2:5000".into(),
                &mut tried,
            )
        );
        assert!(unreachable.contains("pairing failed"), "{unreachable}");
        assert_eq!(tried.len(), 4, "every step is recorded: {tried:?}");
    }

    #[test]
    fn unreachable_lists_every_transport_and_points_at_diag_pair() {
        let tried = vec![
            Tried::new(
                "mesh.local (mDNS)",
                "devices in pairing mode",
                "none answered",
            ),
            Tried::new("mesh.iroh (QUIC)", "10.0.0.2:5000", "failed: timed out"),
        ];
        let text = unreachable(&tried, "could not reach studio.").to_string();
        for needle in [
            "ENTANGLE-E0788",
            "mesh.local (mDNS): devices in pairing mode -> none answered",
            "mesh.iroh (QUIC): 10.0.0.2:5000 -> failed: timed out",
            "mesh.tailscale",
            "entangle diag pair",
        ] {
            assert!(text.contains(needle), "missing {needle:?}:\n{text}");
        }
    }

    #[test]
    fn the_qr_payload_carries_the_code_and_the_full_fingerprint() {
        let key = [7u8; 32];
        let code: PairingCode = "734-291".parse().unwrap();
        let sha = sha256_fingerprint(&key);
        assert_eq!(sha.len(), "SHA256:".len() + 64);
        let payload = qr_payload(code, &key);
        assert_eq!(
            payload,
            format!(
                "entangle:pair?code=734291&sha256={}",
                &sha["SHA256:".len()..]
            )
        );
        assert!(crate::cmd::qr::QrCode::encode(payload.as_bytes()).is_some());
    }

    /// The key behind "Their SHA-256" is the other device's, decoded from
    /// the exchange; an undecodable one is an error, not a zero key.
    #[test]
    fn their_key_is_the_paired_devices_key_or_an_error() {
        let key = [9u8; 32];
        let mut paired = PairedPeer {
            peer_id: PeerId::from_public_key_bytes(&key),
            pubkey_hex: hex::encode(key),
            display_name: "laptop".into(),
            fingerprint: ShortFingerprint::from_public_key(&key),
            capability_token: None,
            issued_revocation_ids: Vec::new(),
        };
        assert_eq!(their_key(&paired).unwrap(), key);
        paired.pubkey_hex = "zz".into();
        let err = their_key(&paired).unwrap_err().to_string();
        assert!(err.contains("nothing was stored"), "{err}");
    }
}
