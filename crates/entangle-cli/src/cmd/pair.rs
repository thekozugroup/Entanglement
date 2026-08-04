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
use entangle_pairing::mesh::{
    dial_and_pair, discover_pairing_hosts, parse_node_addr, start_pairing_transport, IrohPeer,
    PairingCandidate, PairingListener, PairingTransportExt as _, DEFAULT_PAIRING_BIND,
};
use entangle_pairing::net::HostConfig;
use entangle_pairing::{
    fingerprint_from_hex, make_code_commit, signing_payload, PairingAccept, PairingFinalize,
    PairingRequest,
};
use entangle_pairing::{PairedPeer, PairingCode, ShortFingerprint, DEFAULT_MAX_ATTEMPTS};
use entangle_peers::{PeerStore, TrustedPeer};
use entangle_signing::{IdentityPublicKey, Signature};
use entangle_types::peer_id::PeerId;

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

    /// Override the transport bind address (useful in tests).
    #[arg(long, value_name = "ADDR", hide = true)]
    pub bind: Option<String>,

    /// Skip mDNS entirely (useful in tests and on locked-down networks).
    #[arg(long, hide = true)]
    pub no_mdns: bool,
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

/// Store a paired peer, validating that the recorded id really is the
/// fingerprint of the recorded key.
fn persist(args: &PairArgs, peer_id: PeerId, pubkey_hex: &str, name: &str) -> anyhow::Result<()> {
    let peer = TrustedPeer::new_validated(peer_id, pubkey_hex.to_string(), name.to_string())
        .context("refusing to store a peer whose id does not match its public key")?;
    let path = peers_path(args);
    let store = PeerStore::open(&path)?;
    store.add(peer)?;
    eprintln!("✓ added to {}", path.display());
    Ok(())
}

// ── Display name ──────────────────────────────────────────────────────────────

fn resolve_display_name(args: &PairArgs) -> String {
    args.display_name.clone().unwrap_or_else(|| {
        // Try to get a reasonable device name from environment variables.
        std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".to_string())
    })
}

// ── Public entry point ────────────────────────────────────────────────────────

pub async fn run(args: PairArgs) -> anyhow::Result<()> {
    match (args.is_manual(), args.responder) {
        (true, true) => run_manual_responder(args),
        (true, false) => run_manual_initiator(args),
        (false, true) => run_responder(args).await,
        (false, false) => run_initiator(args).await,
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// NETWORK RESPONDER — shows the code, waits for a dial
// ═════════════════════════════════════════════════════════════════════════════

async fn run_responder(args: PairArgs) -> anyhow::Result<()> {
    let kp = ensure_identity(&identity_path(&args))?;
    let display_name = resolve_display_name(&args);
    let ttl = Duration::from_secs(args.timeout.clamp(10, 3600));

    let listener = PairingListener::start(
        kp,
        HostConfig {
            display_name: display_name.clone(),
            ttl,
            max_attempts: args.max_attempts.max(1),
        },
        args.bind_addr()?,
        !args.no_mdns,
    )
    .await
    .context("could not start the pairing listener")?;

    eprintln!("Waiting for another device to pair.\n");
    eprintln!(
        "  Pairing code:  {}   (expires in {}s)",
        listener.code().display_grouped(),
        ttl.as_secs()
    );
    eprintln!("  Fingerprint:   {}", listener.local_fingerprint());
    eprintln!("  This device:   {display_name}");
    if listener.is_announcing() {
        eprintln!("\nOn the other device run:  entangle pair");
    } else {
        eprintln!("\n(no mDNS beacon — the other device needs --peer)");
    }
    for addr in listener.node_addrs() {
        eprintln!("  Direct address: entangle pair --peer {addr}");
    }
    eprintln!();

    let result = listener.wait().await;
    let paired = match result {
        Ok(p) => p,
        Err(e) => {
            listener.shutdown().await;
            return Err(anyhow::anyhow!(e)).context("pairing did not complete");
        }
    };

    report_pairing(&paired, listener.local_fingerprint());
    listener.shutdown().await;
    confirm_or_abort(&args, &paired, "initiator")?;

    persist(
        &args,
        paired.peer_id,
        &paired.pubkey_hex,
        &paired.display_name,
    )
}

// ═════════════════════════════════════════════════════════════════════════════
// NETWORK INITIATOR — finds the device, types the code
// ═════════════════════════════════════════════════════════════════════════════

async fn run_initiator(args: PairArgs) -> anyhow::Result<()> {
    let kp = ensure_identity(&identity_path(&args))?;
    let display_name = resolve_display_name(&args);
    let local_peer_id = PeerId::from_public_key_bytes(kp.public().as_bytes());
    let local_fingerprint = ShortFingerprint::from_public_key(kp.public().as_bytes());

    let (target, target_name) = resolve_target(&args, local_peer_id).await?;
    let code = read_code(&args, &target_name)?;

    eprintln!("\nPairing with {target_name}…");
    let transport = start_pairing_transport(&kp, args.bind_addr()?)
        .await
        .context("could not bind a local endpoint")?;
    let paired = dial_and_pair(&transport, &target, &kp, &display_name, code).await;
    transport.shutdown().await;
    let paired = paired.map_err(|e| anyhow::anyhow!(e)).context(
        "pairing failed — check the code, and that the other device is still showing it",
    )?;

    report_pairing(&paired, local_fingerprint);
    confirm_or_abort(&args, &paired, "other device")?;

    persist(
        &args,
        paired.peer_id,
        &paired.pubkey_hex,
        &paired.display_name,
    )
}

/// Print both fingerprints. The user compares them against the other screen —
/// this is the step that catches a device that learned the code some other way.
fn report_pairing(paired: &PairedPeer, local: ShortFingerprint) {
    eprintln!("\n✓ Exchange complete with '{}'", paired.display_name);
    eprintln!("  Their fingerprint: {}", paired.fingerprint);
    eprintln!("  Your fingerprint:  {local}");
    eprintln!("  Verify BOTH lines appear, swapped, on the other device.");
}

/// Mutual TOFU means *both* sides confirm before storing anything (spec §6.3).
///
/// Without a terminal there is nobody to ask, and silently storing the peer
/// would turn the confirmation into a no-op — so that case is an error that
/// names `--yes` rather than an implicit accept.
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
        "Aborted — nothing stored here.\n\
         Note: the {side} already recorded this pairing; remove it there with\n\
         `entangle mesh untrust {}`.",
        paired.peer_id.to_hex()
    );
    bail!("pairing not confirmed")
}

/// Work out which device to dial: an explicit `--peer`, or a chooser over what
/// mDNS found.
async fn resolve_target(
    args: &PairArgs,
    local_peer_id: PeerId,
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
        let candidates = browse(args, local_peer_id).await?;
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
            [] => bail!("no device in pairing mode matches '{spec}'"),
            many => bail!(
                "'{spec}' matches {} devices — use the full peer id or a long address",
                many.len()
            ),
        };
    }

    if args.no_mdns {
        bail!("mDNS is disabled: pass --peer <pubkey-hex>@<host>:<port>");
    }

    let candidates = browse(args, local_peer_id).await?;
    match candidates.len() {
        0 => bail!(
            "no devices are waiting to pair.\n\
             Run `entangle pair --responder` on the other device, or pass its\n\
             `--peer <pubkey-hex>@<host>:<port>` address if it is on another network."
        ),
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

async fn browse(args: &PairArgs, local_peer_id: PeerId) -> anyhow::Result<Vec<PairingCandidate>> {
    let window = Duration::from_secs(args.discover_secs.clamp(1, 60));
    eprintln!(
        "Searching for devices in pairing mode ({}s)…",
        window.as_secs()
    );
    discover_pairing_hosts(local_peer_id, window)
        .await
        .map_err(|e| anyhow::anyhow!("mDNS discovery failed: {e}"))
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

    eprintln!(
        "\n✓ Paired with peer '{}' ({})",
        accept.responder_display_name, their_fp
    );

    // Build and emit FINALIZE blob (initiator signs too).
    let my_sig = kp.sign(&payload);
    let finalize = PairingFinalize {
        signature_hex: my_sig.to_hex(),
        created_at_secs: now_secs(),
    };
    let fin_blob = encode_blob(PREFIX_FIN, &finalize)?;

    if args.emit_finalize_file.is_none() {
        eprintln!("\nPaste this FINALIZE blob to the other device:\n");
    }
    write_blob(args.emit_finalize_file.as_deref(), &fin_blob)?;

    // Persist their peer.
    persist(
        &args,
        PeerId::from_public_key_bytes(&their_pubkey_arr),
        &accept.responder_pubkey_hex,
        &accept.responder_display_name,
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
        bail!("request expired (>5 min) — restart the pair flow on both sides");
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

    // Sign the payload and emit ACCEPT blob.
    let payload = signing_payload(code, &request.nonce);
    let sig = kp.sign(&payload);
    let peer_id = PeerId::from_public_key_bytes(&pubkey_bytes);
    let accept = PairingAccept {
        responder_peer_id: peer_id,
        responder_pubkey_hex: hex::encode(pubkey_bytes),
        responder_display_name: display_name.clone(),
        signature_hex: sig.to_hex(),
        created_at_secs: now_secs(),
    };
    let acc_blob = encode_blob(PREFIX_ACC, &accept)?;

    if args.emit_accept_file.is_none() {
        eprintln!("\nPaste this ACCEPT blob to the initiator:\n");
    }
    write_blob(args.emit_accept_file.as_deref(), &acc_blob)?;

    // Read FINALIZE blob.
    let fin_raw = if args.consume_finalize_file.is_some() {
        read_blob_line(args.consume_finalize_file.as_deref(), "")?
    } else {
        eprintln!("\nWaiting for FINALIZE blob:");
        read_blob_line(None, "> ")?
    };

    let finalize: PairingFinalize =
        decode_blob(PREFIX_FIN, &fin_raw).context("failed to decode FINALIZE blob")?;

    // Verify initiator's signature over the same payload.
    let their_pubkey = IdentityPublicKey::from_bytes(&their_pubkey_arr)
        .map_err(|e| anyhow::anyhow!("invalid initiator pubkey: {e}"))?;
    let fin_sig = Signature::from_hex(&finalize.signature_hex)
        .map_err(|_| anyhow::anyhow!("signature mismatch: malformed FINALIZE signature"))?;
    their_pubkey
        .verify(&payload, &fin_sig)
        .map_err(|_| anyhow::anyhow!("signature verification failed — pairing aborted"))?;

    eprintln!(
        "\n✓ Paired with peer '{}' ({})",
        request.initiator_display_name, their_fp
    );

    // Persist their peer.
    persist(
        &args,
        PeerId::from_public_key_bytes(&their_pubkey_arr),
        &request.initiator_pubkey_hex,
        &request.initiator_display_name,
    )
}
