//! `entangle pair` — Phase-1 device-pairing flow (manual paste channel).
//!
//! The cryptographic protocol is defined in `entangle-pairing`. This module
//! drives the initiator and responder state machines through a human-assisted
//! copy-paste channel. Real mesh transport arrives in Phase 2; the crypto is
//! identical regardless of channel.
//!
//! # Blob format
//! Each message is encoded as a text blob: `ENT-{REQ,ACC,FIN}-<base64url>`,
//! where the base64url payload is the JSON serialisation of the envelope
//! struct. JSON is used because `serde_json` is already a workspace dep and
//! keeps the blobs human-inspectable.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::Args;
use entangle_pairing::{
    fingerprint_from_hex, make_code_commit, signing_payload, PairingAccept, PairingFinalize,
    PairingRequest,
};
use entangle_pairing::{PairingCode, ShortFingerprint};
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
/// Without flags, acts as the initiator. Pass `--responder` on the other
/// device.
#[derive(Args, Debug)]
pub struct PairArgs {
    /// Act as the responder (second device).
    #[arg(long)]
    pub responder: bool,

    /// Human-readable display name for this device (default: hostname).
    #[arg(long)]
    pub display_name: Option<String>,

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

    /// (Responder) The 6-digit code shown on the initiator (non-interactive).
    #[arg(long, value_name = "CODE")]
    pub code: Option<String>,

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
    if args.responder {
        run_responder(args)
    } else {
        run_initiator(args)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// INITIATOR
// ═════════════════════════════════════════════════════════════════════════════

fn run_initiator(args: PairArgs) -> anyhow::Result<()> {
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
        eprintln!("\nPaste this REQUEST blob to the other device's `entangle pair --responder`:\n");
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
        .map_err(|_| anyhow::anyhow!("error: signature verification failed — pairing aborted"))?;

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
    let their_peer_id = PeerId::from_public_key_bytes(&their_pubkey_arr);
    let peer = TrustedPeer::new(
        their_peer_id,
        accept.responder_pubkey_hex.clone(),
        accept.responder_display_name.clone(),
    );
    let store = PeerStore::open(peers_path(&args))?;
    store.add(peer)?;
    eprintln!("✓ added to {}", peers_path(&args).display());

    Ok(())
}

// ═════════════════════════════════════════════════════════════════════════════
// RESPONDER
// ═════════════════════════════════════════════════════════════════════════════

fn run_responder(args: PairArgs) -> anyhow::Result<()> {
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
        bail!("error: request expired (>5 min) — restart the pair flow on both sides");
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
    let code_str = if let Some(ref c) = args.code {
        c.clone()
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
        .map_err(|_| anyhow::anyhow!("error: could not parse code '{}' as 6 digits", code_str))?;

    // Verify the code matches the commitment.
    let their_pubkey_bytes =
        hex::decode(&request.initiator_pubkey_hex).context("initiator pubkey_hex not valid hex")?;
    if their_pubkey_bytes.len() != 32 {
        bail!("initiator pubkey must be 32 bytes");
    }
    let their_pubkey_arr: [u8; 32] = their_pubkey_bytes.try_into().unwrap();
    let expected_commit = make_code_commit(code, &their_pubkey_arr);
    if expected_commit != request.code_commit {
        bail!("error: code does not match — pairing aborted (no peer added)");
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
        .map_err(|_| anyhow::anyhow!("error: signature verification failed — pairing aborted"))?;

    eprintln!(
        "\n✓ Paired with peer '{}' ({})",
        request.initiator_display_name, their_fp
    );

    // Persist their peer.
    let their_peer_id = PeerId::from_public_key_bytes(&their_pubkey_arr);
    let peer = TrustedPeer::new(
        their_peer_id,
        request.initiator_pubkey_hex.clone(),
        request.initiator_display_name.clone(),
    );
    let store = PeerStore::open(peers_path(&args))?;
    store.add(peer)?;
    eprintln!("✓ added to {}", peers_path(&args).display());

    Ok(())
}
