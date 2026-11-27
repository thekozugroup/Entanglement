//! Receiver-side bridge authorization and durable byte accounting (§6.4).
//!
//! Use one ledger per destination node. Every local receiver process must open
//! that same ledger on a filesystem supporting local file locks and atomic
//! rename. A receiving transport authenticates the immediate bridge, retrieves
//! the origin's trusted signing key, then calls `authorize` before reading frames.

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use entangle_biscuits::PublicKey;
use entangle_types::peer_id::PeerId;
use serde::{Deserialize, Serialize};

use crate::{verify_bridge, BridgeCap, RelayAuthorizationError};

/// Max simultaneous unexpired budgets per node. Reject new budgets at capacity.
const MAX_BUDGETS: usize = 4096;
const MAX_LEDGER_BYTES: u64 = 8 * 1024 * 1024;
/// 100 ms buckets conservatively account for every byte in the previous second.
const TICKS_PER_SECOND: i64 = 10;

#[derive(Debug, thiserror::Error)]
/// Authorization, accounting or delivery failures at the receiving endpoint.
pub enum RelayError {
    /// One endpoint's signed delegation was refused.
    #[error(transparent)]
    Authorization(#[from] RelayAuthorizationError),
    /// The frame would cross either delegation's lifetime byte ceiling.
    #[error("bridge lifetime byte budget exhausted")]
    BridgeBudgetExhausted,
    /// This frame would exceed the rolling one-second bandwidth allowance.
    #[error("bridge rate limit exceeded")]
    RateLimited,
    /// The two endpoint authorizations or destination identities disagree.
    #[error("bridge session endpoints do not match the receiver")]
    EndpointMismatch,
    /// All available accounting entries are still in use.
    #[error("bridge budget ledger is full")]
    LedgerFull,
    /// Clock moved backwards, or the supplied time cannot be represented.
    #[error("bridge receiver clock is invalid or moved backwards")]
    Clock,
    /// Accounting state is unavailable or the frame sink failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Both endpoints independently delegated to the authenticated bridge. Fields
/// are private so only checked grants can reach the receive path.
#[derive(Debug)]
pub struct AuthorizedRelay {
    origin: BridgeCap,
    destination: BridgeCap,
}

/// Frame receiver with persistent process-safe rate and lifetime counters.
pub struct BridgeReceiver {
    path: PathBuf,
    destination: PeerId,
    local_signer: PublicKey,
}

impl BridgeReceiver {
    /// Provision a fresh private ledger. Refuses to replace an existing one.
    /// Its parent directory must already exist and belong to the operator.
    pub fn initialize(path: &Path) -> Result<(), RelayError> {
        let mut tmp = tempfile::NamedTempFile::new_in(parent(path))?;
        serialize(&Ledger::default(), &mut tmp)?;
        tmp.persist_noclobber(path).map_err(|e| e.error)?;
        sync_directory(path)?;
        Ok(())
    }

    /// Open an existing ledger. Missing or corrupt state fails closed.
    pub fn open(
        path: &Path,
        destination: PeerId,
        local_signer: PublicKey,
    ) -> Result<Self, RelayError> {
        let public_bytes: [u8; 32] = local_signer
            .to_bytes()
            .try_into()
            .map_err(|_| RelayError::EndpointMismatch)?;
        if PeerId::from_public_key_bytes(&public_bytes) != destination {
            return Err(RelayError::EndpointMismatch);
        }
        load(path)?;
        Ok(Self {
            path: path.to_owned(),
            destination,
            local_signer,
        })
    }

    /// Bind this session to both endpoint grants. Supply the expected origin
    /// signer from the trusted peer table and the bridge ID from transport
    /// authentication. Both tokens must delegate `mesh.relay` to that bridge.
    pub fn authorize(
        &self,
        trusted_origin: &PublicKey,
        authenticated_bridge: PeerId,
        origin_token: &[u8],
        destination_token: &[u8],
    ) -> Result<AuthorizedRelay, RelayError> {
        if trusted_origin == &self.local_signer {
            return Err(RelayError::EndpointMismatch);
        }
        let now = clock_tick()? / TICKS_PER_SECOND;
        let origin = verify_bridge(
            origin_token,
            trusted_origin,
            authenticated_bridge,
            self.destination,
            now,
        )?;
        let destination = verify_bridge(
            destination_token,
            &self.local_signer,
            authenticated_bridge,
            self.destination,
            now,
        )?;
        Ok(AuthorizedRelay {
            origin,
            destination,
        })
    }

    /// Atomically charge both signed caps for the actual payload size, then
    /// deliver exactly those bytes. A failed/partial sink write stays charged.
    pub fn receive(
        &self,
        session: &AuthorizedRelay,
        frame: &[u8],
        sink: &mut impl Write,
    ) -> Result<(), RelayError> {
        if session.destination.issuer() != &self.local_signer
            || session.destination.facts().dest_pin != self.destination
        {
            return Err(RelayError::EndpointMismatch);
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(self.path.with_added_extension("lock"))?;
        lock.lock()?;
        let tick = clock_tick()?;
        for cap in [&session.origin, &session.destination] {
            cap.authorize_at(tick / TICKS_PER_SECOND)?;
        }
        let mut ledger = load(&self.path)?;
        ledger.charge(
            &[&session.origin, &session.destination],
            frame.len() as u64,
            tick,
        )?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent(&self.path))?;
        serialize(&ledger, &mut tmp)?;
        tmp.persist(&self.path).map_err(|e| e.error)?;
        sync_directory(&self.path)?;
        drop(lock);
        sink.write_all(frame)?;
        Ok(())
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    tick: i64,
    budgets: BTreeMap<String, Usage>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Usage {
    total: u64,
    expires: i64,
    recent: Vec<Bucket>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bucket {
    tick: i64,
    bytes: u64,
}

impl Ledger {
    // This is a tentative transaction. The caller persists it only if BOTH
    // grants succeed and the entire updated ledger is durably written.
    fn charge(&mut self, caps: &[&BridgeCap], bytes: u64, tick: i64) -> Result<(), RelayError> {
        if tick < self.tick {
            return Err(RelayError::Clock);
        }
        self.tick = tick;
        let now = tick / TICKS_PER_SECOND;
        self.budgets.retain(|_, usage| usage.expires > now);
        for cap in caps {
            let facts = cap.facts();
            if now >= facts.expires {
                return Err(RelayAuthorizationError::Expiry.into());
            }
            let id = hex::encode(cap.budget_id());
            if self.budgets.len() >= MAX_BUDGETS && !self.budgets.contains_key(&id) {
                return Err(RelayError::LedgerFull);
            }
            let usage = self.budgets.entry(id).or_default();
            usage.expires = cap.budget_expires();
            if usage.total >= facts.total_bytes_cap || bytes > facts.total_bytes_cap - usage.total {
                return Err(RelayError::BridgeBudgetExhausted);
            }
            usage
                .recent
                .retain(|bucket| bucket.tick >= tick.saturating_sub(TICKS_PER_SECOND));
            let recent = usage
                .recent
                .iter()
                .try_fold(0u64, |n, b| n.checked_add(b.bytes))
                .ok_or(RelayError::RateLimited)?;
            if recent > facts.rate_limit_bps || bytes > facts.rate_limit_bps - recent {
                return Err(RelayError::RateLimited);
            }
            usage.total += bytes;
            if let Some(bucket) = usage.recent.last_mut().filter(|b| b.tick == tick) {
                bucket.bytes += bytes;
            } else {
                usage.recent.push(Bucket { tick, bytes });
            }
        }
        Ok(())
    }
}

fn clock_tick() -> Result<i64, RelayError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RelayError::Clock)?;
    i64::try_from(elapsed.as_millis() / 100).map_err(|_| RelayError::Clock)
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn load(path: &Path) -> io::Result<Ledger> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_LEDGER_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LEDGER_BYTES {
        return Err(io::Error::other("bridge ledger too large"));
    }
    let raw = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
    toml::from_str(raw).map_err(io::Error::other)
}

fn serialize(ledger: &Ledger, tmp: &mut tempfile::NamedTempFile) -> io::Result<()> {
    let raw = toml::to_string(ledger).map_err(io::Error::other)?;
    if raw.len() as u64 > MAX_LEDGER_BYTES {
        return Err(io::Error::other("bridge ledger too large"));
    }
    tmp.write_all(raw.as_bytes())?;
    tmp.as_file().sync_all()
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(parent(path))?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolling_rate_and_overflow_boundaries_are_conservative() {
        const NOW: i64 = 1_000_000;
        let issuer = PublicKey::from_pem(include_str!(
            "../testdata/bridge-vectors/issuer-public.pem.txt"
        ))
        .unwrap();
        let peer = |n| PeerId::from_public_key_bytes(&[n; 32]);
        let cap = verify_bridge(
            include_bytes!("../testdata/bridge-vectors/valid-bridge.bsk"),
            &issuer,
            peer(1),
            peer(2),
            NOW,
        )
        .unwrap();
        let mut ledger = Ledger::default();
        let start = NOW * TICKS_PER_SECOND;
        ledger.charge(&[&cap], 1 << 20, start).unwrap();
        assert!(matches!(
            ledger.charge(&[&cap], u64::MAX, start),
            Err(RelayError::BridgeBudgetExhausted)
        ));
        assert!(matches!(
            ledger.charge(&[&cap], 1, start + 10),
            Err(RelayError::RateLimited)
        ));
        ledger.charge(&[&cap], 1, start + 11).unwrap();
        assert!(matches!(
            ledger.charge(&[&cap], 1, start + 9),
            Err(RelayError::Clock)
        ));
    }
}
