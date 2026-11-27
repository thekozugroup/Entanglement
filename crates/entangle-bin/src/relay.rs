//! Explicit three-node relay of signed application bytes to a local bounded inbox.
use anyhow::{ensure, Context};
use entangle_peers::PeerStore;
use entangle_rpc::{RelayMessage, RelaySend};
use entangle_runtime::config::Config;
use entangle_scheduler::{
    relay::{RelayHandler, PREFIX},
    RemoteDispatch,
};
use entangle_signing::{
    relay_endpoint_key, BridgeReceiver, IdentityKeyPair, IdentityPublicKey, Signature,
};
use entangle_types::peer_id::PeerId;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::SystemTime,
};

const MAX_PAYLOAD: usize = 64 * 1024;
const MAX_GRANT: usize = 64 * 1024;
const INBOX_CAPACITY: usize = 16;

/// Local submitter plus independently optional bridge/receiver roles.
pub struct RelayService {
    cfg: entangle_runtime::config::BridgeConfig,
    tailnet_peers: Vec<entangle_runtime::config::TailnetPeerConfig>,
    ledger: Option<PathBuf>,
    identity: IdentityKeyPair,
    peers: PeerStore,
    client: Arc<RemoteDispatch>,
    inbox: Arc<Mutex<VecDeque<RelayMessage>>>,
}
#[derive(Serialize, Deserialize)]
struct Frame {
    origin: [u8; 32],
    body: RelaySend,
    signature: Vec<u8>,
}
impl Frame {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut v = b"entangle/relay/frame/1\0".to_vec();
        v.extend_from_slice(&self.origin);
        v.extend_from_slice(&self.body.via.as_bytes());
        v.extend_from_slice(&self.body.destination.as_bytes());
        for data in [
            &self.body.origin_grant,
            &self.body.destination_grant,
            &self.body.bytes,
        ] {
            v.extend_from_slice(&(data.len() as u32).to_be_bytes());
            v.extend_from_slice(data);
        }
        v
    }
    fn verify_grants(&self, dest: [u8; 32]) -> anyhow::Result<()> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
            .try_into()?;
        for (token, key) in [
            (&self.body.origin_grant, self.origin),
            (&self.body.destination_grant, dest),
        ] {
            entangle_signing::verify_bridge(
                token,
                &relay_endpoint_key(&key)?,
                self.body.via,
                self.body.destination,
                now,
            )?;
        }
        Ok(())
    }
    fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let mut message = PREFIX.to_vec();
        serde_json::to_writer(&mut message, self)?;
        Ok(message)
    }
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.body.bytes.len() <= MAX_PAYLOAD && !self.body.bytes.is_empty(),
            "relay payload must contain 1..65536 bytes"
        );
        ensure!(
            self.body.origin_grant.len() <= MAX_GRANT
                && self.body.destination_grant.len() <= MAX_GRANT,
            "relay grant too large"
        );
        let id = PeerId::from_public_key_bytes(&self.origin);
        ensure!(
            id != self.body.via
                && id != self.body.destination
                && self.body.via != self.body.destination,
            "relay requires three distinct peers"
        );
        Ok(())
    }
}
impl RelayService {
    /// Construct a sender. Enabling forwarding/receiving also requires persistent initialized accounting.
    pub fn new(
        cfg: &Config,
        identity: IdentityKeyPair,
        peers: PeerStore,
        client: Arc<RemoteDispatch>,
    ) -> anyhow::Result<Self> {
        let policy = cfg.mesh.bridge.clone();
        if policy.enabled {
            ensure!(
                policy.pairs == ["iroh<->tailscale"] || policy.pairs == ["tailscale<->iroh"],
                "enabled bridge requires the supported iroh/tailscale pair"
            );
            ensure!(
                ["iroh", "tailscale"]
                    .iter()
                    .all(|t| cfg.mesh.transports.iter().any(|p| p == t)),
                "bridge requires both iroh and tailscale transports"
            );
            ensure!(
                !cfg.scheduler.relay,
                "bridge forwarding requires direct scheduler routes"
            );
        }
        if policy.enabled || policy.receive {
            let path = policy
                .ledger
                .as_deref()
                .context("enabled relay requires ledger path")?;
            ensure!(path.is_absolute(), "relay ledger path must be absolute");
            BridgeReceiver::open(
                path,
                PeerId::from_public_key_bytes(identity.public().as_bytes()),
                relay_endpoint_key(identity.public().as_bytes())?,
            )
            .context("open relay ledger provisioned with mesh bridge init")?;
        }
        Ok(Self {
            ledger: policy.ledger.clone(),
            cfg: policy,
            tailnet_peers: cfg.scheduler.tailnet_peers.clone(),
            identity,
            peers,
            client,
            inbox: Arc::default(),
        })
    }
    fn id(&self) -> PeerId {
        PeerId::from_public_key_bytes(self.identity.public().as_bytes())
    }
    fn trusted_key(&self, peer: PeerId) -> anyhow::Result<[u8; 32]> {
        let p = self
            .peers
            .list_current()?
            .into_iter()
            .find(|p| p.peer_id == peer && p.trust == entangle_peers::TrustLevel::Trusted)
            .context("relay peer is not currently trusted")?;
        let bytes: [u8; 32] = hex::decode(p.public_key_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid trusted key length"))?;
        ensure!(
            PeerId::from_public_key_bytes(&bytes) == peer,
            "invalid paired identity"
        );
        Ok(bytes)
    }
    pub(crate) async fn send(&self, body: RelaySend) -> anyhow::Result<()> {
        let mut f = Frame {
            origin: *self.identity.public().as_bytes(),
            signature: Vec::new(),
            body,
        };
        f.validate()?;
        self.trusted_key(f.body.via)?;
        let dest = self.trusted_key(f.body.destination)?;
        f.verify_grants(dest)?;
        f.signature = self.identity.sign(&f.signed_bytes()).as_bytes().to_vec();
        let conn = self.client.connect_relay(f.body.via).await?;
        let response = conn.request(&f.encode()?).await?;
        conn.close();
        decode_result(&response)
    }
    pub(crate) fn read(&self) -> anyhow::Result<Option<RelayMessage>> {
        ensure!(self.cfg.receive, "relay inbox disabled");
        Ok(self.inbox.lock().unwrap().pop_front())
    }

    async fn process(
        &self,
        from: PeerId,
        incoming: Option<SocketAddr>,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        ensure!(
            data.len() <= 4 * (MAX_PAYLOAD + 2 * MAX_GRANT) + 2048,
            "relay envelope too large"
        );
        let f: Frame = serde_json::from_slice(data.strip_prefix(PREFIX).context("relay version")?)?;
        f.validate()?;
        let origin = PeerId::from_public_key_bytes(&f.origin);
        ensure!(self.trusted_key(origin)? == f.origin, "origin key mismatch");
        IdentityPublicKey::from_bytes(&f.origin)?
            .verify(&f.signed_bytes(), &Signature::from_bytes(&f.signature)?)?;
        let me = self.id();
        if me == f.body.via && from == origin {
            ensure!(self.cfg.enabled, "relay forwarding disabled");
            let dest = self.trusted_key(f.body.destination)?;
            f.verify_grants(dest)?;
            let conn = self.client.connect_relay(f.body.destination).await?;
            self.check_pair(
                (origin, incoming),
                (f.body.destination, conn.selected_socket()),
            )
            .await?;
            let path = self.ledger.clone().context("relay ledger unavailable")?;
            let (frame, n) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let bytes = account(&path, &f, &dest)?;
                Ok((f.encode()?, bytes.len()))
            })
            .await??;
            let response = conn.request(&frame).await?;
            conn.close();
            decode_result(&response)?;
            tracing::info!(%origin,destination=%PeerId::from_public_key_bytes(&dest),bytes=n,alpn="entangle/scheduler/1","bridge forwarded");
            return Ok(());
        }
        ensure!(
            me == f.body.destination && from == f.body.via && self.cfg.receive,
            "relay destination or forwarding peer mismatch"
        );
        let dest = *self.identity.public().as_bytes();
        let path = self.ledger.clone().context("relay ledger unavailable")?;
        let inbox = self.inbox.clone();
        tokio::task::spawn_blocking(move||->anyhow::Result<()>{
            let mut inbox=inbox.lock().unwrap();
            ensure!(inbox.len()<INBOX_CAPACITY,"relay inbox full");
            let bytes=account(&path,&f,&dest)?;
            tracing::info!(%origin,bridge=%from,bytes=bytes.len(),alpn="entangle/scheduler/1","bridge received");
            inbox.push_back(RelayMessage{origin,bridge:from,bytes});Ok(())
        }).await?
    }
    async fn check_pair(
        &self,
        source: (PeerId, Option<SocketAddr>),
        dest: (PeerId, Option<SocketAddr>),
    ) -> anyhow::Result<()> {
        let status = entangle_mesh_tailscale::MeshTailscale::default()
            .status()
            .await?;
        ensure!(status.is_running(), "Tailscale unavailable");
        let tail = |(peer, addr): (PeerId, Option<SocketAddr>)| -> anyhow::Result<bool> {
            let ip = addr
                .context("relay requires an observed direct IP path")?
                .ip();
            let is_prefix = match ip {
                IpAddr::V4(v) => v.octets()[0] == 100 && (64..=127).contains(&v.octets()[1]),
                IpAddr::V6(v) => v.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
            };
            if !is_prefix {
                return Ok(false);
            }
            let pk = hex::encode(self.trusted_key(peer)?);
            let mapping = self
                .tailnet_peers
                .iter()
                .find(|p| p.public_key.eq_ignore_ascii_case(&pk))
                .context("unconfigured tailnet relay peer")?;
            ensure!(
                status
                    .peers
                    .iter()
                    .any(|p| p.online && p.node_id == mapping.node_id && p.ips.contains(&ip)),
                "tailnet device/IP does not match the paired peer"
            );
            Ok(true)
        };
        ensure!(
            tail(source)? != tail(dest)?,
            "transport pair is not iroh<->tailscale"
        );
        Ok(())
    }
}
fn account(path: &std::path::Path, f: &Frame, dest: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let receiver = BridgeReceiver::open(path, f.body.destination, relay_endpoint_key(dest)?)?;
    let session = receiver.authorize(
        &relay_endpoint_key(&f.origin)?,
        f.body.via,
        &f.body.origin_grant,
        &f.body.destination_grant,
    )?;
    let mut bytes = Vec::new();
    receiver.receive(&session, &f.body.bytes, &mut bytes)?;
    Ok(bytes)
}
fn decode_result(response: &[u8]) -> anyhow::Result<()> {
    ensure!(response.len() <= 1024, "oversized relay receipt");
    let result: Result<(), String> = serde_json::from_slice(response)?;
    result.map_err(anyhow::Error::msg)
}
#[async_trait::async_trait]
impl RelayHandler for RelayService {
    async fn handle(&self, peer: PeerId, path: Option<SocketAddr>, bytes: Vec<u8>) -> Vec<u8> {
        let result = self
            .process(peer, path, bytes)
            .await
            .map_err(|e| e.to_string().chars().take(192).collect::<String>());
        serde_json::to_vec(&result).expect("serialize relay receipt")
    }
}
