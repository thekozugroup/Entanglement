//! Keep the authenticated scheduler service alive when its Tailscale interface disappears.

use super::*;
use entangle_mesh_iroh::{MeshConn, MeshIrohError};

const FIRST_RETRY: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(15);

#[derive(Clone, Debug)]
enum EndpointState {
    Listening(Arc<MeshIroh>),
    Recovering,
    Stopped,
}

/// Stable outbound handle. An interrupted request is never retried on a new endpoint.
#[derive(Debug)]
struct TailnetTransport {
    state: watch::Sender<EndpointState>,
    peer_id: PeerId,
    key: [u8; 32],
}

impl TailnetTransport {
    fn new(identity: &IdentityKeyPair) -> Self {
        let key = *identity.public().as_bytes();
        Self {
            peer_id: PeerId::from_public_key_bytes(&key),
            key,
            state: watch::channel(EndpointState::Recovering).0,
        }
    }

    fn current(&self) -> Option<Arc<MeshIroh>> {
        match &*self.state.borrow() {
            EndpointState::Listening(endpoint) => Some(endpoint.clone()),
            _ => None,
        }
    }

    fn endpoint_for(&self, peer: &IrohPeer) -> Result<Arc<MeshIroh>, MeshIrohError> {
        self.current().ok_or_else(|| MeshIrohError::Connect {
            peer: peer.peer_id,
            reason: "Tailscale scheduler endpoint unavailable".to_owned(),
        })
    }

    fn publish(&self, endpoint: Arc<MeshIroh>) -> bool {
        self.state.send_if_modified(|state| {
            if matches!(state, EndpointState::Recovering) {
                *state = EndpointState::Listening(endpoint);
                true
            } else {
                false
            }
        })
    }

    fn withdraw(&self, next: EndpointState) -> Option<Arc<MeshIroh>> {
        let mut previous = None;
        self.state.send_if_modified(|state| {
            if matches!(state, EndpointState::Stopped) {
                return false;
            }
            if let EndpointState::Listening(endpoint) = std::mem::replace(state, next) {
                previous = Some(endpoint);
            }
            true
        });
        previous
    }

    async fn close(previous: Option<Arc<MeshIroh>>) {
        if let Some(endpoint) = previous {
            // The upstream QUIC receive driver can already be terminal.
            let _ = tokio::time::timeout(BIND_TIMEOUT, endpoint.shutdown()).await;
        }
    }
}

#[async_trait::async_trait]
impl MeshTransport for TailnetTransport {
    fn local_peer_id(&self) -> PeerId {
        self.peer_id
    }

    fn local_public_key(&self) -> [u8; 32] {
        self.key
    }

    fn local_addrs(&self) -> Vec<SocketAddr> {
        self.current().map_or_else(Vec::new, |ep| ep.local_addrs())
    }

    async fn connect(&self, peer: &IrohPeer) -> Result<MeshConn, MeshIrohError> {
        self.endpoint_for(peer)?.connect(peer).await
    }

    async fn request(&self, peer: &IrohPeer, payload: &[u8]) -> Result<Vec<u8>, MeshIrohError> {
        self.endpoint_for(peer)?.request(peer, payload).await
    }

    async fn request_with_upload(
        &self,
        peer: &IrohPeer,
        payload: &[u8],
    ) -> Result<(Vec<u8>, Option<u64>), MeshIrohError> {
        self.endpoint_for(peer)?
            .request_with_upload(peer, payload)
            .await
    }

    async fn accept(&self) -> Result<Option<MeshConn>, MeshIrohError> {
        let mut rx = self.state.subscribe();
        loop {
            let state = rx.borrow_and_update().clone();
            match state {
                EndpointState::Listening(ep) => {
                    if let Some(conn) = ep.accept().await? {
                        return Ok(Some(conn));
                    }
                }
                EndpointState::Stopped => return Ok(None),
                EndpointState::Recovering => {}
            }
            if rx.changed().await.is_err() {
                return Ok(None);
            }
        }
    }

    async fn shutdown(&self) {
        Self::close(self.withdraw(EndpointState::Stopped)).await;
    }
}

pub(super) struct TailnetSupervisor {
    transport: Arc<TailnetTransport>,
    identity: IdentityKeyPair,
    requested: SocketAddr,
    mesh: MeshTailscale,
    mappings: Vec<Mapping>,
    addresses: Arc<SchedulerAddresses>,
    active: watch::Sender<Vec<String>>,
    refresh_interval: Duration,
}

pub(super) async fn prepare(
    requested: SocketAddr,
    identity: &IdentityKeyPair,
    store: &PeerStore,
    mesh: MeshTailscale,
    mappings: Vec<Mapping>,
    peer_ids: BTreeSet<PeerId>,
    refresh_interval: Duration,
) -> anyhow::Result<PreparedScheduler> {
    ensure!(
        requested.ip().is_unspecified() || is_tailnet_ip(requested.ip()),
        "Tailscale scheduler bind must select a local Tailscale IP or an address-family wildcard"
    );
    let addresses = Arc::new(SchedulerAddresses {
        static_peers: HashMap::new(),
        tailnet: RwLock::new(HashMap::new()),
        lan: None,
        trust: PeerStoreAllowlist::new(store.clone()),
    });
    let (active, active_transports) = watch::channel(Vec::new());
    let transport = Arc::new(TailnetTransport::new(identity));
    let mut supervisor = TailnetSupervisor {
        transport: transport.clone(),
        identity: identity.clone(),
        requested,
        mesh,
        mappings,
        addresses: addresses.clone(),
        active,
        refresh_interval,
    };
    if let Err(error) = supervisor.activate().await {
        tracing::warn!(%error, "Tailscale scheduler starting offline; waiting for a verified local bind");
    }
    Ok(PreparedScheduler {
        lan: None,
        transport,
        addresses,
        peer_ids: peer_ids.into_iter().collect(),
        active_transports,
        refresh: None,
        serving: None,
        listener: Some(Listener::Tailnet(Box::new(supervisor))),
    })
}

impl TailnetSupervisor {
    fn report(&self, status: Option<&TailnetStatus>) {
        if let Ok(mut routes) = self.addresses.tailnet.write() {
            *routes = status.map_or_else(HashMap::new, |s| {
                snapshot_routes(s, &self.mappings, self.requested)
            });
        }
        self.active.send_if_modified(|names| {
            if status.is_none() == names.is_empty() {
                return false;
            }
            names.clear();
            if status.is_some() {
                names.push("tailscale".to_owned());
            }
            true
        });
    }

    pub(super) async fn run(mut self, server: Arc<RemoteTaskServer>) {
        let mut state = self.transport.state.subscribe();
        loop {
            if let Some(endpoint) = self.transport.current() {
                let bound = endpoint.local_addrs().into_iter().next();
                tokio::select! {
                    biased;
                    _ = state.wait_for(|s| matches!(s, EndpointState::Stopped)) => break,
                    _ = entangle_scheduler::serve_tasks(endpoint, server.clone()) => {
                        tracing::warn!("Tailscale scheduler accept loop ended; replacing endpoint");
                    }
                    Err(error) = self.monitor_address(bound) => {
                        tracing::warn!(%error, "Tailscale scheduler address unavailable");
                    }
                }
                let previous = self.transport.withdraw(EndpointState::Recovering);
                self.report(None);
                // Complete retirement even if shutdown arrives while the old socket is draining.
                TailnetTransport::close(previous).await;
            }
            tokio::select! {
                biased;
                _ = state.wait_for(|s| matches!(s, EndpointState::Stopped)) => break,
                _ = self.recover() => {}
            }
        }
        self.report(None);
    }

    async fn recover(&mut self) {
        let mut delay = FIRST_RETRY;
        let mut previous_error = None;
        loop {
            tokio::time::sleep(delay).await;
            match self.activate().await {
                Ok(()) => return,
                Err(error) => {
                    let message = error.to_string();
                    if previous_error.as_ref() != Some(&message) {
                        tracing::warn!(%error, "Tailscale scheduler rebind pending");
                        previous_error = Some(message);
                    }
                    delay = (delay * 2).min(MAX_RETRY);
                }
            }
        }
    }

    async fn monitor_address(&self, bound: Option<SocketAddr>) -> anyhow::Result<()> {
        // Check the *current* exact bind; multiple local IPs may change order. On replacement,
        // A new bind may choose a different local IP only when the original config allowed it.
        let bound = bound.context("missing bound Tailscale scheduler socket")?;
        loop {
            tokio::time::sleep(self.refresh_interval).await;
            let (status, _) = online_status(&self.mesh, bound).await?;
            self.report(Some(&status));
        }
    }

    async fn activate(&mut self) -> anyhow::Result<()> {
        // Revalidate the operator's original address/family against current local Tailscale IPs.
        // Keep the actual startup port even when the operator originally selected port zero.
        let (status, local) = online_status(&self.mesh, self.requested).await?;
        let endpoint =
            tokio::time::timeout(BIND_TIMEOUT, bind_scheduler(local, false, &self.identity))
                .await
                .context("Tailscale scheduler bind timed out")??;
        let port = bound_port(local, &endpoint.local_addrs())?;
        if self.transport.publish(endpoint) {
            self.requested.set_port(port);
            self.report(Some(&status));
        }
        Ok(())
    }
}

fn bound_port(requested: SocketAddr, sockets: &[SocketAddr]) -> anyhow::Result<u16> {
    let [actual] = sockets else {
        anyhow::bail!("expected one bound Tailscale scheduler socket")
    };
    ensure!(
        actual.ip() == requested.ip()
            && actual.port() != 0
            && (requested.port() == 0 || requested.port() == actual.port()),
        "unexpected Tailscale scheduler bind {actual} for {requested}"
    );
    Ok(actual.port())
}

#[cfg(test)]
mod tests;
