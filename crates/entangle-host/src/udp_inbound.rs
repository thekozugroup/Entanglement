//! The guest's `wasi:sockets/udp`, with inbound datagrams filtered by the
//! plugin's grants.
//!
//! wasmtime-wasi checks every address a guest *sends* to
//! (`socket_addr_check`), but an unconnected UDP socket — what
//! `UdpSocket::send_to` / `recv_from` use — then *receives* from any source:
//! a plugin limited to `net.wan { hosts = ["resolver.example:53"] }` would
//! hear from any LAN machine or internet host that writes to its port, an
//! inbound channel no grant provides for. [`crate::engine::HostEngine`]
//! therefore links this interface over wasmtime-wasi's: every call is
//! delegated to wasmtime-wasi unchanged, except that `receive` drops each
//! datagram whose source the plugin could not send to — refused by the
//! instance's [`NetRules`](crate::net::NetRules), or allowed only by a
//! grant that has since been withdrawn.

use crate::capability::NetLiveness;
use crate::net::{NetRules, Via};
use crate::state::HostState;
use std::net::SocketAddr;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::bindings::sockets::network::{IpAddressFamily, IpSocketAddress, Network};
use wasmtime_wasi::p2::bindings::sockets::udp::{
    self, HostIncomingDatagramStream, HostOutgoingDatagramStream, HostUdpSocket, IncomingDatagram,
    IncomingDatagramStream, OutgoingDatagram, OutgoingDatagramStream, UdpSocket,
};
use wasmtime_wasi::p2::{DynPollable, SocketResult};
use wasmtime_wasi::sockets::{SocketAddrUse, WasiSocketsView};

/// Which sources an instance's UDP sockets may receive from: the same
/// rules (and grant liveness) that decide where it may send.
#[derive(Debug, Clone)]
pub(crate) struct InboundRules {
    pub(crate) rules: NetRules,
    pub(crate) live: Option<NetLiveness>,
}

impl InboundRules {
    /// `true` when a datagram from `src` may reach the guest.
    pub(crate) fn allows(&self, src: SocketAddr) -> bool {
        match self.rules.check(src, SocketAddrUse::UdpOutgoingDatagram) {
            Some(Via::Lan) => self.live.as_ref().is_none_or(NetLiveness::lan_live),
            Some(Via::Wan) => self.live.as_ref().is_none_or(NetLiveness::wan_live),
            Some(Via::LocalBind) | None => false,
        }
    }
}

impl udp::Host for HostState {}

impl HostUdpSocket for HostState {
    async fn start_bind(
        &mut self,
        this: Resource<UdpSocket>,
        network: Resource<Network>,
        local_address: IpSocketAddress,
    ) -> SocketResult<()> {
        HostUdpSocket::start_bind(&mut self.sockets(), this, network, local_address).await
    }

    fn finish_bind(&mut self, this: Resource<UdpSocket>) -> SocketResult<()> {
        HostUdpSocket::finish_bind(&mut self.sockets(), this)
    }

    async fn stream(
        &mut self,
        this: Resource<UdpSocket>,
        remote_address: Option<IpSocketAddress>,
    ) -> SocketResult<(
        Resource<IncomingDatagramStream>,
        Resource<OutgoingDatagramStream>,
    )> {
        HostUdpSocket::stream(&mut self.sockets(), this, remote_address).await
    }

    fn local_address(&mut self, this: Resource<UdpSocket>) -> SocketResult<IpSocketAddress> {
        HostUdpSocket::local_address(&mut self.sockets(), this)
    }

    fn remote_address(&mut self, this: Resource<UdpSocket>) -> SocketResult<IpSocketAddress> {
        HostUdpSocket::remote_address(&mut self.sockets(), this)
    }

    fn address_family(&mut self, this: Resource<UdpSocket>) -> wasmtime::Result<IpAddressFamily> {
        HostUdpSocket::address_family(&mut self.sockets(), this)
    }

    fn unicast_hop_limit(&mut self, this: Resource<UdpSocket>) -> SocketResult<u8> {
        HostUdpSocket::unicast_hop_limit(&mut self.sockets(), this)
    }

    fn set_unicast_hop_limit(&mut self, this: Resource<UdpSocket>, value: u8) -> SocketResult<()> {
        HostUdpSocket::set_unicast_hop_limit(&mut self.sockets(), this, value)
    }

    fn receive_buffer_size(&mut self, this: Resource<UdpSocket>) -> SocketResult<u64> {
        HostUdpSocket::receive_buffer_size(&mut self.sockets(), this)
    }

    fn set_receive_buffer_size(
        &mut self,
        this: Resource<UdpSocket>,
        value: u64,
    ) -> SocketResult<()> {
        HostUdpSocket::set_receive_buffer_size(&mut self.sockets(), this, value)
    }

    fn send_buffer_size(&mut self, this: Resource<UdpSocket>) -> SocketResult<u64> {
        HostUdpSocket::send_buffer_size(&mut self.sockets(), this)
    }

    fn set_send_buffer_size(&mut self, this: Resource<UdpSocket>, value: u64) -> SocketResult<()> {
        HostUdpSocket::set_send_buffer_size(&mut self.sockets(), this, value)
    }

    fn subscribe(&mut self, this: Resource<UdpSocket>) -> wasmtime::Result<Resource<DynPollable>> {
        HostUdpSocket::subscribe(&mut self.sockets(), this)
    }

    fn drop(&mut self, this: Resource<UdpSocket>) -> wasmtime::Result<()> {
        HostUdpSocket::drop(&mut self.sockets(), this)
    }
}

impl HostIncomingDatagramStream for HostState {
    fn receive(
        &mut self,
        this: Resource<IncomingDatagramStream>,
        max_results: u64,
    ) -> SocketResult<Vec<IncomingDatagram>> {
        let datagrams =
            HostIncomingDatagramStream::receive(&mut self.sockets(), this, max_results)?;
        let received = datagrams.len();
        let kept: Vec<IncomingDatagram> = datagrams
            .into_iter()
            .filter(|d| {
                self.inbound
                    .as_ref()
                    .is_some_and(|i| i.allows(SocketAddr::from(d.remote_address)))
            })
            .collect();
        if kept.len() < received {
            tracing::debug!(
                plugin = %self.plugin_id,
                dropped = received - kept.len(),
                "inbound datagrams from sources outside the plugin's grants dropped"
            );
        }
        Ok(kept)
    }

    fn subscribe(
        &mut self,
        this: Resource<IncomingDatagramStream>,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        HostIncomingDatagramStream::subscribe(&mut self.sockets(), this)
    }

    fn drop(&mut self, this: Resource<IncomingDatagramStream>) -> wasmtime::Result<()> {
        HostIncomingDatagramStream::drop(&mut self.sockets(), this)
    }
}

impl HostOutgoingDatagramStream for HostState {
    fn check_send(&mut self, this: Resource<OutgoingDatagramStream>) -> SocketResult<u64> {
        HostOutgoingDatagramStream::check_send(&mut self.sockets(), this)
    }

    async fn send(
        &mut self,
        this: Resource<OutgoingDatagramStream>,
        datagrams: Vec<OutgoingDatagram>,
    ) -> SocketResult<u64> {
        HostOutgoingDatagramStream::send(&mut self.sockets(), this, datagrams).await
    }

    fn subscribe(
        &mut self,
        this: Resource<OutgoingDatagramStream>,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        HostOutgoingDatagramStream::subscribe(&mut self.sockets(), this)
    }

    fn drop(&mut self, this: Resource<OutgoingDatagramStream>) -> wasmtime::Result<()> {
        HostOutgoingDatagramStream::drop(&mut self.sockets(), this)
    }
}
