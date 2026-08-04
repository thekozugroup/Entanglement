//! mDNS service registration and browsing for the `mesh.local` transport.

use crate::{
    errors::DiscoveryError,
    peer::{HardwareAdvert, LocalPeer, PeerSeen},
};
use entangle_types::peer_id::PeerId;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// mDNS-SD service type for Entanglement daemons.
const SERVICE_TYPE: &str = "_entangle._udp.local.";

/// Upper bound on advertised CPU cores. Non-finite, negative, or larger values
/// are treated as poisoned and coerced to `0.0`.
const MAX_CPU_CORES: f32 = 4096.0;
/// Upper bound on advertised host memory (1 PiB).
const MAX_MEMORY_BYTES: u64 = 1 << 50;
/// Upper bound on advertised GPU VRAM (16 TiB).
const MAX_GPU_VRAM_BYTES: u64 = 1 << 44;
/// Upper bound on advertised network bandwidth (~17.6 Tbit/s).
const MAX_BANDWIDTH_BPS: u64 = 1 << 44;
/// Maximum byte length of a sanitized human-facing label (display name,
/// version, NPU vendor). Longer values are truncated on a UTF-8 char boundary.
const MAX_LABEL_LEN: usize = 128;
/// Maximum byte length of a single DNS host label (RFC 1035 §2.3.4).
const MAX_HOSTNAME_LEN: usize = 63;

/// Events emitted by the discovery layer.
#[derive(Clone, Debug)]
pub enum DiscoveryEvent {
    /// A new peer appeared on the network.
    PeerAppeared(PeerSeen),
    /// An already-known peer re-announced (addresses or metadata changed).
    PeerUpdated(PeerSeen),
    /// A peer sent a goodbye or its TTL expired.
    PeerDisappeared {
        /// Identifier of the departing peer.
        peer_id: PeerId,
        /// Last-known display name.
        display_name: String,
    },
}

/// Configuration for [`Discovery`].
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    /// Description of the local node to advertise.
    pub local: LocalPeer,
    /// Re-announce interval in seconds. Handled internally by mdns_sd; stored
    /// here for documentation purposes. Default: 30.
    pub announce_interval_secs: u64,
    /// Capacity of the broadcast channel. Default: 256.
    pub channel_capacity: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            local: LocalPeer {
                peer_id: PeerId::from_public_key_bytes(&[0u8; 32]),
                display_name: "entangled".to_string(),
                port: 7700,
                version: env!("CARGO_PKG_VERSION").to_string(),
                hardware: None,
            },
            announce_interval_secs: 30,
            channel_capacity: 256,
        }
    }
}

/// mDNS-based LAN peer discovery handle.
///
/// Create with [`Discovery::new`], then call [`Discovery::start_announcing`]
/// and [`Discovery::spawn_browser`] to begin the discovery loop.
pub struct Discovery {
    daemon: ServiceDaemon,
    sender: broadcast::Sender<DiscoveryEvent>,
    peers: Arc<RwLock<HashMap<PeerId, PeerSeen>>>,
    local: LocalPeer,
    instance_name: String,
    /// Set once [`Discovery::start_announcing`] has registered the service, so
    /// a second call is rejected instead of double-registering.
    announcing: AtomicBool,
    /// Handle to the background browse task, if one has been spawned. Guards
    /// against spawning two racing browsers over the shared peer map.
    browser: Mutex<Option<JoinHandle<()>>>,
}

impl Discovery {
    /// Create a new `Discovery` handle from the given config.
    pub fn new(config: DiscoveryConfig) -> Result<Self, DiscoveryError> {
        let daemon = ServiceDaemon::new().map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        let (sender, _) = broadcast::channel(config.channel_capacity);
        let peers = Arc::new(RwLock::new(HashMap::new()));

        // Instance name is the peer_id hex — guaranteed unique on the link.
        let instance_name = config.local.peer_id.to_hex();

        Ok(Self {
            daemon,
            sender,
            peers,
            local: config.local,
            instance_name,
            announcing: AtomicBool::new(false),
            browser: Mutex::new(None),
        })
    }

    /// Register this node as an mDNS service. Blocks until the registration
    /// command is queued in the daemon.
    ///
    /// Idempotency guard: a second call while already announcing returns
    /// [`DiscoveryError::AlreadyRunning`] rather than registering the service
    /// twice.
    pub fn start_announcing(&self) -> Result<(), DiscoveryError> {
        // Only the first caller flips the flag from `false`; anyone else bails.
        if self.announcing.swap(true, Ordering::SeqCst) {
            return Err(DiscoveryError::AlreadyRunning);
        }
        match self.register_service() {
            Ok(()) => {
                debug!(
                    peer_id = %self.local.peer_id,
                    port = self.local.port,
                    "mDNS service registered"
                );
                Ok(())
            }
            Err(e) => {
                // Roll the flag back so a later retry is still possible.
                self.announcing.store(false, Ordering::SeqCst);
                Err(e)
            }
        }
    }

    /// Build the mDNS [`ServiceInfo`] for this node and hand it to the daemon.
    fn register_service(&self) -> Result<(), DiscoveryError> {
        let host_ip = local_ipv4().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let hostname = format!("{}.local.", hostname(&self.local.peer_id));
        let txt = self.txt_map();
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &self.instance_name,
            &hostname,
            host_ip,
            self.local.port,
            txt,
        )
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        self.daemon
            .register(info)
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        Ok(())
    }

    /// Spawn a Tokio task that consumes the mDNS browse stream and forwards
    /// [`DiscoveryEvent`]s to all broadcast subscribers.
    ///
    /// The task handle is stored internally; it runs until the daemon shuts
    /// down, the browse channel closes, or [`Discovery::stop_browser`] (or drop)
    /// aborts it. Calling this a second time while a browser is already running
    /// returns [`DiscoveryError::AlreadyRunning`] instead of spawning a second
    /// task racing the shared peer map.
    pub fn spawn_browser(&self) -> Result<(), DiscoveryError> {
        // Hold the slot lock across the spawn so two callers can't both win.
        let mut slot = self.browser.lock();
        if slot.is_some() {
            return Err(DiscoveryError::AlreadyRunning);
        }

        let receiver = self
            .daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        let sender = self.sender.clone();
        let peers = self.peers.clone();
        let self_id = self.local.peer_id;

        let handle = tokio::spawn(async move {
            loop {
                match receiver.recv_async().await {
                    Ok(event) => match event {
                        ServiceEvent::ServiceResolved(info) => {
                            if let Some(peer) = parse_service(&info) {
                                if peer.peer_id == self_id {
                                    continue; // skip our own announcement
                                }
                                let mut map = peers.write().await;
                                let evt = if map.contains_key(&peer.peer_id) {
                                    DiscoveryEvent::PeerUpdated(peer.clone())
                                } else {
                                    DiscoveryEvent::PeerAppeared(peer.clone())
                                };
                                map.insert(peer.peer_id, peer);
                                let _ = sender.send(evt);
                            }
                        }
                        ServiceEvent::ServiceRemoved(_, fullname) => {
                            // fullname: "<instance>.<service-type>"; instance == peer_id hex
                            if let Some((instance, _)) = fullname.split_once('.') {
                                if let Ok(peer_id) = PeerId::from_hex(instance) {
                                    let mut map = peers.write().await;
                                    if let Some(p) = map.remove(&peer_id) {
                                        let _ = sender.send(DiscoveryEvent::PeerDisappeared {
                                            peer_id,
                                            display_name: p.display_name,
                                        });
                                    }
                                }
                            }
                        }
                        _ => {} // SearchStarted, ServiceFound — not actionable here
                    },
                    Err(_) => {
                        debug!("mDNS browse channel closed; browser task exiting");
                        break;
                    }
                }
            }
        });

        *slot = Some(handle);
        Ok(())
    }

    /// Abort the background browser task if one is running.
    ///
    /// Returns [`DiscoveryError::NotRunning`] if no browser has been spawned
    /// (or it was already stopped).
    pub fn stop_browser(&self) -> Result<(), DiscoveryError> {
        match self.browser.lock().take() {
            Some(handle) => {
                handle.abort();
                Ok(())
            }
            None => Err(DiscoveryError::NotRunning),
        }
    }

    /// Subscribe to [`DiscoveryEvent`]s. Can be called multiple times for fan-out.
    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.sender.subscribe()
    }

    /// Return a point-in-time snapshot of all currently known remote peers.
    pub async fn snapshot_peers(&self) -> Vec<PeerSeen> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Unregister the mDNS service and shut down the daemon.
    ///
    /// Also aborts the browser task and clears the announcing guard so the
    /// handle is left in a consistent, restartable state.
    pub fn shutdown(&self) -> Result<(), DiscoveryError> {
        if let Some(handle) = self.browser.lock().take() {
            handle.abort();
        }
        self.announcing.store(false, Ordering::SeqCst);
        self.daemon
            .shutdown()
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        Ok(())
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn txt_map(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("peer_id".into(), self.local.peer_id.to_hex());
        m.insert("display_name".into(), self.local.display_name.clone());
        m.insert("version".into(), self.local.version.clone());
        if let Some(hw) = &self.local.hardware {
            m.insert("cpu_cores".into(), hw.cpu_cores.to_string());
            m.insert("memory_bytes".into(), hw.memory_bytes.to_string());
            if let Some(backend) = hw.gpu_backend {
                // Use serde's kebab-case representation for forward-compat.
                let backend_str = match backend {
                    entangle_types::resource::GpuBackend::Metal => "metal",
                    entangle_types::resource::GpuBackend::Cuda => "cuda",
                    entangle_types::resource::GpuBackend::Vulkan => "vulkan",
                    entangle_types::resource::GpuBackend::Rocm => "rocm",
                    entangle_types::resource::GpuBackend::Any => "any",
                };
                m.insert("gpu_backend".into(), backend_str.into());
                m.insert("gpu_vram".into(), hw.gpu_vram_bytes.to_string());
            }
            m.insert(
                "network_bandwidth_bps".into(),
                hw.network_bandwidth_bps.to_string(),
            );
            if let Some(npu) = &hw.npu_vendor {
                m.insert("npu_vendor".into(), npu.clone());
            }
        }
        m
    }
}

// ── free functions ────────────────────────────────────────────────────────────

/// Parse a [`mdns_sd::ResolvedService`] into a [`PeerSeen`], returning `None`
/// if mandatory TXT fields are missing or malformed.
fn parse_service(info: &mdns_sd::ResolvedService) -> Option<PeerSeen> {
    let txt = info.get_properties();
    let peer_id_hex = txt.get_property_val_str("peer_id")?;
    let peer_id = PeerId::from_hex(peer_id_hex)
        .map_err(|e| warn!("bad peer_id in mDNS TXT: {e}"))
        .ok()?;
    // display_name / version are untrusted and flow into CLI output and logs;
    // strip control chars and bound their length before storing them.
    let display_name = sanitize_label(txt.get_property_val_str("display_name").unwrap_or(""));
    let version = sanitize_label(txt.get_property_val_str("version").unwrap_or(""));

    // Convert ScopedIp → IpAddr (extract address, drop interface scope).
    // ScopedIp is #[non_exhaustive] so we must have a wildcard arm.
    let addresses: Vec<IpAddr> = info
        .get_addresses()
        .iter()
        .filter_map(|s| match s {
            mdns_sd::ScopedIp::V4(v4) => Some(IpAddr::V4(*v4.addr())),
            mdns_sd::ScopedIp::V6(v6) => Some(IpAddr::V6(*v6.addr())),
            _ => None, // forward-compat with future variants
        })
        .collect();

    // ── parse optional hardware advertisement ────────────────────────────
    let hardware = parse_hardware(txt);

    Some(PeerSeen {
        peer_id,
        display_name,
        addresses,
        port: info.get_port(),
        version,
        hardware,
        last_seen: SystemTime::now(),
    })
}

/// Parse hardware advertisement fields from a mDNS TXT property map.
///
/// Returns `None` if the mandatory `cpu_cores` key is absent (i.e. the remote
/// peer does not advertise hardware).
fn parse_hardware(txt: &mdns_sd::TxtProperties) -> Option<HardwareAdvert> {
    use entangle_types::resource::GpuBackend;

    // `f32::from_str` accepts "NaN"/"inf"/"1e40"; sanitize before use so poisoned
    // values never reach the scheduler.
    let cpu_cores = parse_cpu_cores(txt.get_property_val_str("cpu_cores")?);

    let memory_bytes = parse_bytes(txt.get_property_val_str("memory_bytes"), MAX_MEMORY_BYTES);

    let gpu_backend: Option<GpuBackend> =
        txt.get_property_val_str("gpu_backend")
            .and_then(|s| match s {
                "metal" => Some(GpuBackend::Metal),
                "cuda" => Some(GpuBackend::Cuda),
                "vulkan" => Some(GpuBackend::Vulkan),
                "rocm" => Some(GpuBackend::Rocm),
                "any" => Some(GpuBackend::Any),
                other => {
                    warn!("unknown gpu_backend in mDNS TXT: {other}");
                    None
                }
            });

    let gpu_vram_bytes = parse_bytes(txt.get_property_val_str("gpu_vram"), MAX_GPU_VRAM_BYTES);

    let network_bandwidth_bps = parse_bytes(
        txt.get_property_val_str("network_bandwidth_bps"),
        MAX_BANDWIDTH_BPS,
    );

    // npu_vendor is untrusted and surfaces in logs/CLI output — sanitize it.
    let npu_vendor = txt.get_property_val_str("npu_vendor").map(sanitize_label);

    Some(HardwareAdvert {
        cpu_cores,
        memory_bytes,
        gpu_backend,
        gpu_vram_bytes,
        network_bandwidth_bps,
        npu_vendor,
    })
}

/// Parse a CPU-core count from an untrusted TXT value.
///
/// `f32::from_str` happily accepts `"NaN"`, `"inf"`, `"-inf"`, and huge
/// exponents like `"1e40"`, so the naive `.parse().unwrap_or(0.0)` fallback
/// never fires for those poisoned inputs. Anything non-finite, negative, or
/// above [`MAX_CPU_CORES`] is coerced to `0.0`.
fn parse_cpu_cores(raw: &str) -> f32 {
    raw.parse::<f32>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0 && *v <= MAX_CPU_CORES)
        .unwrap_or(0.0)
}

/// Parse a byte-count TXT value, defaulting to `0` on absence/parse failure and
/// clamping to `ceiling` (an untrusted peer can otherwise advertise
/// `u64::MAX`).
fn parse_bytes(raw: Option<&str>, ceiling: u64) -> u64 {
    raw.and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
        .min(ceiling)
}

/// Sanitize an untrusted TXT string for safe display and structured logging.
///
/// Drops control characters (`char::is_control`, e.g. ANSI escapes, NULs,
/// newlines) and truncates to [`MAX_LABEL_LEN`] bytes on a UTF-8 char boundary
/// so a malicious peer cannot forge log lines or blow up CLI output.
fn sanitize_label(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_LABEL_LEN));
    for c in input.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_LABEL_LEN {
            break;
        }
        out.push(c);
    }
    out
}

/// Return a DNS-safe host label for this node's mDNS address record.
///
/// Preference order:
/// 1. `$HOSTNAME` / `$HOST` (explicit override, e.g. in containers),
/// 2. the trimmed contents of `/etc/hostname`,
/// 3. `entangled-<peer_id_hex[..8]>` as a guaranteed-unique last resort.
///
/// The literal `"entangled"` is intentionally *not* used as a fallback: under
/// systemd neither env var is set, so every node would advertise
/// `entangled.local.` and mdns-sd would merge all colliding nodes' `A` records
/// into each peer's address list. The chosen value is always sanitized to the
/// DNS label charset.
fn hostname(peer_id: &PeerId) -> String {
    if let Ok(env_host) = std::env::var("HOSTNAME").or_else(|_| std::env::var("HOST")) {
        let label = sanitize_hostname_label(&env_host);
        if !label.is_empty() {
            return label;
        }
    }

    if let Ok(contents) = std::fs::read_to_string("/etc/hostname") {
        let label = sanitize_hostname_label(contents.trim());
        if !label.is_empty() {
            return label;
        }
    }

    unique_fallback_hostname(peer_id)
}

/// Guaranteed-unique-on-the-link host label derived from the peer id.
fn unique_fallback_hostname(peer_id: &PeerId) -> String {
    let hex = peer_id.to_hex();
    let suffix = &hex[..hex.len().min(8)];
    format!("entangled-{suffix}")
}

/// Reduce an arbitrary string to a single DNS host label: keep only ASCII
/// letters, digits and hyphens, lower-case it, strip leading/trailing hyphens,
/// and bound it to [`MAX_HOSTNAME_LEN`] bytes. Returns an empty string if
/// nothing usable remains.
fn sanitize_hostname_label(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(MAX_HOSTNAME_LEN)
        .collect::<String>()
        .to_ascii_lowercase()
        .trim_matches('-')
        .to_string()
}

/// Best-effort detection of the primary outbound IPv4 address by probing a
/// UDP connect (no packets are sent).
fn local_ipv4() -> Option<IpAddr> {
    use std::net::UdpSocket;
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

impl Drop for Discovery {
    /// Best-effort cleanup so no background task or daemon socket outlives the
    /// handle: abort the browser task and shut the daemon down (errors ignored,
    /// e.g. if [`Discovery::shutdown`] was already called).
    fn drop(&mut self) {
        if let Some(handle) = self.browser.get_mut().take() {
            handle.abort();
        }
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_cores_rejects_poisoned_values() {
        // f32::from_str accepts every one of these; they must map to 0.0.
        for bad in [
            "NaN",
            "nan",
            "inf",
            "-inf",
            "+inf",
            "infinity",
            "-infinity",
            "1e40",
            "-1",
            "-0.5",
        ] {
            assert_eq!(parse_cpu_cores(bad), 0.0, "poisoned input {bad:?}");
        }
        // Non-numeric / empty also fall back.
        assert_eq!(parse_cpu_cores("abc"), 0.0);
        assert_eq!(parse_cpu_cores(""), 0.0);
        // Finite but out of range clamps to 0.0.
        assert_eq!(parse_cpu_cores("1000000"), 0.0);
        // Sane values pass through unchanged.
        assert_eq!(parse_cpu_cores("0"), 0.0);
        assert_eq!(parse_cpu_cores("8"), 8.0);
        assert_eq!(parse_cpu_cores("8.5"), 8.5);
    }

    #[test]
    fn bytes_default_and_clamp() {
        assert_eq!(parse_bytes(None, MAX_MEMORY_BYTES), 0);
        assert_eq!(parse_bytes(Some("not-a-number"), MAX_MEMORY_BYTES), 0);
        assert_eq!(parse_bytes(Some("1024"), MAX_MEMORY_BYTES), 1024);
        // u64::MAX is clamped down to each ceiling.
        let huge = u64::MAX.to_string();
        assert_eq!(parse_bytes(Some(&huge), MAX_MEMORY_BYTES), MAX_MEMORY_BYTES);
        assert_eq!(
            parse_bytes(Some(&huge), MAX_GPU_VRAM_BYTES),
            MAX_GPU_VRAM_BYTES
        );
    }

    #[test]
    fn sanitize_label_strips_control_chars() {
        assert_eq!(sanitize_label("a\0b\tc\r\nd"), "abcd");
        assert_eq!(sanitize_label("plain"), "plain");
        // ANSI escape sequence introducer (ESC) is a control char and dropped.
        assert_eq!(sanitize_label("\u{1b}[31mred\u{1b}[0m"), "[31mred[0m");
        // Non-control multi-byte scalars are preserved.
        assert_eq!(sanitize_label("café"), "café");
    }

    #[test]
    fn sanitize_label_truncates_on_char_boundary() {
        // ASCII: exactly MAX_LABEL_LEN bytes retained.
        let long_ascii = "x".repeat(MAX_LABEL_LEN + 50);
        assert_eq!(sanitize_label(&long_ascii).len(), MAX_LABEL_LEN);

        // Multi-byte: never split a scalar, never exceed the byte budget.
        let long_multi = "é".repeat(MAX_LABEL_LEN); // 2 bytes each
        let s = sanitize_label(&long_multi);
        assert!(s.len() <= MAX_LABEL_LEN);
        assert!(s.is_char_boundary(s.len()));
        assert!(s.chars().all(|c| c == 'é'));
    }

    #[test]
    fn hostname_label_is_dns_safe() {
        assert_eq!(sanitize_hostname_label("My.Host_Name!"), "myhostname");
        assert_eq!(sanitize_hostname_label("  spaced  "), "spaced");
        assert_eq!(
            sanitize_hostname_label("-lead-and-trail-"),
            "lead-and-trail"
        );
        assert!(sanitize_hostname_label("").is_empty());
        assert!(sanitize_hostname_label("!!!").is_empty());
        // Bounded to the DNS label limit.
        assert!(sanitize_hostname_label(&"a".repeat(200)).len() <= MAX_HOSTNAME_LEN);
    }

    #[test]
    fn unique_fallback_hostname_is_per_peer_and_dns_safe() {
        let id = PeerId::from_public_key_bytes(&[0x11; 32]);
        let label = unique_fallback_hostname(&id);
        assert!(label.starts_with("entangled-"));
        assert!(label.ends_with(&id.to_hex()[..8]));
        // The label already conforms to the DNS charset.
        assert_eq!(sanitize_hostname_label(&label), label);

        // Distinct peers get distinct labels (no address-list merging).
        let other = PeerId::from_public_key_bytes(&[0x22; 32]);
        assert_ne!(
            unique_fallback_hostname(&id),
            unique_fallback_hostname(&other)
        );
    }
}
