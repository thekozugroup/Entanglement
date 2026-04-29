# Distributed Compute, Auto-Discovery, and Heterogeneous Hardware: Prior Art for Centrifuge

*Research date: 2026-04-28. Versions cited where stable.*

Centrifuge wants any device on a LAN/WAN to (a) auto-discover peers, (b) advertise its CPU/GPU/NPU and link bandwidth, (c) accept opt-in batched compute under a plugin model. This document surveys what already exists so we can stand on shoulders rather than reinvent shins.

---

## 1. Discovery and Transport

### 1.1 mDNS / DNS-SD (Bonjour, Zeroconf)
Multicast DNS (RFC 6762) plus DNS-SD (RFC 6763) lets nodes advertise `_centrifuge._tcp.local` records on a link-local segment. Solves zero-config LAN discovery brilliantly: a fresh laptop sees a fresh phone in <2s with no infrastructure. **Fails the moment you cross any router** — multicast is link-local, VLANs and consumer Wi-Fi APs often filter it (especially "client isolation"), and corporate networks block it outright. Rust ecosystem: `mdns-sd` (active, 0.13.x as of 2026) and `astro-dnssd`. **Verdict: keep as the LAN-local fast path, but never the only path.**

### 1.2 libp2p (rust-libp2p)
A modular networking framework born in IPFS. Star count ~5.5k; release cadence is a tagged version every ~4 weeks. Provides:
- **Peer identity**: every node is a `PeerId` derived from a public key (Ed25519/secp256k1/RSA).
- **Transports**: TCP, QUIC, WebTransport, WebRTC, plus Noise/TLS handshake.
- **Discovery**: mDNS, Kademlia DHT, rendezvous, bootstrap lists.
- **NAT traversal**: AutoNAT, `identify`, hole-punching via DCUtR (Direct Connection Upgrade through Relay) and Circuit Relay v2.
- **Pub/sub**: gossipsub, floodsub.

NAT/firewall behavior is *good* via DCUtR but the Rust impl is famously heavyweight — the `Swarm` / `NetworkBehaviour` API has a steep learning curve, the public-relay infrastructure is community-run, and DHT participation drags every node into a global namespace whether you want it or not. Used by Iroh's predecessor, Lighthouse, Forest, Subspace. **Verdict: powerful but a tax. Worth the tax only if Centrifuge needs DHT-based public peer routing.**

### 1.3 Iroh (n0-computer)
A Rust-first take on the same problem space: a `Endpoint::bind()` gives you a peer addressable by a 32-byte `NodeId` (Ed25519). Connections are QUIC over either direct UDP, hole-punched UDP, or — when both fail — a TCP relay (DERP-derived). Workspace crates as of mainline (`iroh` 0.34+ in 2026): `iroh`, `iroh-relay`, `iroh-base`, `iroh-dns-server` (powers pkarr-style discovery via `dns.iroh.link`), `iroh-net-report`. Includes `iroh-gossip` and `iroh-blobs`/`iroh-docs` plugins.

Compared to libp2p: smaller surface, more opinionated (QUIC only), better ergonomics (`endpoint.connect(node_id, ALPN)` and you have a stream), and excellent NAT traversal numbers — n0 publishes continuous measurements at perf.iroh.computer. The relay protocol is open source and self-hostable. **Verdict: best-in-class fit for a Rust LAN+WAN mesh today.**

### 1.4 Tailscale / Headscale
WireGuard data plane (userspace `wireguard-go`), control plane that distributes peer pubkeys + endpoint candidates, NAT-busting via STUN/ICE, and DERP relays for UDP-hostile networks. Identity via SSO (Google/Okta/GitHub). Headscale is the open-source control-plane reimplementation. Excellent NAT story, kernel-level performance, but: **(a)** it's a *VPN*, not an application transport — Centrifuge would still need an app-layer protocol on top, **(b)** centralized control plane (even Headscale), **(c)** mesh size capped by tailnet. **Verdict: viable as an underlay if users already run it, but wrong abstraction for a self-bootstrapping app mesh.**

### 1.5 NATS / NATS leaf nodes
Subject-based pub/sub. Leaf nodes extend a cluster across security domains and are the canonical edge story — a Raspberry Pi runs a leaf that bridges to a hub super-cluster. Mature Rust client (`async-nats` 0.39+). JetStream gives durable queues. **Strength**: dead-simple semantics; **weakness**: needs at least one reachable hub server, so it's not truly peer-to-peer, and NAT-busting between leaves isn't its job. Used as the lattice transport in **wasmCloud**. **Verdict: great control-plane bus if Centrifuge optionally federates to a hub; not a base layer.**

### 1.6 Serf / memberlist (HashiCorp)
SWIM gossip protocol for cluster membership, failure detection, and user events. Powers Consul, Nomad. The library is Go; Rust analogues exist (`chitchat` from Quickwit, `foca`). SWIM gives O(log N) failure detection without a central coordinator. **Verdict: the right algorithm for "who's alive in this mesh"; Centrifuge should adopt SWIM-style gossip on top of whatever transport it picks.** The Serf project itself was effectively retired (serf.io shut down Oct 2024) but the protocol and Rust ports are alive.

### 1.7 Yggdrasil
End-to-end encrypted IPv6 overlay using a compact-routing scheme; every node gets a `200::/7` IPv6 address derived from its key. Self-healing, fully P2P, alpha-stage. Userspace router. **Verdict: interesting research; too niche and IP-address-centric for a hobbyist→prosumer product. Reject.**

### 1.8 WebRTC data channels
Required if browser tabs are first-class peers. ICE + STUN + TURN. Rust has `webrtc-rs` and libp2p ships a WebRTC transport. **Verdict: necessary plugin if Centrifuge ever wants browser nodes; not the base.**

### 1.9 Hyperswarm / Holepunch (Pear runtime)
Node.js-centric DHT-based peer discovery from the Hypercore stack. Battle-tested for Beaker/Keet. Rust port is partial. **Verdict: ecosystem mismatch. Reject.**

---

## 2. Distributed Compute Frameworks

### 2.1 Ray (2.55.x, 2026)
Actor + task model. The killer feature for us is **resource specs**: `@ray.remote(num_cpus=2, num_gpus=0.5)` and the scheduler does admission control. Ray distinguishes *physical* and *logical* resources — `num_gpus` is a scheduling token, not an isolation primitive (CUDA isolation comes via `CUDA_VISIBLE_DEVICES`). Custom resources are just key→float pairs (`accelerator_type:NPU=1`), which is exactly what Centrifuge wants for advertising heterogeneous accelerators. Python-only worker side, gRPC plasma object store, single GCS head. **Verdict: copy the resource model; reject the runtime.**

### 2.2 Dask
Scheduler + worker, pure Python, optimized for dataframe/array workloads. Smaller scope than Ray. Resource hints exist (`worker_resources={'GPU': 1}`) but are advisory. **Verdict: not a fit for cross-language compute; useful only as a comparison point.**

### 2.3 Bacalhau
Compute-over-data orchestrator from Expero/Protocol Labs. Single Go binary that acts as client, orchestrator, or compute node. Supports Docker and WebAssembly execution engines. Originally rode libp2p; the v1+ architecture moved most coordination to NATS. Resilient to partitions — compute nodes keep running with intermittent orchestrator connectivity. **This is the closest existing project to Centrifuge in spirit**, especially the "single binary, multiple modes" design and the data-locality framing. **Verdict: study its job spec and orchestrator-compute split closely; the WASM execution path is exemplary.**

### 2.4 HashiCorp Nomad
Generic scheduler with first-class device plugins. Job spec syntax is the cleanest in the industry for heterogeneous hardware:

```hcl
device "nvidia/gpu" {
  count = 2
  constraint { attribute = "${device.attr.memory}" operator = ">=" value = "2 GiB" }
  affinity   { attribute = "${device.attr.memory}" operator = ">=" value = "4 GiB" weight = 75 }
}
```

Device plugins fingerprint hardware and report attributes; the scheduler does constraint matching and affinity-weighted bin packing. Linux-only for device isolation. **Verdict: steal this DSL wholesale for Centrifuge job specs.**

### 2.5 Apache Spark
JVM, driver-executor, batch-oriented, assumes HDFS-class storage. Mentioning only to dismiss: completely wrong for edge / heterogeneous / hobbyist. **Reject.**

### 2.6 BOINC
The grandfather of volunteer compute (SETI@home, Rosetta@home, since 1999). Centralized work-unit dispatcher, client pulls, runs, returns. Aged well: opt-in trust model, credit/quota economy, app versioning per platform. Aged badly: monolithic C++ codebase, X86-centric, no GPU heterogeneity story until late, server-required. **Verdict: borrow the work-unit dispatcher mental model and trust posture; do not borrow the architecture.**

### 2.7 Folding@home
GPU work distribution at petaflop scale. Same pull-based dispatch as BOINC but with proper GPU work units (OpenMM cores). Demonstrated that volunteer GPU compute *works* — peaked at 2.4 exaflops in early 2020. Same architectural limits as BOINC.

### 2.8 Apple Distributed Actors (Swift)
Swift 5.7 added the `distributed actor` keyword. The `swift-distributed-actors` cluster library (Apple, October 2021 announcement) provides a reference transport with cluster membership, receptionist (service discovery), and supervision. Type-safe remote calls — the compiler enforces that distributed methods can fail and are async. **Verdict: the *type system* lesson is the gold: typed remote actors are the right user-facing API. Rust can't get there cleanly without macros, but we can come close.**

### 2.9 Erlang/OTP distribution
The gold standard since the late 1980s. Node-to-node mesh, transparent message passing, `monitor`/`link` for failure detection, supervision trees. Caveats: TCP-only, weak security model (cookie-based), assumes a trusted LAN by default. Lessons that *do* transfer: location transparency, let-it-crash, supervisor hierarchies, the `gen_server` pattern. **Verdict: shape Centrifuge's actor model after OTP, not after Akka.**

### 2.10 Petals / Hivemind
Petals (BigScience, hosted at petals.dev) runs Llama-3.1 405B and Mixtral 8x22B BitTorrent-style across volunteer GPUs — a node loads a few transformer blocks and serves them; clients route requests through a swarm. Up to 6 tok/s for Llama-2 70B. Built on Hivemind (decentralized DHT-based parameter routing). **Verdict: proves heterogeneous-GPU swarm inference is viable. Centrifuge should treat "Petals-style sharded model serving" as a flagship plugin scenario.**

### 2.11 EdgeX Foundry / KubeEdge / k3s
Edge-flavored Kubernetes. Heavy. Assumes a control plane and YAML literacy. **Verdict: wrong audience (ops teams, not prosumers). Reject as a base, but Centrifuge should be deployable *into* k3s as a workload.**

### 2.12 wasmCloud + WasmEdge
wasmCloud's "lattice" is a self-forming mesh over **NATS**, with WebAssembly components as the unit of work. WasmEdge is the runtime. The lattice gives location-transparent dispatch: a component invokes a capability and the lattice routes to whichever host has it. **Verdict: validates two design choices for Centrifuge — (a) NATS or NATS-like pub/sub for control plane, (b) WASM as a portable, sandboxed work-unit format. We should ship a WASM execution plugin out of the gate.**

---

## 3. Hardware Advertising and Heterogeneous Scheduling

### 3.1 The advertise-then-match pattern
Every system above converges on the same pattern:
1. Each node *fingerprints* its hardware at start (Ray auto-detects CPU/GPU; Nomad's device plugin fingerprints attributes; K8s device plugins post `Allocatable`).
2. Resources are **logical tokens** (Ray is explicit about this: `num_gpus=1` reserves a slot, isolation is a separate concern via `CUDA_VISIBLE_DEVICES`).
3. Job specs declare requirements + constraints + affinities; scheduler bin-packs.

Centrifuge should adopt: (resource = key→float), (constraints = predicate over device attributes), (affinity = soft preference with weight). Nomad's syntax is the cleanest reference.

### 3.2 NUMA, network bandwidth, locality
Nomad supports NUMA-aware placement (`numa { affinity = "require" }`). Ray has `node:<ip>` placement groups. K8s has topology-aware hints. Network-bandwidth-aware placement is the laggard everywhere — most schedulers treat the network as uniform, which is wrong on a Wi-Fi+Ethernet+5G LAN. **Centrifuge differentiator**: have nodes continuously measure link bandwidth/latency to peers and surface it as a first-class scheduling input.

### 3.3 NPU detection — the cross-platform gap
There is **no portable NPU API** as of 2026. State of the art:
- **Apple Neural Engine (ANE)**: only via Core ML framework, only via `MLModel` with a `.mlpackage`. Detected indirectly via `MLComputeUnits.cpuAndNeuralEngine`. No public IOKit interface.
- **Qualcomm Hexagon**: QNN SDK (proprietary) or via Windows DirectML.
- **Intel NPU (Meteor Lake and later)**: OpenVINO is the only sane path; Linux exposes `/dev/accel/accel0`.
- **Rockchip RK3588 NPU**: RKNN toolkit, vendor-specific.
- **Cross-platform**: ONNX Runtime + Execution Providers gets you ~70% of the way; WebNN is emerging but not production. WASI-NN is the WASM-side answer.

**Practical recommendation**: Centrifuge should fingerprint *capability surfaces* (`onnx-runtime:cuda`, `onnx-runtime:coreml`, `onnx-runtime:openvino`, `wasi-nn`) rather than chase per-vendor SDKs. Treat each as a custom resource. The work-unit declares `requires: ["wasi-nn"]` and the scheduler matches.

---

## 4. Security

### 4.1 Identity
Two viable patterns:
- **Per-device keypair, self-sovereign** (Iroh, libp2p, WireGuard, Tailscale's node keys): every node is a public key, `PeerId`/`NodeId` is its hash. No CA. Trust via TOFU + out-of-band fingerprint.
- **Cluster CA** (K8s, Nomad mTLS, NATS NKeys w/ operator JWTs): a root signs node certs.

For LAN-first prosumer use, **per-device keypair wins** — no CA infrastructure to bootstrap, friction-free pairing via QR code or short-code.

### 4.2 Channel
Both Iroh (QUIC + TLS 1.3) and libp2p (Noise XX or TLS 1.3) give modern AEAD. WireGuard is also Noise. There is no reason to design a custom handshake — pick QUIC.

### 4.3 Job authorization (capability tokens)
Macaroons or biscuit-auth (Rust, `biscuit-auth` 5.x, 2026) — capability tokens with attenuable scopes. A job-submission token says "node X may run jobs of class Y on this mesh, expires Z, gpu-budget=N". Better than ACLs because tokens are offline-verifiable and delegate-able.

### 4.4 Supply chain for work units
This is the unsexy critical piece. A Centrifuge node *will* execute code from the network. Mitigations:
- **WASM-by-default**: WASI sandbox + capability-based imports. No filesystem unless granted.
- **Signed work units**: the submitter signs the WASM blob; nodes verify against an allowlist of publisher keys.
- **Resource limits**: fuel/epoch interruption (Wasmtime), memory caps, network egress rules.
- **Reproducibility**: content-address the work unit (BLAKE3 of bytes); same bytes same result.

This is roughly the wasmCloud + Bacalhau model and it's the only sane one for opt-in compute sharing.

---

## 5. Synthesis: Recommended Stack for Centrifuge

**Be opinionated. Reject the rest.**

### Transport: **Iroh**
- QUIC is the right wire format in 2026.
- `NodeId` (Ed25519 hash) is the right identity primitive.
- Hole-punching + relay fallback covers >95% of consumer NAT topologies with no user config.
- Pure Rust, n0-computer ships releases monthly, observable production usage.
- Reject libp2p: more surface than we need, DHT is a liability, ergonomics worse.
- Reject Tailscale: VPN underlay, wrong abstraction, requires user setup.

### LAN-fast-path discovery: **mdns-sd** (`_centrifuge._udp.local`)
- Sub-second peer discovery on a flat LAN.
- Iroh handles WAN/cross-NAT discovery via `iroh-dns-server` (pkarr) and relays.

### Membership / failure detection: **SWIM gossip** (`chitchat` or `foca`)
- O(log N) failure detection, eventually consistent member list.
- Layer it *above* Iroh streams, not below. Each node opens a gossip stream to a few peers.

### Control plane: **embedded NATS optional, native otherwise**
- For the v1 mesh, native gossip + direct QUIC RPC suffices.
- Offer a NATS bridge as a plugin so users can federate Centrifuge meshes into existing NATS deployments (and into wasmCloud lattices for free).

### Scheduler: **Nomad-style DSL, Ray-style resources, custom Rust impl**
- Resources = `HashMap<String, f64>` (mirrors Ray's logical resource model).
- Job spec borrows Nomad's `device` block syntax (constraints, affinities, weights).
- Bin-packing scheduler with network-bandwidth + latency as first-class inputs (the differentiator).
- One-elected-leader-per-job model (Raft via `openraft` for the scheduler shard); workers are stateless.

### Execution unit: **WASM components (Wasmtime + WASI 0.2 + WASI-NN)**
- Sandboxed, capability-based, content-addressed, signed.
- Native plugin for "raw process" execution behind an explicit user opt-in for non-sandboxed work.
- Future: GPU access via WASI-NN execution providers (CUDA/CoreML/OpenVINO) — gets us NPU heterogeneity for free.

### Identity & auth: **Per-device Ed25519 keypair (= Iroh `NodeId`) + biscuit capabilities**
- Pairing via 6-word fingerprint or QR.
- Job tokens are biscuits, attenuable, offline-verifiable.

### Hardware advertising: **capability surfaces, not raw devices**
- Advertise `cpu.cores`, `cpu.arch`, `mem.bytes`, `gpu.cuda.mem`, `gpu.metal.mem`, `accel.coreml`, `accel.openvino`, `wasi-nn:*`, plus measured `net.bw_to.<peer>` and `net.rtt_to.<peer>`.
- Plugins can register additional resource keys.

### What we are explicitly rejecting
- **libp2p** (too heavy, DHT not needed)
- **Tailscale/Headscale** (wrong layer)
- **Yggdrasil**, **Hyperswarm** (ecosystem mismatch)
- **Kubernetes / k3s / KubeEdge** (wrong audience)
- **Spark, Dask** (wrong shape)
- **BOINC/Folding@home architecture** (centralized dispatcher) — though we keep their *trust posture* lessons.

---

## Appendix: Sources
- Iroh docs and repo (n0-computer/iroh, mainline 2026): https://www.iroh.computer/docs , https://github.com/n0-computer/iroh
- rust-libp2p: https://github.com/libp2p/rust-libp2p
- Tailscale "How Tailscale works" (Avery Pennarun, 2020): https://tailscale.com/blog/how-tailscale-works
- Ray Resources (Ray 2.55.1): https://docs.ray.io/en/latest/ray-core/scheduling/resources.html
- Nomad device block: https://developer.hashicorp.com/nomad/docs/job-specification/device
- Bacalhau: https://docs.bacalhau.org/
- wasmCloud platform: https://wasmcloud.com/docs
- NATS Leaf Nodes: https://docs.nats.io/running-a-nats-service/configuration/leafnodes
- Serf docs (post-shutdown mirror): https://github.com/hashicorp/serf
- Petals: https://petals.dev/
- Yggdrasil Network: https://yggdrasil-network.github.io/
- Swift Distributed Actors (Apple, Oct 2021): https://www.swift.org/blog/distributed-actors/
