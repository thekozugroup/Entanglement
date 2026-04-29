# BitTorrent Feasibility for Strata/Covalence

*Research note 06 — should the framework adopt BitTorrent (BEP) anywhere in its stack?*

## Executive verdict

**Don't adopt BitTorrent as a primary transport at any layer.** The current stack
(Iroh QUIC + iroh-blobs BLAKE3 content addressing + Ed25519 publisher signatures + biscuit
capability tokens) already covers everything BitTorrent would do, and it does the parts
that matter for a controlled-mesh compute system meaningfully better: NAT traversal via
QUIC hole-punching with DERP fallback, content-addressed verifiable streaming via
BLAKE3, and bearer-capability access control via tickets/biscuits. BitTorrent's
strengths — multi-source swarm download, mature ecosystem, browser interop via
WebTorrent — apply only at swarm sizes Strata is unlikely to reach in its target
deployments (small-to-mid private meshes), and they come bundled with discovery
centralization (trackers), DHT-traffic privacy leaks, corporate-network blocking on
sight, and a protocol that doesn't carry capability tokens. There is **one narrow,
optional, opt-in slot** where BitTorrent makes sense: a "public plugin mirror"
distribution mode for OSS plugin authors who want a free CDN with no infrastructure.
Treat it as an alternate publishing format, not a transport the framework speaks.

---

## Layer-by-layer analysis

### 1. Plugin distribution (replace OCI / signed tarball)

**Verdict: no.** Plugins are typically 1–50 MB. At those sizes BitTorrent's swarm
parallelism is irrelevant — a single HTTPS GET from an OCI registry or a CDN-fronted
tarball URL completes in under a second on a residential link, faster than the time it
takes a BitTorrent client to bootstrap the DHT and find peers. The Strata trust model
already requires an Ed25519 publisher signature on the artifact, so the transport's
hash function (SHA-1 in BEP 3, SHA-256 in BEP 52) is irrelevant; signatures live one
layer up regardless. Switching to BitTorrent would add a dependency (librqbit + DHT
state), open a peer-listening UDP/TCP port on every node, and introduce the
"BitTorrent-shaped traffic on the wire" problem at corporate sites — all in exchange
for nothing the OCI/HTTPS path doesn't already do faster.

### 2. Work-unit input data distribution

**Verdict: no — Iroh blobs already wins this.** This is the layer where multi-source
parallelism *would* help: a scheduler distributing a 10 GB dataset to 50 workers benefits
from peers fetching from each other rather than all hammering the scheduler. But that's
exactly what `iroh-blobs` already provides, with three advantages over BitTorrent: (a)
BLAKE3 is faster to verify than SHA-256 and supports streaming verification of arbitrary
ranges via Bao trees, so workers can begin computation on partial data; (b) transport is
QUIC with the same hole-punching machinery the rest of the mesh uses, so there's one set
of firewall rules and one identity system to reason about; (c) authentication is a
ticket/biscuit at the iroh layer rather than a bolt-on. BitTorrent here would mean
running two parallel content-addressed-blob systems with two cache layers and two
authorization stories — strict regression.

### 3. Plugin update propagation across an existing mesh

**Verdict: no — but this is the strongest case for BitTorrent and worth re-examining
later.** Once a plugin is loaded by node A in a 100-node mesh, propagating an update to
the other 99 is a textbook swarm scenario. However, `iroh-blobs` plus `iroh-gossip` (the
n0 pub/sub overlay built on the same QUIC transport) already lets nodes announce content
they hold and request it from any peer that has it — a content-addressed pull-from-any-
peer pattern that gives the swarm benefit without BitTorrent's protocol overhead. If
benchmarks ever show iroh-blobs swarm distribution underperforming librqbit at large
mesh sizes, revisit; the data we'd need to make that decision doesn't exist yet.

### 4. Result aggregation

**Verdict: no.** Result flow is many-to-one, the inverse of BitTorrent's many-to-many
sweet spot. Workers stream outputs to the scheduler over their existing Iroh QUIC
connection; there's no swarm to leverage.

### 5. Mesh discovery (Mainline DHT instead of pkarr)

**Verdict: no — but the underlying primitive is shared.** This deserves a careful look
because pkarr (the n0 discovery layer) literally publishes records *to the BitTorrent
Mainline DHT* using BEP 44 (mutable items signed with Ed25519). So Strata is, in a
narrow technical sense, already using the BitTorrent DHT for discovery — just through
the pkarr abstraction. There is no benefit to switching to a direct Mainline DHT client
(`pubky/mainline` is the leading Rust crate) unless we want pkarr-incompatible custom
records, which we don't. Keep pkarr; recognize that its substrate is BEP 5 + BEP 44 and
that we are, technically, already a BitTorrent-DHT participant for discovery.

---

## Comparison table

| Property | BitTorrent (BEP 3 / 52) | Iroh blobs | OCI registry |
|---|---|---|---|
| Content addressing | SHA-1 (v1) / SHA-256 (v2) | BLAKE3 (Bao tree) | SHA-256 manifest digest |
| Streaming verification | Piece-level after full piece | Range-level via Bao | Full-blob only |
| Transport | TCP / uTP / WebRTC (WebTorrent) | QUIC | HTTPS |
| NAT traversal | UPnP, NAT-PMP, manual port-forward | QUIC hole-punching + DERP relay | None needed (client-initiated) |
| Discovery | Trackers + Mainline DHT + PEX | pkarr (uses Mainline DHT) + mDNS | DNS + registry URL |
| Identity / auth | None native | Ed25519 NodeId + tickets | Registry auth (token / mTLS) |
| Multi-source parallel fetch | Yes (mature) | Yes (newer, less battle-tested at scale) | No |
| Browser interop | WebTorrent | Iroh JS (experimental) | Browser HTTP fetch |
| Firewall posture in corporate networks | Frequently blocked | QUIC + 443 fallback typically allowed | HTTPS — universally allowed |
| Privacy leak from discovery | DHT announces interest in info-hash | pkarr signed records, narrower exposure | None (direct fetch) |
| Capability-token compatible | No (must layer) | Yes (tickets / biscuits native) | Yes (registry tokens) |
| Rust library maturity | librqbit — strong | iroh-blobs — n0 first-party | oci-distribution / oras — strong |

---

## Rust library landscape

**librqbit** (`ikatson/rqbit`) — the dominant Rust BitTorrent client. ~1.6k stars,
~2,000 commits, actively maintained, Apache-2.0 / MIT dual-licensed (matches the
ecosystem). Modular: separate crates for `librqbit-core`, `dht`, `peer_binary_protocol`,
`bencode`, plus a uTP implementation. Has a desktop frontend (Tauri) and WebTorrent
bridge support. No formal third-party security audit published. Verdict: production-
quality if you need it, but a heavy dependency tree and a new attack surface (peer
listener, DHT, tracker traffic) for any binary that links it.

**cratetorrent** — older teaching project, not a viable production choice.

**pubky/mainline** — focused, embeddable Mainline DHT client/server in Rust. ~94 stars,
~500 commits, supports BEP 5 / 42 / 43 / 44 (mutable items). Has documented Sybil-
resistance measures. Already a transitive dependency through pkarr; no reason to
take a direct dependency.

**iroh-blobs** (`n0-computer/iroh-blobs`) — what Strata uses today. BLAKE3 + Bao,
n0-maintained, Apache-2.0 / MIT, ~120 stars but the canonical implementation behind a
funded company with shipping production users. Composes naturally with `iroh-gossip` and
`iroh-docs` for the higher-level patterns.

**oci-distribution / oras-rs** — the OCI registry client side. Mature, used by every
container tool in the Rust ecosystem.

Net: there is no Rust BitTorrent library that's *missing* — librqbit is genuinely good.
The question is only whether we want a second content-distribution stack, not whether
the implementation exists.

---

## Security & perception risks

**Signature layering is fine.** BitTorrent piece hashes authenticate bytes against a
publisher-chosen merkle root, but they do not authenticate the publisher. Strata
already mandates Ed25519 publisher signatures on the artifact contents one layer up,
which works identically over BitTorrent, HTTPS, OCI, or smoke signals. No new
cryptography needed; this is a non-issue.

**DHT privacy leak is real.** A node that fetches a plugin via Mainline DHT publishes
"I am interested in info-hash X" to a public, globally-observable hash table. For a
public OSS plugin that's fine; for a private internal plugin the metadata leak is
operationally dangerous (attackers can enumerate which versions of which plugins your
fleet runs). Mitigation requires private trackers + DHT disabled, which negates most
of BitTorrent's advantages. Iroh-blobs over QUIC leaks much less — only the NodeIds
of communicating peers, and only to peers they actually talk to.

**Sybil attacks on small swarms.** A 5-peer swarm is trivial to overwhelm with sybils
that serve garbage; BitTorrent's per-piece hash check catches the garbage but wastes
bandwidth. Real-world Strata deployments have small swarms by definition.

**Corporate network posture.** BitTorrent UDP and TCP traffic is blocked outright by a
large fraction of enterprise edge appliances, and "ships a BitTorrent client" is a
common item on procurement security questionnaires that triggers automatic rejection.
The damage is mostly perceptual but it's real damage. Iroh's QUIC-on-443 with DERP
relay sidesteps this entirely.

**Legal exposure.** Shipping a BitTorrent client doesn't create direct liability — the
protocol is content-neutral — but it does expand the threat model: if a host runs
Strata and a plugin tells it to seed something the host doesn't know about, the host
inherits whatever liability the seeded content carries. Strata's plugin sandbox should
prevent this regardless, but it's another reason BitTorrent should not be a default
transport.

---

## Recommendation

**Default: do not adopt BitTorrent at any layer.** Iroh + iroh-blobs + OCI/HTTPS covers
plugin distribution, work-unit data, and update propagation with better security,
better firewall posture, native capability tokens, and one identity system instead of
two. The pkarr discovery layer already uses Mainline DHT under the hood, which
satisfies the only legitimate "we should use BitTorrent infrastructure" claim.

**Optional opt-in: BitTorrent as a publish target for public OSS plugins.** Plugin
authors publishing to the Strata public registry MAY additionally publish a BEP 52
v2 magnet link alongside the OCI manifest and signed tarball URL. Hosts MAY enable a
`distribution.bittorrent = true` config flag to consume that link. The flag defaults
**off**. When enabled it must:

1. Use librqbit with DHT disabled by default (tracker-only) to limit metadata leak;
   DHT may be enabled per-plugin by the host operator only.
2. Verify the publisher's Ed25519 signature on the downloaded artifact before
   loading, identical to the OCI/HTTPS path. The torrent infohash is **not** a
   trust anchor.
3. Never seed without explicit operator opt-in (`distribution.bittorrent.seed = true`).
4. Refuse to participate at all in `mesh.tailscale` deployments (corporate sites
   should not be tempted into BitTorrent traffic by default).

**Rejected hybrids:** "Iroh primary, BitTorrent fallback for >1 GB with ≥3 seeders"
sounds clever and isn't — it doubles the dependency surface and operational complexity
to optimize a tail case that iroh-blobs swarm pull already handles. "WebTorrent for a
future browser frontend" should be revisited only if and when that frontend is
specced; today's answer is "the browser fetches via HTTPS from the same signed-
artifact URL the desktop client uses."

The path of least regret is to keep BitTorrent firmly out of the architecture v5
critical path and give it exactly one optional, well-fenced role: a publish-side
mirror for public plugins, behind a default-off flag, with the same publisher-
signature trust model as every other transport. If swarm distribution ever becomes a
measured bottleneck for in-mesh plugin updates, revisit by extending iroh-blobs
behavior, not by adding a second stack.
