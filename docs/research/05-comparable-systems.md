# Comparable Systems Research: Designs Adjacent to Centrifuge

Centrifuge is a Rust-based platform with a tiny kernel, layered permission tiers (1=sandbox through 5=root), plugin manifests that declare resource needs (CPU/GPU/NPU/storage/network), Docker-easy install, integrated network management, a cross-device agent and compute mesh, batched distributed compute, and built-in maintenance. No single existing project hits all of those axes, but a long list of systems hit individual axes well — and the failures are as instructive as the successes.

This document walks 21 systems, then synthesizes which 2-3 are the closest analogs and which concrete patterns Centrifuge should adopt or reject.

---

## 1. Fuchsia (Zircon kernel + Components v2)

**Architecture.** Tiny capability-only microkernel (Zircon) plus a userspace **component framework**. Everything outside the kernel is a component instance organized in a *topology* of *realms* (sub-trees). The component manager is the runtime that resolves, starts, and stops components.

**Plugin model.** Components are declared by **CML manifests** that say `use`, `offer`, `expose` for capabilities (protocols, directories, services, runners, resolvers). Runners (e.g. ELF runner, Dart runner) are themselves capabilities — adding a new language is just shipping a runner.

**Permission/security.** Pure capability routing. A component receives only what its parent explicitly `offer`s. The framework enforces *cycle detection* on capability graphs and supports `dependency: "weak"` to break cycles. There is no ambient authority — no globals like a filesystem.

**Distribution.** Components are referenced by URL; resolvers fetch and verify them. Hermetic packages (Fuchsia Archives).

**Worked / failed.** The capability model is the cleanest in the industry. What failed: complexity. Manifests, realms, routers, monikers — onboarding an outside developer is brutal. Google has had trouble shipping Fuchsia outside Nest hubs.

**Copy.** `use`/`offer`/`expose` semantics, cycle-detected capability graph, runner-as-capability, hermetic packaging.
**Avoid.** Manifest sprawl. Don't let a one-pager plugin require five files of CML to start.

---

## 2. HashiCorp Nomad

**Architecture.** Single Go binary that runs as either *server* or *client*. Servers form a Raft consensus group per region; regions are loosely federated via gossip. Clients fingerprint their own hardware and stream capacity to servers.

**Plugin model.** **Task drivers** (Docker, exec, qemu, raw_exec, java) and **device plugins** (NVIDIA GPU, USB, FPGA, custom) are go-plugin RPC subprocesses. The driver advertises the resources it can handle; jobs declare requirements; the scheduler bin-packs.

**Permission/security.** ACL system with policies; Sentinel for governance; Vault integration for secrets. Workload identity tokens minted per allocation.

**Distribution.** One binary, easy `nomad agent -dev` start. HCL job specs.

**Worked / failed.** Single-binary ergonomics is the gold standard. Device-plugin abstraction (declare resource → scheduler bin-packs) is exactly the model Centrifuge needs for CPU/GPU/NPU. What failed: HashiCorp's licensing changes hurt community trust; ecosystem is thinner than Kubernetes.

**Copy.** Single-binary server/client/dev modes; device-plugin fingerprint→advertise→schedule loop; Raft for the control plane; gossip for region federation.
**Avoid.** HCL as the only manifest format (TOML/YAML are friendlier for hobbyists).

---

## 3. k3s / k0s

**Architecture.** Full Kubernetes distribution packaged as a single ~70 MB binary with embedded SQLite/etcd, traefik, flannel, local-path provisioner. Server + agent roles.

**Plugin model.** Inherits the K8s ecosystem (CRDs, operators, CSI, CNI, device plugins). 

**Permission/security.** RBAC, NetworkPolicy, PodSecurity, secrets — full K8s surface.

**Distribution.** `curl -sfL https://get.k3s.io | sh -`. ARM64/ARMv7 first-class; runs on a Pi.

**Worked / failed.** Proves you can ship "Kubernetes for an appliance" in a single binary. What failed: K8s YAML and CRD complexity still bleeds through. The conceptual surface area is enormous for someone who just wants to run a Plex addon.

**Copy.** Single-binary install, ARM-first, edge-first defaults, embedded datastore so no external dependency.
**Avoid.** Inheriting Kubernetes' manifest model. Centrifuge plugins should not require Deployment/Service/Ingress/ConfigMap quartets.

---

## 4. Home Assistant (Core + Supervisor + Add-ons)

**Architecture.** Three layers: **HAOS** (minimal Linux), **Supervisor** (Python container orchestrator), **Core** (the Python automation engine). Add-ons run as Docker containers managed by Supervisor.

**Plugin model.** Two distinct extension surfaces:
- **Integrations** — Python modules in-process inside Core. ~2,500+ exist.
- **Add-ons** — Docker images with a `config.yaml` that declares ports, host_network, services, AppArmor profile, panel UI, ingress, tier-like `host_*` and `privileged` flags.

**Permission/security.** Add-on configs declare AppArmor profile, capabilities (`SYS_ADMIN`, `NET_ADMIN`), `privileged` access list, `host_dbus`, `host_network`, `udev`, `usb`, `gpio`, `kernel_modules`. This is the closest existing analog to Centrifuge's tier 1-5.

**Distribution.** Docker images via Add-on Store (curated repos). One-click install in the UI.

**Worked / failed.** The add-on declarative permission list is the right shape. The Docker addon model is the pattern most users actually understand. What failed: the integration code lives inside Core's process, so a buggy integration crashes Core. Migrating between minor versions is famously painful.

**Copy.** Declarative permission flags in plugin manifest (`network`, `usb`, `gpio`, `host_dbus` style). Docker as the default addon runtime. Curated + community plugin repos.
**Avoid.** In-process integrations sharing the kernel's address space. Centrifuge plugins must be isolated.

---

## 5. Mycroft / OVOS (OpenVoiceOS)

**Architecture.** Message-bus core (websockets); skills are independent Python processes that subscribe to intents on the bus. OVOS forked Mycroft after the company shut down.

**Plugin model.** Skills are pip-installable; declare intent regexes/utterances; isolate via subprocess or container.

**Permission/security.** Weak. Skills run with user privileges; trust is via the marketplace.

**Worked / failed.** Bus-based decoupling let the community keep the project alive after the company died. What failed: no real sandboxing, no resource declarations, monetization pressure broke trust.

**Copy.** Internal message bus as the canonical plugin↔plugin communication.
**Avoid.** Trusting plugins by default; tying the project's survival to a single corporate sponsor.

---

## 6. Yunohost

**Architecture.** Debian-based self-host distribution. Apps are bash scripts wrapped in a manifest that nginx-proxies and SSO-fronts.

**Plugin model.** App packages have `manifest.toml` with version, install args, services, permissions; install/upgrade/restore lifecycle hooks as bash.

**Permission/security.** SSO (LDAP+SSOwat) shared across apps. Permission system per app: who can access which URL.

**Worked / failed.** Beautifully usable for non-technical users. Catalog of 400+ apps. What failed: bash install scripts age badly; tightly coupled to Debian.

**Copy.** Per-app SSO and shared identity. Lifecycle hooks (install / upgrade / backup / restore) as first-class manifest entries.
**Avoid.** Bash-as-installer. Centrifuge should declare, not script.

---

## 7. CasaOS / Umbrel / Start9 (EmbassyOS)

**Architecture.** All three are Docker-Compose-on-easy-mode for home servers. Umbrel and Start9 lean Bitcoin/sovereignty; CasaOS is general home cloud.

**Plugin model.** App = Docker image + a manifest (Umbrel: `umbrel-app.yml`; Start9: a Service wrapper SDK). Start9 is most ambitious: each app gets a wizard-driven config, health checks, dependency declarations, and Tor-only addressing.

**Permission/security.** Mostly Docker-default. Start9 enforces Tor + LAN-only, no exposed ports.

**Distribution.** App stores with one-click install. Umbrel and Start9 sell hardware.

**Copy.** App store UX, Docker-Compose underneath, dependency declarations between services (Start9), per-app Tor onion (Start9 — relevant for Centrifuge's network mgmt).
**Avoid.** Locking into a single hardware SKU.

---

## 8. Sandstorm

**Architecture.** Capability-secure personal cloud. Each *grain* is a sandbox containing one document/object plus its app code. Apps don't run continuously — grains spin up on access and freeze.

**Plugin model.** Apps are SPK packages declaring entry points and required APIs. Grains communicate only through Cap'n Proto capabilities passed via the *Powerbox*.

**Permission/security.** Pure object-capability. The Powerbox is a system-mediated picker UI: when an app needs an HTTP endpoint or another app's data, the user picks a target through a system dialog and only that capability is granted. No ambient authority, no app-config-files-with-permissions.

**Distribution.** SPK files; community app market.

**Worked / failed.** Mitigates "most security bugs by default" (their claim, fairly defensible). What failed: forcing apps into the grain model required heavy porting; very few apps were rewritten; project moved to community maintenance.

**Copy.** **The Powerbox pattern is the single most important UX idea in this whole document for Centrifuge.** Permission grants happen at use time, mediated by the system, and produce unforgeable capability handles. Tier 1-5 should map roughly: tier 1 = no Powerbox grants, tier 5 = ambient.
**Avoid.** Requiring full app rewrites to fit the model. Centrifuge needs an escape hatch (raw Docker container at a higher tier).

---

## 9. NixOS modules

**Architecture.** The system is a function from configuration to a derivation. Modules are typed config trees that compose.

**Plugin model.** A module = `options` declaration + `config` body. The module system merges configs deterministically.

**Permission/security.** systemd unit hardening (`DynamicUser`, `ProtectSystem`, `PrivateNetwork`) is exposed through module options.

**Worked / failed.** Atomic upgrades and rollbacks via generations are unmatched. What failed: Nix language is famously unfriendly; flakes still divisive.

**Copy.** Atomic, generation-based upgrades with one-command rollback. Typed manifest schema with deterministic merging.
**Avoid.** A bespoke configuration language.

---

## 10. systemd units + portable services

**Architecture.** PID 1 with unit files (service, socket, timer, mount, slice). Portable services bundle a unit + a small image and a profile.

**Permission/security.** Unit hardening directives are excellent: `PrivateTmp`, `ProtectKernelTunables`, `RestrictAddressFamilies`, `SystemCallFilter`, `CapabilityBoundingSet`, `DynamicUser`. Slices+cgroups for resource caps.

**Worked / failed.** Universally available; unit hardening is mature. What failed: discoverability — most users don't know these directives exist.

**Copy.** Map Centrifuge tiers onto a curated subset of systemd hardening directives. Don't reinvent cgroup resource limits — use slices.
**Avoid.** Exposing the full systemd surface as plugin config.

---

## 11. Bevy ECS

**Architecture.** Pure data + systems (functions over component queries) + a deterministic schedule. Plugins are bundles of systems and resources registered against an `App`.

**Plugin model.** `Plugin` trait has `build(&self, app: &mut App)`. Systems request typed parameters; the scheduler parallelizes non-conflicting access.

**Copy.** The Plugin trait pattern. Centrifuge plugins should be `impl Plugin for MyPlugin { fn build(...) }` — registering handlers, resources, schedules. Typed "what do you need" requests (Bevy: `Query<&Foo>`; Centrifuge: `needs(GPU, NetworkOut)`) compose cleanly.
**Avoid.** ECS proper for systems work — wrong abstraction outside games.

---

## 12. Tauri 2

**Architecture.** Rust core, system webview frontend, IPC commands. Plugin system mirrors the host capability system.

**Plugin model.** Plugins ship Rust crates plus permissions JSON files. Commands are explicitly registered; capabilities (JSON or TOML) bind a set of permissions to a set of windows/webviews.

**Permission/security.** Each plugin declares **permissions** (e.g. `fs:allow-home-read`, `window:allow-set-title`). Capabilities aggregate permissions and scope them to windows. Default-deny.

**Worked / failed.** Centrifuge's permission tiers map almost 1:1 to Tauri's design. What failed: writing capability files by hand is tedious.
**Copy.** Permission strings as identifiers (`net:allow-outbound`, `gpu:allow-cuda`). Capability files that aggregate permissions and scope them. Default-deny everywhere.
**Avoid.** Per-window scoping (irrelevant for headless plugins). Provide tooling to generate manifests rather than hand-write.

---

## 13. VS Code extension host

**Architecture.** Extensions run in a separate node process, talk to the editor over RPC. Manifest (`package.json`) declares `activationEvents`, `contributes`, `engines`.

**Plugin model.** Lazy activation by trigger (open file type, command run); contributions populate menus, languages, debuggers, etc.

**Permission/security.** Weak — extensions get full Node access. Mitigated by code signing and curation.

**Copy.** **Lazy activation by trigger** — Centrifuge plugins should declare what wakes them (event, schedule, request) and stay cold otherwise. Reduces baseline resource use enormously on a Pi-sized device.
**Avoid.** The full-Node-access trust model. Centrifuge must default-sandbox.

---

## 14. Eclipse OSGi

**Architecture.** JVM modular runtime. Bundles (jars + manifest) declare `Import-Package`/`Export-Package`/`Require-Capability`/`Provide-Capability`. The runtime resolves the dependency graph and produces isolated classloaders. A *service registry* lets bundles publish/discover services dynamically.

**Plugin model.** Bundles can be installed/started/stopped/uninstalled at runtime. Services come and go as bundles do; consumers track availability.

**Permission/security.** Java Security Manager + `OSGi Permissions` — fine-grained but notoriously hard to configure. Mostly abandoned.

**Worked / failed.** Service registry pattern is timeless. Dynamic install/start/stop without restart is exactly what Centrifuge wants. What failed: classloader hell, manifest verbosity, the security manager UX.

**Copy.** Dynamic service registry. Hot-install/start/stop/uninstall lifecycle. Capability-based dependency resolution (`Require-Capability` is conceptually identical to manifest resource needs).
**Avoid.** A separate permissions language layered on top of an already-complex manifest. Permissions and capabilities should be one system.

---

## 15. Erlang/OTP releases + applications

**Architecture.** Lightweight processes, supervision trees, applications (a unit = supervision tree + dependencies + env), releases (boot script + apps + ERTS).

**Plugin model.** Applications have `.app` resource files: modules, registered names, dependencies, start mod, env. Hot code loading is built in.

**Copy.** **Supervision trees as the runtime backbone.** Each Centrifuge plugin should declare its supervisor strategy (one_for_one, rest_for_one) and crash boundaries. Applications-as-units (manifest + supervision + env) is the right unit of deployment. Hot code reload is realistic in Rust via dynamic linking + state hand-off.
**Avoid.** Treating supervision as the *security* boundary; Erlang doesn't sandbox.

---

## 16. Nebula (Slack), Tailscale, ZeroTier

**Nebula.** Open-source overlay; certificate-authority-issued identities; hosts use lighthouses for discovery; mTLS-equivalent over UDP.

**Tailscale.** WireGuard mesh; coordinator (control plane) hands out keys; identity comes from your IdP (Google, Okta); ACLs as JSON; peer-to-peer with DERP relay fallback. MagicDNS, exit nodes, subnet routers, Funnel for public ingress.

**ZeroTier.** Layer-2 virtual Ethernet; central or self-hosted controller; rule-based flow control.

**Copy.** Tailscale's identity-first model and ACL JSON. Coordinator/control plane that hands out signed configs. WireGuard for the data plane. DERP-style relays so plugins on devices behind CGNAT still reach each other.
**Avoid.** Mandatory cloud coordinator. Centrifuge mesh must work fully self-hosted (Headscale-like option).

---

## 17. Ockam

**Architecture.** Rust framework for end-to-end secure channels routed across arbitrary transports. Built around *workers* (actor-like) and *routes*. Identities are public keys; secure channels are mutually authenticated.

**Copy.** Worker/route abstraction for cross-device messaging. End-to-end (channel-level) auth that's transport-agnostic — useful when a plugin on device A talks to a plugin on device B through whatever path is available.
**Avoid.** Adopting Ockam's full stack — pick the secure-channel primitives, don't take the orchestration layer too.

---

## 18. Iroh

**Architecture.** Rust p2p networking + content-addressed protocols. QUIC transport over a hole-punching dialer with relay fallback. Compose protocols on top: `iroh-blobs` (BLAKE3 content-addressed transfer), `iroh-gossip` (pub/sub overlay), `iroh-docs` (eventually consistent KV).

**Plugin model.** Protocols are ALPN strings; you `connect(addr, ALPN)` and get a QUIC stream.

**Permission/security.** Tickets — bearer capabilities encoded as base32 strings — grant access to a blob/doc.

**Copy.** **QUIC + ALPN + tickets.** Centrifuge's cross-device agent mesh should look exactly like this: every plugin advertises an ALPN, peers connect over QUIC, capabilities are bearer tickets. Iroh-blobs is a free content-addressed cache layer for distributing plugin packages and batched compute inputs/outputs.
**Avoid.** Reimplementing hole-punching/relay. Use iroh as a dependency rather than rebuilding.

---

## 19. wasmCloud (deep dive — most ideologically aligned)

**Architecture.** **Hosts** run a Wasmtime runtime + extra layers. Hosts cluster into a **lattice** — a self-forming, self-healing flat mesh built on NATS that spans cloud, on-prem, and edge transparently. Components and providers communicate across the lattice as if local.

**Plugin model — two kinds of citizens.**
1. **Components**: portable Wasm binaries, stateless, declare imports/exports as WIT interfaces. Business logic.
2. **Providers**: long-lived OS processes that implement capabilities (HTTP server, key-value store, NATS messaging, blobstore, SQL). Providers are OCI-distributed, swappable, and (in v2) will move to a "wRPC server" model where any language can implement a capability that's served over TCP/NATS/QUIC/UDP.

**Permission/security.** Components can call a provider only if they are explicitly **linked** to it at runtime. Links are declarative configuration in **wadm** application manifests. There is no ambient capability — a component that wants to do HTTP cannot unless the operator linked it to an http-server provider. Identities are signed (nkeys/JWT).

**Distribution.** Components and providers are **OCI artifacts**. `wash app deploy myapp.yaml` reads a wadm manifest (component refs, provider refs, links, scaling) and the lattice schedules.

**Operations.** Wadm = declarative app reconciliation across the lattice. `wash` CLI for everything. NATS leaf nodes carry the lattice across NAT boundaries.

**Worked / failed.** The component/provider split is the cleanest decomposition of "portable logic vs. system access" in any platform. OCI-as-distribution removes a registry from your problem list. NATS lattice is genuinely transparent — a component on a Pi at home can be linked to a Postgres provider in the cloud and not know the difference. What's hard: WIT/WASI components are still a learning curve; the project is small and the production track record is thin compared to K8s.

**Copy (a lot).**
- **Components-vs-providers split.** Centrifuge's plugins should likely have an analogous split: pure-logic plugins (sandboxed Wasm) vs. system-capability plugins (native Rust or Docker, more privileged).
- **Capability via interface contract.** A plugin imports `wasi:keyvalue` (or Centrifuge's equivalent) and the runtime binds it to whatever provider is linked.
- **OCI distribution** for everything.
- **NATS or NATS-shaped lattice** for transparent cross-device messaging. Or use iroh-gossip to avoid running NATS.
- **Declarative app manifests** (`wadm`-shaped) on top of plugin manifests — apps compose plugins.

**Avoid.** Forcing all plugin authors into Wasm/WIT. Keep Docker plugins as a first-class option for tier 4-5.

---

## 20. Spin (Fermyon)

**Architecture.** Wasmtime host that runs Wasm components on triggers (HTTP, Redis, cron). `spin.toml` manifest. Built-in services: KV store, SQLite, AI inference, secrets.

**Plugin model.** Apps are collections of components per trigger. Built-in services injected as WASI imports.

**Distribution.** OCI registries; `spin registry push/pull`.

**Copy.** Trigger-based component activation (HTTP/cron/event). Built-in standard services (KV, SQLite) as host-provided WASI imports — plugins don't bring their own database. `spin.toml` is a clean, readable plugin manifest format to learn from.
**Avoid.** Wasm-only — Spin is narrower than wasmCloud or Centrifuge wants to be.

---

## 21. Roc (Nubank) / Fly.io machines

**Roc Pattern (Nubank).** Architecture isn't widely public; cite cautiously.

**Fly.io Machines.** Firecracker VMs (microVM) launched on demand globally; per-machine config; auto-stop/auto-start; built-in private networking via WireGuard mesh (6PN). Volumes attached per machine, region-local.

**Copy.** Auto-stop/auto-start as a billing-and-resource pattern: plugins should hibernate when idle, wake on trigger. Per-region (per-device) volumes. WireGuard mesh as the private network underneath.
**Avoid.** Firecracker on a Pi — too heavy. But the *operational shape* (declare desired state, machines reconcile) is right.

---

## What would they do? — Hypothetical Centrifuge redesigns

**If wasmCloud redesigned Centrifuge:** Single Rust host running Wasmtime. Plugins are Wasm components for logic; providers are native Rust binaries for system access. Lattice over NATS or QUIC, transparent device boundaries. Tiers 1-3 = component, tier 4-5 = provider. wadm-style app manifests compose plugins. OCI for everything.

**If Fuchsia redesigned Centrifuge:** Pure capability routing. Tiny Rust runtime (analogous to component_manager). Plugins declare `use`/`offer`/`expose` capabilities. Tiers wouldn't exist — they'd be replaced by the routes a parent realm chose to grant. No ambient anything. Beautiful, hard to onboard.

**If Nomad redesigned Centrifuge:** One Rust binary, server/client/dev modes. Raft cluster for the control plane. Device plugins fingerprint CPU/GPU/NPU/storage. HCL (or TOML) job specs declare resource requirements; scheduler bin-packs across devices. Pragmatic, boring, ships.

**If Home Assistant redesigned Centrifuge:** A Rust Supervisor manages Docker addons. Each addon manifest declares `host_network`, `gpio`, `usb`, `gpu`, `kernel_modules`, AppArmor profile. Curated + community addon stores. Ingress proxy + SSO baked in. Web UI for everything. Wins on UX, loses on isolation guarantees.

---

## Synthesis: closest analogs and what to do

The three closest analogs to Centrifuge, in priority order:

1. **wasmCloud** — closest ideologically. Component/provider split, capability-via-interface, OCI distribution, transparent mesh. Centrifuge is *almost* "wasmCloud + permission tiers + home-server UX + Docker escape hatch."
2. **Home Assistant Supervisor** — closest in *user experience and addon-permission shape*. The `config.yaml` declarative permission flags (`host_network`, `usb`, `gpio`, `privileged`, `apparmor`) are the UX template for tier 1-5.
3. **Nomad** — closest in *operational shape*: single binary, declarative jobs with resource needs, device plugins, multi-region federation.

**Top patterns to adopt:**

1. **Component/provider split (wasmCloud).** Sandboxed logic plugins vs. privileged system-capability plugins. Tiers 1-3 are sandboxed; 4-5 are providers.
2. **Capability-via-interface + runtime linking (wasmCloud + Fuchsia + OSGi).** Plugins declare `imports`/`exports` (or `use`/`offer`); the runtime binds them. No ambient authority. Cycle-detect the graph.
3. **Powerbox-style permission grants (Sandstorm).** When a plugin needs a capability it didn't preauthorize, the system mediates: user picks the source through a system UI, an unforgeable handle is granted. This is how tier escalation should feel.
4. **Single-binary, fingerprint-and-advertise device plugins (Nomad).** One Rust binary in server/agent/dev modes. Hardware fingerprinting auto-populates resource pool. Scheduler bin-packs.
5. **OCI everywhere + lazy activation (Spin/wasmCloud + VS Code).** Plugins are OCI artifacts; activation is trigger-driven; idle plugins hibernate. Critical on Pi-class devices.

**Patterns to explicitly reject:**

- **In-process plugins sharing the kernel address space (Home Assistant integrations).** A buggy plugin must not crash the kernel.
- **Bash install scripts (Yunohost).** Declare, don't script.
- **A bespoke configuration language (NixOS).** TOML manifest + a small typed schema is enough.
- **Manifest sprawl (Fuchsia CML, Kubernetes YAML).** A "hello world" plugin is one short manifest, not five.
- **Mandatory cloud coordinator (Tailscale default).** Centrifuge must be fully self-hostable.
- **Wasm-only (Spin).** Centrifuge needs a Docker escape hatch for tier 4-5 plugins (databases, ML servers, GPU drivers).
- **Trust-by-default plugin model (VS Code, Mycroft).** Default-deny, capabilities are explicit.

**The unifying picture.** Centrifuge = (wasmCloud's component/provider+lattice model) × (Home Assistant's declarative permission UX) × (Nomad's single-binary device-plugin scheduling) × (Sandstorm's Powerbox for runtime grants) × (Iroh for the cross-device transport). Tiers 1-5 map onto a curated subset of capability bundles, with tier escalation requiring an explicit Powerbox-style user grant.
