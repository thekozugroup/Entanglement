# Prior Art: Layered & Tiered Permission Models

Research note for the Centrifuge plugin framework. Survey of how production systems express, enforce, and fail at granting partial authority to untrusted code, followed by a candid argument about whether a 5-tier numeric model is the right abstraction.

---

## 1. Linux Capabilities (`CAP_*`)

Linux 2.2 split "root" into ~40 per-thread bits (`capabilities(7)`): `CAP_NET_BIND_SERVICE`, `CAP_SYS_PTRACE`, `CAP_DAC_OVERRIDE`, `CAP_BPF`, etc. Checked at syscall time. Five sets: permitted, effective, inheritable, ambient, bounding.

**Granularity:** coarse-to-medium. Bit per syscall family. No path or argument scoping.

**Failure mode — `CAP_SYS_ADMIN` is "the new root."** The man page annotates it `Note: this capability is overloaded`. It controls mounts, swap, namespaces, quota, BPF (until 5.8 split out `CAP_BPF`), perf (5.8 → `CAP_PERFMON`), checkpoint/restore (5.9 → `CAP_CHECKPOINT_RESTORE`). Splitting took years and kernel releases.

**Use in practice:** Docker's default drops most caps and keeps a curated set; systemd's `CapabilityBoundingSet=`/`AmbientCapabilities=` declare exact bits per unit. Both treat the kernel set as a *menu*, not a tier.

**Takeaway:** naming a capability is a forever decision; once code depends on `CAP_X`, you can't subdivide it without a shim. **Design coarse names with arguments, or fine names that compose.**

---

## 2. SELinux & AppArmor (MAC layers)

Both are Linux LSMs. Same goal, opposite philosophies.

- **SELinux**: type enforcement. Every subject and object carries a label (`httpd_t`, `httpd_log_t`). Policy is a rule matrix `(source_type, target_type, class) → allow/deny`. Compiled, not path-based — moving a file does not change its label. Roles and MLS sit on top.
- **AppArmor**: path-based profiles. `/usr/bin/foo { /etc/foo.conf r, /var/log/foo.log w, network tcp, }`. Easier to read, easier to bypass via mount tricks or hardlinks.

**Enforcement:** kernel LSM hook before each operation.

**Failure modes:** SELinux's complaint corpus is legendary — "just `setenforce 0`" is the meme. RHEL ships sensible policies; everywhere else admins disable it. AppArmor profiles drift when paths change (e.g. snap updates). Both struggle with dynamic plugins because policy is authored by an admin, not the program.

**Takeaway:** label-based (type) enforcement survives refactoring; path-based does not. For a plugin framework where plugins ship their own resources, **label/identifier scoping beats path scoping.**

---

## 3. Android UID Isolation + Permission Model

Each app gets its own Linux UID/GID, sandboxed by the kernel. Permissions are declared in `AndroidManifest.xml`.

- **Pre-Marshmallow (≤5.1):** install-time, all-or-nothing. Wall of permissions; declining meant "don't install." Users clicked through; apps over-requested.
- **Marshmallow (6.0, 2015):** runtime grants for "dangerous" perms (location, contacts, mic, camera, storage, SMS) via `requestPermissions()`. "Normal" perms stay install-time.
- **Android 10+:** scoped storage, one-time grants, "while in use" location, photo picker bypassing gallery permission.

**Why coarse failed:** users had no signal at install time about *why* an app wanted "read SMS." Use-time prompts, attached to a verb the user just performed, raised refusal rates for shady apps.

**Takeaway:** **temporal proximity matters.** Asking right when a capability is used is the most legible UX. Tier-at-install fails because the user has no narrative.

---

## 4. iOS Entitlements + App Sandbox

Declarative manifest. Code is signed against a `.entitlements` plist. Sandbox is a kernel-level seatbelt profile (descended from TrustedBSD MAC). Some entitlements are restricted to Apple-approved use; the App Store rejects unjustified ones.

**Granularity:** fine (`com.apple.security.network.client`, `com.apple.security.files.user-selected.read-only`, HealthKit, HomeKit, push, background modes, app groups).

**User-visible runtime prompts:** orthogonal to entitlements — for sensitive resources (mic, camera, photos, contacts, location), iOS additionally prompts at first use with a developer-supplied purpose string in `Info.plist` (`NSCameraUsageDescription`).

**Failure mode:** purpose strings get gamed ("we need contacts to enhance your experience"). Entitlement gating depends on App Store review; sideloaded enterprise builds historically abused this.

**Takeaway:** **two layers — declared manifest + runtime prompts with developer-authored rationale — is more robust than either alone.**

---

## 5. macOS TCC + `sandbox-exec`

Two coexisting systems.

- **TCC (Transparency, Consent, Control):** the `tccd` daemon stores per-app grants in a SQLite DB, prompts user on first sensitive access (Documents, Desktop, Downloads, Camera, Mic, Full Disk Access, Accessibility, Screen Recording). Reset via `tccutil`.
- **`sandbox-exec` / Seatbelt:** SBPL Scheme-like profile language (`(allow file-read* (subpath "/usr"))`). Apple ships profiles for system services; documented as private API for third parties.

**Failure modes:** TCC fatigue ("yet another prompt"); enterprise IT can't pre-grant non-MDM grants without MDM PPPC profiles; many TCC bypasses have been found and patched (CVE-2020-9771, CVE-2021-30713).

**Takeaway:** prompt-on-first-use is good UX, but a pure prompt model needs an out-of-band override path (MDM, signed config) for fleets. Pure user prompts don't scale.

---

## 6. WebAssembly Component Model & WASI Preview 2

Object-capability semantics. Components have *no ambient authority* — they cannot open files, sockets, or clocks except via interfaces the host imports. Interfaces declared in WIT (`wasi:filesystem/preopens`, `wasi:http/outgoing-handler`, `wasi:sockets/tcp`).

The spec defines `own`/`borrow` *handle types* — opaque indices into a per-instance table, "analogous to file descriptors" per the Explainer. Host hands out handles; guest cannot fabricate them.

**Granularity:** per-interface, per-handle. Give one directory by preopening it and passing the handle — no syscall where the guest can name `/etc/shadow`.

**Enforcement:** runtime, at canonical-ABI lift/lower. No "deny" — there's no syntactic way to name a non-given resource.

**Friction:** preview 2 is young; shimming POSIX `open()` is painful.

**Takeaway:** **capability handles > permission flags.** "You cannot misuse what you cannot name."

---

## 7. Deno Permissions

Runtime flags: `--allow-read`, `--allow-write`, `--allow-net`, `--allow-env`, `--allow-run`, `--allow-sys`, `--allow-ffi`. Each takes optional scoping: `--allow-net=api.github.com:443`, `--allow-read=/etc/myapp`. Mirror `--deny-*` flags take precedence. Interactive prompts at first use unless `--no-prompt`. `--allow-all` (`-A`) disables the sandbox.

Per the docs: "All code executing on the same thread shares the same privilege level. It is not possible for different modules to have different privilege levels within the same thread."

**Failure modes:**
- That last property is the killer: a transitive dep gets the same authority as your app. There's no per-module scoping inside a process.
- `-A` is the de facto default in tutorials and Dockerfiles, defeating the model.
- FFI and `--allow-run` are escape hatches that grant arbitrary code execution.
- Permission prompts during long-running scripts interrupt automation.

**Takeaway:** **flag-level orthogonal capabilities are the right shape, but per-process granularity is too coarse for plugin systems.** A plugin framework needs per-plugin isolation, not per-process.

---

## 8. Browser Extensions: Manifest V2 → V3

MV2: `permissions: ["tabs", "<all_urls>", "webRequest", "webRequestBlocking", "cookies"]`. Granted at install. Reviewer-visible warnings.

MV3 changes that matter:
- `host_permissions` separated from API `permissions`.
- `optional_permissions` and `optional_host_permissions` requestable at runtime via `permissions.request()`.
- `activeTab` — implicit, ephemeral host permission for the tab the user just clicked the action on. Avoids broad host permissions for most extensions.
- Background pages → ephemeral service workers (no persistent DOM with privileged APIs).
- Remotely hosted code banned: per Chrome docs, "You can no longer execute external logic using `executeScript()`, `eval()`, and `new Function()`." Forces static review of what code actually runs.
- `webRequest` blocking → declarative `declarativeNetRequest` rules.

**Complaints:** uBO and similar adblockers lost dynamic filtering performance. Migration churn.

**Takeaways:** (a) **separate API permissions from resource scopes** — host patterns are not the same kind of thing as `cookies`. (b) **prefer ephemeral activations over standing grants.** (c) **declarative > programmatic** when the host needs to reason about what code can do.

---

## 9. Capsicum (FreeBSD)

`cap_enter()` puts a process into capability mode. After that, no global namespaces — no absolute paths, no PIDs outside descendants, no `socket()` to arbitrary addresses. Only file descriptors the process already holds, refined by per-FD `cap_rights_t` (`CAP_READ`, `CAP_WRITE`, `CAP_SEEK`, `CAP_MMAP`...). `cap_rights_limit(fd, &rights)` narrows what an FD can do.

**Granularity:** per-FD rights mask. Compositional, monotonically narrowing.

**Enforcement:** kernel, at syscall.

**Failure modes:** software written against POSIX assumes ambient authority everywhere; porting requires "capsicum-izing" — explicit FD passing, often via privsep helper. Adoption stayed niche.

**Takeaway:** **cleanest object-capability model in a Unix kernel**, but social adoption shows: capability systems demand the program be *written* for them. Retrofitting POSIX code is expensive.

---

## 10. OpenBSD `pledge` + `unveil`

`pledge(promises, execpromises)`: "approximately 3 dozen subsystems" (per the man page) declared by space-separated names — `stdio`, `rpath`, `wpath`, `cpath`, `dpath`, `inet`, `unix`, `dns`, `proc`, `exec`, `id`, `tty`, `fattr`, `getpw`, `prot_exec`, `unveil`, etc. Subsequent calls can only narrow. Violation → uncatchable `SIGABRT`.

`unveil(path, "rwxc")`: filesystem becomes invisible except for the unveiled subtrees. Combined with pledge, the program declares "I will only need DNS, stdio, and read access to `/etc/myapp`."

**Granularity:** subsystem-level for syscalls, path-prefix for filesystem.

**Enforcement:** kernel, syscall-level.

**Failure modes:** kill-on-violation makes incremental adoption hard — one missed subsystem and the program crashes in production. The `pledge` set is OpenBSD-specific and tied to OpenBSD's syscall taxonomy.

**Takeaways:** (a) **declarative narrowing called from inside the program** (rather than externally configured) puts the developer who knows what's needed in charge. (b) **monotonic reduction** is a great invariant — capabilities can shrink but never grow. (c) crash-on-violation forces honesty but punishes ambiguity.

---

## 11. Fuchsia Component Framework

The most modern production design. Components declare capabilities in CML (`use`, `offer`, `expose`, `capabilities`). At runtime, the framework performs **capability routing** through the component tree. From the docs: a parent must explicitly `offer` a capability to a child for the child to `use` it; children `expose` capabilities upward; the framework **rejects routing cycles** unless tagged `dependency: "weak"`.

**Capability types:** protocol (FIDL), directory, storage, runner, resolver, service, event, dictionary.

**Granularity:** per-named-capability, per-component-instance. Topology is the policy.

**Enforcement:** component framework + Zircon kernel handles. A component literally cannot reach what wasn't routed to it — it has no namespace entry for it.

**Failure modes:** verbosity. Manifests are large and routing graphs nontrivial. Tooling (`ffx component`, scopes) compensates.

**Takeaways:** (a) **routed capabilities through a topology** — the path of authority is visible and auditable. (b) **typed capabilities** (protocol vs directory vs storage) match the substrate they grant. (c) cycle detection prevents accidental confused-deputy structures.

---

## 12. Rust-Adjacent Plugin Systems (Zellij, Helix, Neovim)

- **Zellij** runs plugins as Wasm via wasmtime; permissions are an enum (`ReadApplicationState`, `ChangeApplicationState`, `OpenFiles`, `RunCommands`, `OpenTerminalsOrPlugins`, `WriteToStdin`, `WebAccess`, `ReadCliPipes`, `MessageAndLaunchOtherPlugins`). User confirms on first load; choices stored in a permissions cache. Coarse buckets, but Wasm sandboxing means the worst case is bounded by what the host exposes.
- **Helix** has no plugin system in tree as of this writing; the long-running discussion (issues #122, #3806) explicitly cites "permission model" as a blocker — they don't want to ship Vim-style ambient-authority Lua. The community is leaning toward Wasm + capability-style hostcalls precisely to avoid Neovim's situation.
- **Neovim** Lua/RPC plugins run with full user authority. No permission model. Plugins routinely shell out, read arbitrary files, hit the network. The ecosystem's answer is social ("only install reputable plugins"). This is exactly what Centrifuge is trying not to be.

**Takeaway:** the Rust-Wasm plugin community has converged on **Wasm-as-sandbox + named hostcall capabilities** because the alternative (Neovim model) is unsalvageable.

---

## 13. Tauri Capabilities

Tauri 2 introduced a capabilities/permissions split. Plugins ship `permissions/*.toml` (e.g. `fs:allow-read-text-file`, `fs:scope-home-recursive`). The application authors `capabilities/*.json` that bind sets of permissions to specific windows/webviews — and optionally to specific remote URL patterns:

```json
{ "identifier": "main", "windows": ["main"],
  "permissions": ["core:window:default", "fs:allow-read-text-file",
                  "core:window:allow-set-title"] }
```

The CLI compiles these into a static ACL the Rust core checks for every IPC command. Scope objects (path globs, URL patterns) refine permissions. Per the docs, "Windows and WebViews which are part of more than one capability effectively merge the security boundaries."

**Failure modes / caveats:** the docs explicitly warn that on Linux/Android, Tauri cannot distinguish iframe-originated requests from window-originated ones — a reminder that capability systems live or die by the granularity of the underlying identifier.

**Takeaways:** (a) **two-layer split**: plugin authors define *permissions*; app authors compose them into *capabilities* with scopes. (b) **compile-time ACL** > runtime registry — review-friendly, no startup races. (c) capability identity must align with what the OS can actually distinguish.

---

## Synthesis: Does a 5-Tier Numeric Model Make Sense?

### The case *for* tiers
1. **Cognitive load.** Plugin authors and end users can't reason about 40 capabilities. "Level 2: read-only, no network" is communicable. Tiers are good *labels*.
2. **Defaults & policy.** "Run all plugins at ≤level 3 unless the user opts in" is a one-line policy. Capability sets give nothing to point at.
3. **Audit.** "What plugins requested level 5?" is a one-query answer.
4. **Distribution gating.** App stores want a number for review prioritization.

### The case *against* tiers (stronger)
1. **Real authority is orthogonal.** Network access and GPU access are independent. Storage scope and CPU compute are independent. Forcing them onto a line means level 4 = "network + GPU" includes "storage write" because someone had to put it somewhere. This is exactly how `CAP_SYS_ADMIN` rotted.
2. **Every system surveyed that started linear has split.** Linux split `CAP_BPF`, `CAP_PERFMON`, `CAP_CHECKPOINT_RESTORE` *out of* `CAP_SYS_ADMIN`. Android split runtime/normal/signature tiers and now has finer-grained per-API grants. iOS entitlements never were tiered. The arrow of history points away from tiers.
3. **Confused-deputy risk.** A tier-3 plugin that can be coerced by a tier-5 host into doing tier-5 things is a bug class tiers naturally produce. Object-capability models structurally prevent it (Fuchsia, WASI, Capsicum).
4. **Compositionality.** Capability *sets* compose by union/intersection. Tiers don't — `min(2,4)` isn't meaningful.
5. **Plugin authors lie about what tier they need.** With orthogonal capabilities, the manifest has to enumerate what's actually used; static analysis can verify. With tiers, "level 5 to be safe" is the path of least resistance, identical to the Android pre-Marshmallow disaster.

### Recommendation

**Don't make tiers the *primitive*. Make capabilities the primitive and tiers a *presentation layer*.**

Concretely for Centrifuge:

1. **Primitive layer — capability handles, à la Fuchsia / WASI.** Plugin manifest declares typed capabilities with scopes:
   - `compute.cpu { max_threads: 4 }`
   - `compute.gpu { vendor: "any", vram_mb: 2048 }`
   - `compute.npu { ... }`
   - `storage.read { path: "$plugin_data" }`
   - `storage.write { path: "$plugin_data" }`
   - `net.outbound { hosts: ["api.example.com:443"] }`
   - `ipc.peer { plugin_id: "..." }`
   The kernel hands out opaque handles. Plugins cannot name resources they weren't given. This is the enforcement substrate.

2. **Policy layer — named profiles, not levels.** Ship curated profiles (`sandboxed`, `local-tool`, `network-tool`, `compute-heavy`, `trusted-system`) that *expand to* capability sets. Users pick a profile; advanced users edit the underlying set. Profiles are documentation and defaults, not the security boundary.

3. **If you must keep numbers,** use them only as a UX summary computed from the capability set ("this plugin requests broad authority — score 4/5"), like macOS's "App Privacy" labels. Never as the enforcement primitive.

4. **Borrow specifically:**
   - **From WASI/Fuchsia:** capability handles, no ambient authority.
   - **From `pledge`:** monotonic narrowing — a plugin can voluntarily drop capabilities mid-run and never regain them.
   - **From Tauri:** two-layer split (plugin declares permissions; host composes capabilities with scopes); compile-time ACL.
   - **From Android Marshmallow:** runtime prompts for sensitive caps with a developer-authored rationale string, not just install-time.
   - **From MV3:** ban dynamic code loading (`eval`, remote Wasm) so the manifest tells the truth about what runs.
   - **From SELinux:** label-based scopes, not path strings, for resources plugins create.

The 5-level mental model is fine for marketing copy and a settings UI. Just don't let it become the type the kernel checks.
