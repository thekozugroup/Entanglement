# 04 — Agent Layer

How Centrifuge wraps locally-installed AI coding agents as first-class plugins, and how those agents reach across devices for compute and tools.

Status snapshot: April 2026. Names of products and protocols below are verified against their current docs/repos; ambiguous items are flagged.

---

## 1. The protocol & SDK landscape

### 1.1 Model Context Protocol (MCP)

- **Status**: Open spec stewarded by Anthropic with multi-vendor adoption (OpenAI, Google, Microsoft). Latest stable revision **2025-06-18** (`modelcontextprotocol.io/specification/2025-06-18`). Schema is the TypeScript file `schema/2025-06-18/schema.ts` in the spec repo.
- **Wire format**: JSON-RPC 2.0, UTF-8.
- **Transports** (only two are normative):
  1. **stdio** — server is a child process; client writes JSON-RPC lines to stdin, reads from stdout. Stderr is free-form logs. Default for locally-installed servers.
  2. **Streamable HTTP** — single MCP endpoint that accepts POST and GET; GET upgrades to SSE for server→client streams. Replaces the older "HTTP+SSE" transport from 2024-11-05. Sessions are tracked via the `Mcp-Session-Id` header (cryptographically random, ASCII-only). Spec mandates `Origin` validation, localhost binding for local servers, and "SHOULD" auth.
- **Primitives**: `tools` (model-callable functions), `resources` (read-only context the host pulls), `prompts` (parameterised templates the user invokes), plus client-side `roots`, `sampling`, and the new `elicitation` channel for mid-task user prompts.
- **Auth**: OAuth 2.1 with PKCE for HTTP transports; stdio inherits the parent's auth.
- **Why it matters to Centrifuge**: every modern coding agent now speaks MCP either as host (consumes servers) or as server (exposes itself). It is the lowest common denominator.

### 1.2 Claude Agent SDK

- **What it is** (renamed from "Claude Code SDK" in late 2025): a Python and TypeScript SDK at `docs.claude.com/en/api/agent-sdk/overview` that exposes the Claude Code agent loop as an embeddable library. Same harness, your harness.
- **Building blocks**: `query()` / streaming input, `ClaudeAgentOptions` (permissions, hooks, allowed tools, working directory), `AgentDefinition` for in-process subagents, `HookMatcher` for `PreToolUse` / `PostToolUse` / `UserPromptSubmit` / `Stop` interception, custom in-process tools, and MCP server wiring.
- **Hooks** are the primary extension point — they fire synchronously around tool calls, can mutate args, deny, or log. This is exactly the seam a host framework hooks into for sandboxing and audit.
- **Centrifuge wraps**: the SDK in-process where possible; otherwise the `claude` CLI in `--print` / streaming JSON mode.

### 1.3 Codex CLI (OpenAI)

- **Status**: `openai/codex` on GitHub, `npm i -g @openai/codex` or `brew install --cask codex`. Mostly Rust now (`codex-rs/`) with a thin TS wrapper (`codex-cli/`). There is also an `sdk/` directory.
- **Config**: `~/.codex/config.toml`, plus `.codex/skills/` for repo-local skills.
- **MCP**: Codex is both an MCP **client** (configure servers in `config.toml`) and ships an MCP **server mode** (`codex mcp`) so other agents can drive it.
- **Sandboxing**: docs at `docs/sandbox.md` redirect to `developers.openai.com/codex/security`. macOS uses Apple Seatbelt (`sandbox-exec` with a generated profile); Linux uses Landlock + seccomp. Three approval modes: `read-only`, `workspace-write`, `danger-full-access`.
- **Centrifuge wraps**: spawn `codex exec --json` for headless runs, or attach to `codex mcp` for tool-style invocation.

### 1.4 OpenCode (sst / anomalyco)

- **Status**: `opencode.ai`, distributed via npm (`opencode-ai`), Homebrew (`anomalyco/tap/opencode`), Arch, Chocolatey, Docker. TUI + desktop + IDE extension share one Go core with TS plugins.
- **Plugin API**: TS/JS modules under `.opencode/plugins/` or `~/.config/opencode/plugins/`, or npm packages declared in `opencode.json`. Plugins export an async function returning a hooks object — `tool.execute.before`, `tool.execute.after`, `experimental.session.compacting`, etc. Bun-installed deps via `package.json` in the plugin dir.
- **Transport for external control**: OpenCode exposes an HTTP server (`opencode serve`) with a JSON API and an MCP-compatible mode. Plugins themselves live in-process.
- **Centrifuge wraps**: same dual approach as Codex — drive the HTTP API, or treat OpenCode as an MCP-speaking peer.

### 1.5 Aider

- **Status**: `aider.chat`, Python CLI, no daemon, no extension. Repo-map heuristic plus tree-sitter to assemble context.
- **Integration surface**: stdin/stdout chat, `/commands`, exit codes, optional `--message` for one-shot. No MCP server, no plugin system. Always commits via git for undoability.
- **Centrifuge wraps**: as a **subprocess agent** with file-system rendezvous — give it a workspace path and a prompt, capture diff via git.

### 1.6 Cline / Roo Code

- **Status**: `cline/cline` is a VS Code extension (61k+ stars). Roo Code is a community fork. Both also ship a CLI (`cli/` dir in the cline repo) that runs the same agent core outside VS Code.
- **Surface**: VS Code extension API for in-editor use; CLI for headless. Cline is an MCP **client** — it connects to MCP servers a user adds. It is **not** an MCP server itself.
- **Bridging outside the editor**: use `cline-cli` (subprocess), or run a headless VS Code (`code --install-extension` + `code-server`).

### 1.7 Continue.dev

- **Status as of 2026**: `continue.dev` has pivoted toward **PR-time AI checks** (markdown-defined checks in `.continue/checks/` that GitHub treats as status checks). The IDE extension still exists but is no longer the primary product.
- **Surface**: GitHub App + IDE extensions (VS Code, JetBrains). Config-driven, YAML/markdown.
- **Centrifuge wraps**: best treated as a CI/PR-side integration, not a local agent plugin. The legacy IDE assistant has been outpaced by Cline/Codex/Claude Code.

### 1.8 "Hermes" — ambiguous

- Two plausible referents: (a) **NousResearch Hermes models** (Hermes 3, Hermes 4) — these are *model weights*, not an agent harness; integrating them means giving Centrifuge a generic OpenAI-compatible inference endpoint, then driving it with Aider/OpenCode/Codex. (b) **`hermes-agent`** style projects on GitHub — none have meaningful adoption as of April 2026.
- **Recommendation**: do not treat "Hermes" as a peer of Claude Code. Treat Hermes models as an **inference backend** for the model-runtime tier (research note 03), not the agent tier.

### 1.9 "OpenClaw" — unable to confirm

- No project of that name appears in npm, crates.io, PyPI, the MCP registry, or GitHub trending as of April 2026. Possible user-coined shorthand or misremembered name (OpenClaude? OpenHands? Cline?). Flag for clarification before allocating a plugin slot.

### 1.10 Agent2Agent (A2A)

- **Status**: originally Google, donated to the Linux Foundation. Live at `a2a-protocol.org`. SDKs in Python, JS, Java, .NET, Go.
- **Model**: each agent publishes an **Agent Card** (a `/.well-known/agent.json`-style descriptor with name, skills, auth scheme, endpoints). A2A speaks JSON-RPC over HTTP/SSE. Designed to be **complementary** to MCP — MCP is agent↔tool, A2A is agent↔agent.
- **Centrifuge wraps**: A2A is the right wire for cross-device agent-to-agent calls. Each Centrifuge node hosts an A2A endpoint that exposes its local agents as named skills.

### 1.11 Orchestration frameworks (LangGraph, CrewAI, AutoGen)

- These are *frameworks for building agents*, not agents themselves. They sit one layer above the kernel: a Centrifuge plugin could embed LangGraph, but Centrifuge does not need to wrap LangGraph as a peer of Claude Code. Out of scope for the agent-plugin tier.

---

## 2. Integration patterns (with trade-offs)

| Pattern | Examples | Pros | Cons |
|---|---|---|---|
| **Subprocess + stdio JSON-RPC** | MCP stdio, Codex `mcp`, Claude Code `--print` | Zero network surface, OS-level isolation via the parent, simple lifecycle | Per-call startup cost; no native multi-client; harder to bridge across hosts |
| **Local HTTP/SSE server** | OpenCode `serve`, MCP Streamable HTTP, A2A | Multi-client, long-lived, network-bridgeable, supports streaming | Origin/DNS-rebind risk; needs auth; port management |
| **Filesystem rendezvous** | Aider, raw `claude` CLI | Trivially scriptable, language-agnostic | No streaming, no structured tool calls, polling-based |
| **Editor extension only** | Cline (legacy), Continue IDE | Best UX inside editor | Hard to drive headlessly; bridge needs a headless VS Code or a CLI sibling |
| **Containerised agent** | Codex devcontainer, Claude Code in Docker, OpenCode `ghcr.io/anomalyco/opencode` | Strong isolation, reproducible env, easy multi-tenant | Image size, GPU passthrough, slower spawn |

---

## 3. Cross-device agent networking

A Centrifuge node should be able to ask a peer node, "run this refactor with your local Codex on your GPU."

- **Tool calls (agent → remote tool)**: Streamable-HTTP MCP. Auth with mTLS (kernel issues per-node certs) plus a short-lived capability token in the `Authorization` header. Local-only servers stay on stdio; only kernel-mediated tools leave the box.
- **Agent dispatch (agent → remote agent)**: A2A. Each kernel publishes one Agent Card listing every local agent as a skill (`claude-code.refactor`, `codex.exec`, `aider.edit`). The remote node enqueues a Task, streams updates over SSE, returns Artifacts.
- **Inference offload (agent → remote GPU)**: not the agent layer's job — that's the model-runtime tier. The agent talks to a kernel-local OpenAI-compatible endpoint; the kernel decides if it serves locally or forwards to a peer.
- **Identity**: kernel holds the device identity (mTLS cert from a Centrifuge CA). Agents inherit it implicitly by going through the kernel proxy. User identity rides as an OIDC ID-token claim inside the capability token. This composes with MCP's OAuth 2.1 — Centrifuge issues the OAuth tokens MCP servers expect.

Prior art worth borrowing from: Roo Code's remote-worker pool (HTTP queue), Devin's cloud sessions (per-task containers, signed webhooks), and `claude-code-router` style proxies.

---

## 4. Sandboxing — what the host can enforce

- **Codex** (reference impl): seatbelt profile on macOS, Landlock+seccomp on Linux, network off by default in `workspace-write`. Three modes named explicitly.
- **Claude Code**: permission engine in the SDK; `permission_mode` of `acceptEdits` / `plan` / `bypassPermissions`; `PreToolUse` hooks can deny. No kernel-level sandbox by itself.
- **Centrifuge baseline**: every agent plugin runs inside a kernel-managed sandbox (`bubblewrap` / `landlock` / `seatbelt` / Windows AppContainer) regardless of whether the agent has its own. Filesystem roots, network ACL, and CPU/mem caps are kernel-set, not agent-set. Agent self-sandboxing becomes defence in depth, not the only line.

---

## 5. The Centrifuge agent-plugin contract

```rust
trait AgentPlugin {
    fn manifest(&self) -> AgentManifest;     // id, version, capabilities, transport
    fn health(&self) -> Health;              // installed?, version, auth ok?
    async fn invoke(&self, task: Task) -> TaskHandle;   // streaming
    async fn cancel(&self, id: TaskId) -> Result<()>;
}
```

- **Manifest** declares: `id` (e.g. `claude-code`), `transport` (`Stdio | Http | Mcp | A2A | Subprocess`), `capabilities` (`edit`, `plan`, `review`, `exec`, `repo-map`), `model_requirements`, `sandbox_profile`, `cost_model`.
- **Discovery** (in priority order):
  1. Native registry — kernel ships a curated list with detection probes (`which claude`, `codex --version`, npm/global/bin scan, VS Code extension dir scan, MCP `~/.config/*/mcp.json`).
  2. User-declared in `centrifuge.toml`.
  3. Auto-import from MCP and A2A registries on the local network (mDNS-advertised).
- **Routing**: a small policy engine picks an agent per task — capability match, cost cap, locality (prefer local, fall through to peer node), and prior success rate. Tasks marshal as `{prompt, files[], constraints, policy}`; agents stream `{tool_call, file_change, log, result}` events.
- **Cross-device A2A bridge**: each kernel runs one A2A endpoint and one MCP gateway. Local agents see them as ordinary tools; remote calls are kernel-proxied so identity, sandbox, and audit stay uniform.
- **Hooks**: every plugin must accept kernel-injected `before_tool` / `after_tool` / `on_artifact` callbacks — this is how Centrifuge enforces audit logs and cross-agent permission policy without trusting the agent.

---

## 6. Open questions

1. Should Centrifuge ship its own MCP **gateway** (one endpoint, multiplexed to all installed servers) or expect each agent to discover MCP servers itself? Gateway is cleaner for cross-device but duplicates work agents already do.
2. A2A vs raw MCP-over-HTTP for agent-to-agent: A2A is purpose-built (Tasks, Artifacts, Agent Cards) but smaller ecosystem than MCP. Probably **both**, with A2A for agent dispatch and MCP for tool calls.
3. Confirm "OpenClaw" with the user before reserving a plugin slot.
