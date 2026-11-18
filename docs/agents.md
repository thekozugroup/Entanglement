# Running AI coding agents behind the MCP gateway

`entangle agent run <agent>` launches an AI coding agent so that every MCP
tool call goes through a per-session gateway that authenticates, applies tool
policy, and writes an audit record (spec §8.3).

```bash
entangle agent list
entangle agent run claude-code -- --model opus
entangle agent run codex --deny 'shell/*'
entangle agent run claude-code --allow 'fs/*' --allow 'git/status'
entangle agent run claude-code --trust-project-servers   # see "Project MCP servers"
```

Arguments after `--` go to the agent unchanged. The exit code of the agent
is the exit code of `entangle agent run`.

On Linux the agent process runs inside an OS sandbox (see
[The OS sandbox](#the-os-sandbox)). **The sandbox does not restrict network
access**: the agent can connect to any host, as it could when started
directly.

## What happens

1. Your agent's MCP config is read (never written) and every declared MCP
   server is recorded.
2. A gateway starts in-process on `127.0.0.1:<ephemeral port>` with a fresh
   256-bit bearer token.
3. A rewritten config is written to a private session directory
   (`$ENTANGLE_SESSIONS_DIR`, else `$XDG_RUNTIME_DIR/entangle/sessions/<id>`,
   else `~/.entangle/sessions/<id>`). Each server entry becomes
   `http://127.0.0.1:<port>/mcp/<name>`. The token is **not** written to disk;
   the config references the `ENTANGLE_SESSION_TOKEN` environment variable.
4. The agent is started with `ENTANGLE_SESSION_ID` and `ENTANGLE_SESSION_TOKEN`
   set, pointed at the session config, inside the OS sandbox (Linux). One
   line on stderr reports which sandbox layers are engaged and what is
   writable.
5. On exit the gateway stops, downstream MCP server processes are killed,
   and the session directory is deleted. If the original config changed
   meanwhile, a warning (`ENTANGLE-E0660`) is printed, also when the agent
   could not be launched.

Ctrl-C does not end the session. Interactive agents use it to interrupt
the current turn, so the agent decides what it means and the session lasts
until the agent exits. At a terminal the agent already receives Ctrl-C (the
terminal signals its whole foreground process group), so it is not sent
again; without a terminal the SIGINT reached `entangle agent run` alone and
is passed on. SIGTERM and SIGHUP (terminal closed) are passed on to the
agent, which then has 5 s to exit; `entangle agent run` exits with the
agent's status, and an agent still running after that is killed and the
exit status is 143 (SIGTERM) or 129 (SIGHUP). All three handlers are
installed before the gateway starts, and a signal that arrives before the
agent was started (Ctrl-C included) stops the session without starting it
(exit status 130 for SIGINT). Only the agent process
itself is signalled or killed, not processes it started: it stays in the
terminal's foreground process group so that it can read the terminal, and
signalling that group would signal the CLI too.

| Agent | Binary | Session config is passed via |
|---|---|---|
| `claude-code` | `claude` | `--mcp-config <file> --strict-mcp-config`; header `Authorization: Bearer ${ENTANGLE_SESSION_TOKEN}` |
| `codex` | `codex` | `CODEX_HOME=<session>/codex-home` (the other files next to the config that was read, `~/.codex` by default or the directory of `--config`, are symlinked in, e.g. `auth.json`; a failed link is an error); `bearer_token_env_var` |
| `opencode` | `opencode` | `OPENCODE_CONFIG=<file>`, and its `mcp` section again in `OPENCODE_CONFIG_CONTENT`; header `Bearer {env:ENTANGLE_SESSION_TOKEN}` (see below) |

Use `--config <path>` to read the MCP config from a non-default file and
`--bin <path>` to launch a specific executable.

### Project MCP servers need consent

Claude Code's default config is the `.mcp.json` in the current directory,
which ships with whatever repository you are in. Claude Code itself asks
before using a project's servers, but in a session it only sees gateway
URLs, and it is the gateway that starts the servers' commands and connects
to the remote ones. So when the config comes from the current directory
(not from `--config`), `entangle agent run` first lists every stdio server
it declares (name, command, arguments, and the *names* of its environment
variables, never their values) and every remote HTTP server, with or
without headers (name, URL without query or credentials, header *names*),
and then:

* starts the session if `--trust-project-servers` was given;
* otherwise, when stdin is a terminal, asks `Start these servers? [y/N]`
  (default No);
* otherwise refuses with an error naming `--trust-project-servers`.

A file named with `--config` is your own choice and is not prompted for.

Note: the spec's example uses `CLAUDE_CONFIG_DIR`; the Claude Code adapter
reads the project `.mcp.json`, so it uses `--mcp-config` instead (setting
`CLAUDE_CONFIG_DIR` would also hide the user's login).

### OpenCode

OpenCode's MCP servers are `mcp.<name>` entries: `{"type": "local",
"command": ["bin", "arg"], "environment": {...}}` or `{"type": "remote",
"url": "...", "headers": {...}}`, each with an optional `"enabled"`;
`{env:VAR}` in a value is replaced by the variable. JSONC (comments,
trailing commas) is accepted. The gateway runs the enabled servers of one
file: `--config <path>`, else the global config in
`$XDG_CONFIG_HOME/opencode` (default `~/.config/opencode`): `opencode.json`,
else `opencode.jsonc`, else `config.json`.

OpenCode **deep-merges** every config file it finds instead of using one of
them, so the session config cannot simply leave the user's servers out.
Instead, for every server name declared in any file OpenCode merges (the
global files above; `opencode.json`, `opencode.jsonc` and
`.opencode/opencode.json(c)` in the current directory and each parent up to
the repository root; and the `--config` file) it carries an entry with the
**same name**, which overrides the user's entry:

```json
"<name>": {"type": "remote", "url": "http://127.0.0.1:<port>/mcp/<name>",
           "headers": {"Authorization": "Bearer {env:ENTANGLE_SESSION_TOKEN}"},
           "enabled": true}
```

With `type: "remote"` OpenCode connects to `url`. Fields the override does
not set survive the merge (a local entry's `command` and `environment`, a
remote entry's other `headers`); OpenCode does not use `command` or
`environment` for a remote server, and extra headers only reach the
gateway. `enabled` is `true` only for servers the gateway runs: a server
the user disabled, or one declared only in another file (for example a
project's `opencode.json`), gets `"enabled": false` and stays off (were it
`true`, an OpenCode that merges a project's `local` entry after the
override would end up with that entry's `command` enabled), and
`entangle agent run` prints a warning naming the file (pass
`--config <file>` to run that file's servers through the gateway). A config
file that exists but cannot be parsed stops the session (`ENTANGLE-E0600`),
so no server can stay outside the gateway unnoticed.

Assumption, not verified against a live OpenCode: newer versions merge
`OPENCODE_CONFIG` *before* the project's `opencode.json` and merge
`OPENCODE_CONFIG_CONTENT` last, so the overrides are passed in both (the
inline copy holds only the `mcp` section, so the rest of the user's config
is not put in the environment). An OpenCode that merges the project file
last and ignores `OPENCODE_CONFIG_CONTENT` would let a project entry that
itself sets `type`, `command` and `"enabled": true` win over the override.

## The OS sandbox

On Linux, `entangle agent run` confines the agent process (and everything it
starts: shells, compilers, test runs, MCP servers it launches itself) before
it executes. The status is printed at session start and by `entangle doctor`
("agent sandbox"):

```
sandbox: Landlock ABI 7 filesystem allowlist + seccomp socket filter + no_new_privs; chmod, chown, timestamps and extended attributes NOT restricted by Landlock; local Unix sockets (D-Bus, ssh-agent, tmux, X11, Docker, the Entanglement daemon) stay reachable; network egress NOT restricted; writable: /home/you/project, /tmp, /var/tmp, /home/you/.claude, /home/you/.claude.json
note: the sandbox limits files and socket families; it is not a containment boundary. ...
```

**Read this first: the sandbox is defence in depth, not a containment
boundary.** It restricts which files the agent can open and which socket
families it can create. It does not stop the agent from talking to programs
that run outside the sandbox as you, and through them an agent can act
outside it: see [What the sandbox does not contain](#what-the-sandbox-does-not-contain).
Run an agent you do not trust on a machine or account you do not mind it
controlling.

**Untested with real agent sessions.** The allowlist was exercised with test
programs and with `claude --version`; no full Claude Code, Codex or OpenCode
session has been run under it. Claude Code in particular rewrites
`~/.claude.json` through a temporary file in the home directory, which the
allowlist does not permit, so saving its settings may fail. When a sandboxed
agent exits with a non-zero status, `entangle agent run` prints a hint naming
`--sandbox-write <path>` and `--no-sandbox`.

What is enforced:

* **Filesystem allowlist (Landlock).** The agent can read, write and
  execute in:
  - the **project directory**: the git work tree that contains the current
    directory, else the current directory. The home directory or `/` is
    never taken as the project because of a `.git` there, and a session
    started *in* the home directory or `/` is refused (`ENTANGLE-E0683`):
    `cd` into a project, or pass `--no-sandbox`. For a linked git work tree,
    the main repository's git directory is writable too (git keeps the work
    tree's objects and refs there), but only when the layout is the one
    `git worktree add` creates (the work tree's metadata points back to its
    `.git` file and lies under `<common>/worktrees/`, and the common
    directory holds `HEAD`, `objects/` and `refs/`) and the directory is not
    the home directory, `/` or a key directory: the `.git` file is a project
    file an earlier agent could have rewritten;
  - the temporary directories `/tmp`, `/var/tmp` and `$TMPDIR`, and
    `/dev/shm`;
  - the agent's own state: `~/.claude` and `~/.claude.json` (claude-code);
    `~/.codex` and the session directory, which holds its `CODEX_HOME`
    (codex); `~/.local/share/opencode`, `~/.cache/opencode` and
    `~/.local/state/opencode` (opencode — these three are OpenCode's
    documented defaults and were not checked against a live OpenCode);
  - anything you add with `--sandbox-write <path>` (repeatable).

  It can read and execute, but not write: the system directories (`/usr`,
  `/bin`, `/sbin`, `/lib*`, `/etc`, `/opt`, `/nix`, `/snap`, `/proc`,
  `/sys`), every directory on your `PATH`, the directories the agent is
  installed in (the directory of its executable; for an npm-installed agent
  its package directory and the `bin` next to it; for a `<root>/bin/`
  executable also `<root>/lib` and `<root>/libexec`), `~/.gitconfig` and
  `~/.config/git`, the session config directory, OpenCode's global config
  directory, and anything you add with `--sandbox-read <path>` (repeatable).
  The terminal devices (`/dev/tty`, `/dev/ptmx`, `/dev/pts`) are usable.
  An implicit read grant (a `PATH` entry, the agent's install tree) that is
  or contains `/`, the home directory, `~/.entangle`, `~/.ssh`, `~/.aws` or
  `~/.gnupg` is skipped with a warning; naming such a path with
  `--sandbox-read`/`--sandbox-write` is allowed but warned about. Home is
  compared after resolving symbolic links.

  **No other file can be opened**, for reading or writing: the rest of your
  home directory (`~/.ssh`, `~/.aws`, browser profiles, other projects).
  (Opening files is all this covers; see the next section for what is still
  reachable.) A tool the agent runs that needs more — a toolchain under
  `~/.cargo` or `~/.rustup`, a package cache such as `~/.npm` or
  `~/.cache/pip`, your SSH keys for `git push` — fails with "Permission
  denied" until you name the path with `--sandbox-read` or
  `--sandbox-write`. A named path must exist (`ENTANGLE-E0682`).
  On Landlock ABI 6 and later the agent also cannot signal processes outside
  the sandbox or connect to their abstract Unix sockets.
* **`no_new_privs`, no capabilities.** Setuid programs gain nothing, so
  `sudo` does not work inside a session; an agent started by root holds no
  capabilities.
* **Syscall filter (seccomp).** Sockets can be created only for Unix-domain,
  IPv4, IPv6 and netlink with protocol `NETLINK_ROUTE` (name resolution,
  `ip`); raw and packet sockets, other netlink protocols (audit, uevent,
  netfilter, sock_diag, generic) and every other family (Bluetooth, CAN,
  `AF_ALG`, …) are refused. The `TIOCSTI` and `TIOCLINUX` terminal ioctls
  are refused, so the agent cannot push keystrokes into your shell through
  the terminal it shares with you. `io_uring` is
  refused (it can create sockets unfiltered) and so is creating or joining
  namespaces, so tools that build their own sandbox from user namespaces
  (bubblewrap, Chromium's sandbox, rootless containers) do not work inside a
  session.
* **Resource limits.** Core dumps are disabled. `--sandbox-max-memory-mb`
  (address space; off by default because JavaScript runtimes reserve very
  large virtual regions) and `--sandbox-max-open-files` are optional.

### What the sandbox does not contain

Stated plainly:

* **Local Unix sockets are reachable, and through them the agent can act
  outside the sandbox.** Landlock does not mediate `connect()` to a
  path-named Unix socket, and the agent needs Unix sockets, so anything your
  user can connect to is reachable from inside the sandbox, for example:
  the D-Bus session bus (`$XDG_RUNTIME_DIR/bus`: `systemd-run --user` starts
  an unconfined process, the Secret Service hands out stored passwords),
  tmux and screen sockets (send keys to another shell), X11 and Wayland
  sockets, the Docker socket (root on the host), the ssh-agent socket (signs
  with your keys), and the **Entanglement daemon's RPC socket** (every
  daemon method, without the gateway's policy or audit). A test
  (`path_named_unix_sockets_outside_the_allowlist_stay_reachable`) pins this
  gap so the docs change when it closes.
* **Secrets in environment variables reach the agent.** The agent inherits
  your environment: `SSH_AUTH_SOCK`, `DBUS_SESSION_BUS_ADDRESS`, `AWS_*`,
  `GH_TOKEN`, `GITHUB_TOKEN`, API keys. Unset what it should not have before
  starting the session.
* **What Landlock never restricts:** changing permissions, owner,
  timestamps and extended attributes of files the agent can reach. Below
  ABI 3 it also does not restrict truncation (a readable file can be
  emptied), below ABI 5 device ioctls, below ABI 6 signals to your other
  processes and abstract Unix sockets; ABI 1 refuses renaming or linking
  files across directories altogether. The status line names the gaps of
  the running ABI, and below ABI 3 the sandbox counts as degraded.
* **Hooks an agent writes into its own config.** The agent's state
  directories are writable (below). Hooks, `notify` commands and MCP
  servers it adds there run when you later start that agent *directly*,
  outside any sandbox. `entangle agent run` asks before using new or
  changed user-level MCP servers (see [User-level MCP servers need
  consent](#user-level-mcp-servers-need-consent)) and reports at the end of a
  session which parts of the config changed.
* **Network egress is not restricted.** The agent keeps normal network
  access to every host. Restricting it to the gateway plus an allowlist of
  hosts (spec §8.3) needs a network namespace and a filtering proxy, which
  are not implemented. A tool call the gateway denies can therefore still be
  attempted by the agent over its own network connection if it has another
  way to reach the service.
* The agent's own state directories are writable, including the files that
  hold its credentials.
* macOS and other platforms: no sandbox is engaged for agents (the Seatbelt
  profile of spec §8.2 is not implemented for them); the session start says
  so.

Flags:

| Flag | Effect |
|---|---|
| `--no-sandbox` | Start the agent without the sandbox. A warning is printed. Tool calls still go through the gateway. |
| `--require-sandbox` | Refuse to start (`ENTANGLE-E0680`) unless every layer is engaged — a Landlock allowlist at ABI 3 or later, the seccomp filter and `no_new_privs` — instead of starting with a warning. It does not close the gaps listed above. |
| `--sandbox-read <path>` / `--sandbox-write <path>` | Extend the allowlist (repeatable). |
| `--sandbox-max-memory-mb <n>` / `--sandbox-max-open-files <n>` | Optional rlimits. |

**Degraded mode.** On a kernel without Landlock (older than 5.13, or
Landlock not enabled at boot) there is no filesystem allowlist. The agent
is still started, with `no_new_privs`, the capability drop, the socket
filter and the rlimits, and a warning says that its filesystem access is
not confined and why; `--require-sandbox` turns that into a refusal (as it
does for Landlock below ABI 3 and a host without seccomp). Landlock below
ABI 6 (no signal scoping) or below ABI 3, or a host without seccomp, is
reported as "reduced isolation". `entangle doctor` shows the same status
without starting anything. (In debug builds only,
`ENTANGLE_AGENT_SANDBOX_PROBE=no-landlock` makes a session or `doctor`
behave as on a kernel without Landlock, to try the degraded path; release
builds ignore it.)

A failure to build the sandbox (`ENTANGLE-E0681`) stops the session before
the agent starts: the agent never runs half-confined.

## Entanglement plugins as tools (`--entangle-tools`)

Off by default. With `entangle agent run <agent> --entangle-tools` the
session gets one more MCP server, named `entangle`, that the gateway
implements itself: its tools are the plugins loaded in the local daemon.

* `tools/list` returns one tool per loaded plugin. The tool name is the
  plugin's name (characters outside `[A-Za-z0-9_-]` become `_`, at most 64
  characters; a second plugin with the same name gets `_2`, in plugin-id
  order). The description carries the full plugin id and its tier. Plugin
  manifests declare no input schema, so every tool has the same generic
  one: `input` (UTF-8 text) or `input_base64` (binary), both optional.
* `tools/call` runs the plugin through the daemon's `plugins/invoke` RPC on
  this machine and returns its output: as text when it is UTF-8, otherwise
  as a base64 `resource` blob. A plugin failure is a tool error
  (`isError: true`, `ENTANGLE-E0688` followed by the daemon's error).
  Dispatch to other nodes is not offered through this server.
* It is a gateway route like any other: the bearer token, `--allow` /
  `--deny` (patterns `entangle/<tool>`, `entangle/*`), the audit log, the
  4 MiB request cap, the 120 s timeout (also passed to the daemon as the
  invocation timeout) and the 64 MiB reply cap all apply.
* The daemon decides what exists. A plugin over `[security]
  max_tier_allowed`, or listed in `[plugins] disabled`, is not loaded, so it
  is neither listed nor callable; a plugin unloaded during the session stops
  being callable at once (`ENTANGLE-E0686`). Capabilities are whatever the
  daemon granted the plugin; the agent gets none of its own.
* The daemon must be running when the session starts (`ENTANGLE-E0685`
  otherwise), and your agent config must not already have a server called
  `entangle` (`ENTANGLE-E0687`).

There is no config key for this yet: it is per session, by flag.

## Agents that are not supported yet

The spec (§8.3.1) also lists Aider, Cline and Continue. No adapter ships for
them: an adapter has to know exactly how the agent declares MCP servers and
how to hand it a session-scoped config, and for these three that could not
be confirmed from material available offline when the adapters were
written. A guessed format would leave tool calls outside the gateway without
anyone noticing, so `entangle agent run aider` (or `cline`, `continue`)
stops with `ENTANGLE-E0689` and the reason, `entangle agent list` shows them
as "not supported yet", and the shell wrapper installs no shim for them.

## Gateway behaviour

* `POST /mcp/<server>` with MCP JSON-RPC 2.0 (single message or batch),
  `Authorization: Bearer <token>` required (compared in constant time).
  Replies are `application/json`; notifications get `202`. Only
  `notifications/*` methods are forwarded without an id; a `tools/call`
  without an id is audited as denied (`tools/call sent as notification`) and
  dropped, and any other id-less method is dropped. A message that is not
  valid JSON-RPC 2.0 (`jsonrpc` not `"2.0"`, non-string `method`, an `id`
  that is not a string/number/null, scalar `params`, a "response" without
  exactly one of `result`/`error`) gets error `-32600` (`ENTANGLE-E0666`).
* Downstream **stdio** servers are started lazily from the original
  command/args/env, one process per server per session. `initialize` is passed
  through and cached; request ids are remapped internally, and an agent's
  `notifications/cancelled` is translated to the downstream id of the
  request it names (dropped when nothing in flight matches). A request that
  times out is cancelled downstream with `notifications/cancelled`. Server-initiated
  requests cannot be relayed to the agent: the gateway answers them itself
  (`ping` with an empty result, anything else with JSON-RPC `-32601`) so the
  server does not hang, and drops server notifications. The agent's `roots`,
  `sampling` and `elicitation` capabilities are removed from the
  `initialize` sent downstream for the same reason.
* Each stdio server runs in its own process group (unix); stopping it kills
  the whole group, so the real server behind a wrapper such as `npx` or
  `uvx` is stopped too.
* Downstream **HTTP** (`url`) servers are proxied over MCP Streamable HTTP:
  - each message is `POST`ed to the server's URL with the headers from your own
    agent config (Claude Code `headers`, Codex `http_headers` /
    `env_http_headers` / `bearer_token_env_var`, OpenCode `headers`; `${VAR}`,
    `${VAR:-default}` and `{env:VAR}` references are expanded from your
    environment). The gateway's bearer token is never sent downstream, and the
    headers never reach the agent: the rewritten session config only holds the
    gateway URL and token. `Host`, `Accept`, any `Content-*` or `Mcp-*`
    name and the hop-by-hop names (`Connection`, `Keep-Alive`,
    `Proxy-Connection`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`,
    `Trailer`, `Transfer-Encoding`, `Upgrade`) cannot be configured
    (`ENTANGLE-E0664`); a configured `User-Agent` replaces the gateway's;
  - replies may be `application/json` (an object or a batch) or
    `text/event-stream`: events are read until the response to the request id
    arrives, other server notifications are dropped, and a server `ping`
    request is answered (anything else with `-32601`) by a separate `POST`;
  - the gateway handshakes once per route (the agent's `initialize` is cached,
    the gateway sends its own `notifications/initialized`, and handshakes
    itself if the agent skipped `initialize`), keeps the `Mcp-Session-Id` the
    server assigns and sends it, with `MCP-Protocol-Version`, on every later
    request; the id is also returned in the `Mcp-Session-Id` header of the
    gateway's replies. If the server forgets the session (404) that request
    fails (`ENTANGLE-E0671`) and the next one starts a fresh session; at
    shutdown the gateway sends `DELETE` to end it. Every client of a route
    shares that one session, so, as for stdio, request ids are remapped to
    gateway-unique ones (the agent gets its own id back) and an agent's
    `notifications/cancelled` is translated to the downstream id (dropped
    when no single in-flight request matches). A request that times out is
    cancelled downstream with `notifications/cancelled`, since a closed
    connection is not a cancellation in Streamable HTTP;
  - policy, `after_tool` and audit hooks are the same as for stdio; the
    request timeout (E0663) covers connecting, the TLS handshake, sending and
    reading the whole reply, and a JSON body or SSE event over the downstream
    message cap (64 MiB by default) fails with E0663;
  - only `https://` URLs, except loopback hosts (`http://127.0.0.1:…`,
    `http://localhost:…`, `http://[::1]:…`, re-checked against the connected
    address); a URL with embedded credentials or any other scheme is refused
    with `ENTANGLE-E0664` without being contacted (`entangle agent run` warns
    about it at start). So is a Claude Code `"type": "sse"` server: the
    deprecated HTTP+SSE transport is not proxied, point the entry at the
    server's Streamable HTTP endpoint (`"type": "http"`). Redirects are never followed, so configured headers
    cannot be handed to another host; a non-2xx status, an unexpected
    content-type or invalid JSON is `ENTANGLE-E0671`. Each request opens its own
    connection (`Connection: close`);
  - for a **project** config (not `--config`), every HTTP server is listed in
    the consent prompt too (URL without query, header *names*): it is a host
    chosen by the repository, whose tool descriptions and results reach the
    agent, and the environment references in its headers would send your
    variables there.
* Connections: at most 128 open at once (further ones wait unaccepted);
  a connection that has not sent a complete request head after 30 s, or
  has been idle that long between keep-alive requests, is closed.
* Limits: 16 requests in flight (excess get `503`, `ENTANGLE-E0665`), 4 MiB
  body (`413`, E0667), 120 s downstream timeout (E0663, covering both
  writing the request to the server's stdin and waiting for its reply),
  unknown server `404` (E0668), bad token `401` (E0670). A request for a
  server that is not in the session config — for example one added by hand
  to the session's temporary config — is refused, and the error names the
  durable file to edit instead (`~/.claude/settings.json` or the project's
  `.mcp.json` for claude-code, `~/.codex/config.toml`, OpenCode's
  `opencode.json`, or the `--config` file) and says to start a new session. A server whose stdin write
  is cut short (it stopped reading) is killed and restarted on the next
  request, and so is one that writes a single message over 64 MiB (its
  in-flight calls fail with E0663).
* Policy: `--deny` wins over `--allow`; patterns are `server/tool`,
  `server/*`, `*`, compared with the whole `server/tool` text (so a server
  named `gh/admin` is covered by `gh/admin/*`). There are no other
  wildcards: a pattern such as `*/delete_file` or `fs` is refused at start
  (`ENTANGLE-E0625`) instead of silently matching nothing, and a pattern
  that names no configured server is logged as a warning. Denied calls
  return JSON-RPC error `ENTANGLE-E0661` and never reach the downstream
  server.
* A request that has been accepted is processed to the end even if the
  agent closes the connection: the downstream call still completes, counts
  against the in-flight limit until it does, and is audited.
* Audit: every `tools/call` emits a structured `tracing` event on target
  `entangle::audit` (server, tool, decision, duration, outcome) and is kept in
  an in-memory log (`GatewayHandle::audit_log`, last 10 000 records; tool
  names over 256 bytes and reason/error texts over 1 KiB are truncated with
  a marker giving the original length). Enable with
  `RUST_LOG=entangle::audit=info`.

## Error codes

`E0620` (former "not implemented" gateway stub) is retired and no longer
emitted. In use: E0621 bind, E0622 non-loopback refused, E0623 empty token,
E0624 zero `max_in_flight`, E0625 invalid policy pattern, E0660 original
config modified, E0661-E0668
JSON-RPC/HTTP failures listed above, E0669 session not activated, E0670 auth,
E0671 HTTP downstream status/protocol failure. E0664 now means an HTTP
downstream URL or header was refused (it used to mean "HTTP unsupported").

Sandbox, built-in server and adapters: E0680 `--require-sandbox` on a host
that cannot engage every layer, E0681 the sandbox could not be prepared,
E0682 an unusable sandbox path, E0683 a sandboxed session whose project
directory would be the home directory or `/`, E0685 the daemon cannot be reached for
`--entangle-tools`, E0686 a plugin tool that does not exist (or bad tool
arguments), E0687 the name `entangle` is already taken by a configured
server, E0688 a plugin invocation failed, E0689 an agent whose adapter is
deferred.

Running the agent directly (without `entangle agent run`) bypasses all of this
by design.
