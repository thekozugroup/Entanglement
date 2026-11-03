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
   set, pointed at the session config.
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
before starting a project's servers, but in a session it only sees gateway
URLs, and it is the gateway that starts the servers' commands. So when the
config comes from the current directory (not from `--config`),
`entangle agent run` first lists every stdio server it declares (name,
command, arguments, and the *names* of its environment variables, never
their values) and then:

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
* Downstream **HTTP** (`url`) servers are not proxied; calls fail with
  `ENTANGLE-E0664` and `entangle agent run` prints a warning at start.
* Connections: at most 128 open at once (further ones wait unaccepted);
  a connection that has not sent a complete request head after 30 s, or
  has been idle that long between keep-alive requests, is closed.
* Limits: 16 requests in flight (excess get `503`, `ENTANGLE-E0665`), 4 MiB
  body (`413`, E0667), 120 s downstream timeout (E0663, covering both
  writing the request to the server's stdin and waiting for its reply),
  unknown server `404`, bad token `401` (E0670). A server whose stdin write
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
JSON-RPC/HTTP failures listed above, E0669 session not activated, E0670 auth.

Running the agent directly (without `entangle agent run`) bypasses all of this
by design.
