# Running AI coding agents behind the MCP gateway

`entangle agent run <agent>` launches an AI coding agent so that every MCP
tool call goes through a per-session gateway that authenticates, applies tool
policy, and writes an audit record (spec §8.3).

```bash
entangle agent list
entangle agent run claude-code -- --model opus
entangle agent run codex --deny 'shell/*'
entangle agent run claude-code --allow 'fs/*' --allow 'git/status'
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
5. On exit (including Ctrl-C and SIGTERM) the gateway stops, downstream MCP
   server processes are killed, and the session directory is deleted. If the
   original config changed meanwhile, a warning (`ENTANGLE-E0660`) is printed.

| Agent | Binary | Session config is passed via |
|---|---|---|
| `claude-code` | `claude` | `--mcp-config <file> --strict-mcp-config`; header `Authorization: Bearer ${ENTANGLE_SESSION_TOKEN}` |
| `codex` | `codex` | `CODEX_HOME=<session>/codex-home` (other files in `~/.codex` are symlinked in); `bearer_token_env_var` |
| `opencode` | `opencode` | `OPENCODE_CONFIG=<file>`; header `Bearer {env:ENTANGLE_SESSION_TOKEN}` |

Use `--config <path>` to read the MCP config from a non-default file and
`--bin <path>` to launch a specific executable.

Note: the spec's example uses `CLAUDE_CONFIG_DIR`; the Claude Code adapter
reads the project `.mcp.json`, so it uses `--mcp-config` instead (setting
`CLAUDE_CONFIG_DIR` would also hide the user's login).

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
* Downstream **HTTP** (`url`) servers are not proxied; calls fail with
  `ENTANGLE-E0664` and `entangle agent run` prints a warning at start.
* Limits: 16 requests in flight (excess get `503`, `ENTANGLE-E0665`), 4 MiB
  body (`413`, E0667), 120 s downstream timeout (E0663, covering both
  writing the request to the server's stdin and waiting for its reply),
  unknown server `404`, bad token `401` (E0670). A server whose stdin write
  is cut short (it stopped reading) is killed and restarted on the next
  request.
* Policy: `--deny` wins over `--allow`; patterns are `server/tool`,
  `server/*`, `*`. Denied calls return JSON-RPC error `ENTANGLE-E0661` and
  never reach the downstream server.
* A request that has been accepted is processed to the end even if the
  agent closes the connection: the downstream call still completes, counts
  against the in-flight limit until it does, and is audited.
* Audit: every `tools/call` emits a structured `tracing` event on target
  `entangle::audit` (server, tool, decision, duration, outcome) and is kept in
  an in-memory log (`GatewayHandle::audit_log`). Enable with
  `RUST_LOG=entangle::audit=info`.

## Error codes

`E0620` (former "not implemented" gateway stub) is retired and no longer
emitted. In use: E0621 bind, E0622 non-loopback refused, E0623 empty token,
E0624 zero `max_in_flight`, E0660 original config modified, E0661-E0668
JSON-RPC/HTTP failures listed above, E0669 session not activated, E0670 auth.

Running the agent directly (without `entangle agent run`) bypasses all of this
by design.
