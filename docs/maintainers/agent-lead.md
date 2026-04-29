# Agent Lead

## Responsibilities

You own the AI sysadmin layer (Phase 2): the agent host plugin, the MCP gateway, the configuration adapter that wraps Claude Code / Codex / OpenCode, and the wrapper-bypass UX detection (`entangle wrapper status`).

You also own the spec sections that define agent integration — §8 in its entirety. Tier-5 plugins need security-lead co-sign because they sit at the highest trust level.

## Onboarding

1. Spec §8 (agent host plugin), §3.5 (per-OS sandbox), §4.4.1 case 3 (runtime/tier mismatch rules).
2. Read the [Model Context Protocol spec](https://modelcontextprotocol.io/specification) and [Anthropic's Claude Agent SDK docs](https://docs.claude.com/en/docs/claude-code/sdk).
3. Walk the agent flow: install Claude Code locally, run `entangle agent claude-code --dry-run`, inspect the rewritten config, restore the original.
4. Pair with security-lead on the threat-model entries for §11 #6, #10, #14 before touching agent code.

## Decisions you can make solo

- Adding new agent adapters that follow the configuration-adapter pattern.
- Internal refactors to the MCP gateway routing logic.
- Test additions.

## Decisions that need quorum (≥2 agent-leads + 1 security-lead)

- Changing the configuration-adapter contract (snapshot/rewrite/restore semantics).
- Adding tier-5 capabilities to the agent host plugin.
- Bundling a runtime (Node, Python) with the daemon — explicit non-goal in v6 spec; reversal needs project-wide RFC.
- Direct-invocation behavior (when the user runs the agent outside the wrapper).

## Escalation

Tier escalation, sandbox-escape concerns, supply-chain decisions about agent adapters → security-lead. UX decisions → mesh-lead and core-runtime-lead.
