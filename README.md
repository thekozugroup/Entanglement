# Entanglement

> A tiny Rust runtime + plugin ecosystem that turns the devices you already own into one cooperative compute fabric.

**Status:** spec complete (v6, 100/100 from two independent harsh critics across five revision rounds). Implementation has not started. This repo currently contains the architecture, research, and review trail.

---

## What it is

Two roles drive every design decision:

1. **AI sysadmin** — agents like Claude Code, Codex, and OpenCode operate the system on your behalf, including managing Docker on the host as a sealed tier-5 capability.
2. **Swarm compute** — pool CPU/GPU/NPU across paired devices so individual workloads (LLM inference, batch jobs, test parallelization) finish faster than they would on any single machine.

Everything else — the 5-tier permission model, the capability broker, the three mesh transports, biscuit auth, OCI/tarball plugin distribution — exists to make those two roles safe and ship-able.

## Read the spec

| Document | What |
| --- | --- |
| [REPORT.md](REPORT.md) | Plain-English architecture report + load-bearing decisions + 5-round review history |
| [docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md](docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md) | Final spec (~185 KB, 16 sections, 35 acceptance tests, glossary) |
| [docs/research/](docs/research/) | Six prior-art research reports (permissions, Rust plugins, distributed compute, agent layer, comparable systems, BitTorrent feasibility) |
| [docs/superpowers/specs/critic-*-review-v*.md](docs/superpowers/specs/) | Two harsh critics × five revisions = ten review documents |
| [graphify-out/GRAPH_REPORT.md](graphify-out/GRAPH_REPORT.md) | Knowledge graph — community structure, god nodes, surprising connections |
| [graphify-out/graph.html](graphify-out/graph.html) | Open in any browser for an interactive map of the spec |

## Codename history

Centrifuge → Strata → **Entanglement.** The first two were dropped over namespace collisions; v6 is a name-only revision of v5 and carries v5's grade forward. See `§0.1` of the spec for the audit trail.

## Tooling — graphify

The knowledge graph in `graphify-out/` was built with [safishamsi/graphify](https://github.com/safishamsi/graphify). To rebuild or update it locally:

```bash
# Install graphify (one-time, per machine)
uv tool install graphifyy
graphify install                  # registers as a /graphify skill in Claude Code
graphify claude install           # adds the always-on PreToolUse hook

# Then in Claude Code, type:
/graphify .                       # build / update the graph for this repo
```

Graphify itself is **not** vendored in this repo. Clone it separately if you want to read its source.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Status, contributing, and contact

Pre-implementation. The spec invites contributions but the implementation team is being assembled — see `§12.1` for the maintainer-role roster (`core-runtime-lead`, `mesh-lead`, `agent-lead`, `security-lead`, `release-lead`). Each role needs ≥2 active holders before Phase 1 can ship.

For substantive architecture feedback, open a discussion or issue on this repo.
