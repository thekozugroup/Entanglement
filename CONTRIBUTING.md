# Contributing to Entanglement

Entanglement is a tiny Rust runtime that turns the devices you own into one cooperative compute fabric. Every contribution should reference a section of [`docs/architecture.md`](docs/architecture.md) — the spec is the source of truth for behavior.

## Local dev setup

Prerequisites:
- Rust 1.91 or newer (pinned via `rust-toolchain.toml`).
- `wasm32-wasip2` target: `rustup target add wasm32-wasip2`.
- macOS, Linux (tier-1), or Windows + WSL2.

```bash
git clone https://github.com/thekozugroup/Entanglement
cd Entanglement
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Building example plugins

```bash
cargo xtask hello-world build       # builds the hello-world wasm + signs it
cargo xtask hash-it build           # builds the hash-it wasm + signs it
```

Both require `~/.entangle/identity.key` (run `entangle init --non-interactive` first).

## Running the daemon locally

```bash
cargo run --release -p entangle-bin -- run
# In another terminal:
cargo run --release -p entangle-cli -- doctor
cargo run --release -p entangle-cli -- plugins list
```

Or `--allow-local` to skip the daemon and use an in-process kernel.

## §16 acceptance tests

Every spec change adds an ATC ID and a test. The test name maps to the ATC ID (lowercased, hyphen → underscore): `ATC-MAN-1` → `fn atc_man_1_<slug>`. The matrix runner at `crates/entangle-atc-matrix` scrapes them.

## Code review

PRs need 1 maintainer approval (per spec §12.1 role policy). Tier-5 / signing / cross-node changes need security-lead co-sign. Conventional Commits encouraged but not required. Sign your commits (`git commit -S`) where possible.

## Style

- `#![forbid(unsafe_code)]` is the workspace default. `unsafe` requires security-lead approval.
- Every public item gets a `///` doc comment. `cargo doc --workspace --no-deps` must pass with `RUSTDOCFLAGS='-D warnings'`.
- Use the existing `entangle-observability` crate for tracing setup; don't construct your own subscriber.
- Capability surfaces, error codes, and ATC IDs follow the spec — don't invent new ones without spec changes.

## Testing patterns

- Unit tests in `src/<mod>.rs` `#[cfg(test)]`. Integration tests in `tests/<scenario>.rs`.
- Tests that mutate `current_dir` or environment variables: mark `#[ignore = "mutates state"]` and document the run command.
- Don't depend on `wasm32-wasip2` being installed in test code; commit pre-built fixtures (e.g. `crates/entangle-host/tests/fixtures/hello-pong.wasm`).

## Filing an issue

Use the templates in `.github/ISSUE_TEMPLATE/`. Reference the spec section if behavior is in question. Security issues go to the [SECURITY.md](SECURITY.md) channel, NOT public issues.

## Code of Conduct

We follow the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Reports to `conduct@entanglement.dev`.

## Supply-chain audits

```bash
cargo install cargo-vet cargo-deny cargo-audit
cargo deny check          # bans / licenses / advisories / sources
cargo audit               # RustSec database
cargo vet                 # supply-chain audit set; populate with `cargo vet certify <crate>`
```

The `supply-chain/` directory holds the workspace's vet config and audit set.
Phase 1 ships the seed (`config.toml` + an empty `audits.toml`); maintainers
certify crates as they review them.

## Iteration sprint

`.iterations/` carries a snapshot of the 80-iteration completion sprint that
took the codebase from Phase-1-complete to Phase-2-scaffolded. See
`.iterations/PLAN.md` for the criteria list and `LOG.md` for the per-iter
grading record. Phase-2 implementers can use the criteria as a punch list:
each item that returned `NotImplemented` has a stable error code and a unit
test pinning the contract.

## Bus factor

Every named role in `docs/maintainers/roles.toml` should have ≥2 holders.
The weekly `.github/workflows/bus-factor.yml` job fails by design until
additional maintainers are seated; if you want to take on a role, open a
PR adding yourself to the relevant role doc.
