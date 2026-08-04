# Multi-stage build for entangled daemon + entangle CLI.
# See spec §9.1 — Docker is the recommended Linux server install path.
# docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md
#
# Build context is the repository ROOT (see docker/README.md):
#   docker build -f docker/Dockerfile .

FROM rust:1.91-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
COPY tools tools
# --locked pins to the committed Cargo.lock so the image is reproducible and a
# drifting registry cannot silently change the resolved dependency graph.
RUN cargo build --release --workspace --bins --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --user-group --home /var/lib/entangle entangle && \
    mkdir -p /var/lib/entangle && \
    chown entangle:entangle /var/lib/entangle && \
    chmod 700 /var/lib/entangle
COPY --from=builder /build/target/release/entangled /usr/local/bin/entangled
COPY --from=builder /build/target/release/entangle  /usr/local/bin/entangle
USER entangle
# The daemon resolves its config/socket from $HOME/.entangle (no config-dir
# flag; see crates/entangle-bin/src/config.rs), so HOME must be set.
ENV HOME=/var/lib/entangle
# Phase 1: the daemon listens ONLY on a Unix-domain socket at
# $HOME/.entangle/sock — there is no TCP listener, so nothing is EXPOSEd.
# `entangled status` connects to that socket and round-trips a `version` RPC,
# exiting non-zero if the daemon is unreachable or hung.
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/entangled", "status"]
ENTRYPOINT ["/usr/local/bin/entangled"]
CMD ["run"]
