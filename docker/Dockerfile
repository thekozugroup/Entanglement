# Multi-stage build for entangled daemon + entangle CLI.
# See spec §9.1 — Docker is the recommended Linux server install path.
# docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md

FROM rust:1.91-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
COPY tools tools
RUN cargo build --release --workspace --bins

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
ENV HOME=/var/lib/entangle
EXPOSE 7001
ENTRYPOINT ["/usr/local/bin/entangled"]
CMD ["run"]
