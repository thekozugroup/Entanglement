# Multi-stage build for entangled daemon + entangle CLI.
# See spec §9.1 — Docker is the recommended Linux server install path.
# docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md
#
# Build context is the repository ROOT (see docker/README.md):
#   docker build -f docker/Dockerfile .

# Keep the builder and runtime on the same Debian release so the loader has
# the glibc symbols the binaries were linked against.
FROM rust:1.91-slim-trixie AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
COPY tools tools
# Use the pinned image's installed 1.91 toolchain and the workspace lockfile.
RUN cargo +"${RUST_VERSION}" build --release --workspace --bins --locked

FROM debian:trixie-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --user-group --home /var/lib/entangle entangle && \
    mkdir -p /var/lib/entangle && \
    chown entangle:entangle /var/lib/entangle && \
    chmod 700 /var/lib/entangle
COPY --from=builder --chmod=755 /build/target/release/entangled /usr/local/bin/entangled
COPY --from=builder --chmod=755 /build/target/release/entangle  /usr/local/bin/entangle
USER entangle
# The daemon resolves its config/socket from $HOME/.entangle (no config-dir
# flag; see crates/entangle-bin/src/config.rs), so HOME must be set.
ENV HOME=/var/lib/entangle
RUN /usr/local/bin/entangled --version && /usr/local/bin/entangle --version
# Operator RPC uses $HOME/.entangle/sock. `entangled status` sends a version
# request through that socket and exits nonzero if the daemon is unavailable.
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/entangled", "status"]
ENTRYPOINT ["/usr/local/bin/entangled"]
CMD ["run"]
