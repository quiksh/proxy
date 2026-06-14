# syntax=docker/dockerfile:1.6
# Static, minimal image for the quik-register service-registration sidecar.
#
# Build context is the REPO ROOT (quik-register is a workspace member):
#   docker build -f quik-register/Dockerfile -t quik-register .
#
# Produces a fully static musl binary on a distroless base (CA certs included,
# for tls:// NATS and https liveness probes). Two uses:
#   1. Run directly as a standalone registrar sidecar (tiers 2a / 3); or
#   2. As a COPY --from source to bundle the agent into an arbitrary service
#      image for a shared-fate single container (tier 2b) - see
#      examples/nats/bundled/ and docs/service-registration.md §6:
#        COPY --from=ghcr.io/quiksh/quik-register:1 /usr/local/bin/quik-register /usr/local/bin/

ARG RUST_VERSION=1.95

# ─── Builder (musl → static) ─────────────────────────────────────────────────
# The sidecar is ring/rustls only (no aws-lc/OpenSSL), so it links cleanly
# against musl with no cmake/BoringSSL toolchain. musl-dev + gcc cover ring's C.
FROM rust:${RUST_VERSION}-alpine AS builder
RUN apk add --no-cache musl-dev gcc
WORKDIR /build

# Dependency cache: resolve the workspace with dummy sources first, so a change
# under quik-register/src/ doesn't rebuild the (slow) dependency graph. The root
# `quik` manifest must be present for the workspace to resolve, but is never
# compiled here (`-p quik-register` builds only the sidecar and its deps).
COPY Cargo.toml Cargo.lock ./
COPY quik-register/Cargo.toml quik-register/Cargo.toml
RUN mkdir -p src benches quik-register/src \
 && echo 'fn main() {}' > src/main.rs \
 && : > src/lib.rs \
 && echo 'fn main() {}' > benches/hot_path.rs \
 && echo 'fn main() {}' > quik-register/src/main.rs \
 && cargo build --release -p quik-register 2>/dev/null || true

COPY quik-register/src ./quik-register/src
RUN find quik-register/src -name '*.rs' -exec touch {} + \
 && cargo build --release -p quik-register \
 && cp target/release/quik-register /quik-register

# ─── Runtime (distroless, static, nonroot) ───────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=builder /quik-register /usr/local/bin/quik-register
ENTRYPOINT ["/usr/local/bin/quik-register"]
CMD ["--config", "/etc/quik-register/quik-register.toml"]
