# syntax=docker/dockerfile:1.6
# Multi-stage build for the quik reverse proxy.
#
#   target=quik-runtime  → minimal image running quik (default)
#   target=echo-runtime  → echo backend image used by docker-compose for demos

ARG RUST_VERSION=1.95
ARG DEBIAN_VERSION=bookworm

# ─── Builder ─────────────────────────────────────────────────────────────────
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder

WORKDIR /build

# aws-lc-rs (rustls' default crypto provider) compiles BoringSSL via cmake.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake perl pkg-config \
 && rm -rf /var/lib/apt/lists/*

# Cache dependency compilation: build with a dummy source tree first, then
# replace with the real source. Any change under src/ only invalidates the
# quik crate, not its (slow-to-build) dependencies.
# The root manifest declares `quik-register` as a workspace member, so cargo
# must be able to load that member's manifest even when we only build the
# `quik` binary. Copy its Cargo.toml and stub its source for the cache layer;
# the real source is copied in below.
COPY Cargo.toml Cargo.lock ./
COPY quik-register/Cargo.toml ./quik-register/Cargo.toml
RUN mkdir -p src benches examples tests quik-register/src \
 && echo 'fn main() {}' > src/main.rs \
 && : > src/lib.rs \
 && echo 'fn main() {}' > benches/hot_path.rs \
 && echo 'fn main() {}' > examples/echo_backend.rs \
 && echo 'fn main() {}' > examples/load_test.rs \
 && echo 'fn main() {}' > quik-register/src/main.rs \
 && cargo build --release --bin quik --example echo_backend 2>/dev/null || true

COPY src ./src
COPY benches ./benches
COPY examples ./examples
COPY tests ./tests
COPY config ./config
COPY quik-register ./quik-register

# Ensure cargo notices the real source replaced the dummy.
RUN find src benches examples tests quik-register -name '*.rs' -exec touch {} + \
 && cargo build --release --bin quik --example echo_backend

# ─── Runtime: quik proxy ─────────────────────────────────────────────────────
FROM debian:${DEBIAN_VERSION}-slim AS quik-runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -s /usr/sbin/nologin -u 10001 quik \
 && mkdir -p /etc/quik /etc/quik/tls \
 && chown -R quik /etc/quik

COPY --from=builder /build/target/release/quik /usr/local/bin/quik

USER quik
WORKDIR /etc/quik
EXPOSE 8443 9090
ENTRYPOINT ["/usr/local/bin/quik"]
CMD ["--config", "/etc/quik/quik.toml"]

# ─── Runtime: echo backend ───────────────────────────────────────────────────
FROM debian:${DEBIAN_VERSION}-slim AS echo-runtime

RUN useradd -r -s /usr/sbin/nologin -u 10001 echo

COPY --from=builder /build/target/release/examples/echo_backend /usr/local/bin/echo_backend

USER echo
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/echo_backend"]
