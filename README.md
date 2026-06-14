# quik

**A small, fast, configurable reverse proxy in Rust.**

quik terminates TLS, validates JWTs, load-balances across a pool of backends,
and gets out of the way. It's designed to be the kind of proxy you can read in
an afternoon, deploy in five minutes, and trust in front of services you care
about. No control-plane sidecar, no plug-in runtime, no surprise allocations
on the hot path.

```bash
quik --config config/example.toml
```

- that's the whole interface. Configuration is one TOML file. Updates to the
running fleet (adding a backend, draining one for replacement) go through a
small HTTP admin API.

---

## What's in the box

- **HTTP/1.1 + HTTP/2** on the inbound listener (ALPN-negotiated).
- **TLS termination** via [rustls] (no OpenSSL).
- **WebSockets**, **SSE**, **gRPC trailers** all forwarded transparently.
- **Routing** by host, method, exact path, or segment-aware prefix -
  most-specific match wins.
- **Per-route modules**: timeout, max body size, prefix stripping, JWT auth.
- **JWT authentication** with JWKS auto-refresh on `kid` miss; verified
  claims project into upstream-bound headers.
- **Load balancing**: round-robin, random, or least-connections; **passive
  health** (consecutive-failure ejection with exponential backoff) plus
  optional **active health probes**.
- **Online member management** via a separate admin listener: add, drain,
  undrain, or remove members without restarting.
- **Service registration** (optional `nats` feature): backends self-register
  into a NATS JetStream KV bucket and quik reconciles them into the pool - with
  a registrable-address allow-list, member caps, and operator overrides. See
  [docs/service-registration.md](docs/service-registration.md).
- **Optional egress (forward) proxy** mode - HTTP CONNECT with host/CIDR
  policy and SNI verification.
- **Prometheus metrics** + **structured JSON / key-value logs**.
- **Graceful shutdown** on `SIGTERM`/`SIGINT` - drains in-flight requests, with
  an optional edge-withdraw grace so a perimeter stops routing first
  ([docs/graceful-shutdown.md](docs/graceful-shutdown.md)); force-exit on a
  second signal.

## What it isn't

- Not a service mesh. No sidecars, no xDS, no clusters discovering each other.
- Not a web server. No static files, no PHP-FPM, no body rewriting.
- Not a Layer-7 firewall. The egress mode is allow-list traffic control, not
  request inspection.

## Performance

A single binary, ~5 MB stripped, ~30 MB RSS under load. The forwarding path
avoids per-request allocations where it can - metric handles are pre-built
per upstream member, the in-flight counter is a single atomic, and bodies
stream end-to-end without buffering. See `benches/hot_path.rs` for the
microbenchmarks.

## Deployment scenarios

| Scenario                              | Guide                                             |
|---------------------------------------|---------------------------------------------------|
| One host, a handful of homelab services | [docs/homelab.md](docs/homelab.md)              |
| Multi-backend production reverse proxy  | [docs/ha-reverse-proxy.md](docs/ha-reverse-proxy.md) |
| Outbound HTTP CONNECT egress filter   | [docs/forward-proxy.md](docs/forward-proxy.md)    |
| Managing pools on a running proxy     | [docs/admin-api.md](docs/admin-api.md)            |
| Backends that self-register (NATS)    | [docs/service-registration.md](docs/service-registration.md) · [examples/nats](examples/nats) |
| Graceful shutdown behind a perimeter  | [docs/graceful-shutdown.md](docs/graceful-shutdown.md) |
| Exposing quik outside a CDN           | [docs/hardening.md](docs/hardening.md)            |
| The full config schema                | [docs/config-reference.md](docs/config-reference.md) |

## Five-minute quickstart

```bash
# 1. Build
cargo build --release

# 2. Generate a self-signed cert (valid for localhost)
./scripts/gen-dev-cert.sh

# 3. Start an example backend
cargo run --example echo_backend -- 127.0.0.1:8080 &

# 4. Run the proxy. config/example.toml expects backends on :8080 and :8081
#    - point the second one elsewhere or edit the config first.
./target/release/quik --config config/example.toml
```

Send a request and watch the metrics:

```bash
curl -k https://localhost:8443/api/v1/users/42
curl    http://127.0.0.1:9090/metrics | grep quik_
```

## Try it with docker compose

The compose stack runs the proxy plus two echo backends. Useful for kicking
the tyres without installing Rust.

```bash
./scripts/gen-dev-cert.sh             # once
docker compose up --build -d

curl -k https://localhost:8443/echo/hello
curl    http://localhost:9090/metrics
docker compose logs -f quik
```

Default backends are baked into the compose stack; override either with
`BACKEND_A_ADDR` / `BACKEND_B_ADDR` env vars at `docker compose up` time.

## Building from source

```bash
make build          # debug
make release        # optimised
make test           # full test suite
make ci             # fmt-check + clippy + tests, as CI runs them
```

Requires Rust 1.88+ (edition 2024). No system dependencies beyond a C linker.

### Optional features

quik builds lean by default. NATS-based service registration is behind a cargo
feature so the default binary carries no NATS dependency:

```bash
cargo build --release --features nats     # adds the NATS registration watcher
```

## Project layout

```
src/                    proxy core
  proxy/                request handler, per-request span, modules
  routing/              route table - exact > prefix, longest-prefix-first
  upstream/             pools, balancers, passive + active health, drain
    nats/               NATS registration watcher (feature `nats`)
  auth/                 JWT validation, JWKS cache, claim injection
  admin/                admin listener + /admin/pools API
  egress/               optional HTTP CONNECT forward proxy
  observability/        tracing init + Prometheus exporter

config/                 example configurations
  example.toml          every matcher + module
  homelab.toml          single-host homelab setup
  docker.toml           used by docker-compose
  auth-demo.toml        multi-auth-block demo

tests/                  integration tests
examples/               echo_backend, load_test
  nats/                 service-registration demos (homelab + HA)
benches/                criterion benchmarks
docs/                   user-facing documentation

quik-register/          service-registration sidecar agent (workspace member)
```

This is a Cargo workspace: the `quik` proxy (root) plus `quik-register`, a small
sidecar that registers a backend into NATS - gated on a liveness probe - for the
proxy to pick up. `make build` / `make test` cover both.

## Releases

Releases are cut from the **Release** workflow (`.github/workflows/release.yml`),
triggered manually from the repo's Actions tab - there is no local `git tag` step.
One run computes the next version from the latest tag, pushes the new tag, and
publishes two multi-tagged images to GHCR - the `proxy` and the `quik-register`
sidecar, versioned in lockstep - all from `main`.

Git tags (`vX.Y.Z`) are the source of truth for the version; `Cargo.toml` stays at
`0.0.0` and is not bumped.

To cut a release:

1. Actions → **Release** → **Run workflow**.
2. Choose the bump from the dropdown - `patch`, `minor`, or `major`. You pick the
   size of the jump; the workflow derives the actual number from the latest tag.
   You never type a version string.
3. Run. The workflow tags the commit and pushes these tags to both
   `ghcr.io/<owner>/proxy` and `ghcr.io/<owner>/quik-register`:

   ```
   :1.2.3   :1.2   :1   :latest
   ```

Pull the published images:

```bash
docker pull ghcr.io/<owner>/proxy:latest
docker pull ghcr.io/<owner>/quik-register:latest
```

## Licence

MIT - see [LICENSE](LICENSE).

[rustls]: https://github.com/rustls/rustls
