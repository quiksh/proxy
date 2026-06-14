# CLAUDE.md

Guidance for working in the `quik` repo. For user-facing detail, README.md and
`docs/` are the source of truth — prefer linking to them over duplicating here.

## What this is

`quik` is a low-latency reverse proxy in Rust (edition 2024): TLS termination,
HTTP/1.1 + HTTP/2, JWT auth, dynamic upstream pools with health checking, a
runtime admin API, an optional HTTP CONNECT egress mode, and Prometheus
metrics. Single binary, one TOML config file. It is deliberately *not* a service
mesh, web server, or L7 firewall (see README "What it isn't").

## Build, test, lint

Use the Makefile — it mirrors what CI runs.

```bash
make build        # cargo build --all-targets (debug)
make release      # optimised binary
make test         # full suite (unit + tests/e2e_*.rs integration)
make check        # fmt-check + clippy (no test compile) — fast pre-commit gate
make ci           # fmt-check + lint + test — run this before pushing
make bench        # criterion benchmarks (benches/hot_path.rs)
```

- Toolchain: **Rust 1.88+**, edition 2024 (dependency floor; CI + the release
  image build on current stable). No system deps beyond a C linker.
- Lints are warnings in `Cargo.toml` but **`make lint` treats them as errors
  (`-D warnings`)** — CI will fail on any clippy warning. Run `make check`
  before declaring work done.
- `unsafe_code` is `warn`; avoid adding `unsafe`.

## Running locally

```bash
./scripts/gen-dev-cert.sh                              # once: self-signed localhost cert into tls/
cargo run --example echo_backend -- 127.0.0.1:8080 &   # a backend
make run                                               # runs against config/example.toml
```

`make run CONFIG=config/homelab.toml` to point at a different config. The CLI is
just `quik --config <path>` — no other flags.

## Architecture

`src/lib.rs` has the authoritative module map and request-flow comment — read it
first. Rough inbound request flow:

`tls` (rustls acceptor, ALPN) → `proxy` (per-connection handler: spans, header
rewriting, module evaluation) → `routing` (exact > segment-prefix,
longest-prefix-first) → `auth` (per-route JWT + JWKS cache + claim injection) →
`upstream` (`balance` LB algorithms, passive + `state`/`probe` active health,
`drain` graceful removal) → response forwarding.

Side paths: `admin/` (separate listener: `/healthz`, `/metrics`,
`/admin/pools/*` registration API, optional mTLS/bearer), `egress/` (optional
CONNECT forward proxy with `policy` host/CIDR + `sni` checks),
`headers` (hop-by-hop stripping, identity-header generation),
`observability` (tracing + Prometheus init), `shutdown` (SIGTERM/SIGINT drain).

## Conventions

- **Hot path is allocation-sensitive.** Forwarding streams bodies end-to-end
  without buffering; metric handles are pre-built per upstream member; in-flight
  is a single atomic. Don't add per-request allocations or metric lookups on the
  forwarding path — see `benches/hot_path.rs` before changing it.
- **Shared mutable state uses `arc-swap`** (e.g. routing table, pool membership)
  so config/membership updates are lock-free for readers. Follow that pattern
  rather than introducing locks on read paths.
- Config is TOML with env-var expansion + validation in `src/config.rs`; add new
  options there and document them in `docs/config-reference.md`.
- Integration tests live in `tests/e2e_*.rs` with helpers in `tests/common/`;
  they spin up real listeners. Add coverage there for behavioural changes.
- Reserved/identity headers are protected against client spoofing — preserve
  that when touching `headers.rs` or `auth`.

## Releases

Releases are cut from the **Release** GitHub Actions workflow (manual trigger,
pick patch/minor/major) — **not** via local `git tag`. Git tags `vX.Y.Z` are the
version source of truth; `Cargo.toml` stays pinned at `0.0.0`. Do not bump the
version in `Cargo.toml`. See README "Releases".
