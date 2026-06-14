# Graceful shutdown - edge-withdraw before local drain

When quik runs behind a perimeter (a load balancer, Cloudflare, a service mesh),
a plain drain races the perimeter's health check: quik stops accepting before the
edge has noticed it's going away, so in-flight requests get cut. The **pre-drain
grace** closes that gap.

## Problem

When quik drains on `SIGTERM`, a perimeter (e.g. Cloudflare) keeps routing to it
until its own health check notices, so in-flight requests get cut. We want quik
to stop *looking* healthy to the edge **before** it stops accepting locally -
the standard Kubernetes preStop / fail-readiness-before-terminate pattern.

## Design

On the first signal the shutdown `Coordinator` runs three phases:

1. **pre-drain (edge-withdraw):** `/healthz` flips to 503 immediately, but the
   listeners keep accepting for `pre_drain_grace_seconds`. The edge notices the
   503 via its own health check and stops routing.
2. **drain:** listeners stop accepting; in-flight requests get up to
   `drain_grace_seconds` to finish.
3. **exit.**

A second signal forces immediate exit, short-circuiting both the pre-drain grace
and the drain grace.

Implementation: a third `tokio::sync::watch` channel (`health_drain`) on
`Coordinator` (`src/shutdown.rs`), decoupling "looks unhealthy to the edge"
(drives `/healthz` via `is_health_draining()`) from "stops accepting locally"
(the existing `drain` channel that listeners select on). `/healthz`
(`src/admin/mod.rs`) reads `is_health_draining()` so it 503s across both the
pre-drain and drain phases.

`ShutdownConfig.pre_drain_grace_seconds` (`src/config.rs`) defaults to **0** -
zero collapses pre-drain and drain into the same instant, so behaviour is
identical to a proxy with no edge in front. No external dependency: the only new
wait is the bounded grace timer, and force-exit short-circuits it.

Health sync is therefore **pull** by construction (the edge health-checks
`/healthz`); any Cloudflare-specific registrar is a separate sidecar built on
quik's existing surfaces, out of scope for quik core.

## Tests

- Unit (`src/shutdown.rs`): the phase sequencer - pre-drain precedes drain;
  force during pre-drain cuts the grace; `pre_drain_grace_seconds = 0` collapses
  to immediate drain.
- e2e (`tests/e2e_shutdown.rs`): after `begin_pre_drain`, `/healthz` is 503
  **while a new proxy connection still succeeds** (asserts the ordering), then
  the listener stops accepting once the drain phase begins.
