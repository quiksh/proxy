# NATS-based service registration

NATS is a **first-class but optional** membership source for quik, gated behind a
cargo feature. The default build carries no NATS code or dependency and gets its
membership from the config file + admin API; a `--features nats` build can
additionally run an in-process watcher that reconciles a JetStream KV bucket into
the live member list, so backends register themselves and quik converges. This
doc is the design + security + operations reference; for runnable stacks see
[`examples/nats/`](../examples/nats/).

---

## 1. Build profiles — what "first-class but optional" means

| Build | Membership sources | NATS dep |
|---|---|---|
| Default (`cargo build`) | static config + admin API | none |
| `--features nats` | the above **plus** an in-process NATS KV watcher when `[nats]` is configured | `async-nats` |

- **Config-from-file is always the floor.** Static `[[upstreams]]` members are
  present immediately at boot regardless of NATS; the watcher is purely
  additive.
- The `nats` feature only *links* the client; the watcher only *runs* when a
  `[nats]` block is present. A feature-enabled binary with no `[nats]` block
  behaves exactly like the default build.

This is what lets NATS be first-class (reconciliation lives in quik, not a
sidecar) without imposing it: homelab/edge ships the lean, dependency-free
binary; fleets build with `--features nats`.

---

## 2. Architecture & data flow — in-process watcher, no bridge

```
  service ──(kv.put own key, NATS client + scoped creds)──▶  NATS JetStream KV
                                                               │ (desired state)
  operator ──(write override key, or via admin facade §9)───▶ │
                                                               ▼
                       quik [--features nats, [nats] set]:  in-process watcher
                         reconciles Put/Delete/expiry  ──▶  members: ArcSwap<…>
                                                            (serves traffic)
```

- **Services** write only their own key and refresh it to stay alive. They never
  call quik.
- **Operators** write the `override.>` namespace (durable drain/cordon intent),
  either directly (`nats kv put`) or via the admin API acting as a facade (§9).
- **Each quik instance** watches the bucket itself and reconciles directly into
  its own member list. N instances converge independently; **NATS fans out one
  `kv.put` to every watcher** — no shared component in the path.

### Why in-process, not an external bridge

An earlier draft used a separate bridge process that watched NATS and drove
quik's admin API over HTTP. Rejected, because then **quik cannot self-heal to the
truth** — desired state lives in NATS, but quik's actual state is a copy
maintained by a separate failure domain. If the bridge dies or is partitioned,
quik serves stale membership indefinitely and never notices, because it has no
concept of NATS. A bridge also half-defeats the point of NATS: you'd run either
one bridge (a SPOF that funnels convergence to N proxies over HTTP) or one per
proxy (N reconcile loops, N privileged admin tokens), rebuilding the fan-out
problem NATS solves natively. In-process, converging on NATS is intrinsic to quik
being up.

---

## 3. Relationship to the admin API

The watcher reuses the admin API's member primitives **in-process** —
`build_member`, the drain task, `is_routable`, and the `write_lock` + `ArcSwap`
swap — rather than over HTTP. NATS KV TTL is the liveness lease; the watcher is
the reaper.

| Deployment | Dynamic-membership path |
|---|---|
| Default build, or no `[nats]` | admin API (operator-driven add/drain/remove) |
| `--features nats` + `[nats]` | in-process watcher + NATS TTL (self-registration) |

The two are alternatives per deployment: without NATS, an external orchestrator
drives membership through the admin API; with NATS, backends self-register and
the watcher reconciles. (An HTTP self-registration surface with quik-side leases
was prototyped and dropped — NATS KV provides the lease/expiry/fan-out for free.)

---

## 4. Key namespace & permissions

The one decision that is **expensive to reverse**: NATS permissions are subject
prefixes plus wildcards (`*` = one token, `>` = the tail), and KV keys map to
subjects (`$KV.<bucket>.<key>`). The key hierarchy *is* the permission model you
can later express — you can only carve a boundary that's already a clean prefix,
and services + credentials bind to the schema. **Design and freeze it now**, even
if enforcement is deferred.

### Hierarchy — identity-keyed, ordered broad→narrow

```
reg.<env>.<team>.<pool>.<service>.<instance>      # service-written
override.<env>.<team>.<pool>.<member>             # operator-written
```

- **Key on identity, not address.** Addresses aren't stable identity and binding
  a credential to a `host:port` subject is brittle. The address lives in the
  value (authoritative); the key is stable `service` + `instance`. Bonus: no
  `:`-encoding gymnastics in the key.
- **Token order matters.** Every grant is a prefix + wildcard tail, so the axis
  you scope on most must sit highest. `team` above `pool` lets a team own its
  namespace across pools in one grant. Order around who you mint creds for.
- **Two top-level namespaces.** `reg.>` (service-written, scoped per service) and
  `override.>` (operator-written). This split *is* the resurrection boundary
  (§5): a heartbeating service cannot write `override.>`, so it can never clobber
  operator intent.

Value payload (the contract services write):

```json
{ "address": "10.0.0.5:8080", "scheme": "http", "weight": 1,
  "metadata": { "deploy_id": "abc123", "zone": "rack-2" },
  "registered_at": "2026-06-05T10:00:00Z" }
```

### Per-role permissions (bucket `B`)

| Role | Permission |
|---|---|
| Service instance | publish `$KV.B.reg.prod.teamA.pool-a.checkout.*` |
| Per-replica creds | publish `$KV.B.reg.prod.teamA.pool-a.checkout.<instance>` |
| Team | publish `$KV.B.reg.prod.teamA.>` |
| Operator | publish `$KV.B.override.>` |
| **quik instance** | subscribe `$KV.B.>`; publish `$KV.B.override.>` only if the admin facade (§9) is enabled |

Credential issuance (per-service / per-instance, scoped subject baked in) is an
orchestrator concern; quik only consumes. quik cannot enforce this — it is
NATS-server config, the NATS-native equivalent of "a task registers only
itself".

### Isolation ladder — plan all three, build tier 1

1. Subject permissions within one account/bucket (the hierarchy above).
2. Bucket per env/tenant — separate TTL, replication, quota, blast radius.
3. NATS account per tenant — genuine multi-tenant isolation.

The frozen schema is what lets you climb without re-keying.

### Scaling

- **Sharded watches.** Each quik instance can watch a filtered subtree
  (`reg.prod.teamA.>`) rather than everything, so a proxy only reconciles the
  pools it serves. The prefix design is the shard key — no schema change.
- **Write load** ≈ `N / (TTL/3)` (10k services @ 30 s ≈ ~1k writes/s — trivial).
- **`history = 1`** on the bucket; no old revisions needed.

### Decide now (cheap now, expensive later)

1. Token order — confirm `env.team.pool.service.instance`.
2. Identity-keyed, address-in-value — adopt.
3. `env` as a separate bucket (lean: yes) vs token.
4. Credential granularity — per-service vs per-instance.
5. The `reg.>` / `override.>` split — lock it.

MVP may ship broad creds; the schema is frozen from day one regardless.

---

## 5. Reconciliation & the resurrection rule

The watcher holds **desired** (the live KV snapshot) vs **actual** (its in-memory
member list) and reconciles each event:

- key `Put`, no member → build + add (swap under `write_lock`)
- key `Delete`/expiry, member present **and NATS-sourced** → remove (§8)
- both present → no-op

Add a member **source tag** — `Config | Runtime | Nats` — so the watcher only
ever touches `Nats`-sourced members; static config and admin-added members are
untouched.

**Resurrection — operator intent lives in NATS.** Operator drain/cordon writes
`override.>`, so it is durable desired state: it survives a **quik restart**
(quik re-snapshots the bucket on boot and would otherwise re-add a drained-then-
removed member whose `reg` key persists). The watcher merges **operator-wins** and
never re-adds a member with a live override.

---

## 6. Liveness — three layers

Liveness is defended at three levels; use all three.

1. **Lease TTL (the registry's liveness).** The key has a TTL (e.g. 30 s) and the
   registrant refreshes it at ~TTL/3 with a re-`put` (no separate subject). If
   the registrant stops heartbeating — because the **registrant/sidecar itself
   died**, or because it deliberately stopped — the lease expires and the watcher
   reaps the member. Per-key TTL needs NATS server **≥ 2.11**; otherwise use a
   short bucket-level max-age.
2. **Health-gated heartbeat (the service's liveness).** The heartbeat must be
   *conditional on the service being healthy*, not unconditional — otherwise a
   **dead service with a live sidecar** keeps getting heartbeated and stays
   registered. The registrant health-checks its service and only refreshes the
   key while it answers; once the service fails, it stops refreshing and the
   lease (layer 1) expires it. Gating-then-letting-the-TTL-expire is naturally
   debounced — a brief blip that recovers within the TTL never deregisters.
   (The example registrar, `examples/nats/register.sh`, does exactly this.)
3. **quik active health (the data-path backstop).** Independently of the
   registry, quik probes each member from its *own* vantage point
   (`[upstreams.active_health]`). This catches failure modes the registrant
   can't see — a network partition between quik and the backend, or a buggy
   registrant that wrongly keeps a dead service registered — and stops routing
   to it even while it's still listed as a member. NATS answers "registered and
   heartbeating"; active health answers "actually reachable and serving".

The distinction matters: a member can be **registered** (in the member list) but
not **routable** (active health failing) — traffic stops at layer 3 immediately,
while layers 1–2 remove it from the list within a TTL.

## 7. Failure mode: disconnect = freeze; startup = fail-static

The single most important property. On NATS disconnect the watcher **stops
reconciling and keeps membership as-is** — a blip must never read as "all members
gone". On reconnect it **re-snapshots the whole bucket and reconciles forward**
(full reconcile, not delta replay — to catch expiries that fired while
disconnected). At **startup with NATS down**, quik serves static config and keeps
retrying — it never fails boot on a control-plane dependency. Cover all three in
tests.

## 8. Graceful deregister vs expiry

- Explicit `kv.delete` on shutdown = intentional → graceful drain.
- TTL expiry = presumed dead → short bounded remove, with a separately
  configurable timeout shorter than the operator-delete default.

## 9. Admin API in NATS mode

- **Reads** (`GET /admin/pools`, snapshot) always work — the in-memory view.
- **Writes** become an optional **facade into NATS**: an operator `drain` writes
  an `override.>` key, which quik's own watcher then applies. One reconcile loop,
  one source of truth.
- Direct in-process admin mutation still exists (tagged `Runtime`, so the watcher
  won't reap it) as an emergency/manual path — but durable operator intent must
  go through NATS to survive a restart.
- Caveat: facade writes require NATS to be reachable; reads never do.

## 10. Security

NATS-backed registration makes the bucket a **control plane for traffic
routing**: write access to it is traffic-steering power, and the `address` field
in each value is **self-asserted** by whoever holds a write credential. The
following are *requirements*, implemented in the watcher, not optional extras.

### H1 — registrable-address allow-list (implemented, mandatory)
A self-asserted address outside the pool's `allow_addresses` (CIDR or
host-suffix) is **rejected** before a member is built (`reconcile::admit` →
`address_allowed`). Without this, a compromised service credential could point a
pool member at an SSRF target (`169.254.169.254`), an internal host, or an
attacker box — and because quik injects verified JWT claims as identity headers,
a malicious member in an authenticated pool would receive trusted traffic.
`allow_addresses` is **required and non-empty** (config validation rejects an
empty list): a pool that admits self-registered members must state where they may
live. This control **fails safe** — too strict merely rejects a registration.

### H2 — member caps, fail-loud (implemented)
- `max_instances_per_service` (per `reg.<ns>.<service>.*`) is the surgical
  control: it bounds a single runaway/compromised credential.
- `max_members` (per pool) is a generous backstop.
- Both are **off by default** and must be sized *well above* the real fleet,
  because a member cap **fails unsafe** — set near real capacity it locks out
  legitimate new hosts during a scale-up (the classic "the safety limit caused
  the outage"). This is the opposite default posture to H1's allow-list.
- Rejections are **loud, never silent**: `quik_nats_registration_rejected_total
  {reason}` plus an audit line on the transition into rejection. Alert on the
  rejection rate so a cap that starts biting is visible before it hurts.
- The primary anti-abuse work is `max_instances_per_service` + JetStream
  account/bucket limits (set on the NATS side); the pool cap is defence in depth.

### H3 — credentials & least privilege
- quik connects over TLS with nkey/JWT creds from a file (never inline).
- A service's credential may publish **only** its own `reg.<ns>.<service>.*`
  subtree; it can never write `override.>`. This subject-permission split (§4) is
  what makes operator-wins (§5) structural rather than advisory, and it is
  enforced by the NATS server, not quik.
- quik's own credential subscribes its watched subtree and publishes
  `override.>` only if the admin facade is enabled — scope it to the pools it
  serves, not the whole bucket.
- No privileged admin token sits in a separate process — there is no separate
  process (the watcher is in quik).

### Residual — intra-allow-list address spoofing (accepted)
Subject permissions scope which *key* a service may write, but the `address` in
the value is free-form. A correctly-scoped (or compromised) service credential
can therefore register **any address inside the pool's `allow_addresses` range**,
including one belonging to another service — quik does **not** bind the value
address to the registrant's identity (the key is identity-based, so there is
nothing to consistency-check against). The allow-list bounds the blast radius
(no SSRF target, nothing outside the CIDR/suffix) but does not prevent
in-range impersonation. **Mitigation: keep `allow_addresses` as tight as the
deployment allows** (smallest CIDR / specific host-suffix per pool) and prefer
per-instance credentials. This is an accepted residual, not an implemented
control.

### Residual / operational
- Set **JetStream limits** (max keys/bytes) on the bucket so NATS bounds a noisy
  writer server-side.
- Run NATS **HA** in production — it is a routing dependency (freeze-on-disconnect
  bounds the blast radius, but a change can't propagate while it's down).
- Use **`tls://`** whenever `creds_file` is set — the credential JWT is presented
  on connect and is sniffable over plaintext (quik warns if you don't).
- `weight`-based traffic steering is a deliberate non-goal until clamped.

## 10a. Blue/green & rolling deploys

Two independent layers, different mechanisms:

**Backends behind quik (NATS registration).** Green instances register (new
`reg.*` keys); blue instances `kv.delete` on graceful shutdown → quik drains them
(in-flight finishes). Operational rules:
- **Size caps for the overlap.** During cutover blue + green are both registered,
  so the pool holds ~2× steady-state members. `max_members` /
  `max_instances_per_service` sized near steady state would **reject green and
  fail the deploy** — set them to ≥ 2× and alert on the rejection counter.
- **Gate readiness with active health.** A member is routable the instant its key
  appears. Enable `[upstreams.active_health]` (pessimistic `initial_state =
  "unhealthy"`) on NATS-backed pools so green takes traffic only once it probes
  healthy.
- **Cut over by explicit delete, not TTL** — TTL expiry leaves a removed blue
  taking traffic for up to one TTL.

**quik itself (pre-drain grace).** Rolling quik instances use
`pre_drain_grace_seconds` (§ pre-drain): `/healthz` → 503 first so the perimeter
withdraws, then drain. Independent of the backend layer above.

**Consistency.** Each quik watches independently; during a NATS partition
instances may briefly disagree (one frozen on last-known, one updated) and
converge on reconnect — so cutover is fast but not globally instantaneous.

## 11. Observability

quik-side: `quik_nats_connected` gauge (the disconnect alarm),
`quik_nats_reconcile_total{action}`, `quik_nats_watch_events_total{op}`, plus the
existing pool metrics. Because reconciliation is in-process, the
`quik_pool_member_removed_total{reason="nats_expiry"}` value is trivial to emit
directly — no admin-API reason-hint hack a bridge would have needed.

## 12. Config sketch

```toml
# Only meaningful in a `--features nats` build; absent ⇒ no watcher.
[nats]
url        = "tls://nats.internal:4222"
creds_file = "${QUIK_NATS_CREDS}"
bucket     = "quik_registrations"
# Optional: which pools are NATS-backed, watch filter, expiry-drain timeout, etc.
```

## 13. Phased plan

1. Cargo `nats` feature + `async-nats`; connect/watch behind the feature, no-op
   without `[nats]`.
2. Watcher MVP — snapshot + live `Put`/`Delete` → reconcile into `members`;
   source tag; static-config floor.
3. Liveness — TTL; expiry → remove.
4. Robustness — disconnect-freeze + reconnect re-snapshot; `override.>`
   precedence; address-vs-key validation; startup fail-static.
5. Security — TLS + creds; documented subject-permission template; optional
   admin→`override` facade.
6. Observability + docs + a sample backend registration snippet.

## 14. Tests (with an embedded NATS server fixture)

- put key → member added, takes traffic; heartbeat keeps it past one TTL; stop →
  expiry → removed; explicit delete → graceful drain;
- **disconnect → membership frozen, not flushed; reconnect → reconciles**;
- operator override + persistent `reg` key → not resurrected, including across a
  simulated quik restart;
- static config served when NATS is down at startup;
- registration churn under sustained traffic → zero failed requests (reuses the
  lock-free swap guarantee, now exercised through the watcher);
- subject-permission denial when a service writes another's key (server-enforced).

## 15. Non-goals

- Persisting watcher state across restart — NATS KV *is* the durable store; quik
  re-derives from the bucket on boot.
- Pool create/delete via NATS — member-level only (consistent with the admin API).
- Replacing active health checks — keep both.
- NATS in the **default** build — it is strictly behind the `nats` cargo feature.
- Using NATS for anything beyond registration (config push, metrics, routing).
