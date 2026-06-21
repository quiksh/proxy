---
title: NATS-based service registration
description: Reconcile a NATS JetStream KV bucket into a pool with the optional nats feature.
---

NATS is a **first-class but optional** membership source for quik, gated behind a
cargo feature. The default build carries no NATS code or dependency and gets its
membership from the config file + admin API; a `--features nats` build can
additionally run an in-process watcher that reconciles a JetStream KV bucket into
the live member list, so backends register themselves and quik converges. This
doc is the design + security + operations reference; for runnable stacks see
[`examples/nats/`](../examples/nats/).

---

## 1. Build profiles - what "first-class but optional" means

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

## 2. Architecture & data flow - in-process watcher, no bridge

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
  `kv.put` to every watcher** - no shared component in the path.

### Why in-process, not an external bridge

An earlier draft used a separate bridge process that watched NATS and drove
quik's admin API over HTTP. Rejected, because then **quik cannot self-heal to the
truth** - desired state lives in NATS, but quik's actual state is a copy
maintained by a separate failure domain. If the bridge dies or is partitioned,
quik serves stale membership indefinitely and never notices, because it has no
concept of NATS. A bridge also half-defeats the point of NATS: you'd run either
one bridge (a SPOF that funnels convergence to N proxies over HTTP) or one per
proxy (N reconcile loops, N privileged admin tokens), rebuilding the fan-out
problem NATS solves natively. In-process, converging on NATS is intrinsic to quik
being up.

---

## 3. Relationship to the admin API

The watcher reuses the admin API's member primitives **in-process** -
`build_member`, the drain task, `is_routable`, and the `write_lock` + `ArcSwap`
swap - rather than over HTTP. NATS KV TTL is the liveness lease; the watcher is
the reaper.

| Deployment | Dynamic-membership path |
|---|---|
| Default build, or no `[nats]` | admin API (operator-driven add/drain/remove) |
| `--features nats` + `[nats]` | in-process watcher + NATS TTL (self-registration) |

The two are alternatives per deployment: without NATS, an external orchestrator
drives membership through the admin API; with NATS, backends self-register and
the watcher reconciles. (An HTTP self-registration surface with quik-side leases
was prototyped and dropped - NATS KV provides the lease/expiry/fan-out for free.)

---

## 4. Key namespace & permissions

The one decision that is **expensive to reverse**: NATS permissions are subject
prefixes plus wildcards (`*` = one token, `>` = the tail), and KV keys map to
subjects (`$KV.<bucket>.<key>`). The key hierarchy *is* the permission model you
can later express - you can only carve a boundary that's already a clean prefix,
and services + credentials bind to the schema. **Design and freeze it now**, even
if enforcement is deferred.

### Hierarchy - identity-keyed, ordered broad→narrow

```
reg.<namespace>.<service>.<instance>      # service-written
override.<namespace>.<service>.<instance> # operator-written
```

`<namespace>` is the project/team (e.g. `shop`), `<service>` the pool (e.g.
`checkout`), `<instance>` the unique replica id. This is exactly what the code
emits (`ServiceConfig::key` → `reg.shop.checkout.<instance>`) and what the
watcher subscribes (`[upstreams.nats] subject`).

- **Key on identity, not address.** Addresses aren't stable identity and binding
  a credential to a `host:port` subject is brittle. The address lives in the
  value (authoritative); the key is stable `service` + `instance`. Bonus: no
  `:`-encoding gymnastics in the key.
- **Environment & region are not key tokens - they are the account or cluster.**
  alpha/beta/gamma/prod (and region) separate by a distinct NATS account on one
  cluster (named for the identity it issues, e.g. `checkout-prod-use1`) or by a
  separate cluster entirely - see the isolation ladder. The account/bucket *is*
  the env boundary, so the key stays env-agnostic and a service's config is
  identical across envs bar the credential it presents. (Folding env into the
  key as a token is possible but deliberately not done - it pushes the boundary
  into a place that's only soft-enforced by subject permissions, where an
  account is a hard wall.)
- **Token order matters.** Every grant is a prefix + wildcard tail, so the axis
  you scope on most must sit highest. `namespace` above `service` lets a project
  own its whole subtree in one grant (the project-key model); narrowing to
  `…<service>.>` is the per-service key. Order around who you mint creds for.
- **Two top-level namespaces.** `reg.>` (service-written, scoped per service) and
  `override.>` (operator-written). This split *is* the resurrection boundary
  (§5): a heartbeating service cannot write `override.>`, so it can never clobber
  operator intent.

Value payload (the contract services write):

```json
{ "address": "10.0.0.5:8080", "scheme": "http", "weight": 1,
  "metadata": { "deploy_id": "abc123", "zone": "rack-2" } }
```

`address` + `scheme` are the only fields the watcher reads today
(`reconcile::Registration`); `weight` and `metadata` are accepted and ignored
(weight steering is a non-goal until clamped, §10). Only `address` is required.

### Per-role permissions (bucket `B`)

| Role | Permission |
|---|---|
| Project (project key) | publish `$KV.B.reg.shop.>` - any service in the project (homelab demo) |
| Per-service creds | publish `$KV.B.reg.shop.checkout.>` - one service only (HA demo) |
| Per-instance creds | publish `$KV.B.reg.shop.checkout.<instance>` - one replica (tightest) |
| Operator | publish `$KV.B.override.>` |
| **quik instance** | subscribe `$KV.B.>`; publish `$KV.B.override.>` only if the admin facade (§9) is enabled |

These are nested prefixes of the same key, so the three service rows are the
same model at widening scope - pick the tightest your credential issuer can
mint. (Each also needs `$JS.API…` + `_INBOX.>` for the JetStream open/put
round-trip; the demo creds show the exact grants.)

Credential issuance (per-service / per-instance, scoped subject baked in) is an
orchestrator concern; quik only consumes. quik cannot enforce this - it is
NATS-server config, the NATS-native equivalent of "a task registers only
itself".

### Isolation ladder - plan all three, build tier 1

1. Subject permissions within one account/bucket (the hierarchy above).
2. Bucket per env/tenant - separate TTL, replication, quota, blast radius.
3. NATS account per tenant - genuine multi-tenant isolation.

The frozen schema is what lets you climb without re-keying.

### Scaling

- **Sharded watches.** Each quik instance can watch a filtered subtree
  (`reg.prod.teamA.>`) rather than everything, so a proxy only reconciles the
  pools it serves. The prefix design is the shard key - no schema change.
- **Write load** ≈ `N / (TTL/3)` (10k services @ 30 s ≈ ~1k writes/s - trivial).
- **`history = 1`** on the bucket; no old revisions needed.

### Decided (the expensive-to-reverse calls, now locked)

1. Key schema - `reg.<namespace>.<service>.<instance>` (3 tokens). Matches the code.
2. Identity-keyed, address-in-value - adopted.
3. **Env/region = account or cluster, not a key token** (account a hard wall;
   subject prefixes only soft-enforce). Account naming `<service>-<env>-<region>`.
4. The `reg.>` / `override.>` split - locked (it makes operator-wins structural).

Credential granularity is the one knob that varies per deployment, not a schema
decision: project key (homelab) → per-service (HA) → per-instance (tightest).
All three are prefixes of the same frozen key.

---

## 5. Reconciliation & the resurrection rule

The watcher holds **desired** (the live KV snapshot) vs **actual** (its in-memory
member list) and reconciles each event:

- key `Put`, no member → build + add (swap under `write_lock`)
- key `Delete`/expiry, member present **and NATS-sourced** → remove (§8)
- both present → no-op

Add a member **source tag** - `Config | Runtime | Nats` - so the watcher only
ever touches `Nats`-sourced members; static config and admin-added members are
untouched.

**Resurrection - operator intent lives in NATS.** Operator drain/cordon writes
`override.>`, so it is durable desired state: it survives a **quik restart**
(quik re-snapshots the bucket on boot and would otherwise re-add a drained-then-
removed member whose `reg` key persists). The watcher merges **operator-wins** and
never re-adds a member with a live override.

---

## 6. Liveness vs readiness, and the three layers

Two different questions, deliberately answered by different mechanisms - the
same split ECS draws between *container* health and *target-group* health:

- **Readiness - "should traffic route here right now?"** quik's own active
  health probe answers this (layer 3). It may flap (overload, shedding) without
  meaning the instance should leave the registry.
- **Liveness - "should this instance be in the registry at all?"** The
  registrant's lease + its liveness gate answer this (layers 1-2). This is the
  question the registry exists to track.

Conflating them is the classic mistake: gate the registry on the *routing* probe
and a momentarily-overloaded instance deregisters itself; trust the registry
alone for *routing* and you send traffic to whatever it wrongly believes is up.
Keep them separate - point the registrant's liveness gate at a liveness endpoint
(e.g. `/healthz?source=container`) and quik's active health at the routing one.

Liveness is then defended at three layers; use all three.

1. **Lease TTL (is the registrant alive?).** The bucket carries a TTL (its
   `max-age`, e.g. 30 s, set once at `nats kv add --ttl`), and the registrant
   refreshes its key by re-`put`ting it before that elapses (no separate subject).
   If the registrant stops heartbeating - because it **died**, or deliberately
   stopped - the key ages out and the watcher reaps the member. **The TTL is a
   property of the bucket, not the registrant:** there is one global lease for the
   whole bucket and the registrant cannot set its own. `quik-register` **reads the
   bucket's max-age at startup and derives its heartbeat from it** - capped at
   `max-age / 3`, so the key is always re-put well before it lapses. The
   configured `[liveness] interval_secs` sets liveness responsiveness but is only
   an upper bound on the cadence; the cap pulls it *faster* if it would be too
   slow, never slower. This **fails safe** - a misconfigured interval can only
   make the registrant heartbeat more often (harmless), never let the lease lapse.
   (A bucket with no TTL means keys never expire, so lease-based reaping is off -
   the registrant warns at startup.)
2. **Liveness-gated heartbeat (is the instance alive?).** Without shared fate the
   heartbeat must be *conditional on a liveness probe*, never unconditional -
   otherwise a **dead instance with a live registrant** keeps getting heartbeated
   and lingers in the registry. (Under shared fate the registrant dies with the
   instance, so the probe becomes optional - `[liveness] enabled = false`; see
   the tier note below.) The registrant probes the instance's liveness endpoint and
   refreshes the key only while it answers; once it fails past
   `unhealthy_threshold` it deregisters (and stops refreshing). The
   **`quik-register`** sidecar (`quik-register/`) is the reference registrant: a
   TOML-configured liveness gate (`[liveness]` - http/https/tcp, timeout,
   healthy/unhealthy thresholds, startup grace) that registers while alive,
   deregisters on consecutive failures, and deletes its key on `SIGTERM`.
   (`examples/nats/register.sh` is a minimal shell-only alternative.)
3. **quik active health (the data-path backstop / readiness).** Independently of
   the registry, quik probes each member from its *own* vantage point
   (`[upstreams.active_health]`) and stops routing to ones that fail. This
   catches what the registrant can't see - a partition between quik and the
   backend, or a buggy registrant wrongly keeping a dead instance registered -
   even while it's still listed. NATS answers "registered and heartbeating";
   active health answers "actually reachable and serving".

The distinction matters: a member can be **registered** (in the member list) but
not **routable** (active health failing) - traffic stops at layer 3 immediately,
while layers 1-2 remove it from the list within a TTL.

### The zombie failure mode - the registrant must share fate with the instance

Layer 2 narrows but does not close one gap: a registrant that **outlives the
instance it speaks for** keeps *refreshing the lease* for something that is gone,
so the registry actively lies (worse than going stale - and the TTL never fires,
because the registrant is alive). A wedged-but-reachable process can even keep
answering the liveness probe. Thanks to layer 3 this is never a *routing*
failure - a phantom member gets no traffic - but it is a registry-truth failure,
and a registrant blindly heartbeating a dead instance is exactly what to avoid.

The structural fix is **shared fate**, in order of preference:

1. **Orchestrator / container-level publisher.** Bind membership to the
   lifecycle event itself (ECS task → STOPPED, a Kubernetes endpoints
   controller): the publisher *is* the lifecycle manager, so nothing can zombie.
   This is the ASG-registers-the-target model and the recommended end state
   wherever an orchestrator exists.
2. **Shared-fate sidecar.** Co-locate the registrant with the instance so it
   dies with it - same ECS task with the instance container marked `essential`,
   or the same Kubernetes Pod. It cannot outlive the instance by construction.
3. **Separate registrant + liveness gate + TTL backstop.** The `quik-register`
   demo topology. Acceptable where there is no orchestrator (homelab, bare
   Docker): rely on layer 2 + the TTL, and keep `allow_addresses` tight.

**The liveness gate is optional under shared fate, mandatory without it.** In
tiers 1-2 (orchestrator publisher, same Pod/task, or bundled sidecar) process
death already stops the heartbeat, so the registrant can heartbeat
unconditionally (`[liveness] enabled = false`) and let the TTL reap a dead
instance. Left enabled there, the probe is defence-in-depth - it additionally
catches an *alive-but-wedged* instance (running, so no process exit fires, but
not serving), which shared fate alone cannot. In tier 3 there is no shared fate,
so the probe is the only thing that detects instance death and stays
**required**. The default is **enabled** so the standalone case is safe out of
the box; opt out only once shared fate is doing the work.

`quik-register` is **one writer onto the KV contract (§4), not the mechanism**:
the contract is the `reg.*` schema + TTL semantics, and an orchestrator-driven
publisher or an in-process `async-nats` client are equally valid writers.

## 7. Failure mode: disconnect = freeze; startup = fail-static

The single most important property. On NATS disconnect the watcher **stops
reconciling and keeps membership as-is** - a blip must never read as "all members
gone". On reconnect it **re-snapshots the whole bucket and reconciles forward**
(full reconcile, not delta replay - to catch expiries that fired while
disconnected). At **startup with NATS down**, quik serves static config and keeps
retrying - it never fails boot on a control-plane dependency. Cover all three in
tests.

## 8. Graceful deregister vs expiry

- Explicit `kv.delete` on shutdown = intentional → graceful drain.
- TTL expiry = presumed dead → short bounded remove, with a separately
  configurable timeout shorter than the operator-delete default.

## 9. Admin API in NATS mode

- **Reads** (`GET /admin/pools`, snapshot) always work - the in-memory view.
- **Writes** become an optional **facade into NATS**: an operator `drain` writes
  an `override.>` key, which quik's own watcher then applies. One reconcile loop,
  one source of truth.
- Direct in-process admin mutation still exists (tagged `Runtime`, so the watcher
  won't reap it) as an emergency/manual path - but durable operator intent must
  go through NATS to survive a restart.
- Caveat: facade writes require NATS to be reachable; reads never do.

## 10. Security

NATS-backed registration makes the bucket a **control plane for traffic
routing**: write access to it is traffic-steering power, and the `address` field
in each value is **self-asserted** by whoever holds a write credential. The
following are *requirements*, implemented in the watcher, not optional extras.

### Registrable-address allow-list (implemented, mandatory)
A self-asserted address outside the pool's `allow_addresses` (CIDR or
host-suffix) is **rejected** before a member is built (`reconcile::admit` →
`address_allowed`). Without this, a compromised service credential could point a
pool member at an SSRF target (`169.254.169.254`), an internal host, or an
attacker box - and because quik injects verified JWT claims as identity headers,
a malicious member in an authenticated pool would receive trusted traffic.
`allow_addresses` is **required and non-empty** (config validation rejects an
empty list): a pool that admits self-registered members must state where they may
live. This control **fails safe** - too strict merely rejects a registration.

### Member caps, fail-loud (implemented)
- `max_instances_per_service` (per `reg.<ns>.<service>.*`) is the surgical
  control: it bounds a single runaway/compromised credential.
- `max_members` (per pool) is a generous backstop.
- Both are **off by default** and must be sized *well above* the real fleet,
  because a member cap **fails unsafe** - set near real capacity it locks out
  legitimate new hosts during a scale-up (the classic "the safety limit caused
  the outage"). This is the opposite default posture to the allow-list.
- Rejections are **loud, never silent**: `quik_nats_registration_rejected_total
  {reason}` plus an audit line on the transition into rejection. Alert on the
  rejection rate so a cap that starts biting is visible before it hurts.
- The primary anti-abuse work is `max_instances_per_service` + JetStream
  account/bucket limits (set on the NATS side); the pool cap is defence in depth.

### Credentials & least privilege
- quik connects over TLS with nkey/JWT creds from a file (never inline).
- A service's credential may publish **only** its own `reg.<ns>.<service>.*`
  subtree; it can never write `override.>`. This subject-permission split (§4) is
  what makes operator-wins (§5) structural rather than advisory, and it is
  enforced by the NATS server, not quik.
- quik's own credential subscribes its watched subtree and publishes
  `override.>` only if the admin facade is enabled - scope it to the pools it
  serves, not the whole bucket.
- No privileged admin token sits in a separate process - there is no separate
  process (the watcher is in quik).

### Residual - intra-allow-list address spoofing (accepted)
Subject permissions scope which *key* a service may write, but the `address` in
the value is free-form. A correctly-scoped (or compromised) service credential
can therefore register **any address inside the pool's `allow_addresses` range**,
including one belonging to another service - quik does **not** bind the value
address to the registrant's identity (the key is identity-based, so there is
nothing to consistency-check against). The allow-list bounds the blast radius
(no SSRF target, nothing outside the CIDR/suffix) but does not prevent
in-range impersonation. **Mitigation: keep `allow_addresses` as tight as the
deployment allows** (smallest CIDR / specific host-suffix per pool) and prefer
per-instance credentials. This is an accepted residual, not an implemented
control.

### Residual - host-suffix entries trust DNS (prefer CIDRs)
A `Suffix` allow-list entry (`.svc.local`) admits a *hostname* member on a
string match; quik then resolves that hostname via DNS at connect time and dials
whatever IP it returns. There is no IP containment - anyone who can create or
control a name under the suffix (or perform DNS rebinding) can point quik at an
arbitrary internal IP (cloud metadata, internal services). **Prefer CIDR
allow-lists in real deployments**, where the admitted host *is* the IP and DNS is
not in the trust path. Reserve host-suffix entries for environments where the
DNS namespace under that suffix is itself trusted (e.g. a controlled
`*.svc.cluster.local`). The demos use a `.svc` suffix only because the addresses
are fixed Docker network aliases.

### Residual / operational
- Set **JetStream limits** (max keys/bytes) on the bucket so NATS bounds a noisy
  writer server-side.
- Run NATS **HA** in production - it is a routing dependency (freeze-on-disconnect
  bounds the blast radius, but a change can't propagate while it's down).
- Use **`tls://`** whenever `creds_file` is set - the credential JWT is presented
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
  fail the deploy** - set them to ≥ 2× and alert on the rejection counter.
- **Gate readiness with active health.** A member is routable the instant its key
  appears. Enable `[upstreams.active_health]` (pessimistic `initial_state =
  "unhealthy"`) on NATS-backed pools so green takes traffic only once it probes
  healthy.
- **Cut over by explicit delete, not TTL** - TTL expiry leaves a removed blue
  taking traffic for up to one TTL.

**quik itself (pre-drain grace).** Rolling quik instances use
`pre_drain_grace_seconds` (§ pre-drain): `/healthz` → 503 first so the perimeter
withdraws, then drain. Independent of the backend layer above.

**Consistency.** Each quik watches independently; during a NATS partition
instances may briefly disagree (one frozen on last-known, one updated) and
converge on reconnect - so cutover is fast but not globally instantaneous.

## 11. Observability

quik-side: `quik_nats_connected` gauge (the disconnect alarm),
`quik_nats_reconcile_total{action}`, `quik_nats_watch_events_total{op}`, plus the
existing pool metrics. Because reconciliation is in-process, the
`quik_pool_member_removed_total{reason="nats_expiry"}` value is trivial to emit
directly - no admin-API reason-hint hack a bridge would have needed.

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
2. Watcher MVP - snapshot + live `Put`/`Delete` → reconcile into `members`;
   source tag; static-config floor.
3. Liveness - TTL; expiry → remove.
4. Robustness - disconnect-freeze + reconnect re-snapshot; `override.>`
   precedence; address-vs-key validation; startup fail-static.
5. Security - TLS + creds; documented subject-permission template; optional
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

- Persisting watcher state across restart - NATS KV *is* the durable store; quik
  re-derives from the bucket on boot.
- Pool create/delete via NATS - member-level only (consistent with the admin API).
- Replacing active health checks - keep both.
- NATS in the **default** build - it is strictly behind the `nats` cargo feature.
- Using NATS for anything beyond registration (config push, metrics, routing).
