# Homelab auth - throwaway demo creds

The homelab stack is **authenticated by default** (`docker-compose.yml`): NATS
runs decentralised JWT, and every `kv put` must present a credential scoped to
exactly the subjects it may touch. The creds + server config are **generated on
first `up`** by the `creds-init` step (running [`gen-demo-creds.sh`](gen-demo-creds.sh)
inside `nats-box`) and are **git-ignored - never committed**:

| File (generated) | Identity | Scope |
|------------------|----------|-------|
| `register.creds` | the **project key** | publish `$KV.quik_registrations.reg.shop.>` only - any service in the `shop` project, never `override.*` |
| `quik.creds` | the proxy | subscribe the whole bucket; publish `override.>` (the admin facade) |
| `admin.creds` | bucket setup | full account; used once by `nats-setup` to create the bucket |
| `server.conf` | the NATS server | operator + mem-resolver (accounts inline) + JetStream |

This is the **project-key** model: one credential for the whole `shop` project,
shared by every service. The HA stack demonstrates the tighter **per-service**
model (`checkout` ≠ `blog`).

> [!WARNING]
> **Demo-only - these are not secrets.** They're minted locally against a
> throwaway operator each `up`, scoped to the demo bucket, and exist only so the
> secure-by-default stack comes up in one command on `localhost`. **Never** reuse
> them outside a local demo, and don't commit them (the `.gitignore` here keeps
> them out). To rotate, delete `auth/*.creds` and `up` again; for anything real
> mint per-deployment creds (HA stack /
> [`../../nats/bootstrap-creds.sh`](../../nats/bootstrap-creds.sh)).

NATS still runs on plaintext `nats://` here (loopback only), so quik and the
registrar log a "JWT sent in clear - use tls://" warning. That's expected for
the localhost demo; production terminates TLS at NATS (the HA `server-jwt.conf`
shows the `tls {}` block) and uses `tls://`.
