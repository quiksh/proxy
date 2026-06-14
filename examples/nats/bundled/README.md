# Bundled sidecar - tier-2b shared-fate single container

This example bundles a service and the `quik-register` sidecar into **one
container** so the registrar cannot outlive the service. It's the pattern for a
single-container runtime - plain Docker, or a PaaS that runs one container -
where you control the image but have no orchestrator to give you Pod/task-level
shared fate. (Where an orchestrator *does* exist, prefer **tier 2a**: run the
sidecar as a second container in the same Pod / ECS task - same shared fate, no
image change. See `docs/service-registration.md` §6.)

## How it works

- [`Dockerfile`](Dockerfile) pulls the sidecar binary from the published image
  (`COPY --from=ghcr.io/quiksh/quik-register:1 …`) into the service image - the
  canonical way to add the agent to *your* image without building it from
  source.
- [`bundle-entrypoint.sh`](bundle-entrypoint.sh) is a `wait -n` supervisor that
  runs both processes and tears the other down when **either** exits. That
  mutual teardown is the whole point: the registrar shares fate with the
  service, so it can never heartbeat for something that's gone (the zombie gap).
- [`quik-register.toml`](quik-register.toml) sets `[liveness] enabled = false` -
  shared fate already deregisters on death, so the probe is redundant here. Flip
  it to `true` to add the alive-but-wedged defence layer back.

## Run against the homelab demo

The homelab stack builds the `quik-echo:demo` and `quik-register:demo` images
this Dockerfile reuses, and creates the `quik-nats` network the bundle joins:

```sh
docker compose -f examples/nats/homelab/docker-compose.yml up -d --build

# Build the bundle (REGISTER_IMAGE defaults to quik-register:demo, built above).
docker build -f examples/nats/bundled/Dockerfile -t checkout-bundled .

# Run it on the demo network. ADDR is the network-reachable alias quik routes
# to - NOT localhost (quik is in another container).
docker run -d --rm --name checkout-bundled \
  --network quik-nats --network-alias checkout-bundled.svc \
  -e BIND_ADDR=0.0.0.0:8080 -e BACKEND_NAME=checkout-bundled \
  -e INSTANCE=checkout-bundled -e ADDR=checkout-bundled.svc:8080 \
  checkout-bundled

# It joins the pool, then shares fate - stopping the container deregisters it.
curl -s localhost:9090/admin/pools/checkout | jq '.members[].address'
docker stop checkout-bundled    # SIGTERM → registrar deregisters → quik drains
```

## Bundling into your own image

Replace the `quik-echo:demo` base with your service image (needs `bash` for the
supervisor; for a shell-only base use dumb-init + s6 or supervisord instead),
adjust the `echo_backend` line in `bundle-entrypoint.sh` to your service's
command, and point `REGISTER_IMAGE` at the pinned published tag:

```sh
docker build -f examples/nats/bundled/Dockerfile \
  --build-arg REGISTER_IMAGE=ghcr.io/quiksh/quik-register:1 -t my-service-bundled .
```
