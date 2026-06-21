# quik Helm chart

Deploys [quik](https://github.com/quiksh/proxy) - a TLS-terminating reverse
proxy - on Kubernetes. The chart renders quik's TOML config from `values.yaml`,
so routes and upstream pools are declared the same way as the rest of your
manifests.

## How config is applied

quik has **no runtime config reload**. The chart works around this: the rendered
config is hashed into the pod template (`checksum/config` annotation), so any
change to `config:` triggers a rolling restart. Graceful drain
(`config.shutdown`) means in-flight requests survive the roll.

What this means in practice:

| Change | How it applies |
| --- | --- |
| Add/change a route or pool (`config.routes`, `config.upstreams`) | `helm upgrade` → rolling restart |
| Add/remove pool *members* | runtime, no restart - admin API, or NATS (`nats.enabled`) |
| TLS cert rotation | secret update; cert-manager handles renewal in place |

So: **topology is declarative (GitOps the values), membership is dynamic.**

## TLS

quik's data-plane listener is TLS-only. Provide a cert one of two ways:

```yaml
# (a) reference an existing kubernetes.io/tls secret
tls:
  secretName: quik-tls

# (b) let the chart emit a cert-manager Certificate
tls:
  certManager:
    enabled: true
    issuerRef:
      name: letsencrypt-prod
      kind: ClusterIssuer
    # dnsNames defaults to the union of all route hosts
```

> quik does not serve plaintext and has no `:80` HTTP→HTTPS redirect. Put a
> redirect at the ingress/LB layer if you need one.

## Quick start

```bash
helm install edge ./deploy/helm/quik \
  --set tls.secretName=quik-tls \
  -f my-values.yaml
```

Minimal `my-values.yaml`:

```yaml
config:
  upstreams:
    - name: web
      members:
        - address: web.default.svc:3000
  routes:
    - hosts: ["example.com"]
      pathPrefix: /
      upstream: web
```

## Probes & metrics

Liveness and readiness both hit the admin `/healthz`, which returns `503` while
draining - so a terminating pod is pulled from Service endpoints before it stops
accepting. Prometheus metrics are on the admin port; set
`service.exposeAdmin=true` and `serviceMonitor.enabled=true` to scrape them
(secure the admin port with `config.admin.auth` first).

## Values

See [`values.yaml`](values.yaml) for the full, commented schema. The `config:`
tree mirrors quik's TOML (see `docs/config-reference.md`); the rest covers the
Kubernetes deployment (image, replicas, service, probes, security context).

An end-to-end example mirroring a multi-site homelab setup is in
[`examples/homelab-values.yaml`](examples/homelab-values.yaml).
