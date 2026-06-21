# Deploying quik with IaC

Declarative deployment of quik for Kubernetes.

- [`helm/quik`](helm/quik) - Helm chart. The source of truth: it renders quik's
  TOML config from `values.yaml` and deploys it.
- [`terraform/quik`](terraform/quik) - Terraform module wrapping the chart, for
  teams whose topology lives in Terraform state.

## The model: topology is declarative, membership is dynamic

quik splits cleanly into two layers, and IaC should treat them differently:

- **Topology** - which pools and routes exist (`config.upstreams`,
  `config.routes`). This is static config. quik has **no runtime config reload**,
  so the chart hashes the rendered config into the pod template
  (`checksum/config`); changing topology rolls the Deployment on the next
  `helm upgrade` / `terraform apply`. Graceful drain keeps in-flight requests
  alive across the roll. **Declare it in Git.**

- **Membership** - which backend instances are in a pool. This is dynamic: it
  changes at runtime via the admin API, or via NATS self-registration
  (`nats.enabled`, requires a `nats`-feature image) - no restart. **Let the
  orchestrator drive it.**

So a genuinely new service (new pool + new route) is always a config change;
scaling an existing service in/out is not.

## TLS

quik's data-plane listener is TLS-only - it does not serve plaintext and has no
built-in `:80` HTTP→HTTPS redirect. Provide a cert via an existing
`kubernetes.io/tls` secret or cert-manager (see the chart README). Put any
HTTP→HTTPS redirect at the ingress/LB layer.
