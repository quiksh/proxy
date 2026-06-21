# quik Terraform module

Deploys quik on Kubernetes by wrapping the [Helm chart](../../helm/quik). The
chart owns config (TOML) rendering; this module gives you a typed Terraform
interface and puts the topology in Terraform state.

Topology (routes, pools) is declarative: a change rolls the Deployment on
`apply`, because quik has no runtime reload (the chart hashes the config into
the pod template). Pool *membership* stays dynamic at runtime (admin API / NATS).

## Usage

```hcl
module "quik" {
  source = "github.com/quiksh/proxy//deploy/terraform/quik"

  name      = "edge"
  namespace = "edge"

  cert_manager = {
    enabled     = true
    issuer_name = "letsencrypt-prod"
  }

  upstreams = [
    { name = "web", members = [{ address = "web.default.svc:3000" }] },
  ]

  routes = [
    { hosts = ["example.com"], upstream = "web" },
  ]
}
```

Requires a configured `helm` provider. A full example is in
[`examples/homelab`](examples/homelab).

## TLS

Set either `tls_secret_name` (mount an existing `kubernetes.io/tls` secret) or
`cert_manager = { enabled = true, issuer_name = "..." }`. With cert-manager and
no `dns_names`, the cert SANs default to the union of all route hosts.

## Inputs (common)

| Variable | Default | Description |
| --- | --- | --- |
| `name` / `namespace` | `quik` / `default` | Release name and namespace |
| `chart` | `../../helm/quik` | Local chart path; set `repository` for a published chart |
| `image_repository` / `image_tag` | `ghcr.io/quiksh/proxy` / chart appVersion | Pin the tag in production |
| `upstreams` | (required) | Pools: `{ name, balancer?, httpVersion?, members:[{address, scheme?}], tls?, activeHealth?, nats? }` |
| `routes` | (required) | Routes: `{ hosts?, methods?, pathExact?\|pathPrefix?, stripPrefix?, timeoutMs?, maxBodyBytes?, auth?, upstream }` |
| `tls_secret_name` / `cert_manager` | `""` / disabled | Pick one |
| `service_type` / `service_port` | `LoadBalancer` / `443` | |
| `nats` | disabled | `{ enabled, url, bucket, creds_secret }` for self-registration |
| `extra_values` | `{}` | Arbitrary chart values merged on top |

`upstreams`, `routes`, and `auth_blocks` are typed `any` so optional sub-fields
pass straight through to the chart. See the
[chart values](../../helm/quik/values.yaml) for the authoritative schema.
