terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 3.0"
    }
  }
}

# helm provider v3 syntax (kubernetes is an attribute, not a block). For
# provider v2, use a `kubernetes { ... }` block instead.
provider "helm" {
  kubernetes = {
    config_path = "~/.kube/config"
  }
}

# Multi-site homelab fan-out, declared in Terraform. Mirrors the Helm
# examples/homelab-values.yaml. Topology lives in state; changing a route or
# pool here rolls the Deployment on `terraform apply`.
module "quik" {
  source = "../../"

  name      = "edge"
  namespace = "edge"

  cert_manager = {
    enabled     = true
    issuer_name = "letsencrypt-prod"
  }

  upstreams = [
    { name = "web", members = [{ address = "web:3000" }] },
    { name = "api", members = [{ address = "api:8080" }] },
    { name = "auth", members = [{ address = "auth:8080" }] },
    { name = "blog", members = [{ address = "blog:2368" }] },
    { name = "wiki", members = [{ address = "wiki:80" }] },
  ]

  routes = [
    { hosts = ["example.com", "www.example.com"], upstream = "web" },
    { hosts = ["api.example.com"], upstream = "api" },
    { hosts = ["auth.example.com"], upstream = "auth" },
    { hosts = ["blog.example.com"], upstream = "blog" },
    { hosts = ["wiki.example.com"], upstream = "wiki" },
  ]
}
