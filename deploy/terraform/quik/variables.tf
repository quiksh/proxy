variable "name" {
  type        = string
  default     = "quik"
  description = "Helm release name."
}

variable "namespace" {
  type        = string
  default     = "default"
  description = "Namespace to deploy into."
}

variable "create_namespace" {
  type        = bool
  default     = false
  description = "Create the namespace if it does not exist."
}

# ─── Chart source ─────────────────────────────────────────────────────────────
# Default: the local chart in this repo. Set `repository` (and `chart_version`)
# instead once the chart is published to a Helm repository.
variable "chart" {
  type        = string
  default     = "../../helm/quik"
  description = "Chart path (local) or chart name (when repository is set)."
}

variable "repository" {
  type        = string
  default     = null
  description = "Helm repository URL. Leave null to use a local chart path."
}

variable "chart_version" {
  type        = string
  default     = null
  description = "Chart version (only meaningful with a remote repository)."
}

# ─── Image ────────────────────────────────────────────────────────────────────
variable "image_repository" {
  type        = string
  default     = "ghcr.io/quiksh/proxy"
  description = "quik container image repository."
}

variable "image_tag" {
  type        = string
  default     = null
  description = "quik image tag. Null falls back to the chart's appVersion. Pin in production."
}

variable "replica_count" {
  type    = number
  default = 2
}

# ─── TLS ──────────────────────────────────────────────────────────────────────
variable "tls_secret_name" {
  type        = string
  default     = ""
  description = "Existing kubernetes.io/tls secret to mount. Mutually exclusive with cert_manager."
}

variable "cert_manager" {
  type = object({
    enabled     = bool
    issuer_name = optional(string, "")
    issuer_kind = optional(string, "ClusterIssuer")
    dns_names   = optional(list(string), [])
  })
  default     = { enabled = false }
  description = "Emit a cert-manager Certificate instead of mounting an existing secret."
}

# ─── Service ──────────────────────────────────────────────────────────────────
variable "service_type" {
  type    = string
  default = "LoadBalancer"
}

variable "service_port" {
  type    = number
  default = 443
}

variable "service_annotations" {
  type        = map(string)
  default     = {}
  description = "Annotations on the Service (e.g. cloud LB controls)."
}

variable "expose_admin" {
  type        = bool
  default     = false
  description = "Expose the admin/metrics port on the Service. Secure admin auth first."
}

# ─── quik topology ────────────────────────────────────────────────────────────
# These map to the chart's config.upstreams / config.routes. See the chart
# README for the full object shape; both accept `any` so optional sub-fields
# (tls, activeHealth, nats, methods, pathExact, stripPrefix, ...) pass through.
variable "upstreams" {
  type        = any
  description = "List of upstream pools. Each: { name, balancer?, httpVersion?, members:[{address, scheme?}], tls?, activeHealth?, nats? }."
}

variable "routes" {
  type        = any
  description = "List of routes. Each: { hosts?, methods?, pathExact?|pathPrefix?, stripPrefix?, timeoutMs?, maxBodyBytes?, auth?, upstream }."
}

variable "auth_blocks" {
  type        = any
  default     = []
  description = "Named JWT auth blocks (config.authBlocks)."
}

variable "logging" {
  type = object({
    level  = optional(string, "info,quik=info")
    format = optional(string, "json")
  })
  default = {}
}

variable "shutdown" {
  type = object({
    drain_grace_seconds     = optional(number, 30)
    pre_drain_grace_seconds = optional(number, 5)
  })
  default = {}
}

# ─── NATS (optional) ──────────────────────────────────────────────────────────
variable "nats" {
  type = object({
    enabled      = bool
    url          = optional(string, "")
    bucket       = optional(string, "")
    creds_secret = optional(string, "")
  })
  default = { enabled = false }
}

# ─── Escape hatch ─────────────────────────────────────────────────────────────
variable "extra_values" {
  type        = any
  default     = {}
  description = "Arbitrary values merged over the computed values (deep-merged by Helm via an extra values document)."
}
