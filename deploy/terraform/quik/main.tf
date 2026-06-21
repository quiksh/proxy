# Thin wrapper over the quik Helm chart. The chart owns TOML rendering; this
# module gives Terraform users a typed interface and state tracking. Values are
# composed here and handed to helm_release as a single YAML document, with
# var.extra_values layered on top so anything not modelled can still be set.

locals {
  computed_values = {
    replicaCount = var.replica_count

    image = merge(
      { repository = var.image_repository },
      var.image_tag == null ? {} : { tag = var.image_tag },
    )

    # Both keys are always emitted; the chart picks certManager when enabled,
    # otherwise requires secretName. (Avoids a ternary type mismatch, and the
    # chart ignores the unused branch.)
    tls = {
      secretName = var.tls_secret_name
      certManager = {
        enabled  = var.cert_manager.enabled
        dnsNames = var.cert_manager.dns_names
        issuerRef = {
          name = var.cert_manager.issuer_name
          kind = var.cert_manager.issuer_kind
        }
      }
    }

    service = {
      type        = var.service_type
      port        = var.service_port
      annotations = var.service_annotations
      exposeAdmin = var.expose_admin
    }

    nats = {
      enabled     = var.nats.enabled
      url         = var.nats.url
      bucket      = var.nats.bucket
      credsSecret = var.nats.creds_secret
    }

    config = {
      logging = { level = var.logging.level, format = var.logging.format }
      shutdown = {
        drainGraceSeconds    = var.shutdown.drain_grace_seconds
        preDrainGraceSeconds = var.shutdown.pre_drain_grace_seconds
      }
      upstreams  = var.upstreams
      routes     = var.routes
      authBlocks = var.auth_blocks
    }
  }
}

resource "helm_release" "quik" {
  name             = var.name
  namespace        = var.namespace
  create_namespace = var.create_namespace

  chart      = var.chart
  repository = var.repository
  version    = var.chart_version

  # Computed values first, user escape-hatch last (Helm merges later docs over
  # earlier ones).
  values = [
    yamlencode(local.computed_values),
    yamlencode(var.extra_values),
  ]
}
