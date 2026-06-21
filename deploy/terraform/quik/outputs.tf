output "release_name" {
  value       = helm_release.quik.name
  description = "Helm release name."
}

output "namespace" {
  value       = helm_release.quik.namespace
  description = "Namespace the release was deployed into."
}

output "chart_version" {
  value       = helm_release.quik.version
  description = "Resolved chart version."
}

output "service_name" {
  value       = "${helm_release.quik.name}-quik"
  description = "Name of the Service fronting quik (chart fullname)."
}
