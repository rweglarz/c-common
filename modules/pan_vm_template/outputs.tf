output "template_name" {
  value = panos_panorama_template.this.name
}

output "zones" {
  value = local.zones
}
