output "interfaces" {
  value = merge(
    panos_panorama_ethernet_interface.this,
    panos_panorama_loopback_interface.this,
    panos_panorama_tunnel_interface.this,
  )
}

output "template_name" {
  value = panos_panorama_template.this.name
}

output "vr_name" {
  value = panos_virtual_router.this.name
}

output "zones" {
  value = local.zones
}
