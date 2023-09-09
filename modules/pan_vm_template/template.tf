resource "panos_panorama_template" "this" {
  name = var.name
}

resource "panos_panorama_management_profile" "ping" {
  template = panos_panorama_template.this.name

  name = "ping"
  ping = true
}

resource "panos_panorama_management_profile" "hc_azure" {
  template = panos_panorama_template.this.name

  name  = "hc-azure"
  ping  = true
  http  = true
  https = true
  permitted_ips = [
    "168.63.129.16/32",
    "10.0.0.0/8",
    "172.16.0.0/12",
  ]
}

resource "panos_panorama_management_profile" "https" {
  template = panos_panorama_template.this.name

  name  = "https"
  ping  = true
  https = true
}

resource "panos_panorama_ethernet_interface" "this" {
  for_each = { for k, v in var.interfaces : k => v if length(regexall("^eth", k)) > 0 }
  template = panos_panorama_template.this.name

  name = each.key
  vsys = "vsys1"
  mode = "layer3"

  static_ips                = lookup(each.value, "static_ips", [])
  enable_dhcp               = lookup(each.value, "enable_dhcp", false)
  create_dhcp_default_route = lookup(each.value, "create_dhcp_default_route", false)

  management_profile = lookup(each.value, "management_profile", panos_panorama_management_profile.ping.name)
}

resource "panos_panorama_tunnel_interface" "this" {
  for_each = { for k, v in var.interfaces : k => v if length(regexall("^tunnel", k)) > 0 }
  template = panos_panorama_template.this.name

  name = each.key
  vsys = "vsys1"

  static_ips = lookup(each.value, "static_ips", [])

  management_profile = panos_panorama_management_profile.ping.name
}

resource "panos_panorama_loopback_interface" "this" {
  for_each = { for k, v in var.interfaces : k => v if length(regexall("^loop", k)) > 0 }
  template = panos_panorama_template.this.name

  name = each.key

  static_ips = lookup(each.value, "static_ips", [])

  management_profile = lookup(each.value, "management_profile", panos_panorama_management_profile.ping.name)
}

locals {
  zones = { for k, v in var.interfaces : v.zone => k... }
}


resource "panos_zone" "this" {
  for_each = local.zones
  template = panos_panorama_template.this.name

  name       = each.key
  mode       = "layer3"
  interfaces = each.value

  depends_on = [
    panos_panorama_ethernet_interface.this,
    panos_panorama_tunnel_interface.this,
    panos_panorama_loopback_interface.this,
  ]
}


resource "panos_virtual_router" "this" {
  template = panos_panorama_template.this.name

  name = "vr1"

  enable_ecmp             = var.enable_ecmp
  ecmp_max_path           = 4
  ecmp_strict_source_path = var.enable_ecmp
  ecmp_symmetric_return   = var.enable_ecmp

  interfaces = [for e, v in var.interfaces : e]

  depends_on = [
    panos_panorama_ethernet_interface.this,
    panos_panorama_tunnel_interface.this,
    panos_panorama_loopback_interface.this,
  ]
}


resource "panos_panorama_static_route_ipv4" "this" {
  for_each = var.routes
  template = panos_panorama_template.this.name

  virtual_router = panos_virtual_router.this.name
  name           = each.key
  destination    = each.value.destination
  interface      = each.value.interface
  type           = lookup(each.value, "type", "")
  next_hop       = lookup(each.value, "next_hop", null)

  depends_on = [
    panos_panorama_ethernet_interface.this,
    panos_panorama_tunnel_interface.this,
    panos_panorama_loopback_interface.this,
    panos_virtual_router.this,
  ]
}

resource "panos_panorama_monitor_profile" "this" {
  template  = panos_panorama_template.this.name
  name      = "fail-over"
  interval  = 5
  threshold = 3
  action    = "fail-over"
}

resource "panos_panorama_template_variable" "this" {
  for_each = var.variables
  template = panos_panorama_template.this.name
  name     = "${"$"}${each.key}"
  type     = "ip-netmask"
  value    = each.value
}
