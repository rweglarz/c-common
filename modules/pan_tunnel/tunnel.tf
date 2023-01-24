locals {
  peer = {
    left  = var.peers.right
    right = var.peers.left
  }
}

resource "panos_panorama_ike_gateway" "this" {
  for_each = { for k, v in var.peers : k => v if lookup(v, "do_not_configure", false) == false }

  template = each.value.template
  name     = local.peer[each.key].name

  #this can be overriden by local values
  peer_ip_type  = lookup(each.value, "peer_ip_type", "ip")
  peer_ip_value = lookup(each.value, "peer_ip_value", local.peer[each.key].ip)

  interface      = each.value.interface.phys
  pre_shared_key = var.psk
  version        = "ikev2"

  local_id_type  = each.value.id.type
  local_id_value = each.value.id.value
  peer_id_type   = local.peer[each.key].id.type
  peer_id_value  = local.peer[each.key].id.value


  enable_nat_traversal              = true
  nat_traversal_keep_alive          = 10
  nat_traversal_enable_udp_checksum = true

  enable_passive_mode = lookup(each.value, "enable_passive_mode", false)

  enable_dead_peer_detection   = true
  dead_peer_detection_interval = 2
  dead_peer_detection_retry    = 5
  enable_liveness_check        = true
  liveness_check_interval      = 10
}


resource "panos_panorama_ipsec_tunnel" "this" {
  for_each = { for k, v in var.peers : k => v if lookup(v, "do_not_configure", false) == false }

  template = each.value.template
  name     = local.peer[each.key].name

  tunnel_interface = each.value.interface.tunnel
  ak_ike_gateway   = local.peer[each.key].name

  anti_replay = false

  enable_tunnel_monitor = lookup(each.value, "enable_tunnel_monitor", false)
  tunnel_monitor_destination_ip  = lookup(each.value, "tunnel_monitor_destination_ip", null)
  #tunnel_monitor_source_ip - (Optional) Source IP to send ICMP probe
  tunnel_monitor_profile = "fail-over"

  depends_on = [
    panos_panorama_ike_gateway.this
  ]
}
