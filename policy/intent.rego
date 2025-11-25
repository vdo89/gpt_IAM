package intent

import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

default vrfs := []
default tenants := []

vrfs := input.vrfs
tenants := input.tenants

vrf_by_name[name] = vrf {
  vrf := vrfs[_]
  vrf.name == name
}

vrf_names := {vrf.name | vrf := vrfs[_]}

deny[msg] {
  some i, j
  i < j
  vrfs[i].name == vrfs[j].name
  msg := sprintf("VRF name duplicate: %v", [vrfs[i].name])
}

deny[msg] {
  some i, j
  i < j
  vrfs[i].l3vni == vrfs[j].l3vni
  msg := sprintf("L3VNI duplicate: %v (%v vs %v)", [vrfs[i].l3vni, vrfs[i].name, vrfs[j].name])
}

deny[msg] {
  some t
  t := tenants[_]
  not vrf_names[t.vrf]
  msg := sprintf("Tenant %v references unknown VRF %v", [t.tenant, t.vrf])
}

deny[msg] {
  some t
  vrf := vrf_by_name[t.vrf]
  vrf.l3vni != t.l3vni
  msg := sprintf("Tenant %v L3VNI %v does not match VRF %v (%v)", [t.tenant, t.l3vni, t.vrf, vrf.l3vni])
}

deny[msg] {
  some t
  t := tenants[_]
  t.l2vni != 11000 + t.vlan
  msg := sprintf("Tenant %v: L2VNI must equal 11000+VLAN (%v != 11000+%v)", [t.tenant, t.l2vni, t.vlan])
}

deny[msg] {
  some i, j
  i < j
  tenants[i].vlan == tenants[j].vlan
  msg := sprintf("VLAN duplicate across tenants: %v (%v) vs %v (%v)", [tenants[i].vlan, tenants[i].tenant, tenants[j].vlan, tenants[j].tenant])
}

deny[msg] {
  some i, j
  i < j
  tenants[i].l2vni == tenants[j].l2vni
  msg := sprintf("L2VNI duplicate across tenants: %v (%v) vs %v (%v)", [tenants[i].l2vni, tenants[i].tenant, tenants[j].l2vni, tenants[j].tenant])
}

deny[msg] {
  some t
  t := tenants[_]
  not endswith(t.lb_vip, "/32")
  msg := sprintf("Tenant %v: lb_vip must be /32 CIDR", [t.tenant])
}

deny[msg] {
  some t
  t := tenants[_]
  contains(t.gateway, "/")
  msg := sprintf("Tenant %v: gateway must be plain IP (no prefix): %v", [t.tenant, t.gateway])
}

deny[msg] {
  some t
  t := tenants[_]
  not net.cidr_contains(t.subnet, t.gateway)
  msg := sprintf("Tenant %v: gateway %v not in subnet %v", [t.tenant, t.gateway, t.subnet])
}

deny[msg] {
  some i, j
  i < j
  ti := tenants[i]
  tj := tenants[j]
  ti.vrf == tj.vrf
  net.cidr_intersects(ti.subnet, tj.subnet)
  msg := sprintf("Overlapping subnets in VRF %v: %v (%v) intersects %v (%v)", [ti.vrf, ti.subnet, ti.tenant, tj.subnet, tj.tenant])
}

vip_export_allowed(export) {
  vrf := vrf_by_name[export.vrf]
  export.prefix == vrf.allowed_vip_exports[_]
}

deny[msg] {
  some export
  export := tenants[_].vip_exports[_]
  not endswith(export.prefix, "/32")
  msg := sprintf("vip_export %v must be a /32 prefix", [export.prefix])
}

deny[msg] {
  some export
  export := tenants[_].vip_exports[_]
  not vrf_names[export.vrf]
  msg := sprintf("vip_export %v references unknown VRF %v", [export.prefix, export.vrf])
}

deny[msg] {
  some export
  export := tenants[_].vip_exports[_]
  vrf_names[export.vrf]
  not vip_export_allowed(export)
  msg := sprintf("vip_export %v not permitted for VRF %v", [export.prefix, export.vrf])
}
