package intent.lib

import rego.v1

vrf_entries := [{
  "file_index": i,
  "vrf_index": j,
  "vrf": vrf,
} |
  file := input[i]
  file.vrfs
  vrf := file.vrfs[j]
]

vrfs := [entry.vrf | entry := vrf_entries[_]]

vrf_names := {vrf.name | vrf := vrfs[_]}

vrf_by_name := {entry.vrf.name: entry.vrf | entry := vrf_entries[_]}

tenant_entries := [{
  "file_index": i,
  "tenant": file,
} |
  file := input[i]
  file.tenant
]

tenants := [entry.tenant | entry := tenant_entries[_]]

tenant_names := {tenant.tenant | tenant := tenants[_]}

l3vni_values := [entry.vrf.l3vni | entry := vrf_entries[_]]

vlan_values := [entry.tenant.vlan | entry := tenant_entries[_]]

subnets := [entry.tenant.subnet | entry := tenant_entries[_]]

strict_mode := true {
  not data.policy.strict
}

strict_mode := data.policy.strict

strict_hint(msg) := sprintf("%s (strict=%t; override via data.policy.strict)", [msg, strict_mode])

allowed_leaf_pairs := {leaf | leaf := data.policy.mobility_leaf_pairs[_]}

allowed_leaf_pairs := {} {
  not data.policy.mobility_leaf_pairs
}

allowed_ceph_public_vips := {lower(prefix) | prefix := data.policy.allowed_ceph_public_vips[_]}

allowed_ceph_public_vips := {} {
  not data.policy.allowed_ceph_public_vips
}

ipv4_host_prefix(prefix) {
  re_match("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/32$", prefix)
}

ipv6_host_prefix(prefix) {
  re_match("^[0-9a-fA-F:]+/128$", prefix)
}

is_host_prefix(prefix) {
  ipv4_host_prefix(prefix)
}

is_host_prefix(prefix) {
  ipv6_host_prefix(prefix)
}

prefix_ip(prefix) := ip {
  parts := split(prefix, "/")
  ip := lower(parts[0])
}

is_ipv6(prefix) {
  contains(prefix, ":")
}

blocked_ipv6_prefix(prefix) {
  is_ipv6(prefix)
  ip := prefix_ip(prefix)
  net.cidr_contains("fe80::/10", ip)
}

blocked_ipv6_prefix(prefix) {
  is_ipv6(prefix)
  ip := prefix_ip(prefix)
  net.cidr_contains("ff00::/8", ip)
}

blocked_ipv6_prefix(prefix) {
  is_ipv6(prefix)
  ip := prefix_ip(prefix)
  net.cidr_contains("fc00::/7", ip)
}

expected_l2vni(vlan, base) := base + vlan

canonical_prefix(prefix) := lower(prefix)
