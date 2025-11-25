package intent.routing

import rego.v1
import data.intent.lib

l3vni_overlap[l3vni] {
  l3vni := lib.l3vni_values[_]
  count({idx | lib.l3vni_values[idx] == l3vni}) > 1
}

deny[error] {
  l3 := l3vni_overlap[_]
  dup_entries := [entry | entry := lib.vrf_entries[_]; entry.vrf.l3vni == l3]
  names := sort([entry.vrf.name | entry := dup_entries[_]])
  target := dup_entries[1]
  error := {
    "msg": lib.strict_hint(sprintf("duplicate L3VNI %d present in VRFs %s", [l3, concat(", ", names)])),
    "path": sprintf("input[%d].vrfs[%d].l3vni", [target.file_index, target.vrf_index]),
  }
}

deny[error] {
  tenant_entry := lib.tenant_entries[_]
  tenant := tenant_entry.tenant
  lib.vrf_names[tenant.tenant]
  vrf := lib.vrf_by_name[tenant.tenant]
  tenant.l3vni != vrf.l3vni
  error := {
    "msg": lib.strict_hint(sprintf("tenant %s L3VNI %d must match VRF %s", [tenant.tenant, tenant.l3vni, vrf.name])),
    "path": sprintf("input[%d].l3vni", [tenant_entry.file_index]),
  }
}

overlapping_subnets(s1, s2) {
  net.cidr_contains(s1, lib.prefix_ip(s2))
}

overlapping_subnets(s1, s2) {
  net.cidr_contains(s2, lib.prefix_ip(s1))
}

deny[error] {
  some idx1
  some idx2
  idx1 < idx2
  s1 := lib.subnets[idx1]
  s2 := lib.subnets[idx2]
  overlapping_subnets(s1, s2)
  t1 := lib.tenant_entries[idx1]
  t2 := lib.tenant_entries[idx2]
  error := {
    "msg": lib.strict_hint(sprintf("tenant prefixes %s and %s overlap", [t1.tenant.subnet, t2.tenant.subnet])),
    "path": sprintf("input[%d].subnet", [t2.file_index]),
  }
}

deny[error] {
  tenant_entry := lib.tenant_entries[_]
  tenant := tenant_entry.tenant
  lib.blocked_ipv6_prefix(tenant.subnet)
  error := {
    "msg": lib.strict_hint(sprintf("tenant %s subnet %s is a reserved IPv6 range", [tenant.tenant, tenant.subnet])),
    "path": sprintf("input[%d].subnet", [tenant_entry.file_index]),
  }
}

deny[error] {
  tenant_entry := lib.tenant_entries[_]
  tenant := tenant_entry.tenant
  lib.blocked_ipv6_prefix(tenant.gateway)
  error := {
    "msg": lib.strict_hint(sprintf("tenant %s gateway %s is a reserved IPv6 address", [tenant.tenant, tenant.gateway])),
    "path": sprintf("input[%d].gateway", [tenant_entry.file_index]),
  }
}
