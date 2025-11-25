package intent.validation

vrf_entries := [{"file_index": i, "vrf_index": j, "vrf": vrf} |
  some i
  file := input[i]
  file.vrfs
  some j
  vrf := file.vrfs[j]
]

vrfs := [entry.vrf | entry := vrf_entries[_]]

vrf_by_name := {entry.vrf.name: entry.vrf | entry := vrf_entries[_]}

tenant_entries := [{"file_index": i, "tenant": file} |
  some i
  file := input[i]
  file.tenant
]

allowable_vip_exports(vrf_name) = prefixes {
  vrf := vrf_by_name[vrf_name]
  prefixes := vrf.allowed_vip_exports
}

is_ipv4_32(prefix) {
  parts := split(prefix, "/")
  count(parts) == 2
  parts[1] == "32"
  octets := split(parts[0], ".")
  count(octets) == 4
  all_octets_numeric(octets)
  not octet_out_of_range(octets)
}

all_octets_numeric(octets) {
  not octet_not_numeric(octets)
}

octet_not_numeric(octets) {
  some i
  not re_match("^[0-9]+$", octets[i])
}

octet_out_of_range(octets) {
  some i
  octet := to_number(octets[i])
  octet < 0
} {
  some i
  octet := to_number(octets[i])
  octet > 255
}

l3vni_collisions[l3vni] := entries {
  entries := [entry |
    entry := vrf_entries[_]
    entry.vrf.l3vni == l3vni
  ]
  count(entries) > 1
}

deny[error] {
  tenant_entry := tenant_entries[_]
  tenant := tenant_entry.tenant
  tenant.l2vni != 11000 + tenant.vlan
  error := {
    "msg": sprintf("tenant %s: L2VNI must equal 11000 + VLAN (%d != 11000 + %d)", [tenant.tenant, tenant.l2vni, tenant.vlan]),
    "path": sprintf("input[%d].l2vni", [tenant_entry.file_index]),
  }
}

deny[error] {
  some l3vni
  entries := l3vni_collisions[l3vni]
  entry := entries[_]
  vrf_names := [vrf_entry.vrf.name | vrf_entry := entries[_]]
  error := {
    "msg": sprintf("duplicate L3VNI %d across VRFs %s", [l3vni, concat(", ", vrf_names)]),
    "path": sprintf("input[%d].vrfs[%d].l3vni", [entry.file_index, entry.vrf_index]),
  }
}

deny[error] {
  tenant_entry := tenant_entries[_]
  some export_index
  export := tenant_entry.tenant.vip_exports[export_index]
  not is_ipv4_32(export.prefix)
  error := {
    "msg": sprintf("vip_export %s must be a /32 prefix", [export.prefix]),
    "path": sprintf("input[%d].vip_exports[%d].prefix", [tenant_entry.file_index, export_index]),
  }
}

deny[error] {
  tenant_entry := tenant_entries[_]
  some export_index
  export := tenant_entry.tenant.vip_exports[export_index]
  not vrf_by_name[export.vrf]
  error := {
    "msg": sprintf("vip_export prefix %s references unknown VRF %s", [export.prefix, export.vrf]),
    "path": sprintf("input[%d].vip_exports[%d].vrf", [tenant_entry.file_index, export_index]),
  }
}

deny[error] {
  tenant_entry := tenant_entries[_]
  some export_index
  export := tenant_entry.tenant.vip_exports[export_index]
  vrf_by_name[export.vrf]
  allowed := allowable_vip_exports(export.vrf)
  not allowed[_] == export.prefix
  error := {
    "msg": sprintf("vip_export %s not permitted for VRF %s", [export.prefix, export.vrf]),
    "path": sprintf("input[%d].vip_exports[%d].prefix", [tenant_entry.file_index, export_index]),
  }
}
