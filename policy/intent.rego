package intent.validation

vrf_entries := [{"file_index": i, "vrf_index": j, "vrf": vrf} |
  some i
  file := input[i]
  file.vrfs
  some j
  vrf := file.vrfs[j]
]

vrfs := [entry.vrf | entry := vrf_entries[_]]

tenant_entries := [{"file_index": i, "tenant": file} |
  some i
  file := input[i]
  file.tenant
]

tenants := [entry.tenant | entry := tenant_entries[_]]

vrf_by_name := {entry.vrf.name: entry.vrf | entry := vrf_entries[_]}

tenant_entries := [{"file_index": i, "tenant": file} |
  some i
  file := input[i]
  file.tenant
]

allowable_vip_exports(vrf_name) = prefixes {
  some vrf
  vrf := vrfs[_]
  vrf.name == vrf_name
  prefixes := vrf.allowed_vip_exports
}

is_ipv4_32(prefix) {
  re_match("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/32$", prefix)
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
  some i
  some j
  i < j
  vrf_i := vrf_entries[i]
  vrf_j := vrf_entries[j]
  vrf_i.vrf.l3vni == vrf_j.vrf.l3vni
  error := {
    "msg": sprintf("duplicate L3VNI %d in VRFs %s and %s", [vrf_i.vrf.l3vni, vrf_i.vrf.name, vrf_j.vrf.name]),
    "path": sprintf("input[%d].vrfs[%d].l3vni", [vrf_j.file_index, vrf_j.vrf_index]),
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
  not vrf_names[export.vrf]
  error := {
    "msg": sprintf("vip_export prefix %s references unknown VRF %s", [export.prefix, export.vrf]),
    "path": sprintf("input[%d].vip_exports[%d].vrf", [tenant_entry.file_index, export_index]),
  }
}

deny[error] {
  tenant_entry := tenant_entries[_]
  some export_index
  export := tenant_entry.tenant.vip_exports[export_index]
  allowed := allowable_vip_exports(export.vrf)
  not export.prefix == allowed[_]
  error := {
    "msg": sprintf("vip_export %s not permitted for VRF %s", [export.prefix, export.vrf]),
    "path": sprintf("input[%d].vip_exports[%d].prefix", [tenant_entry.file_index, export_index]),
  }
}
