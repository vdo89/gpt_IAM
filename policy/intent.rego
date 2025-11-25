package intent.validation

import rego.v1

# METADATA
# schemas:
#   - input: schema["intent.schema.json"]
#   - data.allowed_exports: schema["allowed_exports.schema.json"]

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

l3vni_values := [entry.vrf.l3vni | entry := vrf_entries[_]]

duplicate_l3vnis := {l3vni |
  l3vni := l3vni_values[_]
  count({idx | l3vni_values[idx] == l3vni}) > 1
}

is_host_prefix(prefix) {
  parts := split(prefix, "/")
  count(parts) == 2
  to_number(parts[1]) == 32
}

allowable_vip_exports(vrf_name) := prefixes {
  allowed_map := data.allowed_exports[vrf_name]
  prefixes := {prefix | allowed_map[prefix]}
}

allowable_vip_exports(vrf_name) := prefixes {
  vrf := vrf_by_name[vrf_name]
  prefixes := {prefix | prefix := vrf.allowed_vip_exports[_]}
}

expected_l2vni(vlan) := 11000 + vlan

deny[error] {
  tenant_entry := tenant_entries[_]
  tenant := tenant_entry.tenant
  expected := expected_l2vni(tenant.vlan)
  tenant.l2vni != expected
  error := {
    "msg": sprintf("tenant %s: L2VNI must equal 11000 + VLAN (%d != 11000 + %d)", [tenant.tenant, tenant.l2vni, tenant.vlan]),
    "path": sprintf("input[%d].l2vni", [tenant_entry.file_index]),
  }
}

deny[error] {
  l3vni := duplicate_l3vnis[_]
  dup_entries := [entry | entry := vrf_entries[_]; entry.vrf.l3vni == l3vni]
  names := sort([entry.vrf.name | entry := dup_entries[_]])
  target := dup_entries[1]
  error := {
    "msg": sprintf("duplicate L3VNI %d present in VRFs %s", [l3vni, concat(", ", names)]),
    "path": sprintf("input[%d].vrfs[%d].l3vni", [target.file_index, target.vrf_index]),
  }
}

deny[error] {
  tenant_entry := tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  not is_host_prefix(export.prefix)
  error := {
    "msg": sprintf("vip_export %s must be a /32 prefix", [export.prefix]),
    "path": sprintf("input[%d].vip_exports[%d].prefix", [tenant_entry.file_index, export_index]),
  }
}

vip_rule_violation[err] {
  tenant_entry := tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  not vrf_names[export.vrf]
  err := violation_record(
    sprintf("vip_export prefix %s references unknown VRF %s", [export.prefix, export.vrf]),
    path_for(tenant_entry.file_index, ["vip_exports", export_index, "vrf"]),
  )
}

vip_rule_violation[err] {
  tenant_entry := tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  allowed := allowable_vip_exports(export.vrf)
  not allowed[export.prefix]
  error := {
    "msg": sprintf("vip_export %s not permitted for VRF %s", [export.prefix, export.vrf]),
    "path": sprintf("input[%d].vip_exports[%d].prefix", [tenant_entry.file_index, export_index]),
  }
}
