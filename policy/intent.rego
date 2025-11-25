package intent.validation

import rego.v1

# METADATA
# schemas:
#   - input: schema["intent.schema.json"]
#   - data.allowed_exports: schema["allowed_exports.schema.json"]

default strict_allowlist := true

strict_allowlist := flag {
  flag := data.policy.strict_allowlist
}

vni_policy := object.union({
  "base_l2vni": 11000,
  "offset": 0,
}, data.policy.vni)

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

path_for(file_index, segments) := path {
  parts := [segment_path(segment) | segment := segments[_]]
  path := sprintf("input[%d]%s", [file_index, concat("", parts)])
}

segment_path(segment) := part {
  is_number(segment)
  part := sprintf("[%d]", [segment])
}

segment_path(segment) := part {
  not is_number(segment)
  part := sprintf(".%s", [segment])
}

is_host_prefix(prefix) {
  re_match("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/32$", prefix)
}

is_host_prefix(prefix) {
  re_match("^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{1,4}/128$", prefix)
}

allowlist_source(vrf_name) := "data" {
  data.allowed_exports[vrf_name]
}

# Explicit precedence: bundle-supplied allowlists override embedded input
# allowlists. Strict mode refuses to use the embedded copies.
allowlist_source(vrf_name) := "input" {
  not data.allowed_exports[vrf_name]
  vrf := vrf_by_name[vrf_name]
  vrf.allowed_vip_exports
}

allowlist_source(_) := "missing"

allowable_vip_exports(vrf_name) := prefixes {
  allowed_map := allowed_exports_map(vrf_name)
  prefixes := {prefix | allowed_map[prefix]}
}

allowed_exports_map(vrf_name) := allowed_map {
  allowed_map := data.allowed_exports[vrf_name]
}

allowed_exports_map(vrf_name) := allowed_map {
  not data.allowed_exports[vrf_name]
  vrf := vrf_by_name[vrf_name]
  allowed_map := {prefix: true | prefix := vrf.allowed_vip_exports[_]}
}

allowed_exports_map(_) := {}

expected_l2vni(vlan) := vni_policy.base_l2vni + vlan + vni_policy.offset

violation_record(msg, path) := {
  "msg": msg,
  "path": path,
  "severity": "error",
}

vip_rule_violation[err] {
  tenant_entry := tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  not is_host_prefix(export.prefix)
  err := violation_record(
    sprintf("vip_export %s must be a /32 or /128 host prefix", [export.prefix]),
    path_for(tenant_entry.file_index, ["vip_exports", export_index, "prefix"]),
  )
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
  err := violation_record(
    sprintf("vip_export %s not permitted for VRF %s", [export.prefix, export.vrf]),
    path_for(tenant_entry.file_index, ["vip_exports", export_index, "prefix"]),
  )
}

vip_rule_violation[err] {
  strict_allowlist
  tenant_entry := tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  allowlist_source(export.vrf) == "input"
  err := violation_record(
    sprintf("vip_export %s for VRF %s requires data-backed allowlist", [export.prefix, export.vrf]),
    path_for(tenant_entry.file_index, ["vip_exports", export_index]),
  )
}

vip_rule_violation[err] {
  strict_allowlist
  tenant_entry := tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  allowlist_source(export.vrf) == "missing"
  err := violation_record(
    sprintf("vip_export %s references VRF %s without any allowlist", [export.prefix, export.vrf]),
    path_for(tenant_entry.file_index, ["vip_exports", export_index]),
  )
}

vni_rule_violation[err] {
  tenant_entry := tenant_entries[_]
  tenant := tenant_entry.tenant
  expected := expected_l2vni(tenant.vlan)
  tenant.l2vni != expected
  err := violation_record(
    sprintf("tenant %s: L2VNI must equal %d + VLAN (%d != %d + %d)", [tenant.tenant, vni_policy.base_l2vni + vni_policy.offset, tenant.l2vni, vni_policy.base_l2vni + vni_policy.offset, tenant.vlan]),
    path_for(tenant_entry.file_index, ["l2vni"]),
  )
}

vni_rule_violation[err] {
  l3vni := duplicate_l3vnis[_]
  dup_entries := [entry | entry := vrf_entries[_]; entry.vrf.l3vni == l3vni]
  names := sort([entry.vrf.name | entry := dup_entries[_]])
  target := dup_entries[1]
  err := violation_record(
    sprintf("duplicate L3VNI %d present in VRFs %s", [l3vni, concat(", ", names)]),
    path_for(target.file_index, ["vrfs", target.vrf_index, "l3vni"]),
  )
}

rt_rule_violation[err] {
  entry := vrf_entries[_]
  vrf := entry.vrf
  not vrf.rd in vrf.rt_import
  err := violation_record(
    sprintf("vrf %s must include its RD %s in rt_import", [vrf.name, vrf.rd]),
    path_for(entry.file_index, ["vrfs", entry.vrf_index, "rt_import"]),
  )
}

rt_rule_violation[err] {
  entry := vrf_entries[_]
  vrf := entry.vrf
  not vrf.rd in vrf.rt_export
  err := violation_record(
    sprintf("vrf %s must include its RD %s in rt_export", [vrf.name, vrf.rd]),
    path_for(entry.file_index, ["vrfs", entry.vrf_index, "rt_export"]),
  )
}

violation[err] {
  some e
  e := vip_rule_violation[_]
  err := e
}

violation[err] {
  some e
  e := vni_rule_violation[_]
  err := e
}

violation[err] {
  some e
  e := rt_rule_violation[_]
  err := e
}

deny[err] {
  err := violation[_]
}
