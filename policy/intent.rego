package intent.validation

import rego.v1

# METADATA
# schemas:
#   - input: schema["intent.schema.json"]
#   - data.allowed_exports: schema["allowed_exports.schema.json"]

# Policy toggles and defaults
policy_config := data.policy {
  data.policy
}

default policy_config := {
  "strict": false,
  "allowed_leafpairs": [],
  "min_vlan": 1,
  "max_vlan": 4094,
  "l2vni_base": 11000,
  "allowed_export_vrfs": ["VRF-STORAGE", "VRF-FIREWALL"],
}

allowed_leafpairs := {pair | pair := policy_config.allowed_leafpairs[_]}

allowed_export_vrfs := {vrf | vrf := policy_config.allowed_export_vrfs[_]}

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

is_ipv4_host_prefix(prefix) {
  re_match(`^(?:\d{1,3}\.){3}\d{1,3}/32$`, prefix)
}

is_ipv6_host_prefix(prefix) {
  re_match(`^[0-9a-fA-F:]+/128$`, prefix)
}

is_host_prefix(prefix) {
  is_ipv4_host_prefix(prefix)
} else {
  is_ipv6_host_prefix(prefix)
}

allowable_vip_exports(vrf_name) := prefixes {
  allowed_map := data.allowed_exports[vrf_name]
  prefixes := {prefix | allowed_map[prefix]}
}

allowable_vip_exports(vrf_name) := prefixes {
  vrf := vrf_by_name[vrf_name]
  prefixes := {prefix | prefix := vrf.allowed_vip_exports[_]}
}

expected_l2vni(vlan) := base + vlan {
  base := policy_config.l2vni_base
}

deny[error] {
  tenant_entry := tenant_entries[_]
  vlan := tenant_entry.tenant.vlan
  vlan < policy_config.min_vlan
  error := {
    "msg": sprintf("tenant %s: VLAN %d below minimum %d", [tenant_entry.tenant.tenant, vlan, policy_config.min_vlan]),
    "path": sprintf("input[%d].vlan", [tenant_entry.file_index]),
  }
}

deny[error] {
  tenant_entry := tenant_entries[_]
  vlan := tenant_entry.tenant.vlan
  vlan > policy_config.max_vlan
  error := {
    "msg": sprintf("tenant %s: VLAN %d above maximum %d", [tenant_entry.tenant.tenant, vlan, policy_config.max_vlan]),
    "path": sprintf("input[%d].vlan", [tenant_entry.file_index]),
  }
}

deny[error] {
  tenant_entry := tenant_entries[_]
  tenant := tenant_entry.tenant
  expected := expected_l2vni(tenant.vlan)
  tenant.l2vni != expected
  error := {
    "msg": sprintf("tenant %s: L2VNI must equal %d + VLAN (%d != %d + %d)", [tenant.tenant, policy_config.l2vni_base, tenant.l2vni, policy_config.l2vni_base, tenant.vlan]),
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
    "msg": sprintf("vip_export %s must be a /32 or /128 host prefix", [export.prefix]),
    "path": sprintf("input[%d].vip_exports[%d].prefix", [tenant_entry.file_index, export_index]),
  }
}

deny[error] {
  tenant_entry := tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  not vrf_names[export.vrf]
  error := {
    "msg": sprintf("vip_export prefix %s references unknown VRF %s", [export.prefix, export.vrf]),
    "path": sprintf("input[%d].vip_exports[%d].vrf", [tenant_entry.file_index, export_index]),
  }
}

deny[error] {
  tenant_entry := tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  allowed := allowable_vip_exports(export.vrf)
  not allowed[export.prefix]
  error := {
    "msg": sprintf("vip_export %s not permitted for VRF %s", [export.prefix, export.vrf]),
    "path": sprintf("input[%d].vip_exports[%d].prefix", [tenant_entry.file_index, export_index]),
  }
}

deny[error] {
  tenant_entry := tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  export.vrf != tenant_entry.tenant.tenant
  not allowed_export_vrfs[export.vrf]
  error := {
    "msg": sprintf("vip_export %s cannot leak to VRF %s (allowed: %s)", [export.prefix, export.vrf, concat(", ", sort(allowed_export_vrfs))]),
    "path": sprintf("input[%d].vip_exports[%d].vrf", [tenant_entry.file_index, export_index]),
  }
}

deny[error] {
  policy_config.strict
  tenant_entry := tenant_entries[_]
  rack := tenant_entry.tenant.racks[_]
  not allowed_leafpairs[rack]
  error := {
    "msg": sprintf("tenant %s rack %s not allowed (strict mode)", [tenant_entry.tenant.tenant, rack]),
    "path": sprintf("input[%d].racks", [tenant_entry.file_index]),
  }
}

deny[error] {
  i := tenant_entries[_]
  j := tenant_entries[_]
  i.file_index < j.file_index
  net.cidr_overlap(i.tenant.subnet, j.tenant.subnet)
  error := {
    "msg": sprintf("tenant %s subnet %s overlaps with tenant %s subnet %s", [i.tenant.tenant, i.tenant.subnet, j.tenant.tenant, j.tenant.subnet]),
    "path": sprintf("input[%d].subnet", [j.file_index]),
  }
}
