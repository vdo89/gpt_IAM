package intent.vni

import rego.v1
import data.intent.lib

deny[error] {
  tenant_entry := lib.tenant_entries[_]
  tenant := tenant_entry.tenant
  expected := lib.expected_l2vni(tenant.vlan, tenant.l2vni_base)
  tenant.l2vni != expected
  error := {
    "msg": lib.strict_hint(sprintf("tenant %s: l2vni must equal l2vni_base + vlan (%d != %d + %d)", [tenant.tenant, tenant.l2vni, tenant.l2vni_base, tenant.vlan])),
    "path": sprintf("input[%d].l2vni", [tenant_entry.file_index]),
  }
}

vlan_overlap[vlan] {
  vlan := lib.vlan_values[_]
  count({idx | lib.vlan_values[idx] == vlan}) > 1
}

deny[error] {
  vlan := vlan_overlap[_]
  tenants := [entry | entry := lib.tenant_entries[_]; entry.tenant.vlan == vlan]
  names := sort([entry.tenant.tenant | entry := tenants[_]])
  target := tenants[1]
  error := {
    "msg": lib.strict_hint(sprintf("duplicate VLAN %d across tenants %s", [vlan, concat(", ", names)])),
    "path": sprintf("input[%d].vlan", [target.file_index]),
  }
}

deny[error] {
  lib.strict_mode == true
  tenant_entry := lib.tenant_entries[_]
  rack := tenant_entry.tenant.racks[_]
  not lib.allowed_leaf_pairs[rack]
  error := {
    "msg": lib.strict_hint(sprintf("tenant %s rack %s is outside mobility domain", [tenant_entry.tenant.tenant, rack])),
    "path": sprintf("input[%d].racks", [tenant_entry.file_index]),
  }
}
