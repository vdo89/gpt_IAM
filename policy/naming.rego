package intent.naming

import rego.v1
import data.intent.lib

deny[error] {
  entry := lib.vrf_entries[_]
  vrf := entry.vrf
  vrf.zone == "TENANT"
  not startswith(vrf.name, "TENANT-")
  error := {
    "msg": lib.strict_hint(sprintf("vrf %s must use TENANT- prefix when zone is TENANT", [vrf.name])),
    "path": sprintf("input[%d].vrfs[%d].zone", [entry.file_index, entry.vrf_index]),
  }
}

deny[error] {
  tenant_entry := lib.tenant_entries[_]
  tenant := tenant_entry.tenant
  not lib.vrf_names[tenant.tenant]
  error := {
    "msg": lib.strict_hint(sprintf("tenant %s has no matching VRF definition", [tenant.tenant])),
    "path": sprintf("input[%d].tenant", [tenant_entry.file_index]),
  }
}
