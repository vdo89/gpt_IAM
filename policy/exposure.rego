package intent.exposure

import rego.v1
import data.intent.lib

allowable_vip_exports(vrf_name) := prefixes {
  allowed_map := data.allowed_exports[vrf_name]
  prefixes := {lib.canonical_prefix(prefix) | allowed_map[prefix]}
}

allowable_vip_exports(vrf_name) := prefixes {
  vrf := lib.vrf_by_name[vrf_name]
  prefixes := {lib.canonical_prefix(prefix) | prefix := vrf.allowed_vip_exports[_]}
}

deny[error] {
  tenant_entry := lib.tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  not lib.is_host_prefix(export.prefix)
  error := {
    "msg": lib.strict_hint(sprintf("vip_export %s must be a /32 or /128 host route", [export.prefix])),
    "path": sprintf("input[%d].vip_exports[%d].prefix", [tenant_entry.file_index, export_index]),
  }
}

deny[error] {
  tenant_entry := lib.tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  not lib.vrf_names[export.vrf]
  error := {
    "msg": lib.strict_hint(sprintf("vip_export prefix %s references unknown VRF %s", [export.prefix, export.vrf])),
    "path": sprintf("input[%d].vip_exports[%d].vrf", [tenant_entry.file_index, export_index]),
  }
}

deny[error] {
  tenant_entry := lib.tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  allowed := allowable_vip_exports(export.vrf)
  canonical := lib.canonical_prefix(export.prefix)
  not allowed[canonical]
  error := {
    "msg": lib.strict_hint(sprintf("vip_export %s not permitted for VRF %s", [export.prefix, export.vrf])),
    "path": sprintf("input[%d].vip_exports[%d].prefix", [tenant_entry.file_index, export_index]),
  }
}

deny[error] {
  tenant_entry := lib.tenant_entries[_]
  tenant := tenant_entry.tenant
  lib.blocked_ipv6_prefix(tenant.lb_vip)
  error := {
    "msg": lib.strict_hint(sprintf("load-balancer VIP %s for %s is a reserved IPv6 address", [tenant.lb_vip, tenant.tenant])),
    "path": sprintf("input[%d].lb_vip", [tenant_entry.file_index]),
  }
}

deny[error] {
  tenant_entry := lib.tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  lib.blocked_ipv6_prefix(export.prefix)
  error := {
    "msg": lib.strict_hint(sprintf("vip_export %s is a reserved IPv6 range", [export.prefix])),
    "path": sprintf("input[%d].vip_exports[%d].prefix", [tenant_entry.file_index, export_index]),
  }
}

deny[error] {
  tenant_entry := lib.tenant_entries[_]
  export := tenant_entry.tenant.vip_exports[export_index]
  lib.vrf_names[export.vrf]
  vrf := lib.vrf_by_name[export.vrf]
  vrf.zone == "STORAGE"
  allowed := lib.allowed_ceph_public_vips
  canonical := lib.canonical_prefix(export.prefix)
  not allowed[canonical]
  error := {
    "msg": lib.strict_hint(sprintf("storage VRF export %s must be in allowed Ceph VIP list", [export.prefix])),
    "path": sprintf("input[%d].vip_exports[%d].prefix", [tenant_entry.file_index, export_index]),
  }
}
