package intent.validation_test

import rego.v1

import data.intent.validation

vrf_file := {
  "vrfs": [
    {
      "name": "VRF-PLATFORM",
      "l3vni": 50000,
      "rd": "65000:50000",
      "rt_import": ["65000:50000"],
      "rt_export": ["65000:50000"],
      "allowed_vip_exports": ["203.0.113.10/32", "2001:db8::203:0:113:10/128"]
    },
    {
      "name": "VRF-TENANT-VALID",
      "l3vni": 6000,
      "rd": "65000:6000",
      "rt_import": ["65000:6000"],
      "rt_export": ["65000:6000"],
      "allowed_vip_exports": ["192.0.2.1/32", "2001:db8::1/128"]
    }
  ]
}

tenant_valid := {
  "tenant": "TENANT-VALID",
  "vlan": 1,
  "subnet": "10.0.0.0/24",
  "gateway": "10.0.0.1/24",
  "l2vni": 11001,
  "l3vni": 6000,
  "rt_l2": "65000:11001",
  "rt_l3": "65000:6000",
  "racks": ["leafpair1"],
  "lb_vip": "192.0.2.1/32",
  "vip_exports": [
    {"vrf": "VRF-TENANT-VALID", "prefix": "192.0.2.1/32"}
  ]
}

valid_input := [vrf_file, tenant_valid]

messages(input_value, allowlists, policy) = {msg |
  validation.deny[err] with input as input_value with data.allowed_exports as allowlists with data.policy as policy
  msg := err.msg
}

paths(input_value, allowlists, policy) = {path |
  validation.deny[err] with input as input_value with data.allowed_exports as allowlists with data.policy as policy
  path := err.path
}

allowed_exports_fixture := {
  "VRF-TENANT-VALID": {"192.0.2.1/32": true, "2001:db8::1/128": true},
  "VRF-PLATFORM": {"203.0.113.10/32": true, "2001:db8::203:0:113:10/128": true}
}

empty_tenant_allowlist := {
  "VRF-TENANT-VALID": {},
  "VRF-PLATFORM": {}
}

duplicate_vrf_file := {
  "vrfs": [
    {
      "name": "VRF-TENANT-A",
      "l3vni": 6100,
      "rd": "65000:6100",
      "rt_import": ["65000:6100"],
      "rt_export": ["65000:6100"],
      "allowed_vip_exports": []
    },
    {
      "name": "VRF-TENANT-B",
      "l3vni": 6100,
      "rd": "65000:6100",
      "rt_import": ["65000:6100"],
      "rt_export": ["65000:6100"],
      "allowed_vip_exports": []
    }
  ]
}

policy_defaults := {"strict_allowlist": true, "vni": {"base_l2vni": 11000, "offset": 0}}

policy_non_strict := {"strict_allowlist": false, "vni": {"base_l2vni": 11000, "offset": 0}}

messages_with_defaults(input_value, allowlists) = messages(input_value, allowlists, policy_defaults)

paths_with_defaults(input_value, allowlists) = paths(input_value, allowlists, policy_defaults)

test_no_denials_for_valid_input {
  count(messages_with_defaults(valid_input, allowed_exports_fixture)) == 0
}

test_reject_non_host_prefix {
  tenant := object.put(tenant_valid, "vip_exports", [{"vrf": "VRF-TENANT-VALID", "prefix": "192.0.2.0/24"}])
  msgs := messages_with_defaults([vrf_file, tenant], allowed_exports_fixture)
  some msg
  msg := msgs[_]
  contains(msg, "must be a /32 or /128")
}

test_accept_ipv6_host_prefix {
  tenant := object.put(tenant_valid, "vip_exports", [{"vrf": "VRF-TENANT-VALID", "prefix": "2001:db8::1/128"}])
  count(messages_with_defaults([vrf_file, tenant], allowed_exports_fixture)) == 0
}

test_duplicate_l3vni_denied {
  msgs := messages_with_defaults([duplicate_vrf_file, tenant_valid], allowed_exports_fixture)
  some msg in msgs
  contains(msg, "duplicate L3VNI")
}

test_unknown_vrf_rejected {
  tenant := object.put(tenant_valid, "vip_exports", [{"vrf": "VRF-MISSING", "prefix": "192.0.2.1/32"}])
  msgs := messages_with_defaults([vrf_file, tenant], allowed_exports_fixture)
  some msg in msgs
  contains(msg, "references unknown VRF")
}

test_allowlist_enforced_from_data_overrides_input {
  tenant := tenant_valid
  msgs := messages_with_defaults([vrf_file, tenant], empty_tenant_allowlist)
  some msg in msgs
  contains(msg, "not permitted for VRF")
}

test_strict_mode_requires_data_allowlist_when_missing {
  tenant := object.put(tenant_valid, "vip_exports", [{"vrf": "VRF-TENANT-VALID", "prefix": "192.0.2.1/32"}])
  msgs := messages([vrf_file, tenant], {}, policy_defaults)
  some msg in msgs
  contains(msg, "requires data-backed allowlist")
}

test_non_strict_mode_allows_input_allowlist {
  tenant := object.put(tenant_valid, "vip_exports", [{"vrf": "VRF-TENANT-VALID", "prefix": "192.0.2.1/32"}])
  msgs := messages([vrf_file, tenant], {}, policy_non_strict)
  count(msgs) == 0
}

test_rt_sets_must_include_rd {
  vrf_missing_rd := {
    "vrfs": [{
      "name": "VRF-TENANT-OOPS",
      "l3vni": 7000,
      "rd": "65000:7000",
      "rt_import": ["65000:7001"],
      "rt_export": ["65000:7002"],
      "allowed_vip_exports": []
    }]
  }
  msgs := messages_with_defaults([vrf_missing_rd], allowed_exports_fixture)
  msg := msgs[_]
  contains(msg, "must include its RD")
}

test_vni_formula_uses_policy_offset {
  tenant := object.put(tenant_valid, "l2vni", 12001)
  msgs := messages([vrf_file, tenant], allowed_exports_fixture, {"strict_allowlist": true, "vni": {"base_l2vni": 12000, "offset": 0}})
  count(msgs) == 0
}
