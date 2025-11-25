package intent.validation_test

import rego.v1

import data.intent.validation

vrf_file := {
  "vrfs": [
    {
      "name": "VRF-PLATFORM",
      "zone": "PLATFORM",
      "l3vni": 50000,
      "rd": "65000:50000",
      "rt_import": ["65000:50000"],
      "rt_export": ["65000:50000"],
      "allowed_vip_exports": ["203.0.113.10/32"]
    },
    {
      "name": "TENANT-VALID",
      "zone": "TENANT",
      "l3vni": 6000,
      "rd": "65000:6000",
      "rt_import": ["65000:6000"],
      "rt_export": ["65000:6000"],
      "allowed_vip_exports": ["192.0.2.1/32", "2001:db8::1/128"]
    },
    {
      "name": "TENANT-OVERLAP",
      "zone": "TENANT",
      "l3vni": 6100,
      "rd": "65000:6100",
      "rt_import": ["65000:6100"],
      "rt_export": ["65000:6100"],
      "allowed_vip_exports": ["192.0.2.2/32"]
    },
    {
      "name": "VRF-STORAGE",
      "zone": "STORAGE",
      "l3vni": 52000,
      "rd": "65000:52000",
      "rt_import": ["65000:52000"],
      "rt_export": ["65000:52000"],
      "allowed_vip_exports": ["10.42.200.42/32"]
    },
    {
      "name": "VRF-FIREWALL",
      "zone": "FIREWALL",
      "l3vni": 53000,
      "rd": "65000:53000",
      "rt_import": ["65000:53000"],
      "rt_export": ["65000:53000"],
      "allowed_vip_exports": []
    }
  ]
}

tenant_valid := {
  "tenant": "TENANT-VALID",
  "vlan": 101,
  "subnet": "10.0.0.0/24",
  "gateway": "10.0.0.1/24",
  "l2vni": 11101,
  "l3vni": 6000,
  "rt_l2": "65000:11101",
  "rt_l3": "65000:6000",
  "racks": ["leafpair1"],
  "lb_vip": "192.0.2.1/32",
  "vip_exports": [
    {"vrf": "TENANT-VALID", "prefix": "192.0.2.1/32"}
  ]
}

tenant_overlap := {
  "tenant": "TENANT-OVERLAP",
  "vlan": 102,
  "subnet": "10.0.0.0/25",
  "gateway": "10.0.0.129/25",
  "l2vni": 11102,
  "l3vni": 6100,
  "rt_l2": "65000:11102",
  "rt_l3": "65000:6100",
  "racks": ["leafpair1"],
  "lb_vip": "192.0.2.2/32",
  "vip_exports": [
    {"vrf": "TENANT-OVERLAP", "prefix": "192.0.2.2/32"}
  ]
}

tenant_bad_rack := {
  "tenant": "TENANT-VALID",
  "vlan": 101,
  "subnet": "10.0.0.0/24",
  "gateway": "10.0.0.1/24",
  "l2vni": 11101,
  "l3vni": 6000,
  "rt_l2": "65000:11101",
  "rt_l3": "65000:6000",
  "racks": ["leafpair1", "leafpair9"],
  "lb_vip": "192.0.2.1/32",
  "vip_exports": [
    {"vrf": "TENANT-VALID", "prefix": "192.0.2.1/32"}
  ]
}

valid_input := [vrf_file, tenant_valid]

allowed_exports_fixture := {
  "TENANT-VALID": {"192.0.2.1/32": true, "2001:db8::1/128": true},
  "TENANT-OVERLAP": {"192.0.2.2/32": true},
  "VRF-PLATFORM": {"203.0.113.10/32": true},
  "VRF-STORAGE": {"10.42.200.42/32": true},
  "VRF-FIREWALL": {}
}

empty_allowlist := {
  "TENANT-VALID": {},
  "TENANT-OVERLAP": {},
  "VRF-PLATFORM": {},
  "VRF-STORAGE": {},
  "VRF-FIREWALL": {},
}

policy_fixture := {
  "strict": true,
  "allowed_leafpairs": ["leafpair1", "leafpair2"],
  "min_vlan": 100,
  "max_vlan": 4094,
  "l2vni_base": 11000,
  "allowed_export_vrfs": ["VRF-STORAGE", "VRF-FIREWALL"]
}

policy_relaxed := object.put(policy_fixture, "strict", false)

messages(input_value, allowed_exports, policy_data) = {msg |
  validation.deny[err] with input as input_value with data.allowed_exports as allowed_exports with data.policy as policy_data
  msg := err.msg
}

paths(input_value, allowed_exports, policy_data) = {path |
  validation.deny[err] with input as input_value with data.allowed_exports as allowed_exports with data.policy as policy_data
  path := err.path
}

table_driven_negatives := [
  {
    "name": "rejects_non_host_ipv4",
    "input": [vrf_file, object.put(tenant_valid, "vip_exports", [{"vrf": "TENANT-VALID", "prefix": "192.0.2.0/31"}])],
    "expect": "must be a /32 or /128",
  },
  {
    "name": "rejects_non_host_ipv6",
    "input": [vrf_file, object.put(tenant_valid, "vip_exports", [{"vrf": "TENANT-VALID", "prefix": "2001:db8::/64"}])],
    "expect": "must be a /32 or /128",
  },
  {
    "name": "rejects_l2vni_not_base_plus_vlan",
    "input": [vrf_file, object.put(tenant_valid, "l2vni", 13000)],
    "expect": "L2VNI must equal",
  },
  {
    "name": "rejects_overlapping_subnets",
    "input": [vrf_file, tenant_valid, tenant_overlap],
    "expect": "overlaps",
  },
  {
    "name": "rejects_rack_outside_allowlist_when_strict",
    "input": [vrf_file, tenant_bad_rack],
    "expect": "not allowed (strict mode)",
  },
  {
    "name": "rejects_vrf_leak_outside_allowed_targets",
    "input": [vrf_file, object.put(tenant_valid, "vip_exports", [{"vrf": "VRF-PLATFORM", "prefix": "203.0.113.10/32"}])],
    "expect": "cannot leak",
  },
  {
    "name": "rejects_vlan_below_minimum",
    "input": [vrf_file, object.put(tenant_valid, "vlan", 10)],
    "expect": "below minimum",
  }
]

test_no_denials_for_valid_input {
  count(messages(valid_input, allowed_exports_fixture, policy_fixture)) == 0
}

test_negative_cases_table_driven {
  case := table_driven_negatives[_]
  msgs := messages(case.input, allowed_exports_fixture, policy_fixture)
  some msg in msgs
  contains(msg, case.expect)
}

test_unknown_vrf_rejected {
  tenant := object.put(tenant_valid, "vip_exports", [{"vrf": "TENANT-MISSING", "prefix": "192.0.2.1/32"}])
  msgs := messages([vrf_file, tenant], allowed_exports_fixture, policy_fixture)
  some msg in msgs
  contains(msg, "references unknown VRF")
}

test_allowlist_enforced_from_data_overrides_input {
  msgs := messages([vrf_file, tenant_valid], empty_allowlist, policy_fixture)
  some msg in msgs
  contains(msg, "not permitted for VRF")
}

test_rack_is_allowed_when_not_strict {
  msgs := messages([vrf_file, tenant_bad_rack], allowed_exports_fixture, policy_relaxed)
  count(msgs) == 0
}

test_ipv6_host_prefix_allowed {
  tenant := object.put(tenant_valid, "vip_exports", [{"vrf": "TENANT-VALID", "prefix": "2001:db8::1/128"}])
  msgs := messages([vrf_file, tenant], allowed_exports_fixture, policy_fixture)
  count(msgs) == 0
}
