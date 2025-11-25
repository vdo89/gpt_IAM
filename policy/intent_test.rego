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
      "allowed_vip_exports": []
    },
    {
      "name": "TENANT-VALID",
      "zone": "TENANT",
      "l3vni": 6000,
      "rd": "65000:6000",
      "rt_import": ["65000:6000"],
      "rt_export": ["65000:6000"],
      "allowed_vip_exports": ["192.0.2.1/32"]
    },
    {
      "name": "VRF-STORAGE",
      "zone": "STORAGE",
      "l3vni": 52000,
      "rd": "65000:52000",
      "rt_import": ["65000:52000"],
      "rt_export": ["65000:52000"],
      "allowed_vip_exports": ["198.51.100.10/32"]
    }
  ]
}

tenant_valid := {
  "tenant": "TENANT-VALID",
  "vlan": 1,
  "l2vni_base": 11000,
  "subnet": "10.0.0.0/24",
  "gateway": "10.0.0.1/24",
  "l2vni": 11001,
  "l3vni": 6000,
  "rt_l2": "65000:11001",
  "rt_l3": "65000:6000",
  "racks": ["leafpair1"],
  "lb_vip": "192.0.2.1/32",
  "vip_exports": [
    {"vrf": "TENANT-VALID", "prefix": "192.0.2.1/32"}
  ]
}

valid_input := [vrf_file, tenant_valid]

messages(input_value, allowed_exports, policy_overrides) = {msg |
  validation.deny[err] with input as input_value with data.allowed_exports as allowed_exports with data.policy as policy_overrides
  msg := err.msg
}

paths(input_value, allowed_exports, policy_overrides) = {path |
  validation.deny[err] with input as input_value with data.allowed_exports as allowed_exports with data.policy as policy_overrides
  path := err.path
}

allowed_exports_fixture := {
  "TENANT-VALID": {"192.0.2.1/32": true},
  "VRF-PLATFORM": {"203.0.113.10/32": true},
  "VRF-STORAGE": {"198.51.100.10/32": true}
}

empty_tenant_allowlist := {
  "TENANT-VALID": {},
  "VRF-PLATFORM": {}
}

duplicate_vrf_file := {
  "vrfs": [
    {
      "name": "TENANT-A",
      "zone": "TENANT",
      "l3vni": 6100,
      "rd": "65000:6100",
      "rt_import": ["65000:6100"],
      "rt_export": ["65000:6100"],
      "allowed_vip_exports": []
    },
    {
      "name": "TENANT-B",
      "zone": "TENANT",
      "l3vni": 6100,
      "rd": "65000:6100",
      "rt_import": ["65000:6100"],
      "rt_export": ["65000:6100"],
      "allowed_vip_exports": []
    }
  ]
}

duplicate_vlan_tenant := {
  "tenant": "TENANT-DUP",
  "vlan": 1,
  "l2vni_base": 11000,
  "subnet": "10.0.1.0/24",
  "gateway": "10.0.1.1/24",
  "l2vni": 11001,
  "l3vni": 6000,
  "rt_l2": "65000:11001",
  "rt_l3": "65000:6000",
  "racks": ["leafpair1"],
  "lb_vip": "192.0.2.2/32",
  "vip_exports": []
}

overlap_tenant := {
  "tenant": "TENANT-OVERLAP",
  "vlan": 2,
  "l2vni_base": 11000,
  "subnet": "10.0.0.0/25",
  "gateway": "10.0.0.1/25",
  "l2vni": 11002,
  "l3vni": 6000,
  "rt_l2": "65000:11002",
  "rt_l3": "65000:6000",
  "racks": ["leafpair1"],
  "lb_vip": "192.0.2.3/32",
  "vip_exports": []
}

authz_overrides := {
  "strict": true,
  "mobility_leaf_pairs": ["leafpair1"],
  "allowed_ceph_public_vips": ["192.0.2.1/32"]
}

test_storage_exports_must_match_ceph_allowlist {
  tenant := object.put(tenant_valid, "vip_exports", [{"vrf": "VRF-STORAGE", "prefix": "198.51.100.20/32"}])
  msgs := messages([vrf_file, tenant], allowed_exports_fixture, authz_overrides)
  some msg in msgs
  contains(msg, "storage VRF export")
}

test_no_denials_for_valid_input {
  count(messages(valid_input, allowed_exports_fixture, authz_overrides)) == 0
}

test_reject_non_host_prefix {
  tenant := object.put(tenant_valid, "vip_exports", [{"vrf": "TENANT-VALID", "prefix": "192.0.2.0/24"}])
  msgs := messages([vrf_file, tenant], allowed_exports_fixture, authz_overrides)
  some msg
  msg := msgs[_]
  contains(msg, "must be a /32 or /128")
}

test_duplicate_l3vni_denied {
  msgs := messages([duplicate_vrf_file, tenant_valid], allowed_exports_fixture, authz_overrides)
  some msg in msgs
  contains(msg, "duplicate L3VNI")
}

test_unknown_vrf_rejected {
  tenant := object.put(tenant_valid, "vip_exports", [{"vrf": "TENANT-MISSING", "prefix": "192.0.2.1/32"}])
  msgs := messages([vrf_file, tenant], allowed_exports_fixture, authz_overrides)
  some msg in msgs
  contains(msg, "references unknown VRF")
}

test_allowlist_enforced_from_data_overrides_input {
  tenant := tenant_valid
  msgs := messages([vrf_file, tenant], empty_tenant_allowlist, authz_overrides)
  some msg in msgs
  contains(msg, "not permitted for VRF")
}

test_duplicate_vlan_denied {
  msgs := messages([vrf_file, tenant_valid, duplicate_vlan_tenant], allowed_exports_fixture, authz_overrides)
  some msg in msgs
  contains(msg, "duplicate VLAN")
}

test_overlap_rejected {
  msgs := messages([vrf_file, tenant_valid, overlap_tenant], allowed_exports_fixture, authz_overrides)
  some msg in msgs
  contains(msg, "overlap")
}

test_mobility_scope_enforced_when_strict {
  tenant := object.put(tenant_valid, "racks", ["edgecore"])
  msgs := messages([vrf_file, tenant], allowed_exports_fixture, authz_overrides)
  some msg in msgs
  contains(msg, "mobility domain")
}

test_l2vni_must_match_base_plus_vlan {
  tenant := object.put(tenant_valid, "l2vni", 11005)
  msgs := messages([vrf_file, tenant], allowed_exports_fixture, authz_overrides)
  some msg in msgs
  contains(msg, "l2vni must equal")
}
