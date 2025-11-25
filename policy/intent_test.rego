package intent.validation_test

import data.intent.validation

valid_input := [
  {
    "vrfs": [
      {
        "name": "TENANT-VALID",
        "l3vni": 6000,
        "rd": "65000:6000",
        "rt_import": ["65000:6000"],
        "rt_export": ["65000:6000"],
        "allowed_vip_exports": ["192.0.2.1/32"]
      }
    ]
  },
  {
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
      {"vrf": "TENANT-VALID", "prefix": "192.0.2.1/32"}
    ]
  }
]

invalid_l2vni := [valid_input[0], {
  "tenant": "TENANT-BAD",
  "vlan": 400,
  "subnet": "10.4.0.0/24",
  "gateway": "10.4.0.1/24",
  "l2vni": 13000,
  "l3vni": 6100,
  "rt_l2": "65000:13000",
  "rt_l3": "65000:6100",
  "racks": ["leafpair1"],
  "lb_vip": "192.0.2.99/32",
  "vip_exports": [
    {"vrf": "TENANT-VALID", "prefix": "192.0.2.99/32"}
  ]
}]

dbl_l3vni_case := [
  {
    "vrfs": [
      {
        "name": "TENANT-A",
        "l3vni": 6001,
        "rd": "65000:6001",
        "rt_import": ["65000:6001"],
        "rt_export": ["65000:6001"],
        "allowed_vip_exports": []
      },
      {
        "name": "TENANT-B",
        "l3vni": 6001,
        "rd": "65000:6001",
        "rt_import": ["65000:6001"],
        "rt_export": ["65000:6001"],
        "allowed_vip_exports": []
      }
    ]
  },
  valid_input[1]
]

vip_outside_allowlist := [valid_input[0], {
  "tenant": "TENANT-VALID",
  "vlan": 2,
  "subnet": "10.0.1.0/24",
  "gateway": "10.0.1.1/24",
  "l2vni": 11002,
  "l3vni": 6000,
  "rt_l2": "65000:11002",
  "rt_l3": "65000:6000",
  "racks": ["leafpair1"],
  "lb_vip": "198.51.100.1/32",
  "vip_exports": [
    {"vrf": "TENANT-VALID", "prefix": "198.51.100.1/32"}
  ]
}]

messages(input_value) = {msg | validation.deny[err] with input as input_value; msg := err.msg}

paths(input_value) = {path | validation.deny[err] with input as input_value; path := err.path}


test_no_denials_for_valid_input {
  count(messages(valid_input)) == 0
}


test_l2vni_rule_triggers {
  some msg
  msg := messages(invalid_l2vni)[_]
  contains(msg, "L2VNI must equal")
}


test_duplicate_l3vni_denied {
  msgs := messages(dbl_l3vni_case)
  paths_for_case := paths(dbl_l3vni_case)

  some msg
  msg := msgs[_]
  contains(msg, "duplicate L3VNI")

  some path
  path := paths_for_case[_]
  contains(path, "vrfs")
}


test_vip_allowlist_enforced {
  some msg
  msg := messages(vip_outside_allowlist)[_]
  contains(msg, "not permitted for VRF")
}
