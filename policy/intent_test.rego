package intent_test

import data.intent

valid_input := {
  "vrfs": [
    {
      "name": "TENANT-VALID",
      "l3vni": 6000,
      "rd": "65000:6000",
      "rt_import": ["65000:6000"],
      "rt_export": ["65000:6000"],
      "allowed_vip_exports": ["192.0.2.1/32"]
    }
  ],
  "tenants": [
    {
      "tenant": "TENANT-VALID",
      "vrf": "TENANT-VALID",
      "vlan": 1,
      "subnet": "10.0.0.0/24",
      "gateway": "10.0.0.1",
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
}

invalid_l2vni := valid_input with {
  "tenants": [valid_input.tenants[0] with {"l2vni": 12000}]
}

dbl_l3vni_case := valid_input with {
  "vrfs": [
    valid_input.vrfs[0],
    valid_input.vrfs[0] with {
      "name": "TENANT-B",
      "rd": "65000:6100",
      "l3vni": 6000
    }
  ]
}

vip_outside_allowlist := valid_input with {
  "tenants": [valid_input.tenants[0] with {
    "vip_exports": [
      {"vrf": "TENANT-VALID", "prefix": "198.51.100.1/32"}
    ]
  }]
}

gateway_outside_subnet := valid_input with {
  "tenants": [valid_input.tenants[0] with {"gateway": "10.0.2.1"}]
}

messages(input_value) = {msg | intent.deny[msg] with input as input_value}

test_no_denials_for_valid_input {
  count(messages(valid_input)) == 0
}

test_l2vni_rule_triggers {
  some msg
  msg := messages(invalid_l2vni)[_]
  contains(msg, "L2VNI must equal")
}

test_duplicate_l3vni_denied {
  some msg
  msg := messages(dbl_l3vni_case)[_]
  contains(msg, "L3VNI duplicate")
}

test_vip_allowlist_enforced {
  some msg
  msg := messages(vip_outside_allowlist)[_]
  contains(msg, "not permitted for VRF")
}

test_gateway_must_reside_in_subnet {
  some msg
  msg := messages(gateway_outside_subnet)[_]
  contains(msg, "gateway")
}
