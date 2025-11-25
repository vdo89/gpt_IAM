package main

import future.keywords.every

# Ensure VRF L3VNIs remain unique to avoid leaking routes between tenants.
deny[message] {
  vrfs := data.vrfs
  l3vni := vrfs[_].l3vni
  count({v | v := vrfs[_].l3vni; v == l3vni}) > 1
  message := sprintf("duplicate l3vni %v detected across VRFs", [l3vni])
}

# Reject any tenant load balancer VIP that is not a /32.
deny[message] {
  some k
  tenant := data[k]
  tenant.lb_vip
  not endswith(tenant.lb_vip, "/32")
  message := sprintf("tenant %v must advertise VIPs as /32 only", [tenant.tenant])
}

# Simple guardrail to avoid overlapping L2VNIs.
deny[message] {
  l2vni := data[k].l2vni
  count({v | some key; v := data[key].l2vni; v == l2vni}) > 1
  message := sprintf("duplicate l2vni %v detected across tenants", [l2vni])
}
