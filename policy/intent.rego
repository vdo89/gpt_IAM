package intent.validation

vrfs := [vrf | file := input[_]; file.vrfs; vrf := file.vrfs[_]]

tenants := [tenant | file := input[_]; tenant.tenant]

vrf_names := {vrf.name | vrf := vrfs[_]}

allowable_vip_exports(vrf_name) = prefixes {
some vrf
vrf := vrfs[_]
vrf.name == vrf_name
prefixes := vrf.allowed_vip_exports
}

is_ipv4_32(prefix) {
re_match("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/32$", prefix)
}

deny[msg] {
some tenant
tenant := tenants[_]
tenant.l2vni != 11000 + tenant.vlan
msg := sprintf("tenant %s: L2VNI must equal 11000 + VLAN (%d != 11000 + %d)", [tenant.tenant, tenant.l2vni, tenant.vlan])
}

deny[msg] {
some i, j
i != j
vrfs[i].l3vni == vrfs[j].l3vni
msg := sprintf("duplicate L3VNI %d in VRFs %s and %s", [vrfs[i].l3vni, vrfs[i].name, vrfs[j].name])
}

deny[msg] {
some export
export := tenants[_].vip_exports[_]
not is_ipv4_32(export.prefix)
msg := sprintf("vip_export %s must be a /32 prefix", [export.prefix])
}

deny[msg] {
some export
export := tenants[_].vip_exports[_]
not vrf_names[export.vrf]
msg := sprintf("vip_export prefix %s references unknown VRF %s", [export.prefix, export.vrf])
}

deny[msg] {
some export
export := tenants[_].vip_exports[_]
allowed := allowable_vip_exports(export.vrf)
not export.prefix == allowed[_]
msg := sprintf("vip_export %s not permitted for VRF %s", [export.prefix, export.vrf])
}
