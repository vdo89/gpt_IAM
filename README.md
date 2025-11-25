# NetAuto EVPN/VXLAN Lab

This repository models a small EVPN/VXLAN fabric with separate inventory, intent, and automation layers. The focus is to keep intent data declarative while providing CI feedback that is closer to production expectations.

## Repository layout
- `ansible/`: playbook entry point (`site.yml`), inventory, and host/group variables.
- `templates/`: device templates (NX-OS focused).
- `intent/`: declarative tenant/fabric intent (for example, `intent/vrfs.yml`).
- `cml/`: Cisco Modeling Labs topology definition.
- `tests/`: placeholder for Batfish/pyATS/Nornir validation.

## GitHub Actions pipeline
The GitLab CI pipeline has been mirrored into GitHub Actions with additional validation to make sure the playbooks stay idempotent and intent data stays well-formed.

Workflow: `.github/workflows/ci.yml`

Stages:
1. **Lint**: installs pinned tooling from `requirements-dev.txt`, runs `yamllint` and `ansible-lint`, enforces Rego policies with `conftest test --combine intent/`, and publishes OPA coverage results as an artifact.
2. **Render**: runs `ansible-playbook ... --check --diff` twice to prove idempotence and uploads the logs as artifacts with 30-day retention.
3. **Validate intent**: JSON Schema (draft 2020-12) validation for `intent/vrfs.yml` and `intent/tenants/*.yml`, with a detailed JSON summary uploaded as an artifact.
4. **Deploy**: manual-only (`workflow_dispatch`) run of the playbook to produce a deployment log artifact.

## Local quickstart
The repository uses local Ansible connections to avoid network dependencies while developing. A representative workflow is:

```bash
python -m pip install --upgrade pip
pip install --requirement requirements-dev.txt
ansible-lint ansible/site.yml
yamllint .
python scripts/validate_intent.py
conftest test intent/ --policy policy --combine
opa test policy
ansible-playbook -i ansible/inventory.yml ansible/site.yml --check --diff
```

If you prefer policy checks, add `policy/` with Conftest Rego rules and run `conftest test intent/`.

## Model invariants

- **L2VNI arithmetic:** `l2vni = l2vni_base + vlan` and is enforced by schema plus OPA policy to avoid drift across spreadsheets or templates.
- **Route-target symmetry and leaks:** import/export RTs are mirrored per VRF; route-leaks are only allowed from explicitly permitted firewall/storage VRFs.
- **VIP exports are hosts only:** `/32` or `/128` host routes only, double-enforced in JSON Schema and OPA (both per VRF allowlist and per storage/ceph guardrails).
- **Mobility domain scope:** tenant `racks` must be part of the allowed leaf-pair set when `data.policy.strict = true` to keep the flood domain small.
- **IPAM hygiene:** VLAN IDs are unique fabric-wide, L3VNIs are unique per VRF, and tenant subnets are required to be disjoint.

### Golden path (minimal)

```yaml
# intent/vrfs.yml
vrfs:
  - name: VRF-PLATFORM
    zone: PLATFORM
    l3vni: 50000
    rd: 65000:50000
    rt_import: [65000:50000]
    rt_export: [65000:50000]
    allowed_vip_exports: []
  - name: TENANT-FOO
    zone: TENANT
    l3vni: 51000
    rd: 65000:51000
    rt_import: [65000:51000]
    rt_export: [65000:51000]
    allowed_vip_exports: [10.10.10.10/32]
  - name: VRF-STORAGE
    zone: STORAGE
    l3vni: 52000
    rd: 65000:52000
    rt_import: [65000:52000]
    rt_export: [65000:52000]
    allowed_vip_exports: [10.42.200.42/32]

# intent/tenants/tenant-foo.yml
tenant: TENANT-FOO
vlan: 242
l2vni_base: 11000
subnet: 10.10.10.0/24
gateway: 10.10.10.1/24
l2vni: 11242
l3vni: 51000
rt_l2: 65000:11242
rt_l3: 65000:51000
racks: [leafpair1]
lb_vip: 10.10.10.10/32
vip_exports:
  - vrf: VRF-STORAGE
    prefix: 10.42.200.42/32
```

Expected policy output:

```bash
opa test policy
# all tests pass; conftest test intent/ --combine surfaces zero denies
```

### How this maps to Nexus

| Intent key                   | NX-OS construct                     |
|------------------------------|-------------------------------------|
| `l2vni`/`l3vni`              | `interface nve` VNI and `vlan vni`   |
| `rt_import`/`rt_export`      | BGP EVPN `route-target import/export`|
| `vip_exports`                | Route-map on tenant VRF leak        |
| `racks` (leaf-pairs)         | `interface nve` `member vni` scope   |
| `allowed_vip_exports`/allowlist | Conftest/OPA guardrails before NX-OS |
