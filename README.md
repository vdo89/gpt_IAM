# NetAuto EVPN/VXLAN Lab

This repository models a small EVPN/VXLAN fabric with separate inventory, intent, and automation layers. The focus is to keep intent data declarative while providing CI feedback that is closer to production expectations.

## Repository layout
- `ansible/`: playbook entry point (`site.yml`), inventory, and host/group variables.
- `templates/`: device templates (NX-OS focused).
- `intent/`: declarative tenant/fabric intent (for example, `intent/vrfs.yml`).
- `policy/`: Rego policies plus policy data (toggles and allowlists).
- `cml/`: Cisco Modeling Labs topology definition.
- `tests/`: placeholder for Batfish/pyATS/Nornir validation.

## GitHub Actions pipeline
Two workflows keep policy enforcement from turning into “policy theater”:

- `.github/workflows/ci.yml` continues to lint, render, and validate while also gating on **OPA coverage ≥90%** to avoid untested rules.
- `.github/workflows/policy.yml` runs on every PR touching intent, schemas, or Rego. It installs `ajv-cli` plus `conftest`/`opa`, validates YAML against JSON Schemas, executes `opa test --threshold 90`, and fails if policies or schemas drift.

The render job still performs two `ansible-playbook --check --diff` passes to prove idempotence and uploads the diffs. The intent validator produces a JSON summary (`artifacts/intent-validation.json`) suitable for PR review.

## Data flow
```mermaid
flowchart LR
  intent[intent/*.yml]
  schemas[JSON Schema (AJV)]
  rego[Rego policies\n(OPA + Conftest)]
  render[Ansible/Jinja2 NX-OS]
  nxos[NX-OS candidate config]

  intent --> schemas --> rego --> render --> nxos
```

## Policy toggles and strictness
`policy/data/policy.json` documents runtime toggles for the Rego package:

- `strict`: when true, tenant racks must be in `allowed_leafpairs` (prevents over-stretching the mobility domain).
- `l2vni_base`, `min_vlan`, `max_vlan`: guardrails that enforce the `l2vni = base + vlan` invariant and keep VLANs in-range.
- `allowed_export_vrfs`: only these VRFs may receive leaked VIP routes (others must stay in-tenant).

## Dual-stack host-only exports
Host-only VIPs are enforced in both schema and policy. Prefixes must be `/32` (IPv4) or `/128` (IPv6) in `vip_exports`, `lb_vip`, and `policy/data/allowed_exports.json`. Negative OPA tests cover `/31` and `/64` attempts so regressions fail fast.

## Nexus rendering
NX-OS templates live under `templates/nxos/` (see `templates/nxos/evpn_vrf.j2` for BGP/EVPN rendering). The `render` stage in CI produces diffable candidates from `ansible/roles/nxos-leaf/templates/nxos_leaf.j2`, so “Nexus mapping” is machine-readable instead of tribal knowledge.

### Golden path (TENANT-042)
TENANT-042 exports a host-only VIP via eBGP while STORAGE stays isolated. The intent produces the following NX-OS skeleton:

```text
router bgp 65000
  vrf TENANT-042
    rd 65000:51000
    address-family ipv4 unicast
      route-target import 65000:51000
      route-target export 65000:51000
!
evpn
  vni 51000 l3
vlan 242
  vn-segment 11242
```

## Local quickstart
The repository uses local Ansible connections to avoid network dependencies while developing. A representative workflow is:

```bash
python -m pip install --upgrade pip
pip install --requirement requirements-dev.txt
ansible-lint ansible/site.yml
yamllint .
python scripts/validate_intent.py
conftest test intent/ --policy policy --combine
opa test policy --coverage --threshold 90
ansible-playbook -i ansible/inventory.yml ansible/site.yml --check --diff
```

If you prefer policy checks, add `policy/` with Conftest Rego rules and run `conftest test intent/`.
