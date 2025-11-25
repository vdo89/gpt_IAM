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
