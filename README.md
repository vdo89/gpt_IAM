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
1. **Lint**: installs Ansible + linting tools, runs `yamllint` and `ansible-lint`, and executes `conftest` Rego policies in `policy/` to catch intent drift.
2. **Render**: runs `ansible-playbook ... --check --diff` twice to prove idempotence, renders device configs under `/etc/ansible/rendered`, and uploads both logs and rendered configs as artifacts.
3. **Validate intent**: JSON Schema validation for VRFs and tenants (`intent/schema/*.json`), with a JSON summary uploaded as an artifact.
4. **Deploy**: manual-only (`workflow_dispatch`) run of the playbook to produce a deployment log artifact.

## Local quickstart
The repository uses local Ansible connections to avoid network dependencies while developing. A representative workflow is:

```bash
python -m pip install ansible yamllint ansible-lint pyyaml jinja2
ansible-lint ansible/site.yml
yamllint .
ansible-playbook -i ansible/inventory.yml ansible/site.yml --check --diff
```

If you prefer policy checks, populate `policy/` with Conftest Rego rules (an example is included) and run `conftest test intent/`.
