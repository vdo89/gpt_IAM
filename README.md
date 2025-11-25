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
1. **Lint**: installs Ansible + linting tools, runs `yamllint` and `ansible-lint`, and optionally executes `conftest` when a `policy/` directory is present.
2. **Render**: runs `ansible-playbook ... --check --diff` twice to prove idempotence and uploads the logs as artifacts.
3. **Validate intent**: lightweight schema validation for `intent/vrfs.yml`, with a JSON summary uploaded as an artifact.
4. **Deploy**: manual-only (`workflow_dispatch`) run of the playbook to produce a deployment log artifact.

## Local quickstart
The repository uses local Ansible connections to avoid network dependencies while developing. A representative workflow is:

```bash
python -m pip install ansible yamllint ansible-lint pyyaml jinja2
ansible-lint ansible/site.yml
yamllint .
ansible-playbook -i ansible/inventory.yml ansible/site.yml --check --diff
```

If you prefer policy checks, add `policy/` with Conftest Rego rules and run `conftest test intent/`.
