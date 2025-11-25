from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from jsonschema import Draft202012Validator

from scripts.combine_intent import load_tenants, load_vrfs, write_combined


def load_schema(path: Path) -> Dict[str, Any]:
    schema = json.loads(path.read_text())
    Draft202012Validator.check_schema(schema)
    return schema


def validate_document(document: Any, schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    validator = Draft202012Validator(schema)
    problems: List[Dict[str, Any]] = []
    for error in sorted(validator.iter_errors(document), key=lambda err: err.path):
        problems.append(
            {
                "path": list(error.path),
                "message": error.message,
                "validator": error.validator,
            }
        )
    return problems


def main() -> None:
    artifacts = Path("artifacts")
    artifacts.mkdir(exist_ok=True)

    vrf_schema = load_schema(Path("schemas/vrf.schema.json"))
    tenant_schema = load_schema(Path("schemas/tenant.schema.json"))

    vrfs = load_vrfs()
    tenants = load_tenants()

    vrf_doc = {"vrfs": vrfs}
    vrf_errors = validate_document(vrf_doc, vrf_schema)

    tenant_files = sorted(Path("intent/tenants").glob("*.yml"))
    tenant_summaries: List[Dict[str, Any]] = []
    tenant_errors: List[Dict[str, Any]] = []

    if len(tenant_files) != len(tenants):
        raise SystemExit(
            "Tenant file discovery does not match loaded tenant documents; "
            "verify intent/tenants/*.yml contents."
        )

    for tenant_file, document in zip(tenant_files, tenants):
        errors = validate_document(document, tenant_schema)
        tenant_summaries.append(
            {
                "file": tenant_file.as_posix(),
                "valid": not errors,
                "error_count": len(errors),
            }
        )
        tenant_errors.extend([{ "file": tenant_file.as_posix(), **err } for err in errors])

    combined_path = write_combined(vrfs, tenants)

    summary = {
        "vrfs": {
            "file": "intent/vrfs.yml",
            "valid": not vrf_errors,
            "error_count": len(vrf_errors),
        },
        "tenants": tenant_summaries,
        "combined_intent": combined_path.as_posix(),
        "errors": vrf_errors + tenant_errors,
    }

    summary_path = artifacts / "intent-validation.json"
    summary_path.write_text(json.dumps(summary, indent=2))

    if summary["errors"]:
        raise SystemExit(
            f"Intent schema validation failed with {len(summary['errors'])} issue(s). "
            f"See {summary_path} for details."
        )

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
