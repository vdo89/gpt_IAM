from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import yaml

INTENT_DIR = Path("intent")
BUILD_DIR = Path("build")


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text()) or {}


def load_vrfs(vrf_path: Path | None = None) -> List[Dict[str, Any]]:
    vrf_path = vrf_path or INTENT_DIR / "vrfs.yml"
    document = load_yaml(vrf_path)
    vrfs = document.get("vrfs", []) if isinstance(document, dict) else []
    if not isinstance(vrfs, list):
        raise TypeError(f"VRF document must contain a vrfs list in {vrf_path}")
    return vrfs


def load_tenants(tenant_dir: Path | None = None) -> List[Dict[str, Any]]:
    tenant_dir = tenant_dir or INTENT_DIR / "tenants"
    tenants: List[Dict[str, Any]] = []
    for tenant_file in sorted(tenant_dir.glob("*.yml")):
        document = load_yaml(tenant_file)
        if not isinstance(document, dict):
            raise TypeError(f"Tenant document {tenant_file} is not a mapping")
        tenants.append(document)
    return tenants


def write_combined(
    vrfs: List[Dict[str, Any]], tenants: List[Dict[str, Any]], output: Path | None = None
) -> Path:
    output = output or BUILD_DIR / "combined.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps({"vrfs": vrfs, "tenants": tenants}, indent=2))
    return output


def main() -> None:
    combined_path = write_combined(load_vrfs(), load_tenants())
    print(f"Wrote combined intent to {combined_path}")


if __name__ == "__main__":
    main()
