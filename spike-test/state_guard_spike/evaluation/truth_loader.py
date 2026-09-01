from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
ROLE_TRUTH_PATH = ROOT / "evaluation_only" / "role_ground_truth.json"
MUTATION_TRUTH_PATH = ROOT / "evaluation_only" / "mutation_ground_truth.json"


def load_role_truth() -> dict[str, dict[str, Any]]:
    return json.loads(ROLE_TRUTH_PATH.read_text(encoding="utf-8"))


def load_mutation_truth() -> dict[str, str]:
    return json.loads(MUTATION_TRUTH_PATH.read_text(encoding="utf-8"))


def state_snapshot(state_module: ModuleType) -> dict[str, Any]:
    snapshot: dict[str, Any] = {}
    for name, value in vars(state_module).items():
        if name.startswith("_") or not isinstance(value, (dict, set, list)):
            continue
        snapshot[name] = sorted(value) if isinstance(value, set) else value.copy()
    return snapshot


def _business_value_present(family_id: str, snapshot: dict[str, Any]) -> bool:
    collection_by_family = {
        "ecommerce": "shipments",
        "saas": "subscriptions",
        "course": "course_access",
        "ticketing": "admission_passes",
        "workspace": "workspace_entitlements",
        "licensing": "license_seats",
    }
    collection = snapshot.get(collection_by_family[family_id], {})
    return bool(collection)

