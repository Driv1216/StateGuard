from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "experiment_contract.json"
CONTRACT_HASH_PATH = ROOT / "contract.sha256"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return sha256_text(canonical_json(value))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_python_tree(path: Path) -> str:
    return sha256_json({
        item.relative_to(path).as_posix(): sha256_file(item)
        for item in sorted(path.rglob("*.py"))
    })


def load_contract(path: Path = CONTRACT_PATH, verify_seal: bool = True) -> dict[str, Any]:
    contract = json.loads(path.read_text(encoding="utf-8"))
    validate_contract(contract)
    if verify_seal:
        expected = CONTRACT_HASH_PATH.read_text(encoding="utf-8").strip()
        actual = sha256_json(contract)
        if expected != actual:
            raise ValueError(f"contract seal mismatch: expected {expected}, got {actual}")
    return contract


def validate_contract(contract: dict[str, Any]) -> None:
    required = {
        "schema_version", "experiment", "benchmarks", "role_taxonomy", "fixtures",
        "mutations", "scenarios", "invariants", "baseline", "ai_mapper",
        "mapping_resolution", "metrics", "pass_conditions", "truth_commitments",
        "dependencies",
    }
    missing = required - set(contract)
    extra = set(contract) - required
    if missing or extra:
        raise ValueError(f"contract keys invalid; missing={sorted(missing)}, extra={sorted(extra)}")
    families = contract["benchmarks"]
    if [item["id"] for item in families] != [
        "ecommerce", "saas", "course", "ticketing", "workspace", "licensing"
    ]:
        raise ValueError("benchmark families are not frozen in the approved order")
    if len(contract["pass_conditions"]) != 10:
        raise ValueError("exactly ten pass conditions are required")
    if contract["fixtures"]["total"] != 18 or contract["fixtures"]["per_family"] != 3:
        raise ValueError("fixture counts must remain 6 x 3 = 18")
    if contract["ai_mapper"]["model"] != "gemini-3.6-flash":
        raise ValueError("the frozen Gemini model changed")
    if contract["ai_mapper"]["max_transport_retries"] != 2:
        raise ValueError("transport retry limit changed")
    for family in families:
        root = ROOT / "benchmarks" / family["id"]
        if sha256_python_tree(root / "family_source") != family["family_source_sha256"]:
            raise ValueError(f"family source hash changed: {family['id']}")
        for fixture_id, expected in family["fixtures"].items():
            if sha256_python_tree(root / "variants" / fixture_id) != expected:
                raise ValueError(f"fixture source hash changed: {family['id']}/{fixture_id}")
    truth = contract["truth_commitments"]
    if sha256_file(ROOT / "evaluation_only" / "role_ground_truth.json") != truth["role_ground_truth_sha256"]:
        raise ValueError("role ground-truth commitment changed")
    if sha256_file(ROOT / "evaluation_only" / "mutation_ground_truth.json") != truth["mutation_ground_truth_sha256"]:
        raise ValueError("mutation ground-truth commitment changed")
    baseline = contract["baseline"]
    if sha256_file(ROOT / "state_guard_spike" / "mappers" / "baseline.py") != baseline["implementation_sha256"]:
        raise ValueError("baseline implementation changed")
    for name, expected in baseline["calibration_fixtures"].items():
        if sha256_python_tree(ROOT / "tests" / "calibration_fixtures" / name) != expected:
            raise ValueError(f"calibration fixture changed: {name}")
    ai = contract["ai_mapper"]
    if sha256_file(ROOT / "state_guard_spike" / "mappers" / "prompt.py") != ai["prompt_implementation_sha256"]:
        raise ValueError("AI prompt implementation changed")
    if sha256_file(ROOT / "state_guard_spike" / "schemas.py") != ai["schema_implementation_sha256"]:
        raise ValueError("mapper schema implementation changed")
