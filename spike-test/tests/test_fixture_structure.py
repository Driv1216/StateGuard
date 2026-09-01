from pathlib import Path

from state_guard_spike.contract import ROOT, sha256_json
from state_guard_spike.evaluation.compliance_audit import run_structural_validation


def _tree_hash(root: Path) -> str:
    return sha256_json({
        path.relative_to(root).as_posix(): __import__("hashlib").sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*.py"))
    })


def test_exact_fixture_inventory_and_canonical_copy(contract_data: dict) -> None:
    families = [item["id"] for item in contract_data["benchmarks"]]
    assert families == ["ecommerce", "saas", "course", "ticketing", "workspace", "licensing"]
    for family in families:
        family_root = ROOT / "benchmarks" / family
        fixtures = sorted(path.name for path in (family_root / "variants").iterdir())
        assert fixtures == ["fixture_01", "fixture_02", "fixture_03"]
        assert _tree_hash(family_root / "family_source") == _tree_hash(family_root / "variants" / "fixture_01")


def test_non_obvious_families_have_structural_non_oracle(contract_data: dict) -> None:
    result = run_structural_validation(contract_data)
    for family in ("ticketing", "workspace", "licensing"):
        row = result["families"][family]
        assert row["hard_distractor_count"] >= 3
        assert row["structural_parity"] is True
        assert row["baseline_resolution"] == "AMBIGUOUS"
        assert row["predicate_oracles_absent"] is True
    assert all(result["calibration_isolation"].values())

