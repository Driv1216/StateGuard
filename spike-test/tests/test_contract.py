from pathlib import Path

from state_guard_spike.contract import ROOT, load_contract


def test_contract_is_sealed_and_exact() -> None:
    contract = load_contract()
    assert contract["fixtures"] == {
        "families": 6, "per_family": 3, "total": 18, "correct": 6, "defective": 12
    }
    assert len(contract["role_taxonomy"]) == 1
    assert len(contract["scenarios"]) == 3
    assert len(contract["invariants"]) == 3
    assert len(contract["pass_conditions"]) == 10
    assert contract["ai_mapper"]["model"] == "gemini-3.6-flash"
    assert contract["ai_mapper"]["temperature"] == 0
    assert contract["ai_mapper"]["fallback"] is None


def test_pre_evaluation_stop_artifacts_are_absent() -> None:
    assert not (ROOT / "artifacts" / "evaluation_approval.json").exists()
    assert not (ROOT / "artifacts" / "evaluation").exists()

