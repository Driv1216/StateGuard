from state_guard_spike.evaluation.compliance_audit import run_structural_validation


def test_structural_validation_is_fully_compliant(contract_data: dict) -> None:
    result = run_structural_validation(contract_data)
    assert all(row["source_matches_fixture_01"] for row in result["families"].values())
    assert all(row["predicate_oracles_absent"] for row in result["families"].values())
    assert all(result["calibration_isolation"].values())

