from state_guard_spike.runtime.invariants import evaluate_invariant
from state_guard_spike.schemas import MapperKind, RuntimeObservation


def observation(scenario: str, count: int) -> RuntimeObservation:
    return RuntimeObservation(
        mapper_kind=MapperKind.STATIC_BASELINE, mapping_hash="m", family_id="f",
        fixture_id="v", selected_symbol="app.domain.action", scenario_id=scenario,
        scenario_hash="s", fixture_source_hash="f", contract_hash="c",
        input_events=[], calls=[], observed_count=count,
    )


def test_exact_invariant_boundaries() -> None:
    assert evaluate_invariant(observation("S1", 1)).result == "PASS"
    assert evaluate_invariant(observation("S1", 0)).result == "FAIL"
    assert evaluate_invariant(observation("S2", 1)).result == "PASS"
    assert evaluate_invariant(observation("S2", 2)).result == "FAIL"
    assert evaluate_invariant(observation("S3", 0)).result == "PASS"
    assert evaluate_invariant(observation("S3", 1)).result == "FAIL"

