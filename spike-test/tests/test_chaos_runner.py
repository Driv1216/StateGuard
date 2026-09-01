from state_guard_spike.contract import ROOT, sha256_json
from state_guard_spike.runtime.chaos_runner import run_scenario_subprocess
from state_guard_spike.schemas import MapperKind


def test_scenario_hash_is_mapper_independent(scenarios: dict) -> None:
    args = (
        ROOT / "benchmarks" / "ecommerce" / "variants" / "fixture_01",
        "ecommerce", "fixture_01", "app.domain.ship_order", scenarios["S1"],
    )
    baseline = run_scenario_subprocess(*args, MapperKind.STATIC_BASELINE, "baseline", "contract")
    ai = run_scenario_subprocess(*args, MapperKind.GEMINI, "ai", "contract")
    assert baseline.scenario_hash == ai.scenario_hash == sha256_json(scenarios["S1"])
    assert baseline.observed_count == ai.observed_count == 1

