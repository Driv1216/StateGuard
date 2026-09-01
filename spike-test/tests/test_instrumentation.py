from state_guard_spike.contract import ROOT
from state_guard_spike.runtime.chaos_runner import run_scenario_subprocess
from state_guard_spike.schemas import MapperKind


def test_single_symbol_instrumentation_preserves_call_order(scenarios: dict) -> None:
    observation = run_scenario_subprocess(
        ROOT / "benchmarks" / "ecommerce" / "variants" / "fixture_02",
        "ecommerce", "fixture_02", "app.domain.ship_order", scenarios["S2"],
        MapperKind.STATIC_BASELINE, "mapping", "contract",
    )
    assert [call.sequence for call in observation.calls] == [1, 2]
    assert {call.symbol for call in observation.calls} == {"app.domain.ship_order"}

