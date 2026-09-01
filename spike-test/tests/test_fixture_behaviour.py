from __future__ import annotations

import importlib
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from state_guard_spike.contract import ROOT
from state_guard_spike.evaluation.truth_loader import _business_value_present, load_role_truth, state_snapshot
from state_guard_spike.runtime.chaos_runner import run_scenario_subprocess
from state_guard_spike.schemas import MapperKind


@contextmanager
def imported_fixture(root: Path):
    sys.path.insert(0, str(root))
    try:
        domain = importlib.import_module("app.domain")
        state = importlib.import_module("app.state")
        yield domain, state
    finally:
        sys.path.remove(str(root))
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                del sys.modules[name]


@pytest.mark.parametrize("family", ["ecommerce", "saas", "course", "ticketing", "workspace", "licensing"])
def test_seeded_fixture_behaviour(family: str, scenarios: dict) -> None:
    symbol = load_role_truth()[family]["role_symbol"]
    expected = {
        ("fixture_01", "S1"): 1,
        ("fixture_01", "S2"): 1,
        ("fixture_01", "S3"): 0,
        ("fixture_02", "S2"): 2,
        ("fixture_03", "S3"): 1,
    }
    for (fixture, scenario_id), count in expected.items():
        observation = run_scenario_subprocess(
            ROOT / "benchmarks" / family / "variants" / fixture,
            family, fixture, symbol, scenarios[scenario_id], MapperKind.STATIC_BASELINE,
            "fixture-validation", "contract-validation",
        )
        assert observation.observed_count == count


@pytest.mark.parametrize("family", ["ticketing", "workspace", "licensing"])
def test_only_true_role_delivers_business_value(family: str, payment_payload: dict) -> None:
    truth = load_role_truth()[family]
    root = ROOT / "benchmarks" / family / "family_source"
    with imported_fixture(root) as (domain, state):
        for symbol in truth["hard_structural_distractors"]:
            state.reset_state()
            getattr(domain, symbol.rsplit(".", 1)[-1])(dict(payment_payload))
            assert _business_value_present(family, state_snapshot(state)) is False
        state.reset_state()
        getattr(domain, truth["role_symbol"].rsplit(".", 1)[-1])(dict(payment_payload))
        assert _business_value_present(family, state_snapshot(state)) is True

