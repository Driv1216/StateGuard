from __future__ import annotations

import json
from pathlib import Path

import pytest

from state_guard_spike.schemas import Scenario


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def contract_data() -> dict:
    return json.loads((ROOT / "experiment_contract.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def scenarios(contract_data: dict) -> dict[str, Scenario]:
    return {item["id"]: Scenario.model_validate(item) for item in contract_data["scenarios"]}


@pytest.fixture(scope="session")
def payment_payload(contract_data: dict) -> dict:
    payment = dict(contract_data["scenarios"][0]["events"][0]["payment"])
    payment["event_id"] = contract_data["scenarios"][0]["events"][0]["id"]
    return payment

