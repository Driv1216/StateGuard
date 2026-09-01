from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from ..contract import sha256_json
from ..schemas import MapperKind, RuntimeObservation, Scenario
from .instrumentation import instrument_symbol


def run_scenario_subprocess(
    fixture_root: Path,
    family_id: str,
    fixture_id: str,
    selected_symbol: str,
    scenario: Scenario,
    mapper_kind: MapperKind,
    mapping_hash: str,
    contract_hash: str,
) -> RuntimeObservation:
    payload = {
        "fixture_root": str(fixture_root.resolve()),
        "family_id": family_id,
        "fixture_id": fixture_id,
        "selected_symbol": selected_symbol,
        "scenario": scenario.model_dump(mode="json"),
        "mapper_kind": mapper_kind.value,
        "mapping_hash": mapping_hash,
        "contract_hash": contract_hash,
    }
    process = subprocess.run(
        [sys.executable, "-m", "state_guard_spike.runtime.chaos_runner", "--worker"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(f"scenario worker failed with exit code {process.returncode}: {process.stderr.strip()}")
    return RuntimeObservation.model_validate_json(process.stdout)


def _worker(payload: dict[str, Any]) -> RuntimeObservation:
    fixture_root = Path(payload["fixture_root"])
    sys.path.insert(0, str(fixture_root))
    from app import main, state

    state.reset_state()
    scenario = Scenario.model_validate(payload["scenario"])
    calls = []
    with instrument_symbol(payload["selected_symbol"], calls):
        with TestClient(main.app) as client:
            for event in scenario.events:
                response = client.post("/webhooks", json=event.model_dump(mode="json"))
                response.raise_for_status()
    source_hash = sha256_json({
        path.relative_to(fixture_root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(fixture_root.rglob("*.py"))
    })
    return RuntimeObservation(
        mapper_kind=MapperKind(payload["mapper_kind"]),
        mapping_hash=payload["mapping_hash"],
        family_id=payload["family_id"],
        fixture_id=payload["fixture_id"],
        selected_symbol=payload["selected_symbol"],
        scenario_id=scenario.id,
        scenario_hash=sha256_json(scenario),
        fixture_source_hash=source_hash,
        contract_hash=payload["contract_hash"],
        input_events=[{"id": event.id, "type": event.type} for event in scenario.events],
        calls=calls,
        observed_count=len(calls),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args()
    if not args.worker:
        parser.error("only internal --worker mode is supported")
    payload = json.loads(sys.stdin.read())
    print(_worker(payload).model_dump_json())


if __name__ == "__main__":
    main()

