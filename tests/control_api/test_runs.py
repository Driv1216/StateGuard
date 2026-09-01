from __future__ import annotations

import asyncio
import http.client
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from stateguard.application.applicability import confirm_merchant_policy
from stateguard.application.control import StateGuardControl
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.contracts.config import FulfilmentPolicy, LateAuthorisationPolicy
from stateguard.control_api.server import ControlHTTPServer

from .conftest import make_repository

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def _request(
    server: ControlHTTPServer,
    method: str,
    path: str,
    body: bytes | None = None,
    *,
    timeout: float = 120,
) -> tuple[int, dict[str, object]]:
    connection = http.client.HTTPConnection("127.0.0.1", server.listener_port, timeout=timeout)
    headers = {}
    if body is not None:
        headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    payload = json.loads(response.read())
    status = response.status
    connection.close()
    return status, payload


def _confirm_authority(repository: Path, config: Path) -> None:
    unresolved = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    symbol = next(
        item.symbol_id
        for item in unresolved.source_index.symbols
        if item.qualified_name == "domain.grant_ticket"
    )
    asyncio.run(confirm_customer_value(repository, config, symbol, generated_at=NOW))
    confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        late_authorisation=LateAuthorisationPolicy.FULFIL_LATER,
        generated_at=NOW,
    )


def _managed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "SG_TEST_WEBHOOK_SECRET": "http-step8-webhook-secret",
        "SG_TEST_CHECKOUT_SECRET": "http-step8-checkout-secret",
        "SG_TEST_SERVER_ORDER": "http-step8-server-order",
        "WEBHOOK_CAPTURE_BEHAVIOR_HOST": "once",
        "SG03_BEHAVIOR_HOST": "initial_multiple",
        "SG04_CUSTOMER_BEHAVIOR_HOST": "safe",
        "SG04_STATE_BEHAVIOR_HOST": "safe",
        "SG06_BEHAVIOR_HOST": "safe",
        "SG08_AUTHORIZED_BEHAVIOR_HOST": "zero",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_verified_failure_creation_and_validated_history_endpoints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    server_factory: Callable[[StateGuardControl, float], ControlHTTPServer],
) -> None:
    repository, config = make_repository(tmp_path, "failure_lab_batch_a", runtime="managed")
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "runtime:\n  mode: managed\n",
            """runtime:
  mode: managed
  env_from_host:
    STATEGUARD_TEST_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET
    MERCHANT_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET
    STATEGUARD_TEST_RAZORPAY_KEY_SECRET: SG_TEST_CHECKOUT_SECRET
    MERCHANT_CHECKOUT_SECRET: SG_TEST_CHECKOUT_SECRET
    STATEGUARD_TEST_SERVER_ORDER_ID: SG_TEST_SERVER_ORDER
    MERCHANT_SERVER_ORDER_ID: SG_TEST_SERVER_ORDER
    WEBHOOK_CAPTURE_BEHAVIOR: WEBHOOK_CAPTURE_BEHAVIOR_HOST
    SG03_BEHAVIOR: SG03_BEHAVIOR_HOST
    SG04_CUSTOMER_BEHAVIOR: SG04_CUSTOMER_BEHAVIOR_HOST
    SG04_STATE_BEHAVIOR: SG04_STATE_BEHAVIOR_HOST
    SG06_BEHAVIOR: SG06_BEHAVIOR_HOST
    SG08_AUTHORIZED_BEHAVIOR: SG08_AUTHORIZED_BEHAVIOR_HOST
""",
        ),
        encoding="utf-8",
    )
    _confirm_authority(repository, config)
    _managed_environment(monkeypatch)
    server = server_factory(StateGuardControl(repository), 2.0)

    status, run = _request(server, "POST", "/api/v1/runs", b"{}")
    assert status == 201
    assert run["status"] == "COMPLETED"
    assert run["summary"]["verified_fail"] >= 1
    run_id = str(run["run_id"])

    status, listed = _request(server, "GET", "/api/v1/runs")
    assert status == 200
    assert listed["runs"][0]["run_id"] == run_id
    assert listed["runs"][0]["summary"] == run["summary"]

    status, latest = _request(server, "GET", "/api/v1/runs/latest")
    assert status == 200
    assert latest["run_id"] == run_id
    assert "runtime_evidence" not in json.dumps(latest)

    status, full = _request(server, "GET", f"/api/v1/runs/{run_id}")
    assert status == 200
    assert full == run

    status, report = _request(server, "GET", f"/api/v1/runs/{run_id}/report")
    assert status == 200
    assert report == latest

    path = repository / ".stateguard" / "runs" / run_id / "run.json"
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["summary"]["verified_fail"] += 1
    path.write_text(json.dumps(tampered), encoding="utf-8")
    status, error = _request(server, "GET", f"/api/v1/runs/{run_id}")
    assert status == 409
    assert error["code"] == "RUN_ARTIFACT_INVALID"
    assert str(repository.resolve()) not in json.dumps(error)
