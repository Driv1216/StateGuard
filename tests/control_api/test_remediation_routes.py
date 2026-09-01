from __future__ import annotations

import http.client
import json
from collections.abc import Callable
from pathlib import Path

from stateguard.application.control import StateGuardControl
from stateguard.control_api.contracts import HealthV1
from stateguard.control_api.server import ControlHTTPServer

from .conftest import make_repository

RUN_ID = "sgvrun_" + "1" * 32
OCCURRENCE_ID = "sgfinding_" + "2" * 32


def _request(
    server: ControlHTTPServer,
    method: str,
    path: str,
    body: bytes | None = None,
) -> tuple[int, dict[str, object], str | None]:
    connection = http.client.HTTPConnection("127.0.0.1", server.listener_port, timeout=3)
    headers = {}
    if body is not None:
        headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    payload = json.loads(response.read())
    status = response.status
    allow = response.getheader("Allow")
    connection.close()
    return status, payload, allow


def test_finding_actions_are_exact_empty_body_post_routes(
    tmp_path: Path,
    monkeypatch,
    server_factory: Callable[[StateGuardControl, float], ControlHTTPServer],
) -> None:
    repository, _ = make_repository(tmp_path)
    control = StateGuardControl(repository)
    calls: list[tuple[str, str, str]] = []

    async def assistance(run_id: str, occurrence_id: str):
        calls.append(("assistance", run_id, occurrence_id))
        return HealthV1(producer_version="test")

    def reverify(run_id: str, occurrence_id: str):
        calls.append(("reverify", run_id, occurrence_id))
        return HealthV1(producer_version="test")

    monkeypatch.setattr(control, "remediation_assistance", assistance)
    monkeypatch.setattr(control, "reverify_finding", reverify)
    server = server_factory(control, 1.0)
    base = f"/api/v1/runs/{RUN_ID}/findings/{OCCURRENCE_ID}"

    status, payload, _ = _request(server, "POST", f"{base}/assistance", b"{}")
    assert status == 200
    assert payload["status"] == "OK"
    status, payload, _ = _request(server, "POST", f"{base}/reverify", b"{}")
    assert status == 201
    assert payload["status"] == "OK"
    assert calls == [
        ("assistance", RUN_ID, OCCURRENCE_ID),
        ("reverify", RUN_ID, OCCURRENCE_ID),
    ]

    status, error, _ = _request(server, "POST", f"{base}/assistance", b'{"unexpected":true}')
    assert status == 422
    assert error["code"] == "REQUEST_SCHEMA_INVALID"
    status, error, allow = _request(server, "GET", f"{base}/assistance")
    assert status == 405
    assert error["code"] == "METHOD_NOT_ALLOWED"
    assert allow == "POST"
