from __future__ import annotations

import http.client
import json
from collections.abc import Callable
from pathlib import Path

from stateguard.application.control import StateGuardControl
from stateguard.control_api.server import ControlHTTPServer

from .conftest import make_repository


def _request(
    server: ControlHTTPServer,
    method: str,
    path: str,
    body: bytes | None = None,
) -> tuple[int, dict[str, object]]:
    connection = http.client.HTTPConnection("127.0.0.1", server.listener_port, timeout=3)
    headers = {}
    if body is not None:
        headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    payload = json.loads(response.read())
    status = response.status
    connection.close()
    return status, payload


def test_core_read_and_action_endpoints_use_typed_facade_results(
    tmp_path: Path,
    server_factory: Callable[[StateGuardControl, float], ControlHTTPServer],
) -> None:
    repository, _ = make_repository(tmp_path)
    control = StateGuardControl(repository)
    server = server_factory(control, 1.0)

    status, health = _request(server, "GET", "/api/v1/health")
    assert status == 200
    assert health == {
        "schema_version": 1,
        "api_version": "v1",
        "status": "OK",
        "producer_version": "0.1.0",
    }

    status, project = _request(server, "GET", "/api/v1/project")
    assert status == 200
    assert project["project_id"] == control.project_setup().project_id

    status, analysis = _request(server, "POST", "/api/v1/analysis", b"{}")
    assert status == 200
    assert analysis["graph_fingerprint"] == control.current_graph().graph_fingerprint
    assert "source_index" not in analysis
    assert not (repository / ".stateguard" / "applicability.json").exists()

    status, graph = _request(server, "GET", "/api/v1/graph")
    assert status == 200
    assert graph["artifact_type"] == "PAYMENT_SAFETY_GRAPH"

    status, applicability = _request(
        server,
        "POST",
        "/api/v1/applicability/analyze",
        b"{}",
    )
    assert status == 200
    assert applicability["artifact_type"] == "SCENARIO_APPLICABILITY"

    status, runtime = _request(server, "POST", "/api/v1/runtime/assess", b"{}")
    assert status == 200
    assert runtime["artifact_type"] == "RUNTIME_CAPABILITY"

    status, runs = _request(server, "GET", "/api/v1/runs")
    assert status == 200
    assert runs == {"schema_version": 1, "runs": []}


def test_empty_action_requests_are_exact_and_bounded(
    tmp_path: Path,
    server_factory: Callable[[StateGuardControl, float], ControlHTTPServer],
) -> None:
    repository, _ = make_repository(tmp_path)
    server = server_factory(StateGuardControl(repository), 1.0)

    assert _request(server, "POST", "/api/v1/analysis", b"{}")[0] == 200
    for invalid in (b'{"schema_version":1}', b'{"anything":true}', b"[]", b"null"):
        status, error = _request(server, "POST", "/api/v1/analysis", invalid)
        assert status == 422
        assert error["code"] == "REQUEST_SCHEMA_INVALID"

    boundary = b"{" + b" " * 65_534 + b"}"
    assert len(boundary) == 65_536
    assert _request(server, "POST", "/api/v1/analysis", boundary)[0] == 200


def test_unknown_transport_operation_errors_are_sanitized(
    tmp_path: Path,
    monkeypatch,
    server_factory: Callable[[StateGuardControl, float], ControlHTTPServer],
) -> None:
    repository, _ = make_repository(tmp_path)
    control = StateGuardControl(repository)

    def fail():
        raise RuntimeError(f"secret exception at {repository.resolve()}")

    monkeypatch.setattr(control, "analyze_project", fail)
    server = server_factory(control, 1.0)
    status, error = _request(server, "POST", "/api/v1/analysis", b"{}")
    serialized = json.dumps(error)
    assert status == 500
    assert error["code"] == "INTERNAL_ERROR"
    assert "secret exception" not in serialized
    assert str(repository.resolve()) not in serialized
