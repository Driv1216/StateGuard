from __future__ import annotations

import asyncio
import http.client
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from stateguard.application.control import StateGuardControl
from stateguard.contracts.identity import new_project_id
from stateguard.control_api.server import ControlHTTPServer
from stateguard.workspace.semantic_artifacts import semantic_artifact_path

from .conftest import make_repository


def _request(
    server: ControlHTTPServer,
    path: str,
    *,
    method: str = "GET",
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", server.listener_port, timeout=5)
    connection.request(method, path)
    response = connection.getresponse()
    payload = response.read()
    headers = {key.casefold(): value for key, value in response.getheaders()}
    status = response.status
    connection.close()
    return status, headers, payload


def test_passive_semantic_snapshot_is_persistence_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = make_repository(tmp_path, "semantic_app")
    control = StateGuardControl(repository)
    empty = control.semantic_snapshot()
    assert not empty.recorded
    assert empty.source_currentness == "NOT_CHECKED"

    resolved = asyncio.run(control.resolve_semantics())
    symbol_id = resolved.selection_options[0].symbol_id
    asyncio.run(control.confirm_semantics(symbol_id))
    artifact_path = semantic_artifact_path(repository)
    before = artifact_path.read_bytes()
    before_stat = artifact_path.stat()

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("passive snapshot attempted fresh analysis")

    monkeypatch.setattr("stateguard.application.control.inspect_applicability", forbidden)
    monkeypatch.setattr("stateguard.application.control.resolve_customer_value", forbidden)
    snapshot = control.semantic_snapshot()

    assert snapshot.recorded
    assert snapshot.source_currentness == "NOT_CHECKED"
    assert snapshot.selected_symbol_id == symbol_id
    assert snapshot.basis == "MANUAL_SELECTION"
    assert snapshot.presented_symbol_ids
    serialized = snapshot.model_dump_json()
    assert "qualified_name" not in serialized
    assert "source_location" not in serialized
    assert "source_excerpts" not in serialized
    assert artifact_path.read_bytes() == before
    assert artifact_path.stat().st_mtime_ns == before_stat.st_mtime_ns


def test_semantic_snapshot_http_is_empty_safe_and_rejects_cross_project(
    tmp_path: Path,
    server_factory: Callable[[StateGuardControl, float], ControlHTTPServer],
) -> None:
    repository, config = make_repository(tmp_path, "semantic_app")
    control = StateGuardControl(repository)
    server = server_factory(control, 2.0)

    status, headers, body = _request(server, "/api/v1/semantics")
    assert status == 200
    assert headers["content-type"] == "application/json; charset=utf-8"
    assert json.loads(body) == {
        "schema_version": 1,
        "source_currentness": "NOT_CHECKED",
        "project_id": control.project_setup().project_id,
        "recorded": False,
        "recorded_at": None,
        "state": None,
        "basis": None,
        "selected_symbol_id": None,
        "semantic_context_fingerprint": None,
        "resolution_fingerprint": None,
        "bundle_completeness": None,
        "provider_id": None,
        "model": None,
        "provider_failure_code": None,
        "provider_failure_status_code": None,
        "presented_symbol_ids": [],
        "candidates": [],
        "human_basis": None,
        "human_acted_at": None,
    }

    asyncio.run(control.resolve_semantics())
    original_id = str(control.project_setup().project_id)
    config.write_text(
        config.read_text(encoding="utf-8").replace(original_id, str(new_project_id())),
        encoding="utf-8",
    )
    status, _, body = _request(server, "/api/v1/semantics")
    assert status == 409
    assert json.loads(body)["code"] == "SEMANTIC_ARTIFACT_INVALID"


def test_dashboard_exact_routes_assets_and_strict_headers(
    tmp_path: Path,
    server_factory: Callable[[StateGuardControl, float], ControlHTTPServer],
) -> None:
    repository, _ = make_repository(tmp_path)
    server = server_factory(StateGuardControl(repository), 1.0)

    pages: list[bytes] = []
    for route in ("/", "/graph", "/failure-lab", "/findings", "/setup"):
        status, headers, body = _request(server, route)
        assert status == 200
        assert headers["content-type"] == "text/html; charset=utf-8"
        assert headers["cache-control"] == "no-cache"
        assert "script-src 'self'" in headers["content-security-policy"]
        assert "style-src 'self'" in headers["content-security-policy"]
        assert "unsafe-inline" not in headers["content-security-policy"]
        assert headers["x-content-type-options"] == "nosniff"
        pages.append(body)
    assert len(set(pages)) == 1

    static = Path(__file__).resolve().parents[2] / "src/stateguard/dashboard/static/assets"
    for asset in static.iterdir():
        status, headers, body = _request(server, f"/assets/{asset.name}")
        assert status == 200
        assert body == asset.read_bytes()
        assert headers["cache-control"] == "public, max-age=31536000, immutable"
        assert headers["content-type"] in {
            "text/css; charset=utf-8",
            "text/javascript; charset=utf-8",
        }

    for target in ("/history", "/assets/../index.html", "/assets/missing.js"):
        status, headers, body = _request(server, target)
        assert status in {400, 404}
        assert headers["content-type"] == "application/json; charset=utf-8"
        assert json.loads(body)["code"] in {"INVALID_REQUEST", "ROUTE_NOT_FOUND"}

    status, headers, body = _request(server, "/graph", method="POST")
    assert status == 405
    assert headers["allow"] == "GET"
    assert json.loads(body)["code"] == "METHOD_NOT_ALLOWED"
