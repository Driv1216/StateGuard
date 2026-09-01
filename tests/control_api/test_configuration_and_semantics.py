from __future__ import annotations

import http.client
import json
from collections.abc import Callable
from pathlib import Path

from stateguard.application.control import StateGuardControl
from stateguard.control_api.server import ControlHTTPServer
from stateguard.workspace.config import load_config

from .conftest import make_repository


def _json_request(
    server: ControlHTTPServer,
    method: str,
    path: str,
    payload: dict[str, object],
) -> tuple[int, dict[str, object]]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    connection = http.client.HTTPConnection("127.0.0.1", server.listener_port, timeout=5)
    connection.request(
        method,
        path,
        body=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    response = connection.getresponse()
    result = json.loads(response.read())
    status = response.status
    connection.close()
    return status, result


def test_ai_and_runtime_configuration_use_bounded_facade_contracts(
    tmp_path: Path,
    server_factory: Callable[[StateGuardControl, float], ControlHTTPServer],
) -> None:
    repository, config_path = make_repository(tmp_path)
    server = server_factory(StateGuardControl(repository), 1.0)

    status, setup = _json_request(
        server,
        "PUT",
        "/api/v1/config/ai",
        {
            "provider": "openai-compatible",
            "model": "bounded-model",
            "api_key_env": "MODEL_PROVIDER_KEY",
            "base_url": "https://models.example/v1",
        },
    )
    assert status == 200
    assert setup["ai_api_key_env"] == "MODEL_PROVIDER_KEY"
    assert "api_key" not in setup
    loaded = load_config(config_path)
    assert loaded.ai is not None and loaded.ai.api_key_env == "MODEL_PROVIDER_KEY"

    before = config_path.read_bytes()
    status, error = _json_request(
        server,
        "PUT",
        "/api/v1/config/ai",
        {
            "provider": "gemini",
            "model": "bounded-model",
            "api_key_env": "MODEL_PROVIDER_KEY",
            "api_key": "literal-secret-sentinel",
        },
    )
    assert status == 422
    assert error["code"] == "REQUEST_SCHEMA_INVALID"
    assert "literal-secret-sentinel" not in json.dumps(error)
    assert config_path.read_bytes() == before

    status, setup = _json_request(
        server,
        "PUT",
        "/api/v1/config/runtime",
        {"mode": "managed", "env_from_host": {"CHILD_SECRET": "HOST_SECRET_NAME"}},
    )
    assert status == 200
    assert setup["runtime"]["mode"] == "managed"
    assert setup["runtime"]["environment_bindings"] == [
        {
            "schema_version": 1,
            "child_name": "CHILD_SECRET",
            "host_name": "HOST_SECRET_NAME",
        }
    ]
    assert "AVAILABLE" not in json.dumps(setup)


def test_semantic_and_policy_mutations_delegate_to_existing_authority(
    tmp_path: Path,
    server_factory: Callable[[StateGuardControl, float], ControlHTTPServer],
) -> None:
    repository, _ = make_repository(tmp_path, "semantic_app")
    server = server_factory(StateGuardControl(repository), 2.0)

    status, semantic = _json_request(
        server,
        "POST",
        "/api/v1/semantics/resolve",
        {},
    )
    assert status == 200
    assert semantic["artifact"]["resolution"] is None
    symbol = semantic["artifact"]["context"]["presented_symbol_ids"][0]

    status, confirmed = _json_request(
        server,
        "POST",
        "/api/v1/semantics/confirm",
        {"symbol_id": symbol},
    )
    assert status == 200
    assert confirmed["artifact"]["resolution"]["state"] == "UNIQUE"
    assert confirmed["artifact"]["resolution"]["selected_symbol_id"] == symbol

    status, applicability = _json_request(
        server,
        "POST",
        "/api/v1/policy/confirm",
        {"fulfilment": "CAPTURE_REQUIRED"},
    )
    assert status == 200
    assert applicability["policy"]["fulfilment"]["confirmed_policy"] == "CAPTURE_REQUIRED"

    status, error = _json_request(server, "POST", "/api/v1/policy/confirm", {})
    assert status == 422
    assert error["code"] == "REQUEST_SCHEMA_INVALID"
