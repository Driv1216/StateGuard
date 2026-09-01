from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from stateguard.contracts.common import ProvenanceKind, ProvenanceRecord, SourceLocation
from stateguard.contracts.config import StateGuardConfig
from stateguard.contracts.identity import (
    graph_edge_id,
    graph_node_id,
    new_project_id,
    sha256_digest,
    source_file_id,
    symbol_id,
)
from stateguard.workspace.config import ConfigLoadError, load_config


def _valid_yaml(project_id: str) -> str:
    return f"""\
schema_version: 2
project:
  id: {project_id}
  source_root: " ./merchant "
  framework: FASTAPI
  app_target: " app.main:app "
analysis:
  include: ["**/*.py"]
  exclude: [".venv/**"]
ai:
  provider: " OpenAI-Compatible "
  model: " example-model "
  api_key_env: EXAMPLE_API_KEY
  base_url: https://example.com/v1/
semantics:
  customer_value:
    symbol_id: sgsym_{"1" * 32}
    semantic_context_fingerprint: sha256:{"3" * 64}
    basis: HUMAN_CONFIRMED
"""


def test_immediate_identities_are_stable_and_narrow() -> None:
    project = new_project_id()
    file_id = source_file_id(project, "app/main.py")
    assert file_id == source_file_id(project, "app/./main.py")
    first_symbol = symbol_id(file_id, "app.main.webhook", "ASYNC_FUNCTION")
    assert first_symbol == symbol_id(file_id, "app.main.webhook", "ASYNC_FUNCTION")
    node = graph_node_id("PAYMENT_INGRESS", first_symbol)
    other = graph_node_id("TRUST_GATE", first_symbol)
    assert graph_edge_id("GUARDS", other, node) == graph_edge_id("GUARDS", other, node)
    assert project.startswith("sgproj_")


def test_source_location_and_provenance_are_explicit_and_immutable() -> None:
    location = SourceLocation(
        path="app/main.py", line_start=3, column_start=1, line_end=4, column_end=0
    )
    provenance = ProvenanceRecord(
        kind=ProvenanceKind.STATIC,
        reference="source-index:call-site",
        source_location=location,
        supporting_fingerprint=sha256_digest("evidence"),
    )
    with pytest.raises(ValidationError):
        provenance.reference = "changed"
    with pytest.raises(ValidationError):
        SourceLocation(path="../secret.py", line_start=1, column_start=0, line_end=1, column_end=1)
    with pytest.raises(ValidationError):
        SourceLocation(path="app/main.py", line_start=3, column_start=0, line_end=2, column_end=0)


def test_user_configuration_normalizes_without_persisted_artifact_rigidity(tmp_path: Path) -> None:
    path = tmp_path / "stateguard.yaml"
    path.write_text(_valid_yaml(new_project_id()), encoding="utf-8")
    config = load_config(path)
    assert config.project.source_root == "merchant"
    assert config.project.framework.value == "fastapi"
    assert config.project.app_target == "app.main:app"
    assert config.ai is not None
    assert config.ai.provider == "openai-compatible"
    assert config.ai.base_url == "https://example.com/v1"
    assert config.analysis.include == ("**/*.py",)
    assert config.analysis.exclude == (".venv/**",)
    with pytest.raises(AttributeError):
        config.analysis.include.append("../outside")  # type: ignore[attr-defined]
    round_trip = StateGuardConfig.model_validate(config.model_dump(mode="json"))
    assert round_trip.semantics == config.semantics


@pytest.mark.parametrize(
    "invalid_yaml",
    [
        "schema_version: 2\nschema_version: 2\nproject: {}\n",
        f"schema_version: 2\nproject:\n  id: sgproj_{'1' * 32}\n  source_root: ../outside\n",
        (
            f"schema_version: 2\nproject:\n  id: sgproj_{'1' * 32}\n"
            "ai:\n  provider: x\n  model: m\n  api_key_env: 9INVALID\n"
        ),
        (
            f"schema_version: 2\nproject:\n  id: sgproj_{'1' * 32}\n"
            "ai:\n  provider: x\n  model: m\n  api_key_env: KEY\n"
            "  base_url: https://user:pass@example.com\n"
        ),
        (
            f"schema_version: 2\nproject:\n  id: sgproj_{'1' * 32}\n"
            "ai:\n  provider: x\n  model: m\n  api_key_env: KEY\n"
            "  api_key: secret-value\n"
        ),
        f"schema_version: 1\nproject:\n  id: sgproj_{'1' * 32}\n",
        (
            f"schema_version: 2\nproject:\n  id: sgproj_{'1' * 32}\n"
            "ai:\n  provider: x\n  model: m\n  api_key_env: KEY\n"
            '  base_url: "https://example.com/v1?api_key=secret"\n'
        ),
        (
            f"schema_version: 2\nproject:\n  id: sgproj_{'1' * 32}\n"
            "ai:\n  provider: x\n  model: m\n  api_key_env: KEY\n"
            '  base_url: "https://example.com/v1#credentials"\n'
        ),
    ],
)
def test_configuration_rejects_unsafe_or_unknown_input(tmp_path: Path, invalid_yaml: str) -> None:
    path = tmp_path / "stateguard.yaml"
    path.write_text(invalid_yaml, encoding="utf-8")
    with pytest.raises(ConfigLoadError) as error:
        load_config(path)
    assert "secret-value" not in str(error.value)


@pytest.mark.parametrize(
    "source_root", ["/tmp/project", r"C:\outside", "C:/outside", r"\\server\share"]
)
def test_configuration_rejects_cross_platform_absolute_paths(source_root: str) -> None:
    with pytest.raises(ValidationError, match="project-relative"):
        StateGuardConfig.model_validate(
            {
                "schema_version": 2,
                "project": {"id": f"sgproj_{'1' * 32}", "source_root": source_root},
            }
        )


@pytest.mark.parametrize("name", ["lowercase_key", "MixedCase_Key", "_private9"])
def test_configuration_accepts_portable_environment_names(name: str) -> None:
    config = StateGuardConfig.model_validate(
        {
            "schema_version": 2,
            "project": {"id": new_project_id()},
            "ai": {"provider": "gemini", "model": "m", "api_key_env": name},
        }
    )
    assert config.ai is not None
    assert config.ai.api_key_env == name


@pytest.mark.parametrize(
    "runtime",
    [
        {
            "mode": "byo",
            "target": {"kind": "local", "base_url": "http://user:pass@localhost"},
            "readiness": {"path": "/health"},
        },
        {
            "mode": "byo",
            "target": {"kind": "local", "base_url": "http://localhost?next=public"},
            "readiness": {"path": "/health"},
        },
        {
            "mode": "byo",
            "target": {"kind": "local", "base_url": "http://localhost#public"},
            "readiness": {"path": "/health"},
        },
        {
            "mode": "byo",
            "target": {"kind": "local", "base_url": "http://localhost"},
            "readiness": {"path": "/health"},
            "launch_argv": "uvicorn main:app",
        },
        {
            "mode": "byo",
            "target": {
                "kind": "declared_test",
                "base_url": "https://test.example.com",
                "declaration": "THIS_IS_PRODUCTION",
            },
            "readiness": {"path": "/health"},
        },
    ],
)
def test_runtime_configuration_rejects_unsafe_target_or_shell_command(
    runtime: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        StateGuardConfig.model_validate(
            {
                "schema_version": 2,
                "project": {"id": new_project_id()},
                "runtime": runtime,
            }
        )
