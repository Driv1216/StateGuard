from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from stateguard.application.control import (
    ControlOperationError,
    StateGuardControl,
)
from stateguard.contracts.config import AIConfig
from stateguard.contracts.identity import new_project_id, new_verification_run_id
from stateguard.control.contracts import ControlErrorCode
from stateguard.workspace.config_edit import ConcurrentConfigEditError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "policy_app", repository)
    config = repository / "stateguard.yaml"
    config.write_text(
        f"""schema_version: 2
project:
  id: {new_project_id()}
  app_target: main:app
analysis:
  include: ["**/*.py"]
  exclude: [".stateguard/**"]
runtime:
  mode: static
""",
        encoding="utf-8",
    )
    return repository, config


def test_project_binding_and_general_analysis_are_bounded_and_non_persisting(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path)
    state = repository / ".stateguard"
    state.mkdir()
    applicability_path = state / "applicability.json"
    sentinel = b"existing non-authoritative sentinel\n"
    applicability_path.write_bytes(sentinel)

    control = StateGuardControl(repository, Path("stateguard.yaml"))
    result = control.analyze_project()

    assert control.project_root == repository.resolve()
    assert control.config_path == config.resolve()
    assert applicability_path.read_bytes() == sentinel
    assert result.project_id
    assert result.applicability.project_id == result.project_id
    assert result.graph_fingerprint == control.current_graph().graph_fingerprint
    payload = result.model_dump(mode="json")
    assert "source_index" not in payload
    assert str(repository.resolve()) not in json.dumps(payload)


def test_project_setup_is_typed_and_exposes_only_allowlisted_setup_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, config = _repository(tmp_path)
    config.write_text(
        config.read_text(encoding="utf-8")
        + """ai:
  provider: openai-compatible
  model: bounded-model
  api_key_env: SECRET_PROVIDER_KEY
  base_url: https://internal-provider.example/v1
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECRET_PROVIDER_KEY", "actual-provider-secret-sentinel")
    setup = StateGuardControl(repository).project_setup()
    serialized = setup.model_dump_json()
    assert setup.ai_provider == "openai-compatible"
    assert setup.ai_model == "bounded-model"
    assert setup.ai_api_key_env == "SECRET_PROVIDER_KEY"
    assert setup.ai_base_url == "https://internal-provider.example/v1"
    assert "actual-provider-secret-sentinel" not in serialized


def test_history_errors_are_structural_and_sanitized(tmp_path: Path) -> None:
    repository, _ = _repository(tmp_path)
    control = StateGuardControl(repository)
    assert control.list_runs().runs == ()

    with pytest.raises(ControlOperationError) as missing:
        control.latest_run()
    assert missing.value.error.code == ControlErrorCode.RUN_NOT_FOUND

    with pytest.raises(ControlOperationError) as invalid:
        control.load_run("../../outside")
    assert invalid.value.error.code == ControlErrorCode.INVALID_RUN_ID

    corrupt = repository / ".stateguard" / "runs" / new_verification_run_id()
    corrupt.mkdir(parents=True)
    with pytest.raises(ControlOperationError) as artifact:
        control.list_runs()
    assert artifact.value.error.code == ControlErrorCode.RUN_ARTIFACT_INVALID
    assert str(repository) not in artifact.value.error.model_dump_json()


def test_verify_delegates_to_canonical_step_seven_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, config = _repository(tmp_path)
    marker = object()
    observed: list[tuple[Path, Path]] = []

    def fake_create_verification_run(repository_root: Path, config_path: Path):
        observed.append((repository_root, config_path))
        return SimpleNamespace(artifact=marker)

    monkeypatch.setattr(
        "stateguard.application.control.create_verification_run",
        fake_create_verification_run,
    )
    assert StateGuardControl(repository).verify() is marker
    assert observed == [(repository.resolve(), config.resolve())]


def test_unknown_errors_do_not_escape_raw_exception_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = _repository(tmp_path)

    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError(f"secret sentinel at {repository.resolve()}")

    monkeypatch.setattr("stateguard.application.control.inspect_applicability", fail)
    with pytest.raises(ControlOperationError) as captured:
        StateGuardControl(repository).analyze_project()
    assert captured.value.error.code == ControlErrorCode.INTERNAL_ERROR
    serialized = captured.value.error.model_dump_json()
    assert "secret sentinel" not in serialized
    assert str(repository.resolve()) not in serialized


def test_setup_concurrency_failure_remains_structural(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = _repository(tmp_path)

    def collide(*args: object, **kwargs: object) -> None:
        raise ConcurrentConfigEditError("raw concurrent detail must remain hidden")

    monkeypatch.setattr("stateguard.application.control.write_ai_configuration", collide)
    with pytest.raises(ControlOperationError) as captured:
        StateGuardControl(repository).configure_ai(
            AIConfig(
                provider="gemini",
                model="bounded-model",
                api_key_env="MODEL_PROVIDER_KEY",
            )
        )
    assert captured.value.error.code == ControlErrorCode.CONCURRENT_CONFIGURATION_CHANGE
    assert "raw concurrent detail" not in captured.value.error.model_dump_json()
