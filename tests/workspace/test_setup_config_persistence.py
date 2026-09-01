from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from stateguard.application.control import StateGuardControl
from stateguard.contracts.config import (
    AIConfig,
    BringYourOwnRuntimeConfig,
    LocalRuntimeTargetConfig,
    RuntimeReadinessConfig,
)
from stateguard.contracts.identity import new_project_id
from stateguard.workspace import config_edit
from stateguard.workspace.config import ConfigLoadError, load_config
from stateguard.workspace.config_edit import (
    ConcurrentConfigEditError,
    write_ai_configuration,
    write_runtime_configuration,
)


def _configuration(tmp_path: Path) -> Path:
    config = tmp_path / "stateguard.yaml"
    config.write_text(
        f"""# preserved project comment
schema_version: 2
project:
  id: {new_project_id()}
  app_target: main:app
analysis:
  include: ["**/*.py"]
  exclude: [".stateguard/**"]
semantics:
  customer_value:
    symbol_id: sgsym_{"1" * 32}
    semantic_context_fingerprint: sha256:{"2" * 64}
    basis: HUMAN_CONFIRMED
policy:
  fulfilment:
    value: CAPTURE_REQUIRED
    evidence_fingerprint: sha256:{"3" * 64}
  late_authorisation:
    value: FULFIL_LATER
    evidence_fingerprint: sha256:{"4" * 64}
runtime:
  mode: static
""",
        encoding="utf-8",
    )
    return config


def test_ai_configuration_is_atomic_and_preserves_unrelated_yaml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _configuration(tmp_path)
    before = load_config(config_path)
    state = tmp_path / ".stateguard"
    state.mkdir()
    existing_artifacts = {
        state / "semantics.json": b"semantic sentinel\n",
        state / "applicability.json": b"applicability sentinel\n",
        state / "runtime.json": b"runtime sentinel\n",
    }
    for path, content in existing_artifacts.items():
        path.write_bytes(content)
    monkeypatch.setenv("MODEL_PROVIDER_KEY", "secret-value-must-not-be-resolved")
    ai = AIConfig(
        provider="openai-compatible",
        model="bounded-model",
        api_key_env="MODEL_PROVIDER_KEY",
        base_url="https://models.example/v1",
    )

    write_ai_configuration(config_path, ai)

    after = load_config(config_path)
    assert after.ai == ai
    assert after.project == before.project
    assert after.analysis == before.analysis
    assert after.semantics == before.semantics
    assert after.policy == before.policy
    assert after.runtime == before.runtime
    assert "# preserved project comment" in config_path.read_text(encoding="utf-8")
    assert all(path.read_bytes() == content for path, content in existing_artifacts.items())
    setup = StateGuardControl(tmp_path).project_setup()
    assert setup.ai_api_key_env == "MODEL_PROVIDER_KEY"
    assert setup.ai_base_url == "https://models.example/v1"
    assert "secret-value-must-not-be-resolved" not in setup.model_dump_json()


def test_runtime_configuration_preserves_authority_and_does_not_assess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _configuration(tmp_path)
    write_ai_configuration(
        config_path,
        AIConfig(
            provider="gemini",
            model="bounded-model",
            api_key_env="GEMINI_KEY_NAME",
        ),
    )
    before = load_config(config_path)
    runtime = BringYourOwnRuntimeConfig(
        working_directory=".",
        env_from_host={"MERCHANT_SECRET": "HOST_SECRET_NAME"},
        target=LocalRuntimeTargetConfig(base_url="http://127.0.0.1:9123"),
        readiness=RuntimeReadinessConfig(path="/ready", accepted_statuses=(200, 204)),
        launch_argv=("python", "-m", "merchant"),
    )

    def forbidden_assessment(*args: object, **kwargs: object) -> None:
        raise AssertionError("runtime configuration must not assess capability")

    monkeypatch.setattr(
        "stateguard.application.control.assess_runtime_capability",
        forbidden_assessment,
    )
    setup = StateGuardControl(tmp_path).configure_runtime(runtime)

    after = load_config(config_path)
    assert after.runtime == runtime
    assert after.ai == before.ai
    assert after.semantics == before.semantics
    assert after.policy == before.policy
    assert setup.runtime is not None
    assert setup.runtime.target is not None
    assert setup.runtime.target.base_url == "http://127.0.0.1:9123"
    assert setup.runtime.environment_bindings[0].host_name == "HOST_SECRET_NAME"
    assert setup.runtime.launch_configured is True
    assert "python" not in setup.model_dump_json()
    assert not (tmp_path / ".stateguard" / "runtime.json").exists()


def test_invalid_typed_section_is_rejected_without_replacing_configuration(
    tmp_path: Path,
) -> None:
    config_path = _configuration(tmp_path)
    original = config_path.read_bytes()
    invalid = AIConfig.model_construct(
        provider="openai-compatible",
        model="bounded-model",
        api_key_env="MODEL_PROVIDER_KEY",
        base_url="https://user:password@models.example/v1",
    )
    with pytest.raises(ConfigLoadError):
        write_ai_configuration(config_path, invalid)
    assert config_path.read_bytes() == original


def test_optimistic_concurrency_prevents_lost_setup_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _configuration(tmp_path)
    original_load = config_edit.load_config
    raced = False

    def racing_load(path: Path):
        nonlocal raced
        loaded = original_load(path)
        if path != config_path and path.suffix == ".tmp" and not raced:
            raced = True
            config_path.write_text(
                config_path.read_text(encoding="utf-8") + "# concurrent edit\n",
                encoding="utf-8",
            )
        return loaded

    monkeypatch.setattr(config_edit, "load_config", racing_load)
    with pytest.raises(ConcurrentConfigEditError):
        write_runtime_configuration(
            config_path,
            BringYourOwnRuntimeConfig(
                target=LocalRuntimeTargetConfig(base_url="http://127.0.0.1:9123"),
                readiness=RuntimeReadinessConfig(),
            ),
        )
    text = config_path.read_text(encoding="utf-8")
    assert "# concurrent edit" in text
    assert "mode: byo" not in text


def test_ai_contract_rejects_secret_fields_and_credential_bearing_urls() -> None:
    with pytest.raises(ValidationError):
        AIConfig.model_validate(
            {
                "provider": "gemini",
                "model": "bounded-model",
                "api_key_env": "MODEL_PROVIDER_KEY",
                "api_key": "literal-secret",
            }
        )
    with pytest.raises(ValidationError):
        AIConfig(
            provider="openai-compatible",
            model="bounded-model",
            api_key_env="MODEL_PROVIDER_KEY",
            base_url="https://user:password@models.example/v1",
        )
