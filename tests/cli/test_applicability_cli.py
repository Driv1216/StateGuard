from __future__ import annotations

import shutil
from pathlib import Path

from stateguard.cli.main import main
from stateguard.contracts.config import FulfilmentPolicy
from stateguard.contracts.identity import new_project_id
from stateguard.workspace.applicability_artifacts import load_applicability_artifact
from stateguard.workspace.config import load_config

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
  exclude: []
""",
        encoding="utf-8",
    )
    return repository, config


def test_applicability_analyze_and_explicit_policy_confirmation_cli(tmp_path: Path, capsys) -> None:
    repository, config = _repository(tmp_path)
    assert (
        main(
            [
                "applicability",
                "analyze",
                "--repository",
                str(repository),
                "--config",
                str(config),
            ]
        )
        == 0
    )
    assert load_applicability_artifact(repository) is not None
    assert "SG-08:" in capsys.readouterr().out

    assert (
        main(
            [
                "policy",
                "confirm",
                "--repository",
                str(repository),
                "--config",
                str(config),
            ]
        )
        == 2
    )
    assert "INVALID_POLICY_CONFIRMATION" in capsys.readouterr().err

    assert (
        main(
            [
                "policy",
                "confirm",
                "--repository",
                str(repository),
                "--config",
                str(config),
                "--fulfilment",
                "CAPTURE_REQUIRED",
            ]
        )
        == 0
    )
    loaded = load_config(config)
    assert loaded.policy is not None and loaded.policy.fulfilment is not None
    assert loaded.policy.fulfilment.value == FulfilmentPolicy.CAPTURE_REQUIRED
