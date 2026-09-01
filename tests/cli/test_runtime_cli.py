from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from stateguard.cli.main import main
from stateguard.contracts.identity import new_project_id
from stateguard.workspace.runtime_artifacts import load_runtime_artifact

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"


def test_runtime_assess_cli_persists_capability_only(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "runtime_app", repository)
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
    assert (
        main(
            [
                "runtime",
                "assess",
                "--repository",
                str(repository),
                "--config",
                str(config),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "StateGuard runtime capability assessment" in output
    assert "mode: static" in output
    assert "PASS" not in output
    assert "FAIL" not in output
    artifact = load_runtime_artifact(repository)
    assert artifact is not None
    assert artifact.artifact_type == "RUNTIME_CAPABILITY"
