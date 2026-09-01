from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from stateguard.cli.main import main
from stateguard.contracts.identity import new_project_id
from stateguard.workspace.config import load_config
from stateguard.workspace.semantic_artifacts import load_semantic_artifact

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"


def test_stable_semantics_resolve_and_confirm_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "semantic_app", repository)
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
    common = ["--repository", str(repository), "--config", str(config)]
    assert main(["semantics", "resolve", *common]) == 0
    output = capsys.readouterr().out
    assert "StateGuard semantic resolution" in output
    assert "state: NO_RESOLUTION" in output
    artifact = load_semantic_artifact(repository)
    assert artifact is not None and artifact.context.presented_symbol_ids

    selected = artifact.context.presented_symbol_ids[0]
    assert main(["semantics", "confirm", *common, "--symbol", selected]) == 0
    output = capsys.readouterr().out
    assert "state: UNIQUE" in output
    loaded = load_config(config)
    assert loaded.semantics is not None
    assert loaded.semantics.customer_value is not None
    assert loaded.semantics.customer_value.symbol_id == selected
