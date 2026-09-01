from __future__ import annotations

from pathlib import Path

import pytest

from stateguard.cli.main import build_parser, main
from stateguard.contracts.identity import new_project_id


def test_cli_exposes_stable_control_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    help_text = capsys.readouterr().out
    assert "config" in help_text
    assert "semantics" in help_text
    assert "analyze" in help_text
    assert "verify" in help_text
    assert "runs" in help_text
    assert "serve" in help_text
    with pytest.raises(SystemExit) as result:
        build_parser().parse_args(["--version"])
    assert result.value.code == 0


def test_cli_validates_configuration(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "stateguard.yaml"
    config.write_text(
        f"schema_version: 2\nproject:\n  id: {new_project_id()}\n  source_root: .\n",
        encoding="utf-8",
    )
    assert main(["config", "validate", str(config)]) == 0
    assert "valid StateGuard configuration" in capsys.readouterr().out

    config.write_text("schema_version: 2\nproject: {}\n", encoding="utf-8")
    assert main(["config", "validate", str(config)]) == 2
    assert "CONFIG_INVALID" in capsys.readouterr().err
