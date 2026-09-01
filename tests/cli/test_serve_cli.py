from __future__ import annotations

import shutil
from pathlib import Path
from threading import Event

import pytest

from stateguard.application.control import StateGuardControl
from stateguard.cli.main import main
from stateguard.contracts.identity import new_project_id

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos" / "policy_app"


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURE, repository)
    config = repository / "stateguard.yaml"
    config.write_text(
        f"""schema_version: 2
project:
  id: {new_project_id()}
  app_target: main:app
runtime:
  mode: static
""",
        encoding="utf-8",
    )
    return repository, config


def test_serve_uses_project_binding_safe_output_and_ipv6_format(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, config = _repository(tmp_path)
    observed: list[tuple[Path, Path, str, int, Event]] = []

    def fake_serve(
        control: StateGuardControl,
        host: str,
        port: int,
        stop_event: Event,
        *,
        on_started,
    ) -> None:
        observed.append((control.project_root, control.config_path, host, port, stop_event))
        on_started(port)

    monkeypatch.setattr("stateguard.cli.main.serve_control_api", fake_serve)
    assert (
        main(
            [
                "serve",
                str(repository),
                "--config",
                "stateguard.yaml",
                "--host",
                "::1",
                "--port",
                "9123",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "http://[::1]:9123" in output
    assert str(repository.resolve()) not in output
    assert str(config.resolve()) not in output
    assert observed[0][0:4] == (repository.resolve(), config.resolve(), "::1", 9123)


def test_serve_compatibility_validation_and_failures_are_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, _ = _repository(tmp_path)

    def fail(*args, **kwargs) -> None:
        raise OSError(f"secret bind detail at {repository.resolve()}")

    monkeypatch.setattr("stateguard.cli.main.serve_control_api", fail)
    assert main(["serve", "--repository", str(repository)]) == 2
    error = capsys.readouterr().err
    assert "OPERATION_FAILED" in error
    assert "secret bind detail" not in error
    assert str(repository.resolve()) not in error

    assert main(["serve", str(repository), "--repository", str(repository)]) == 2
    assert "INVALID_REQUEST" in capsys.readouterr().err
    assert main(["serve", str(repository), "--host", "0.0.0.0"]) == 2
    capsys.readouterr()
    assert main(["serve", str(repository), "--port", "0"]) == 2
    capsys.readouterr()
    assert main(["serve", str(repository), "--json"]) == 2
    capsys.readouterr()
