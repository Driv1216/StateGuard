from __future__ import annotations

import shutil
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from stateguard.application.control import StateGuardControl
from stateguard.contracts.identity import new_project_id
from stateguard.control_api.server import ControlHTTPServer

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"


def make_repository(
    tmp_path: Path,
    fixture: str = "policy_app",
    *,
    runtime: str = "static",
) -> tuple[Path, Path]:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / fixture, repository)
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
  mode: {runtime}
""",
        encoding="utf-8",
    )
    return repository, config


@pytest.fixture
def server_factory() -> Iterator[Callable[[StateGuardControl, float], ControlHTTPServer]]:
    running: list[tuple[ControlHTTPServer, threading.Event, threading.Thread]] = []

    def start(control: StateGuardControl, timeout: float = 1.0) -> ControlHTTPServer:
        server = ControlHTTPServer(
            control,
            "127.0.0.1",
            0,
            input_timeout_seconds=timeout,
            allow_test_port=True,
        )
        stop = threading.Event()
        thread = threading.Thread(target=server.serve_until_stopped, args=(stop,))
        thread.start()
        running.append((server, stop, thread))
        return server

    yield start

    for server, stop, thread in running:
        stop.set()
        thread.join(timeout=120)
        server.server_close()
        assert not thread.is_alive()
