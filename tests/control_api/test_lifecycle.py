from __future__ import annotations

import http.client
import threading
from pathlib import Path

from stateguard.application.control import StateGuardControl
from stateguard.control_api.server import ControlHTTPServer

from .conftest import make_repository


def test_graceful_stop_waits_for_one_synchronous_operation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository, _ = make_repository(tmp_path)
    control = StateGuardControl(repository)
    entered = threading.Event()
    release = threading.Event()
    called = 0

    def slow_verify():
        nonlocal called
        called += 1
        entered.set()
        assert release.wait(timeout=3)
        return control.project_setup()

    monkeypatch.setattr(control, "verify", slow_verify)
    server = ControlHTTPServer(control, "127.0.0.1", 0, allow_test_port=True)
    stop = threading.Event()
    serving = threading.Thread(target=server.serve_until_stopped, args=(stop,))
    serving.start()

    result: list[int] = []

    def request() -> None:
        connection = http.client.HTTPConnection("127.0.0.1", server.listener_port, timeout=5)
        connection.request(
            "POST",
            "/api/v1/runs",
            body=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": "2"},
        )
        response = connection.getresponse()
        response.read()
        result.append(response.status)
        connection.close()

    client = threading.Thread(target=request)
    client.start()
    assert entered.wait(timeout=2)
    stop.set()
    serving.join(timeout=0.1)
    assert serving.is_alive()
    release.set()
    client.join(timeout=3)
    serving.join(timeout=3)
    server.server_close()

    assert called == 1
    assert result == [201]
    assert not serving.is_alive()


def test_client_disconnect_does_not_cancel_control_operation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository, _ = make_repository(tmp_path)
    control = StateGuardControl(repository)
    completed = threading.Event()

    def verify():
        completed.set()
        return control.project_setup()

    monkeypatch.setattr(control, "verify", verify)
    server = ControlHTTPServer(control, "127.0.0.1", 0, allow_test_port=True)
    stop = threading.Event()
    serving = threading.Thread(target=server.serve_until_stopped, args=(stop,))
    serving.start()

    connection = http.client.HTTPConnection("127.0.0.1", server.listener_port, timeout=2)
    connection.connect()
    assert connection.sock is not None
    request = (
        "POST /api/v1/runs HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{server.listener_port}\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 2\r\n\r\n{}"
    )
    connection.sock.sendall(request.encode())
    connection.close()
    assert completed.wait(timeout=2)

    stop.set()
    serving.join(timeout=3)
    server.server_close()
    assert not serving.is_alive()
