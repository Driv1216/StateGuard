from __future__ import annotations

import json
import socket
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from stateguard.application.control import StateGuardControl
from stateguard.control_api.security import validate_bind_address
from stateguard.control_api.server import ControlHTTPServer

from .conftest import make_repository


def _raw(server: ControlHTTPServer, request: bytes) -> bytes:
    connection = socket.create_connection(("127.0.0.1", server.listener_port), timeout=2)
    try:
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while chunk := connection.recv(65_536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        connection.close()


def _response(response: bytes) -> tuple[int, dict[str, str], dict[str, object]]:
    headers, body = response.split(b"\r\n\r\n", 1)
    lines = headers.decode("ascii").split("\r\n")
    status = int(lines[0].split()[1])
    parsed_headers = {
        name.casefold(): value.strip()
        for line in lines[1:]
        for name, value in (line.split(":", 1),)
    }
    return status, parsed_headers, json.loads(body)


def _request(
    server: ControlHTTPServer,
    method: str,
    path: str,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
) -> bytes:
    authority = f"127.0.0.1:{server.listener_port}"
    lines = [f"{method} {path} HTTP/1.1", f"Host: {authority}"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    return _raw(server, ("\r\n".join(lines) + "\r\n\r\n").encode() + body)


def test_bind_host_origin_and_cors_policy(
    tmp_path: Path,
    server_factory: Callable[[StateGuardControl, float], ControlHTTPServer],
) -> None:
    repository, _ = make_repository(tmp_path)
    server = server_factory(StateGuardControl(repository), 1.0)
    port = server.listener_port

    for rejected in ("localhost", "0.0.0.0", "::", "127.0.0.2", "example.test"):
        with pytest.raises(ValueError):
            validate_bind_address(rejected, 8765)
    validate_bind_address("127.0.0.1", 8765)
    validate_bind_address("::1", 8765)
    with pytest.raises(ValueError):
        validate_bind_address("127.0.0.1", 0)
    validate_bind_address("127.0.0.1", 0, allow_zero=True)

    missing = _raw(server, b"GET /api/v1/health HTTP/1.1\r\n\r\n")
    assert _response(missing)[0:3:2] == (
        421,
        {
            "schema_version": 1,
            "code": "HOST_NOT_ALLOWED",
            "message": "the HTTP Host is not allowed",
        },
    )

    hostile_hosts = (
        "evil.example",
        f"127.0.0.1:{port + 1}",
        f"user@127.0.0.1:{port}",
        f"127.0.0.1.,:{port}",
        f"localhost.:{port}",
        f"[::1:{port}",
        f"127.0.0.1 :{port}",
    )
    for host in hostile_hosts:
        response = _raw(
            server,
            f"GET /api/v1/health HTTP/1.1\r\nHost: {host}\r\n\r\n".encode(),
        )
        assert _response(response)[0] == 421
    duplicate = _raw(
        server,
        (
            "GET /api/v1/health HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Host: localhost:{port}\r\n\r\n"
        ).encode(),
    )
    assert _response(duplicate)[0] == 421

    valid_origin = f"http://127.0.0.1:{port}"
    valid = _request(
        server,
        "POST",
        "/api/v1/analysis",
        (("Origin", valid_origin), ("Content-Type", "application/json"), ("Content-Length", "2")),
        b"{}",
    )
    status, headers, _ = _response(valid)
    assert status == 200
    assert "access-control-allow-origin" not in headers

    invalid_origins = (
        "null",
        f"https://127.0.0.1:{port}",
        "http://evil.example",
        f"http://127.0.0.1:{port + 1}",
        f"http://user@127.0.0.1:{port}",
        f"http://127.0.0.1:{port}/path",
        f"http://127.0.0.1:{port}?query",
        f"http://127.0.0.1:{port}#fragment",
    )
    for origin in invalid_origins:
        response = _request(
            server,
            "POST",
            "/api/v1/analysis",
            (("Origin", origin), ("Content-Type", "application/json"), ("Content-Length", "2")),
            b"{}",
        )
        assert _response(response)[0] == 403
    duplicate_origin = _request(
        server,
        "POST",
        "/api/v1/analysis",
        (
            ("Origin", valid_origin),
            ("Origin", valid_origin),
            ("Content-Type", "application/json"),
            ("Content-Length", "2"),
        ),
        b"{}",
    )
    assert _response(duplicate_origin)[0] == 403

    options = _request(server, "OPTIONS", "/api/v1/analysis")
    status, headers, error = _response(options)
    assert status == 405
    assert error["code"] == "METHOD_NOT_ALLOWED"
    assert "access-control-allow-origin" not in headers


def test_framing_body_limit_expect_and_security_headers(
    tmp_path: Path,
    server_factory: Callable[[StateGuardControl, float], ControlHTTPServer],
) -> None:
    repository, _ = make_repository(tmp_path)
    server = server_factory(StateGuardControl(repository), 1.0)

    rejected_headers = (
        (("Content-Type", "application/json"),),
        (("Content-Length", "2"),),
        (("Content-Type", "text/plain"), ("Content-Length", "2")),
        (
            ("Content-Type", "application/json"),
            ("Content-Encoding", "gzip"),
            ("Content-Length", "2"),
        ),
        (("Content-Type", "application/json"), ("Content-Length", "02")),
        (("Content-Type", "application/json"), ("Content-Length", "2"), ("Content-Length", "2")),
        (
            ("Content-Type", "application/json"),
            ("Content-Type", "application/json"),
            ("Content-Length", "2"),
        ),
        (
            ("Content-Type", "application/json"),
            ("Content-Length", "2"),
            ("Transfer-Encoding", "chunked"),
        ),
    )
    for headers in rejected_headers:
        response = _request(server, "POST", "/api/v1/analysis", headers, b"{}")
        assert _response(response)[0] in {400, 415}

    short = _request(
        server,
        "POST",
        "/api/v1/analysis",
        (("Content-Type", "application/json"), ("Content-Length", "3")),
        b"{}",
    )
    assert _response(short)[0] == 400

    malformed = _request(
        server,
        "POST",
        "/api/v1/analysis",
        (("Content-Type", "application/json; charset=utf-8"), ("Content-Length", "1")),
        b"{",
    )
    assert _response(malformed)[0] == 400

    oversized = _request(
        server,
        "POST",
        "/api/v1/analysis",
        (("Content-Type", "application/json"), ("Content-Length", "65537")),
    )
    status, _, error = _response(oversized)
    assert status == 413
    assert error["code"] == "REQUEST_TOO_LARGE"

    expect = _request(
        server,
        "POST",
        "/api/v1/analysis",
        (
            ("Content-Type", "application/json"),
            ("Content-Length", "2"),
            ("Expect", "100-continue"),
        ),
    )
    assert b"100 Continue" not in expect
    assert _response(expect)[0] == 400

    get_body = _request(
        server,
        "GET",
        "/api/v1/health",
        (("Content-Length", "2"),),
        b"{}",
    )
    assert _response(get_body)[0] == 400

    response = _request(server, "GET", "/api/v1/health", (("Content-Length", "0"),))
    status, headers, _ = _response(response)
    assert status == 200
    assert headers["server"] == "StateGuard"
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cross-origin-resource-policy"] == "same-origin"
    assert "python" not in response.decode("utf-8").casefold()


def test_targets_parser_errors_and_input_timeout_are_bounded(
    tmp_path: Path,
    server_factory: Callable[[StateGuardControl, float], ControlHTTPServer],
) -> None:
    repository, _ = make_repository(tmp_path)
    server = server_factory(StateGuardControl(repository), 0.15)

    invalid_targets = (
        "http://127.0.0.1/api/v1/health",
        "/api/v1/health?x=1",
        "/api/v1/%2e%2e/health",
        "/api/v1/../health",
        "/api//v1/health",
        "/api/v1\\health",
    )
    for target in invalid_targets:
        response = _request(server, "GET", target)
        assert _response(response)[0] == 400

    malformed_run = _request(server, "GET", "/api/v1/runs/not-a-run")
    status, _, error = _response(malformed_run)
    assert status == 400
    assert error["code"] == "INVALID_RUN_ID"

    oversized_target = "/" + "a" * 70_000
    parser_error = _request(server, "GET", oversized_target)
    status, headers, error = _response(parser_error)
    assert status == 414
    assert error["code"] == "INVALID_REQUEST"
    assert headers["content-type"] == "application/json; charset=utf-8"

    slow_inputs = (
        b"GET /api/v1/heal",
        b"GET /api/v1/health HTTP/1.1\r\nHo",
        (
            f"POST /api/v1/analysis HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{server.listener_port}\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 2\r\n\r\n{"
        ).encode(),
    )
    for partial in slow_inputs:
        slow = socket.create_connection(("127.0.0.1", server.listener_port), timeout=2)
        started = time.monotonic()
        slow.sendall(partial)
        time.sleep(0.3)
        response = slow.recv(65_536)
        assert time.monotonic() - started < 1.0
        if response:
            assert b" 400 " in response
        slow.close()
