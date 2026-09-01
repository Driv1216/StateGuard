"""Single-project synchronous HTTP transport over :class:`StateGuardControl`."""

from __future__ import annotations

import asyncio
import json
import re
import socket
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.resources import files
from threading import Event
from typing import cast

from pydantic import BaseModel, TypeAdapter, ValidationError

from stateguard import __version__
from stateguard.application.control import ControlOperationError, StateGuardControl
from stateguard.contracts.config import AIConfig, RuntimeConfig
from stateguard.control.contracts import ControlErrorCode, control_error

from .contracts import (
    EmptyActionRequest,
    HealthV1,
    PolicyConfirmRequest,
    SemanticConfirmRequest,
)
from .security import (
    TransportRejection,
    validate_bind_address,
    validate_get_framing,
    validate_host,
    validate_mutation_framing,
    validate_origin,
    validate_request_target,
)

_RUNTIME_ADAPTER: TypeAdapter[RuntimeConfig] = TypeAdapter(RuntimeConfig)
_EXACT_ROUTES: dict[str, dict[str, str]] = {
    "/api/v1/health": {"GET": "/api/v1/health"},
    "/api/v1/project": {"GET": "/api/v1/project"},
    "/api/v1/analysis": {"POST": "/api/v1/analysis"},
    "/api/v1/graph": {"GET": "/api/v1/graph"},
    "/api/v1/semantics": {"GET": "/api/v1/semantics"},
    "/api/v1/semantics/resolve": {"POST": "/api/v1/semantics/resolve"},
    "/api/v1/semantics/confirm": {"POST": "/api/v1/semantics/confirm"},
    "/api/v1/policy/confirm": {"POST": "/api/v1/policy/confirm"},
    "/api/v1/applicability/analyze": {"POST": "/api/v1/applicability/analyze"},
    "/api/v1/runtime/assess": {"POST": "/api/v1/runtime/assess"},
    "/api/v1/config/ai": {"PUT": "/api/v1/config/ai"},
    "/api/v1/config/runtime": {"PUT": "/api/v1/config/runtime"},
    "/api/v1/runs": {"GET": "runs_list", "POST": "runs_create"},
    "/api/v1/runs/latest": {"GET": "/api/v1/runs/latest"},
}
_DASHBOARD_ROUTES = frozenset({"/", "/graph", "/failure-lab", "/findings", "/setup"})
_DASHBOARD_ASSET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_DASHBOARD_CONTENT_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".ico": "image/x-icon",
    ".js": "text/javascript; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
}
_DASHBOARD_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'self'"
)

_CONTROL_STATUS: dict[ControlErrorCode, int] = {
    ControlErrorCode.INVALID_REQUEST: HTTPStatus.BAD_REQUEST,
    ControlErrorCode.REQUEST_SCHEMA_INVALID: HTTPStatus.UNPROCESSABLE_ENTITY,
    ControlErrorCode.ROUTE_NOT_FOUND: HTTPStatus.NOT_FOUND,
    ControlErrorCode.METHOD_NOT_ALLOWED: HTTPStatus.METHOD_NOT_ALLOWED,
    ControlErrorCode.HOST_NOT_ALLOWED: HTTPStatus.MISDIRECTED_REQUEST,
    ControlErrorCode.ORIGIN_NOT_ALLOWED: HTTPStatus.FORBIDDEN,
    ControlErrorCode.UNSUPPORTED_MEDIA_TYPE: HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
    ControlErrorCode.REQUEST_TOO_LARGE: HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
    ControlErrorCode.PROJECT_INVALID: HTTPStatus.SERVICE_UNAVAILABLE,
    ControlErrorCode.CONFIG_INVALID: HTTPStatus.CONFLICT,
    ControlErrorCode.ANALYSIS_UNAVAILABLE: HTTPStatus.CONFLICT,
    ControlErrorCode.CONCURRENT_CONFIGURATION_CHANGE: HTTPStatus.CONFLICT,
    ControlErrorCode.AUTHORITY_CHANGED: HTTPStatus.CONFLICT,
    ControlErrorCode.INVALID_SEMANTIC_SELECTION: HTTPStatus.UNPROCESSABLE_ENTITY,
    ControlErrorCode.INVALID_POLICY_CONFIRMATION: HTTPStatus.UNPROCESSABLE_ENTITY,
    ControlErrorCode.INVALID_RUN_ID: HTTPStatus.BAD_REQUEST,
    ControlErrorCode.RUN_NOT_FOUND: HTTPStatus.NOT_FOUND,
    ControlErrorCode.RUN_ARTIFACT_INVALID: HTTPStatus.CONFLICT,
    ControlErrorCode.SEMANTIC_ARTIFACT_INVALID: HTTPStatus.CONFLICT,
    ControlErrorCode.REMEDIATION_NOT_ELIGIBLE: HTTPStatus.UNPROCESSABLE_ENTITY,
    ControlErrorCode.MODEL_PROVIDER_FAILED: HTTPStatus.BAD_GATEWAY,
    ControlErrorCode.OPERATION_FAILED: HTTPStatus.INTERNAL_SERVER_ERROR,
    ControlErrorCode.INTERNAL_ERROR: HTTPStatus.INTERNAL_SERVER_ERROR,
}


def _dynamic_route(path: str) -> tuple[str, str] | None:
    prefix = "/api/v1/runs/"
    if not path.startswith(prefix):
        return None
    remainder = path.removeprefix(prefix)
    finding_match = re.fullmatch(
        r"(sgvrun_[0-9a-f]{32})/findings/(sgfinding_[0-9a-f]{32})/(assistance|reverify)",
        remainder,
    )
    if finding_match is not None:
        run_id, occurrence_id, action = finding_match.groups()
        return f"finding_{action}", f"{run_id}:{occurrence_id}"
    if not remainder or "/" in remainder.removesuffix("/report"):
        return None
    if remainder.endswith("/report"):
        run_id = remainder.removesuffix("/report")
        return "run_report", run_id
    return "run_full", remainder


class ControlHTTPServer(HTTPServer):
    """One listener, project, configuration, facade, and serving thread."""

    def __init__(
        self,
        control: StateGuardControl,
        host: str,
        port: int,
        *,
        input_timeout_seconds: float = 5.0,
        allow_test_port: bool = False,
    ) -> None:
        validate_bind_address(host, port, allow_zero=allow_test_port)
        if input_timeout_seconds <= 0:
            raise ValueError("input timeout must be positive")
        self.control = control
        self.input_timeout_seconds = input_timeout_seconds
        if host == "::1":
            self.address_family = socket.AF_INET6
        super().__init__((host, port), ControlRequestHandler)
        self.timeout = 0.25

    @property
    def listener_port(self) -> int:
        return int(self.server_address[1])

    def get_request(self) -> tuple[socket.socket, object]:
        connection, address = super().get_request()
        connection.settimeout(self.input_timeout_seconds)
        return connection, address

    def serve_until_stopped(self, stop_event: Event) -> None:
        while not stop_event.is_set():
            self.handle_request()


class ControlRequestHandler(BaseHTTPRequestHandler):
    """Strict HTTP/1.1 request handling with no transport-owned product authority."""

    protocol_version = "HTTP/1.1"
    server_version = "StateGuard"
    sys_version = ""

    def version_string(self) -> str:
        return "StateGuard"

    def log_message(self, format: str, *args: object) -> None:
        return

    def handle_expect_100(self) -> bool:
        self._send_error(HTTPStatus.BAD_REQUEST, ControlErrorCode.INVALID_REQUEST)
        return False

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        status = (
            code
            if code in {HTTPStatus.REQUEST_URI_TOO_LONG, HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE}
            else HTTPStatus.BAD_REQUEST
        )
        self._send_error(status, ControlErrorCode.INVALID_REQUEST)

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_OPTIONS(self) -> None:
        self._handle("OPTIONS")

    def do_HEAD(self) -> None:
        self._handle("HEAD")

    def do_PATCH(self) -> None:
        self._handle("PATCH")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    def do_TRACE(self) -> None:
        self._handle("TRACE")

    def do_CONNECT(self) -> None:
        self._handle("CONNECT")

    @property
    def control_server(self) -> ControlHTTPServer:
        return cast(ControlHTTPServer, self.server)

    def _send_model(
        self,
        status: int,
        model: BaseModel,
        *,
        allow: str | None = None,
    ) -> None:
        payload = model.model_dump_json().encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'",
            )
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Connection", "close")
            if allow is not None:
                self.send_header("Allow", allow)
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionError, OSError):
            pass
        finally:
            self.close_connection = True

    def _send_bytes(
        self,
        status: int,
        payload: bytes,
        *,
        content_type: str,
        cache_control: str,
        content_security_policy: str,
    ) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", cache_control)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", content_security_policy)
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionError, OSError):
            pass
        finally:
            self.close_connection = True

    def _send_error(
        self,
        status: int,
        code: ControlErrorCode,
        *,
        allow: str | None = None,
    ) -> None:
        self._send_model(status, control_error(code), allow=allow)

    def _route(self, path: str, method: str) -> tuple[str, str | None]:
        methods = _EXACT_ROUTES.get(path)
        if methods is not None:
            route = methods.get(method)
            if route is None:
                raise TransportRejection(
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    ControlErrorCode.METHOD_NOT_ALLOWED,
                    allow=", ".join(sorted(methods)),
                )
            return route, None
        if path in _DASHBOARD_ROUTES:
            if method != "GET":
                raise TransportRejection(
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    ControlErrorCode.METHOD_NOT_ALLOWED,
                    allow="GET",
                )
            return "dashboard_index", None
        if path.startswith("/assets/"):
            asset_name = path.removeprefix("/assets/")
            if not asset_name or _DASHBOARD_ASSET.fullmatch(asset_name) is None:
                raise TransportRejection(HTTPStatus.NOT_FOUND, ControlErrorCode.ROUTE_NOT_FOUND)
            if method != "GET":
                raise TransportRejection(
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    ControlErrorCode.METHOD_NOT_ALLOWED,
                    allow="GET",
                )
            return "dashboard_asset", asset_name
        dynamic = _dynamic_route(path)
        if dynamic is None:
            raise TransportRejection(HTTPStatus.NOT_FOUND, ControlErrorCode.ROUTE_NOT_FOUND)
        allowed = "POST" if dynamic[0] in {"finding_assistance", "finding_reverify"} else "GET"
        if method != allowed:
            raise TransportRejection(
                HTTPStatus.METHOD_NOT_ALLOWED,
                ControlErrorCode.METHOD_NOT_ALLOWED,
                allow=allowed,
            )
        return dynamic

    def _serve_dashboard(self, route: str, argument: str | None) -> None:
        static_root = files("stateguard.dashboard").joinpath("static")
        content_type: str | None
        if route == "dashboard_index":
            resource = static_root.joinpath("index.html")
            content_type = "text/html; charset=utf-8"
            cache_control = "no-cache"
        else:
            assert argument is not None
            suffix = "." + argument.rpartition(".")[2] if "." in argument else ""
            content_type = _DASHBOARD_CONTENT_TYPES.get(suffix)
            if content_type is None:
                self._send_error(HTTPStatus.NOT_FOUND, ControlErrorCode.ROUTE_NOT_FOUND)
                return
            resource = static_root.joinpath("assets", argument)
            cache_control = "public, max-age=31536000, immutable"
        if not resource.is_file():
            self._send_error(HTTPStatus.NOT_FOUND, ControlErrorCode.ROUTE_NOT_FOUND)
            return
        try:
            payload = resource.read_bytes()
        except OSError:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, ControlErrorCode.INTERNAL_ERROR)
            return
        self._send_bytes(
            HTTPStatus.OK,
            payload,
            content_type=content_type,
            cache_control=cache_control,
            content_security_policy=_DASHBOARD_CSP,
        )

    def _read_body(self) -> bytes:
        length = validate_mutation_framing(self.headers)
        body = self.rfile.read(length)
        if len(body) != length:
            raise TransportRejection(HTTPStatus.BAD_REQUEST, ControlErrorCode.INVALID_REQUEST)
        return body

    def _request_model(self, route: str, body: bytes) -> BaseModel:
        def reject_constant(value: str) -> None:
            raise ValueError("non-finite JSON number")

        try:
            payload = json.loads(body.decode("utf-8"), parse_constant=reject_constant)
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise TransportRejection(
                HTTPStatus.BAD_REQUEST, ControlErrorCode.INVALID_REQUEST
            ) from exc
        if not isinstance(payload, dict):
            raise TransportRejection(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                ControlErrorCode.REQUEST_SCHEMA_INVALID,
            )
        if route in {
            "/api/v1/analysis",
            "/api/v1/semantics/resolve",
            "/api/v1/applicability/analyze",
            "/api/v1/runtime/assess",
            "runs_create",
            "finding_assistance",
            "finding_reverify",
        }:
            return EmptyActionRequest.model_validate(payload)
        if route == "/api/v1/semantics/confirm":
            return SemanticConfirmRequest.model_validate(payload)
        if route == "/api/v1/policy/confirm":
            return PolicyConfirmRequest.model_validate(payload)
        if route == "/api/v1/config/ai":
            return AIConfig.model_validate(payload)
        if route == "/api/v1/config/runtime":
            return _RUNTIME_ADAPTER.validate_python(payload)
        raise AssertionError("mutation route has no request contract")

    def _dispatch(
        self,
        route: str,
        argument: str | None,
        request: BaseModel | None,
    ) -> tuple[int, BaseModel]:
        control = self.control_server.control
        if route == "/api/v1/health":
            return HTTPStatus.OK, HealthV1(producer_version=__version__)
        if route == "/api/v1/project":
            return HTTPStatus.OK, control.project_setup()
        if route == "/api/v1/analysis":
            return HTTPStatus.OK, control.analyze_project()
        if route == "/api/v1/graph":
            return HTTPStatus.OK, control.current_graph()
        if route == "/api/v1/semantics":
            return HTTPStatus.OK, control.semantic_snapshot()
        if route == "/api/v1/semantics/resolve":
            return HTTPStatus.OK, asyncio.run(control.resolve_semantics())
        if route == "/api/v1/semantics/confirm":
            semantic_request = cast(SemanticConfirmRequest, request)
            return HTTPStatus.OK, asyncio.run(control.confirm_semantics(semantic_request.symbol_id))
        if route == "/api/v1/policy/confirm":
            policy_request = cast(PolicyConfirmRequest, request)
            return HTTPStatus.OK, control.confirm_policy(
                fulfilment=policy_request.fulfilment,
                late_authorisation=policy_request.late_authorisation,
            )
        if route == "/api/v1/applicability/analyze":
            return HTTPStatus.OK, control.analyze_applicability()
        if route == "/api/v1/runtime/assess":
            return HTTPStatus.OK, control.assess_runtime()
        if route == "/api/v1/config/ai":
            return HTTPStatus.OK, control.configure_ai(cast(AIConfig, request))
        if route == "/api/v1/config/runtime":
            return HTTPStatus.OK, control.configure_runtime(cast(RuntimeConfig, request))
        if route == "runs_create":
            return HTTPStatus.CREATED, control.verify()
        if route == "runs_list":
            return HTTPStatus.OK, control.list_runs()
        if route == "/api/v1/runs/latest":
            return HTTPStatus.OK, control.report_latest_run()
        if route == "run_full":
            assert argument is not None
            return HTTPStatus.OK, control.load_run(argument)
        if route == "run_report":
            assert argument is not None
            return HTTPStatus.OK, control.report_run(argument)
        if route in {"finding_assistance", "finding_reverify"}:
            assert argument is not None
            run_id, occurrence_id = argument.split(":", 1)
            if route == "finding_assistance":
                return HTTPStatus.OK, asyncio.run(
                    control.remediation_assistance(run_id, occurrence_id)
                )
            return HTTPStatus.CREATED, control.reverify_finding(run_id, occurrence_id)
        raise AssertionError("matched route has no dispatcher")

    def _handle(self, method: str) -> None:
        try:
            authority = validate_host(self.headers, self.control_server.listener_port)
            if method in {"POST", "PUT"}:
                validate_origin(self.headers, authority)
            path = validate_request_target(self.path)
            route, argument = self._route(path, method)
            request: BaseModel | None = None
            if method == "GET":
                validate_get_framing(self.headers)
            elif method in {"POST", "PUT"}:
                body = self._read_body()
                request = self._request_model(route, body)
            else:
                raise AssertionError("non-routable method passed route validation")
            self.connection.settimeout(None)
            if route in {"dashboard_index", "dashboard_asset"}:
                self._serve_dashboard(route, argument)
                return
            status, response = self._dispatch(route, argument, request)
            self._send_model(status, response)
        except ValidationError:
            self._send_error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                ControlErrorCode.REQUEST_SCHEMA_INVALID,
            )
        except TransportRejection as exc:
            self._send_error(exc.status, exc.code, allow=exc.allow)
        except ControlOperationError as exc:
            self._send_model(_CONTROL_STATUS[exc.error.code], exc.error)
        except TimeoutError:
            self._send_error(HTTPStatus.BAD_REQUEST, ControlErrorCode.INVALID_REQUEST)
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, ControlErrorCode.INTERNAL_ERROR)


def serve_control_api(
    control: StateGuardControl,
    host: str,
    port: int,
    stop_event: Event,
    *,
    on_started: Callable[[int], None] | None = None,
) -> None:
    """Serve one bound project until a cooperative stop is requested."""

    with ControlHTTPServer(control, host, port) as server:
        if on_started is not None:
            on_started(server.listener_port)
        server.serve_until_stopped(stop_event)
