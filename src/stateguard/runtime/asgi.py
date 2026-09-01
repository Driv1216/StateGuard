"""Value-free ASGI correlation and exact route-boundary observations."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from typing import Any

from pydantic import TypeAdapter, ValidationError

from stateguard.contracts.common import (
    GraphNodeId,
    NormalControlId,
    RuntimeRequestId,
    RuntimeSessionId,
)

from .contracts import (
    AcknowledgementRuntimeTarget,
    IngressRuntimeBinding,
    ManagedAcknowledgementFailureMode,
    RuntimeObservationKind,
)
from .instrumentation import (
    ObservationCollector,
    RuntimeRequestContext,
    bind_runtime_request,
    reset_runtime_request,
)

ASGIApp = Callable[
    [dict[str, Any], Callable[..., Awaitable[Any]], Callable[..., Awaitable[Any]]],
    Awaitable[None],
]
_CORRELATION_HEADER = b"x-stateguard-request-id"
_ACK_FAILURE_HEADER = b"x-stateguard-acknowledgement-failure"
_REQUEST_ID = TypeAdapter(RuntimeRequestId)
_GRAPH_NODE_ID = TypeAdapter(GraphNodeId)
_DRIVER_REQUEST: ContextVar[RuntimeRequestId | None] = ContextVar(
    "stateguard_driver_request", default=None
)
_ACK_FAILURE: ContextVar[tuple[ManagedAcknowledgementFailureMode, GraphNodeId] | None] = ContextVar(
    "stateguard_acknowledgement_failure", default=None
)


class CorrelationASGIWrapper:
    """Consume StateGuard correlation before merchant middleware can observe it."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[Any]],
        send: Callable[..., Awaitable[Any]],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        request_id: RuntimeRequestId | None = None
        acknowledgement_failure: tuple[ManagedAcknowledgementFailureMode, GraphNodeId] | None = None
        headers: list[tuple[bytes, bytes]] = []
        for raw_name, raw_value in scope.get("headers", []):
            if raw_name.lower() == _CORRELATION_HEADER and request_id is None:
                try:
                    request_id = _REQUEST_ID.validate_python(raw_value.decode("ascii"))
                except (UnicodeError, ValidationError):
                    request_id = None
                continue
            if raw_name.lower() == _ACK_FAILURE_HEADER and acknowledgement_failure is None:
                try:
                    raw_mode, raw_node_id = raw_value.decode("ascii").split(":", 1)
                    acknowledgement_failure = (
                        ManagedAcknowledgementFailureMode(raw_mode),
                        _GRAPH_NODE_ID.validate_python(raw_node_id),
                    )
                except (UnicodeError, ValueError):
                    acknowledgement_failure = None
                continue
            headers.append((raw_name, raw_value))
        sanitized_scope = dict(scope)
        sanitized_scope["headers"] = headers
        token = _DRIVER_REQUEST.set(request_id)
        acknowledgement_token = _ACK_FAILURE.set(acknowledgement_failure)
        try:
            await self.app(sanitized_scope, receive, send)
        finally:
            _ACK_FAILURE.reset(acknowledgement_token)
            _DRIVER_REQUEST.reset(token)


class ExactRouteASGIWrapper:
    """Observe one already-reconciled FastAPI route without wrapping its endpoint."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        session_id: RuntimeSessionId,
        ingress: IngressRuntimeBinding,
        normal_control_id: NormalControlId | None,
        acknowledgements: tuple[AcknowledgementRuntimeTarget, ...],
        collector: ObservationCollector,
    ) -> None:
        self.app = app
        self.session_id = session_id
        self.ingress = ingress
        self.normal_control_id = normal_control_id
        self.acknowledgements = acknowledgements
        self.collector = collector

    def _acknowledgement_for_status(
        self, status: int, requested_node_id: GraphNodeId | None = None
    ) -> GraphNodeId | None:
        exact = [
            item.acknowledgement_node_id
            for item in self.acknowledgements
            if item.status_code == status
            and (requested_node_id is None or item.acknowledgement_node_id == requested_node_id)
        ]
        return exact[0] if len(exact) == 1 else None

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[Any]],
        send: Callable[..., Awaitable[Any]],
    ) -> None:
        request_id = _DRIVER_REQUEST.get()
        acknowledgement_failure = _ACK_FAILURE.get()
        if scope.get("type") != "http" or request_id is None:
            await self.app(scope, receive, send)
            return
        context = RuntimeRequestContext(
            session_id=self.session_id,
            request_id=request_id,
            ingress=self.ingress,
            normal_control_id=self.normal_control_id,
        )
        token = bind_runtime_request(context)
        response_status: int | None = None
        response_completed = False
        self.collector.emit(RuntimeObservationKind.REQUEST_RECEIVED, context)

        async def observed_send(message: dict[str, Any]) -> None:
            nonlocal response_status, response_completed
            if message.get("type") == "http.response.start":
                merchant_status = int(message["status"])
                requested_node_id = acknowledgement_failure[1] if acknowledgement_failure else None
                acknowledgement_node_id = self._acknowledgement_for_status(
                    merchant_status, requested_node_id
                )
                if (
                    acknowledgement_failure is not None
                    and acknowledgement_failure[0]
                    == ManagedAcknowledgementFailureMode.FORCE_NON_2XX_AFTER_SUCCESS
                    and 200 <= merchant_status < 300
                    and acknowledgement_node_id is not None
                ):
                    response_status = 503
                    self.collector.emit(
                        RuntimeObservationKind.ACKNOWLEDGEMENT_FAILURE_INJECTED,
                        context,
                        acknowledgement_node_id=acknowledgement_node_id,
                        status_code=response_status,
                        original_status_code=merchant_status,
                    )
                    message = dict(message)
                    message["status"] = response_status
                    acknowledgement_node_id = None
                else:
                    response_status = merchant_status
                self.collector.emit(
                    RuntimeObservationKind.RESPONSE_STARTED,
                    context,
                    acknowledgement_node_id=acknowledgement_node_id,
                    status_code=response_status,
                )
            elif message.get("type") == "http.response.body" and not bool(
                message.get("more_body", False)
            ):
                response_completed = True
                if response_status is not None:
                    self.collector.emit(
                        RuntimeObservationKind.RESPONSE_COMPLETED,
                        context,
                        acknowledgement_node_id=self._acknowledgement_for_status(response_status),
                        status_code=response_status,
                    )
            await send(message)

        try:
            await self.app(scope, receive, observed_send)
        finally:
            if not response_completed:
                self.collector.emit(RuntimeObservationKind.REQUEST_ABORTED, context)
            reset_runtime_request(token)
