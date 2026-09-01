"""Exact runtime FastAPI route reconciliation and ASGI attachment."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from pathlib import Path
from types import CodeType
from typing import Any

from stateguard.contracts.common import NormalControlId, RuntimeSessionId
from stateguard.discovery.contracts import SourceIndexArtifact
from stateguard.graph.contracts import CheckoutRequestTransport

from .asgi import CorrelationASGIWrapper, ExactRouteASGIWrapper
from .contracts import (
    AcknowledgementRuntimeTarget,
    IngressRuntimeBinding,
    RuntimeCapabilityReasonCode,
)
from .instrumentation import (
    ObservationCollector,
    TraceCodeDescriptor,
    compile_symbol_descriptor,
    descriptor_matches_code,
)
from .planning import RuntimeTargetPlan


@dataclass(frozen=True)
class RouteAttachment:
    binding: IngressRuntimeBinding
    attached: bool
    reason: RuntimeCapabilityReasonCode


@dataclass(frozen=True)
class RouteAttachmentResult:
    app: Any
    attachments: tuple[RouteAttachment, ...]


def _endpoint_code(route: Any) -> CodeType | None:
    endpoint = getattr(route, "endpoint", None)
    if endpoint is None:
        return None
    try:
        endpoint = inspect.unwrap(endpoint)
    except (TypeError, ValueError):
        return None
    code = getattr(endpoint, "__code__", None)
    return code if isinstance(code, CodeType) else None


def _route_candidates(
    app: Any,
    binding: IngressRuntimeBinding,
    descriptor: TraceCodeDescriptor,
    repository_root: Path,
) -> list[Any]:
    result: list[Any] = []
    for route in getattr(app, "routes", ()):
        methods = {str(item).upper() for item in (getattr(route, "methods", None) or ())}
        if getattr(route, "path", None) != binding.effective_path or binding.method not in methods:
            continue
        code = _endpoint_code(route)
        if code is not None and descriptor_matches_code(descriptor, code, repository_root):
            result.append(route)
    return result


def _route_is_shadowed(
    app: Any,
    route: Any,
    binding: IngressRuntimeBinding,
) -> bool:
    """Use runtime route order to detect an earlier identical method/path registration."""

    for candidate in getattr(app, "routes", ()):
        if candidate is route:
            return False
        methods = {str(item).upper() for item in (getattr(candidate, "methods", None) or ())}
        if getattr(candidate, "path", None) == binding.effective_path and binding.method in methods:
            return True
    return False


def _field_is_required(field: Any) -> bool:
    required = getattr(field, "required", None)
    if isinstance(required, bool):
        return required
    field_info = getattr(field, "field_info", None)
    is_required = getattr(field_info, "is_required", None)
    if callable(is_required):
        try:
            return bool(is_required())
        except (TypeError, ValueError):
            return True
    return True


def _checkout_binding_matches(route: Any, binding: IngressRuntimeBinding) -> bool:
    checkout = binding.checkout_request_binding
    if checkout is None:
        return True
    dependant = getattr(route, "dependant", None)
    if dependant is None:
        return False
    expected = {item.request_name for item in checkout.fields}
    query_fields = tuple(getattr(dependant, "query_params", ()))
    query = {str(getattr(item, "alias", "")) for item in query_fields}
    body_fields = tuple(getattr(dependant, "body_params", ()))
    body = {str(getattr(item, "alias", "")) for item in body_fields}
    unsupported_fields = tuple(
        item
        for group in ("header_params", "cookie_params", "path_params")
        for item in tuple(getattr(dependant, group, ()))
    )
    if any(_field_is_required(item) for item in unsupported_fields):
        return False
    if tuple(getattr(dependant, "dependencies", ())):
        return False
    uncontrolled_required = {
        str(getattr(item, "alias", ""))
        for item in (*query_fields, *body_fields)
        if _field_is_required(item) and str(getattr(item, "alias", "")) not in expected
    }
    if uncontrolled_required:
        return False
    if checkout.transport == CheckoutRequestTransport.QUERY:
        return expected <= query
    if body:
        if not expected <= body:
            return False
        media_types = {
            str(getattr(getattr(item, "field_info", None), "media_type", ""))
            for item in body_fields
            if getattr(item, "alias", None) in expected
        }
        if checkout.transport == CheckoutRequestTransport.FORM_URLENCODED:
            return any("form-urlencoded" in value for value in media_types)
        return not any("form-urlencoded" in value for value in media_types)
    # A Request.json()/Request.form() route has no FastAPI dependency fields; exact
    # endpoint code reconciliation remains the live authority for that bounded shape.
    return checkout.transport in {
        CheckoutRequestTransport.JSON,
        CheckoutRequestTransport.FORM_URLENCODED,
    }


def attach_exact_routes(
    app: Any,
    *,
    repository_root: Path,
    source_index: SourceIndexArtifact,
    plan: RuntimeTargetPlan,
    session_id: RuntimeSessionId,
    collector: ObservationCollector,
) -> RouteAttachmentResult:
    controls_by_ingress: dict[str, list[NormalControlId]] = {}
    for customer_target in plan.customer_values:
        controls_by_ingress.setdefault(customer_target.ingress.ingress_node_id, []).append(
            customer_target.normal_control_id
        )
    acknowledgements_by_ingress: dict[str, list[AcknowledgementRuntimeTarget]] = {}
    for acknowledgement_target in plan.acknowledgements:
        acknowledgements_by_ingress.setdefault(
            acknowledgement_target.ingress.ingress_node_id, []
        ).append(acknowledgement_target)

    attachments: list[RouteAttachment] = []
    claimed_routes: set[int] = set()
    for binding in plan.ingresses:
        try:
            descriptor = compile_symbol_descriptor(
                repository_root,
                source_index,
                binding.ingress_symbol_id,
            )
        except ValueError:
            attachments.append(
                RouteAttachment(
                    binding=binding,
                    attached=False,
                    reason=RuntimeCapabilityReasonCode.TARGET_CODE_MISMATCH,
                )
            )
            continue
        candidates = _route_candidates(app, binding, descriptor, repository_root)
        if not candidates:
            attachments.append(
                RouteAttachment(
                    binding=binding,
                    attached=False,
                    reason=RuntimeCapabilityReasonCode.RUNTIME_ROUTE_NOT_FOUND,
                )
            )
            continue
        if len(candidates) != 1 or id(candidates[0]) in claimed_routes:
            attachments.append(
                RouteAttachment(
                    binding=binding,
                    attached=False,
                    reason=RuntimeCapabilityReasonCode.RUNTIME_ROUTE_AMBIGUOUS,
                )
            )
            continue
        route = candidates[0]
        if _route_is_shadowed(app, route, binding):
            attachments.append(
                RouteAttachment(
                    binding=binding,
                    attached=False,
                    reason=RuntimeCapabilityReasonCode.RUNTIME_ROUTE_SHADOWED,
                )
            )
            continue
        if not _checkout_binding_matches(route, binding):
            attachments.append(
                RouteAttachment(
                    binding=binding,
                    attached=False,
                    reason=RuntimeCapabilityReasonCode.CHECKOUT_REQUEST_BINDING_UNRESOLVED,
                )
            )
            continue
        controls = controls_by_ingress.get(binding.ingress_node_id, [])
        normal_control = controls[0] if len(controls) == 1 else None
        route_app = getattr(route, "app", None)
        if not callable(route_app):
            attachments.append(
                RouteAttachment(
                    binding=binding,
                    attached=False,
                    reason=RuntimeCapabilityReasonCode.RUNTIME_ROUTE_NOT_FOUND,
                )
            )
            continue
        route.app = ExactRouteASGIWrapper(
            route_app,
            session_id=session_id,
            ingress=binding,
            normal_control_id=normal_control,
            acknowledgements=tuple(acknowledgements_by_ingress.get(binding.ingress_node_id, ())),
            collector=collector,
        )
        claimed_routes.add(id(route))
        attachments.append(
            RouteAttachment(
                binding=binding,
                attached=True,
                reason=RuntimeCapabilityReasonCode.AVAILABLE,
            )
        )
    return RouteAttachmentResult(
        app=CorrelationASGIWrapper(app),
        attachments=tuple(attachments),
    )
