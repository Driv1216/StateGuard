"""Fetch-only Razorpay Test Mode grounding adapter."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from stateguard.contracts.common import VerificationRunId
from stateguard.contracts.identity import fingerprint_json, sha256_digest

from .contracts import (
    CapturedPaymentProfile,
    RazorpayGroundingReason,
    RazorpayGroundingSnapshot,
    RazorpayGroundingStatus,
    RazorpaySourceEndpointKind,
    RazorpayTestGroundingRequest,
)

_API_ORIGIN = "https://api.razorpay.com"
_MAX_RESPONSE_BYTES = 64 * 1024
_TEST_KEY = re.compile(r"^rzp_test_[A-Za-z0-9]+$")
_PAYMENT_ID = re.compile(r"^pay_[A-Za-z0-9]+$")
_ORDER_ID = re.compile(r"^order_[A-Za-z0-9]+$")


class _PaymentResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    id: str
    entity: str
    amount: int
    currency: str
    status: str
    captured: bool
    order_id: str | None
    amount_refunded: int
    refund_status: str | None


class _OrderResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    id: str
    entity: str
    amount: int
    amount_paid: int
    amount_due: int
    currency: str
    status: str


@dataclass(frozen=True, repr=False)
class GroundingAcquisitionResult:
    snapshot: RazorpayGroundingSnapshot
    profile: CapturedPaymentProfile | None = None

    def __repr__(self) -> str:
        return "GroundingAcquisitionResult(<safe grounding evidence>)"


class _ResponseTooLarge(ValueError):
    pass


class _MalformedResponse(ValueError):
    pass


def _resource_fingerprint(kind: str, value: str) -> str:
    return sha256_digest(f"STATEGUARD_RAZORPAY_{kind}_V1\0{value}".encode())


def _snapshot(
    *,
    run_id: VerificationRunId,
    acquired_at: datetime,
    status: RazorpayGroundingStatus,
    reason: RazorpayGroundingReason | None = None,
    source_endpoint_kinds: tuple[RazorpaySourceEndpointKind, ...] = (),
    **values: Any,
) -> RazorpayGroundingSnapshot:
    payload = {
        "schema_version": 1,
        "mode": "TEST",
        "status": status,
        "unavailable_reason": reason,
        "run_id": run_id,
        "acquired_at": acquired_at,
        "source_endpoint_kinds": source_endpoint_kinds,
        "key_id_fingerprint": None,
        "payment_id_fingerprint": None,
        "order_id_fingerprint": None,
        "resource_snapshot_fingerprint": None,
        "sanitized_projection_fingerprint": None,
        "payment_captured": False,
        "order_paid": False,
        "linkage_consistent": False,
        "amount_consistent": False,
        "currency_consistent": False,
        "no_current_refund": False,
        **values,
    }
    provisional = RazorpayGroundingSnapshot.model_construct(
        **payload,
        grounding_fingerprint=f"sha256:{'0' * 64}",
    )
    fingerprint_payload = provisional.model_dump(
        mode="json",
        exclude={"grounding_fingerprint"},
    )
    return RazorpayGroundingSnapshot(
        **payload,
        grounding_fingerprint=fingerprint_json(fingerprint_payload),
    )


def _status_reason(status_code: int) -> RazorpayGroundingReason | None:
    if 200 <= status_code < 300:
        return None
    if status_code == 400:
        return RazorpayGroundingReason.REQUEST_REJECTED
    if status_code in {401, 403}:
        return RazorpayGroundingReason.AUTHENTICATION_FAILED
    if status_code == 404:
        return RazorpayGroundingReason.RESOURCE_NOT_FOUND
    if status_code == 429:
        return RazorpayGroundingReason.RATE_LIMITED
    return RazorpayGroundingReason.PROVIDER_FAILED


def _fetch_json(client: httpx.Client, path: str) -> Mapping[str, Any]:
    with client.stream("GET", f"{_API_ORIGIN}{path}") as response:
        reason = _status_reason(response.status_code)
        if reason is not None:
            raise _ProviderResponse(reason)
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > _MAX_RESPONSE_BYTES:
                raise _ResponseTooLarge
    try:
        value = httpx.Response(200, content=bytes(body)).json()
    except ValueError as exc:
        raise _MalformedResponse from exc
    if not isinstance(value, dict):
        raise _MalformedResponse
    return value


class _ProviderResponse(ValueError):
    def __init__(self, reason: RazorpayGroundingReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


def acquire_razorpay_test_grounding(
    request: RazorpayTestGroundingRequest,
    run_id: VerificationRunId,
    *,
    environment: Mapping[str, str] | None = None,
    acquired_at: datetime | None = None,
    transport: httpx.BaseTransport | None = None,
) -> GroundingAcquisitionResult:
    """Fetch and sanitize one captured Payment and its linked paid Order.

    Every expected provider/configuration failure becomes bounded unavailable evidence.
    """

    timestamp = acquired_at or datetime.now(UTC)
    variables = os.environ if environment is None else environment
    key_id = variables.get(request.key_id_env, "")
    key_secret = variables.get(request.key_secret_env, "")
    payment_id = variables.get(request.payment_id_env, "")

    def unavailable(
        reason: RazorpayGroundingReason,
        endpoints: tuple[RazorpaySourceEndpointKind, ...] = (),
    ) -> GroundingAcquisitionResult:
        return GroundingAcquisitionResult(
            snapshot=_snapshot(
                run_id=run_id,
                acquired_at=timestamp,
                status=RazorpayGroundingStatus.UNAVAILABLE,
                reason=reason,
                source_endpoint_kinds=endpoints,
            )
        )

    if not key_id or not key_secret or not payment_id:
        return unavailable(RazorpayGroundingReason.MISSING_ENVIRONMENT)
    if key_id.startswith("rzp_live_"):
        return unavailable(RazorpayGroundingReason.LIVE_CREDENTIAL_REJECTED)
    if _TEST_KEY.fullmatch(key_id) is None:
        return unavailable(RazorpayGroundingReason.INVALID_TEST_CREDENTIAL)
    if _PAYMENT_ID.fullmatch(payment_id) is None:
        return unavailable(RazorpayGroundingReason.INVALID_PAYMENT_REFERENCE)

    endpoints: tuple[RazorpaySourceEndpointKind, ...] = ()
    try:
        with httpx.Client(
            auth=(key_id, key_secret),
            timeout=httpx.Timeout(5.0),
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        ) as client:
            endpoints = (RazorpaySourceEndpointKind.FETCH_PAYMENT,)
            payment_raw = _fetch_json(client, f"/v1/payments/{payment_id}")
            try:
                payment = _PaymentResponse.model_validate(payment_raw)
            except ValidationError as exc:
                raise _MalformedResponse from exc
            eligible_payment = bool(
                payment.entity == "payment"
                and payment.id == payment_id
                and payment.status == "captured"
                and payment.captured is True
                and payment.order_id is not None
                and _ORDER_ID.fullmatch(payment.order_id) is not None
                and payment.amount > 0
                and re.fullmatch(r"[A-Z]{3}", payment.currency) is not None
                and payment.amount_refunded == 0
                and payment.refund_status is None
            )
            if not eligible_payment:
                return unavailable(RazorpayGroundingReason.RESOURCE_INELIGIBLE, endpoints)

            endpoints = (
                RazorpaySourceEndpointKind.FETCH_PAYMENT,
                RazorpaySourceEndpointKind.FETCH_LINKED_ORDER,
            )
            order_raw = _fetch_json(client, f"/v1/orders/{payment.order_id}")
            try:
                order = _OrderResponse.model_validate(order_raw)
            except ValidationError as exc:
                raise _MalformedResponse from exc
    except _ProviderResponse as exc:
        return unavailable(exc.reason, endpoints)
    except _ResponseTooLarge:
        return unavailable(RazorpayGroundingReason.RESPONSE_TOO_LARGE, endpoints)
    except _MalformedResponse:
        return unavailable(RazorpayGroundingReason.MALFORMED_RESPONSE, endpoints)
    except httpx.TimeoutException:
        return unavailable(RazorpayGroundingReason.TIMEOUT, endpoints)
    except httpx.NetworkError:
        return unavailable(RazorpayGroundingReason.NETWORK_FAILED, endpoints)
    except httpx.HTTPError:
        return unavailable(RazorpayGroundingReason.PROVIDER_FAILED, endpoints)

    linkage_consistent = order.entity == "order" and order.id == payment.order_id
    amount_consistent = bool(
        payment.amount == order.amount == order.amount_paid and order.amount_due == 0
    )
    currency_consistent = payment.currency == order.currency
    if not (
        linkage_consistent and order.status == "paid" and amount_consistent and currency_consistent
    ):
        return unavailable(RazorpayGroundingReason.RESOURCE_INELIGIBLE, endpoints)

    profile = CapturedPaymentProfile(amount=payment.amount, currency=payment.currency)
    resource_snapshot_fingerprint = fingerprint_json(
        {
            "payment": {
                "id_fingerprint": _resource_fingerprint("PAYMENT_ID", payment.id),
                "amount": payment.amount,
                "currency": payment.currency,
                "status": payment.status,
                "captured": payment.captured,
                "amount_refunded": payment.amount_refunded,
                "refund_status": payment.refund_status,
                "order_id_fingerprint": _resource_fingerprint("ORDER_ID", order.id),
            },
            "order": {
                "id_fingerprint": _resource_fingerprint("ORDER_ID", order.id),
                "amount": order.amount,
                "amount_paid": order.amount_paid,
                "amount_due": order.amount_due,
                "currency": order.currency,
                "status": order.status,
            },
        }
    )
    projection_fingerprint = fingerprint_json(profile)
    return GroundingAcquisitionResult(
        snapshot=_snapshot(
            run_id=run_id,
            acquired_at=timestamp,
            status=RazorpayGroundingStatus.GROUNDED,
            source_endpoint_kinds=endpoints,
            key_id_fingerprint=_resource_fingerprint("KEY_ID", key_id),
            payment_id_fingerprint=_resource_fingerprint("PAYMENT_ID", payment.id),
            order_id_fingerprint=_resource_fingerprint("ORDER_ID", order.id),
            resource_snapshot_fingerprint=resource_snapshot_fingerprint,
            sanitized_projection_fingerprint=projection_fingerprint,
            payment_captured=True,
            order_paid=True,
            linkage_consistent=True,
            amount_consistent=True,
            currency_consistent=True,
            no_current_refund=True,
        ),
        profile=profile,
    )
