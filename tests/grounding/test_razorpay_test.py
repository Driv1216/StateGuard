from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from stateguard.contracts.identity import new_verification_run_id
from stateguard.grounding.contracts import (
    RazorpayGroundingReason,
    RazorpayGroundingStatus,
    RazorpayTestGroundingRequest,
)
from stateguard.grounding.razorpay import acquire_razorpay_test_grounding

NOW = datetime(2026, 8, 31, tzinfo=UTC)
KEY_ID = "rzp_test_stateGuardKey"
KEY_SECRET = "grounding-secret-sentinel"
PAYMENT_ID = "pay_StateGuardPayment"
ORDER_ID = "order_StateGuardOrder"


def _payment(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": PAYMENT_ID,
        "entity": "payment",
        "amount": 12500,
        "currency": "INR",
        "status": "captured",
        "captured": True,
        "order_id": ORDER_ID,
        "amount_refunded": 0,
        "refund_status": None,
        "email": "must-not-persist@example.invalid",
        "contact": "+910000000000",
        "method": "card",
        "notes": {"private": "must-not-persist"},
    }
    value.update(updates)
    return value


def _order(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": ORDER_ID,
        "entity": "order",
        "amount": 12500,
        "amount_paid": 12500,
        "amount_due": 0,
        "currency": "INR",
        "status": "paid",
        "receipt": "must-not-persist",
    }
    value.update(updates)
    return value


def _request() -> RazorpayTestGroundingRequest:
    return RazorpayTestGroundingRequest(payment_id_env="GROUNDING_PAYMENT_ID")


def _environment(*, key_id: str = KEY_ID, payment_id: str = PAYMENT_ID) -> dict[str, str]:
    return {
        "RAZORPAY_KEY_ID": key_id,
        "RAZORPAY_KEY_SECRET": KEY_SECRET,
        "GROUNDING_PAYMENT_ID": payment_id,
    }


def _transport(
    payment: dict[str, object] | None = None,
    order: dict[str, object] | None = None,
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.razorpay.com"
        assert request.url.scheme == "https"
        if request.url.path == f"/v1/payments/{PAYMENT_ID}":
            return httpx.Response(200, json=payment or _payment())
        if request.url.path == f"/v1/orders/{ORDER_ID}":
            return httpx.Response(200, json=order or _order())
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_success_fetches_exact_pair_and_persists_only_safe_fingerprints() -> None:
    result = acquire_razorpay_test_grounding(
        _request(),
        new_verification_run_id(),
        environment=_environment(),
        acquired_at=NOW,
        transport=_transport(),
    )

    assert result.snapshot.status == RazorpayGroundingStatus.GROUNDED
    assert result.profile is not None
    assert result.profile.amount == 12500
    assert result.profile.currency == "INR"
    assert result.snapshot.payment_captured is True
    assert result.snapshot.order_paid is True
    persisted = result.snapshot.model_dump_json()
    for forbidden in (
        KEY_ID,
        KEY_SECRET,
        PAYMENT_ID,
        ORDER_ID,
        "must-not-persist@example.invalid",
        "+910000000000",
        "card",
        "receipt",
        "private",
    ):
        assert forbidden not in persisted


@pytest.mark.parametrize(
    ("environment", "reason"),
    [
        ({}, RazorpayGroundingReason.MISSING_ENVIRONMENT),
        (
            _environment(key_id="rzp_live_forbidden"),
            RazorpayGroundingReason.LIVE_CREDENTIAL_REJECTED,
        ),
        (_environment(key_id="unknown_key"), RazorpayGroundingReason.INVALID_TEST_CREDENTIAL),
        (
            _environment(payment_id="order_not_a_payment"),
            RazorpayGroundingReason.INVALID_PAYMENT_REFERENCE,
        ),
    ],
)
def test_credentials_and_reference_fail_closed_before_network(
    environment: dict[str, str],
    reason: RazorpayGroundingReason,
) -> None:
    calls = 0

    def forbidden(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise AssertionError("network must not be reached")

    result = acquire_razorpay_test_grounding(
        _request(),
        new_verification_run_id(),
        environment=environment,
        acquired_at=NOW,
        transport=httpx.MockTransport(forbidden),
    )
    assert result.snapshot.status == RazorpayGroundingStatus.UNAVAILABLE
    assert result.snapshot.unavailable_reason == reason
    assert result.profile is None
    assert calls == 0


@pytest.mark.parametrize(
    ("status_code", "reason"),
    [
        (400, RazorpayGroundingReason.REQUEST_REJECTED),
        (401, RazorpayGroundingReason.AUTHENTICATION_FAILED),
        (403, RazorpayGroundingReason.AUTHENTICATION_FAILED),
        (404, RazorpayGroundingReason.RESOURCE_NOT_FOUND),
        (429, RazorpayGroundingReason.RATE_LIMITED),
        (500, RazorpayGroundingReason.PROVIDER_FAILED),
        (302, RazorpayGroundingReason.PROVIDER_FAILED),
    ],
)
def test_provider_statuses_are_bounded_without_raw_response(
    status_code: int,
    reason: RazorpayGroundingReason,
) -> None:
    raw = "raw-provider-secret-sentinel"
    result = acquire_razorpay_test_grounding(
        _request(),
        new_verification_run_id(),
        environment=_environment(),
        acquired_at=NOW,
        transport=httpx.MockTransport(lambda _: httpx.Response(status_code, json={"error": raw})),
    )
    assert result.snapshot.unavailable_reason == reason
    assert raw not in result.snapshot.model_dump_json()


def test_redirects_are_never_followed_to_an_alternate_host() -> None:
    requests: list[httpx.Request] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"Location": "https://example.invalid/private"})

    result = acquire_razorpay_test_grounding(
        _request(),
        new_verification_run_id(),
        environment=_environment(),
        acquired_at=NOW,
        transport=httpx.MockTransport(redirect),
    )
    assert result.snapshot.unavailable_reason == RazorpayGroundingReason.PROVIDER_FAILED
    assert len(requests) == 1
    assert requests[0].url.host == "api.razorpay.com"


@pytest.mark.parametrize(
    "payment,order",
    [
        (_payment(entity="refund"), _order()),
        (_payment(status="authorized", captured=False), _order()),
        (_payment(amount_refunded=1, refund_status="partial"), _order()),
        (_payment(), _order(status="attempted")),
        (_payment(), _order(amount_paid=100, amount_due=12400)),
        (_payment(), _order(currency="USD")),
        (_payment(), _order(id="order_Different")),
    ],
)
def test_ineligible_or_inconsistent_resources_do_not_ground(
    payment: dict[str, object], order: dict[str, object]
) -> None:
    result = acquire_razorpay_test_grounding(
        _request(),
        new_verification_run_id(),
        environment=_environment(),
        acquired_at=NOW,
        transport=_transport(payment, order),
    )
    assert result.snapshot.status == RazorpayGroundingStatus.UNAVAILABLE
    assert result.snapshot.unavailable_reason == RazorpayGroundingReason.RESOURCE_INELIGIBLE
    assert result.profile is None


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (httpx.Response(200, content=b"{"), RazorpayGroundingReason.MALFORMED_RESPONSE),
        (
            httpx.Response(200, content=b"x" * (64 * 1024 + 1)),
            RazorpayGroundingReason.RESPONSE_TOO_LARGE,
        ),
    ],
)
def test_malformed_and_oversized_responses_degrade_safely(
    response: httpx.Response,
    reason: RazorpayGroundingReason,
) -> None:
    result = acquire_razorpay_test_grounding(
        _request(),
        new_verification_run_id(),
        environment=_environment(),
        acquired_at=NOW,
        transport=httpx.MockTransport(lambda _: response),
    )
    assert result.snapshot.unavailable_reason == reason


def test_network_and_timeout_failures_degrade_without_exception_text() -> None:
    for exception, reason in (
        (httpx.ConnectError("network-secret-sentinel"), RazorpayGroundingReason.NETWORK_FAILED),
        (httpx.ReadTimeout("timeout-secret-sentinel"), RazorpayGroundingReason.TIMEOUT),
    ):

        def fail(request: httpx.Request, error: Exception = exception) -> httpx.Response:
            if isinstance(error, httpx.RequestError):
                error.request = request
            raise error

        result = acquire_razorpay_test_grounding(
            _request(),
            new_verification_run_id(),
            environment=_environment(),
            acquired_at=NOW,
            transport=httpx.MockTransport(fail),
        )
        serialized = result.snapshot.model_dump_json()
        assert result.snapshot.unavailable_reason == reason
        assert "secret-sentinel" not in serialized


def test_snapshot_fingerprint_detects_tampering() -> None:
    result = acquire_razorpay_test_grounding(
        _request(),
        new_verification_run_id(),
        environment=_environment(),
        acquired_at=NOW,
        transport=_transport(),
    )
    payload = json.loads(result.snapshot.model_dump_json())
    payload["key_id_fingerprint"] = f"sha256:{'f' * 64}"
    with pytest.raises(ValueError, match="grounding fingerprint"):
        type(result.snapshot).model_validate(payload)
