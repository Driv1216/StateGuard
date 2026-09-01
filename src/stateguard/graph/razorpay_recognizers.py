"""Bounded Razorpay Python SDK recognizer metadata and safe constants."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import StrEnum


class RazorpaySdkRecognizerId(StrEnum):
    WEBHOOK_VERIFIER_RAISES = "RZP-PYSDK-WEBHOOK-VERIFIER-RAISES-001"
    CHECKOUT_VERIFIER_RAISES = "RZP-PYSDK-CHECKOUT-VERIFIER-RAISES-001"


@dataclass(frozen=True)
class RazorpaySdkRecognizer:
    recognizer_id: RazorpaySdkRecognizerId
    method_name: str
    mismatch_behavior: str
    source_url: str
    verified_on: date


_SDK_SOURCE = "https://github.com/razorpay/razorpay-python/blob/master/razorpay/utility/utility.py"
_VERIFIED_ON = date(2026, 8, 25)

RAZORPAY_SDK_RECOGNIZERS = (
    RazorpaySdkRecognizer(
        recognizer_id=RazorpaySdkRecognizerId.WEBHOOK_VERIFIER_RAISES,
        method_name="verify_webhook_signature",
        mismatch_behavior="RAISES_SIGNATURE_VERIFICATION_ERROR",
        source_url=_SDK_SOURCE,
        verified_on=_VERIFIED_ON,
    ),
    RazorpaySdkRecognizer(
        recognizer_id=RazorpaySdkRecognizerId.CHECKOUT_VERIFIER_RAISES,
        method_name="verify_payment_signature",
        mismatch_behavior="RAISES_SIGNATURE_VERIFICATION_ERROR",
        source_url=_SDK_SOURCE,
        verified_on=_VERIFIED_ON,
    ),
)

PAYMENT_EVENTS = frozenset(
    {"payment.authorized", "payment.captured", "payment.failed", "order.paid"}
)
CHECKOUT_IDENTIFIERS = frozenset({"razorpay_payment_id", "razorpay_order_id", "razorpay_signature"})
WEBHOOK_HEADERS = frozenset({"x-razorpay-signature", "x-razorpay-event-id"})
