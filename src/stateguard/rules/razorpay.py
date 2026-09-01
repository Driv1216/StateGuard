"""Small curated catalog of Razorpay facts consumed by static recognizers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import StrEnum

from stateguard.contracts.common import Sha256Digest
from stateguard.contracts.identity import fingerprint_json


class RazorpayProtocolRuleId(StrEnum):
    PAYMENT_CAPTURED_WEBHOOK_EVENT = "RZP-PAYMENT-CAPTURED-WEBHOOK-EVENT-001"
    PAYMENT_AUTHORIZED_WEBHOOK_EVENT = "RZP-PAYMENT-AUTHORIZED-WEBHOOK-EVENT-001"
    WEBHOOK_SIGNATURE_RAW_BODY = "RZP-WEBHOOK-SIGNATURE-RAW-BODY-001"
    WEBHOOK_DUPLICATE_DELIVERY = "RZP-WEBHOOK-DUPLICATE-DELIVERY-001"
    WEBHOOK_ORDER_NOT_GUARANTEED = "RZP-WEBHOOK-ORDER-NOT-GUARANTEED-001"
    WEBHOOK_RETRY_ON_UNSUCCESSFUL_ACK = "RZP-WEBHOOK-RETRY-ON-UNSUCCESSFUL-ACK-001"
    CHECKOUT_SERVER_SIGNATURE_VERIFICATION = "RZP-CHECKOUT-SERVER-SIGNATURE-VERIFICATION-001"
    CHECKOUT_SERVER_ORDER_ID = "RZP-CHECKOUT-SERVER-ORDER-ID-001"
    CAPTURE_BEFORE_FULFILMENT = "RZP-CAPTURE-BEFORE-FULFILMENT-001"
    LATE_AUTHORISATION_BUSINESS_POLICY = "RZP-LATE-AUTHORISATION-BUSINESS-POLICY-001"


@dataclass(frozen=True)
class RazorpayProtocolFact:
    rule_id: RazorpayProtocolRuleId
    fact: str
    source_url: str
    verified_on: date
    recognizer_ids: tuple[str, ...]


_VERIFIED_ON = date(2026, 8, 25)
_WEBHOOK_DOC = "https://razorpay.com/docs/webhooks/validate-test/"
_PAYMENT_WEBHOOK_DOC = "https://razorpay.com/docs/webhooks/payments/"
_WEBHOOK_BEST_PRACTICES = "https://razorpay.com/docs/webhooks/best-practices/"
_CHECKOUT_DOC = (
    "https://razorpay.com/docs/payments/payment-gateway/web-integration/standard/integration-steps/"
)
_LATE_AUTHORISATION_DOC = "https://razorpay.com/docs/payments/payments/late-authorisation/handle/"

RAZORPAY_PROTOCOL_FACTS = (
    RazorpayProtocolFact(
        rule_id=RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT,
        fact=(
            "The payment.captured webhook event represents a payment captured state and its "
            "payload contains a captured payment entity snapshot."
        ),
        source_url=_PAYMENT_WEBHOOK_DOC,
        verified_on=date(2026, 8, 27),
        recognizer_ids=("SG-AST-PAYMENT-STATE-GATE-001",),
    ),
    RazorpayProtocolFact(
        rule_id=RazorpayProtocolRuleId.PAYMENT_AUTHORIZED_WEBHOOK_EVENT,
        fact=(
            "The payment.authorized webhook notifies a merchant when a payment moves to the "
            "Authorized state, including a payment expected to become late authorised."
        ),
        source_url=_LATE_AUTHORISATION_DOC,
        verified_on=date(2026, 8, 29),
        recognizer_ids=("SG-AST-PAYMENT-STATE-GATE-001",),
    ),
    RazorpayProtocolFact(
        rule_id=RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY,
        fact="Webhook signatures use HMAC-SHA256 over the raw request body.",
        source_url=_WEBHOOK_DOC,
        verified_on=_VERIFIED_ON,
        recognizer_ids=("SG-AST-WEBHOOK-SIGNATURE-001",),
    ),
    RazorpayProtocolFact(
        rule_id=RazorpayProtocolRuleId.WEBHOOK_DUPLICATE_DELIVERY,
        fact=(
            "Webhook delivery is at least once, so the same event may be delivered more than "
            "once; x-razorpay-event-id uniquely identifies the event for duplicate detection."
        ),
        source_url=_WEBHOOK_DOC,
        verified_on=date(2026, 8, 27),
        recognizer_ids=("SG-AST-EVENT-IDENTITY-GUARD-001",),
    ),
    RazorpayProtocolFact(
        rule_id=RazorpayProtocolRuleId.WEBHOOK_ORDER_NOT_GUARANTEED,
        fact="Webhook delivery order is not guaranteed.",
        source_url=_WEBHOOK_DOC,
        verified_on=_VERIFIED_ON,
        recognizer_ids=("SG-AST-PAYMENT-STATE-GATE-001",),
    ),
    RazorpayProtocolFact(
        rule_id=RazorpayProtocolRuleId.WEBHOOK_RETRY_ON_UNSUCCESSFUL_ACK,
        fact=(
            "A non-2xx webhook response is a delivery failure; Razorpay uses at-least-once "
            "delivery and may resend when processing occurred but no successful response was "
            "received within 5 seconds."
        ),
        source_url=_WEBHOOK_BEST_PRACTICES,
        verified_on=date(2026, 8, 29),
        recognizer_ids=("SG-AST-ACKNOWLEDGEMENT-001",),
    ),
    RazorpayProtocolFact(
        rule_id=RazorpayProtocolRuleId.CHECKOUT_SERVER_SIGNATURE_VERIFICATION,
        fact=(
            "Standard Checkout verification is performed on the merchant server using "
            "HMAC-SHA256 over order_id + '|' + razorpay_payment_id."
        ),
        source_url=_CHECKOUT_DOC,
        verified_on=date(2026, 8, 28),
        recognizer_ids=("SG-AST-CHECKOUT-SIGNATURE-001",),
    ),
    RazorpayProtocolFact(
        rule_id=RazorpayProtocolRuleId.CHECKOUT_SERVER_ORDER_ID,
        fact=(
            "Checkout verification uses the order ID retrieved from merchant server state, "
            "not the browser-returned order identity."
        ),
        source_url=_CHECKOUT_DOC,
        verified_on=date(2026, 8, 28),
        recognizer_ids=("SG-AST-SERVER-ORDER-BINDING-001",),
    ),
    RazorpayProtocolFact(
        rule_id=RazorpayProtocolRuleId.CAPTURE_BEFORE_FULFILMENT,
        fact=(
            "An authorised payment is not captured; Razorpay guidance recommends providing "
            "products or services only after capture."
        ),
        source_url=_CHECKOUT_DOC,
        verified_on=_VERIFIED_ON,
        recognizer_ids=("SG-AST-PAYMENT-STATE-GATE-001",),
    ),
    RazorpayProtocolFact(
        rule_id=RazorpayProtocolRuleId.LATE_AUTHORISATION_BUSINESS_POLICY,
        fact=(
            "Handling a late-authorised payment depends on whether the merchant can still "
            "provide the service."
        ),
        source_url=_LATE_AUTHORISATION_DOC,
        verified_on=date(2026, 8, 29),
        recognizer_ids=("SG-POLICY-LATE-AUTHORISATION-001",),
    ),
)

RAZORPAY_RULE_CATALOG_VERSION = 1


def razorpay_rule_fingerprint(rule_id: RazorpayProtocolRuleId) -> Sha256Digest:
    """Fingerprint one relevant curated rule revision, never the global catalog."""

    fact = next(item for item in RAZORPAY_PROTOCOL_FACTS if item.rule_id == rule_id)
    return fingerprint_json(
        {
            "rule_id": fact.rule_id.value,
            "fact": fact.fact,
            "source_url": fact.source_url,
            "verified_on": fact.verified_on.isoformat(),
            "recognizer_ids": fact.recognizer_ids,
        }
    )


def razorpay_rule_catalog_fingerprint() -> Sha256Digest:
    """Fingerprint the complete curated catalog without external documentation bodies."""

    return fingerprint_json(
        {
            "catalog_version": RAZORPAY_RULE_CATALOG_VERSION,
            "rules": tuple(
                {
                    "rule_id": fact.rule_id.value,
                    "rule_fingerprint": razorpay_rule_fingerprint(fact.rule_id),
                }
                for fact in sorted(RAZORPAY_PROTOCOL_FACTS, key=lambda item: item.rule_id.value)
            ),
        }
    )
