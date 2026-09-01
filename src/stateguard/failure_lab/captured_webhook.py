"""Pinned, redacted captured-webhook fixture construction shared by Failure Lab scenarios."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from stateguard.contracts.common import ScenarioExecutionId, Sha256Digest
from stateguard.contracts.identity import canonical_json, fingerprint_json, sha256_digest
from stateguard.grounding.contracts import CapturedPaymentProfile
from stateguard.rules.razorpay import RazorpayProtocolRuleId, razorpay_rule_fingerprint

from .contracts import GroundedScenarioInputReference, ScenarioInputReference

CAPTURED_FIXTURE_ID = "RZP_PAYMENT_CAPTURED_SAMPLE_V1"
AUTHORIZED_FIXTURE_ID = "RZP_PAYMENT_AUTHORIZED_SAMPLE_V1"
_FIXTURE_TEMPLATE = {
    "account_id": "acc_STATEGUARD_REDACTED",
    "contains": ["payment"],
    "created_at": 1_700_000_000,
    "entity": "event",
    "event": "payment.captured",
    "payload": {
        "payment": {
            "entity": {
                "acquirer_data": {"bank_transaction_id": "STATEGUARD_REDACTED"},
                "amount": 100,
                "amount_refunded": 0,
                "captured": True,
                "contact": "+910000000000",
                "created_at": 1_700_000_000,
                "currency": "INR",
                "description": "StateGuard offline synthetic fixture",
                "email": "redacted@example.invalid",
                "entity": "payment",
                "error_code": None,
                "error_description": None,
                "fee": 0,
                "id": "__PAYMENT_ID__",
                "international": False,
                "invoice_id": None,
                "method": "netbanking",
                "notes": [],
                "order_id": "__ORDER_ID__",
                "refund_status": None,
                "status": "captured",
                "tax": 0,
            }
        }
    },
}


@dataclass(frozen=True, repr=False)
class PreparedCapturedWebhook:
    raw_body: bytes
    headers: dict[str, str]
    fixture_fingerprint: Sha256Digest
    raw_body_fingerprint: Sha256Digest
    synthetic_event_id: str
    path: str
    grounding_fingerprint: Sha256Digest | None = None
    sanitized_projection_fingerprint: Sha256Digest | None = None

    def __repr__(self) -> str:
        return "PreparedCapturedWebhook(<redacted request material>)"

    def input_reference(self) -> ScenarioInputReference | GroundedScenarioInputReference:
        if (
            self.grounding_fingerprint is not None
            and self.sanitized_projection_fingerprint is not None
        ):
            return GroundedScenarioInputReference(
                fixture_fingerprint=self.fixture_fingerprint,
                raw_body_fingerprint=self.raw_body_fingerprint,
                synthetic_event_id=self.synthetic_event_id,
                path=self.path,
                grounding_fingerprint=self.grounding_fingerprint,
                sanitized_projection_fingerprint=self.sanitized_projection_fingerprint,
            )
        return ScenarioInputReference(
            fixture_fingerprint=self.fixture_fingerprint,
            raw_body_fingerprint=self.raw_body_fingerprint,
            synthetic_event_id=self.synthetic_event_id,
            path=self.path,
        )


def _synthetic_suffix(execution_id: ScenarioExecutionId) -> str:
    return hashlib.sha256(execution_id.encode("ascii")).hexdigest()[:20]


def captured_fixture_fingerprint(
    profile: CapturedPaymentProfile | None = None,
) -> Sha256Digest:
    entity = _FIXTURE_TEMPLATE["payload"]["payment"]["entity"]  # type: ignore[index]
    template = _FIXTURE_TEMPLATE
    if profile is not None:
        template = {
            **_FIXTURE_TEMPLATE,
            "payload": {
                "payment": {
                    "entity": {
                        **entity,
                        "amount": profile.amount,
                        "currency": profile.currency,
                        "status": profile.status,
                        "captured": profile.captured,
                    }
                }
            },
        }
    return fingerprint_json(
        {
            "fixture_id": CAPTURED_FIXTURE_ID,
            "template": template,
            "rule": razorpay_rule_fingerprint(
                RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT
            ),
        }
    )


def payment_event_fixture_fingerprint(event: str) -> Sha256Digest:
    normalized = event.removeprefix("payment.")
    fixture_id = CAPTURED_FIXTURE_ID if normalized == "captured" else AUTHORIZED_FIXTURE_ID
    template = {
        **_FIXTURE_TEMPLATE,
        "event": f"payment.{normalized}",
        "payload": {
            "payment": {
                "entity": {
                    **_FIXTURE_TEMPLATE["payload"]["payment"]["entity"],  # type: ignore[index]
                    "captured": normalized == "captured",
                    "status": normalized,
                }
            }
        },
    }
    return fingerprint_json(
        {
            "fixture_id": fixture_id,
            "template": template,
            "rule": razorpay_rule_fingerprint(
                RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT
                if normalized == "captured"
                else RazorpayProtocolRuleId.PAYMENT_AUTHORIZED_WEBHOOK_EVENT
            ),
        }
    )


def prepare_payment_webhook_event(
    *,
    execution_id: ScenarioExecutionId,
    path: str,
    secret: str,
    event: str,
    event_id_suffix: str,
) -> PreparedCapturedWebhook:
    normalized = event.removeprefix("payment.")
    if normalized not in {"authorized", "captured"} or event_id_suffix not in {"a", "c"}:
        raise ValueError("supported payment event and matching sequence suffix are required")
    suffix = _synthetic_suffix(execution_id)
    entity = _FIXTURE_TEMPLATE["payload"]["payment"]["entity"]  # type: ignore[index]
    fixture = {
        **_FIXTURE_TEMPLATE,
        "event": f"payment.{normalized}",
        "payload": {
            "payment": {
                "entity": {
                    **entity,
                    "id": f"pay_{suffix}",
                    "order_id": f"order_{suffix}",
                    "captured": normalized == "captured",
                    "status": normalized,
                }
            }
        },
    }
    raw_body = canonical_json(fixture).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return PreparedCapturedWebhook(
        raw_body=raw_body,
        headers={
            "Content-Type": "application/json",
            "X-Razorpay-Signature": signature,
            "x-razorpay-event-id": f"evt_stateguard_{suffix}_{event_id_suffix}",
        },
        fixture_fingerprint=payment_event_fixture_fingerprint(normalized),
        raw_body_fingerprint=sha256_digest(raw_body),
        synthetic_event_id=f"evt_stateguard_{suffix}_{event_id_suffix}",
        path=path,
    )


def prepare_captured_webhook(
    *,
    execution_id: ScenarioExecutionId,
    path: str,
    secret: str,
    grounded_profile: CapturedPaymentProfile | None = None,
    grounding_fingerprint: Sha256Digest | None = None,
    sanitized_projection_fingerprint: Sha256Digest | None = None,
) -> PreparedCapturedWebhook:
    if (grounded_profile is None) != (
        grounding_fingerprint is None or sanitized_projection_fingerprint is None
    ):
        raise ValueError("grounded captured input requires the complete safe grounding reference")
    suffix = _synthetic_suffix(execution_id)
    entity = _FIXTURE_TEMPLATE["payload"]["payment"]["entity"]  # type: ignore[index]
    profile_values = (
        {
            "amount": grounded_profile.amount,
            "currency": grounded_profile.currency,
            "status": grounded_profile.status,
            "captured": grounded_profile.captured,
        }
        if grounded_profile is not None
        else {}
    )
    fixture = {
        **_FIXTURE_TEMPLATE,
        "payload": {
            "payment": {
                "entity": {
                    **entity,
                    **profile_values,
                    "id": f"pay_{suffix}",
                    "order_id": f"order_{suffix}",
                }
            }
        },
    }
    raw_body = canonical_json(fixture).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    event_id = f"evt_stateguard_{suffix}"
    return PreparedCapturedWebhook(
        raw_body=raw_body,
        headers={
            "Content-Type": "application/json",
            "X-Razorpay-Signature": signature,
            "x-razorpay-event-id": event_id,
        },
        fixture_fingerprint=captured_fixture_fingerprint(grounded_profile),
        raw_body_fingerprint=sha256_digest(raw_body),
        synthetic_event_id=event_id,
        path=path,
        grounding_fingerprint=grounding_fingerprint,
        sanitized_projection_fingerprint=sanitized_projection_fingerprint,
    )
