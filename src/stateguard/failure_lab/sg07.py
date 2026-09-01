"""SG-07 webhook-only outcome reduction for a deliberately absent callback."""

from __future__ import annotations

from stateguard.contracts.identity import fingerprint_json
from stateguard.rules.razorpay import RazorpayProtocolRuleId, razorpay_rule_fingerprint

from .contracts import (
    CustomerTargetObservationSummary,
    EvidenceTier,
    ScenarioResultReasonCode,
    VerificationResultState,
)
from .sg01 import evaluate_observations as evaluate_normal_control

SG07_DEFINITION_FINGERPRINT = fingerprint_json(
    {
        "scenario": "SG-07",
        "definition_version": 1,
        "condition": "Checkout callback omitted; captured webhook delivered",
        "invariant": "server-side path reaches the exact customer outcome once",
        "rules": (
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY),
        ),
    }
)


def evaluate_webhook_only(
    summary: CustomerTargetObservationSummary,
) -> tuple[VerificationResultState, EvidenceTier | None, ScenarioResultReasonCode]:
    result, tier, reason = evaluate_normal_control(summary)
    if result == VerificationResultState.VERIFIED_PASS:
        return result, tier, ScenarioResultReasonCode.WEBHOOK_ONLY_TARGET_ENTERED_ONCE
    if result == VerificationResultState.VERIFIED_FAIL:
        return result, tier, ScenarioResultReasonCode.WEBHOOK_ONLY_TARGET_ENTERED_MULTIPLE_TIMES
    return result, tier, reason
