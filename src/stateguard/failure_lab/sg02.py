"""SG-02 sequential duplicate-webhook definition and deterministic invariant reduction."""

from __future__ import annotations

from stateguard.contracts.identity import fingerprint_json
from stateguard.rules.razorpay import RazorpayProtocolRuleId, razorpay_rule_fingerprint

from .captured_webhook import CAPTURED_FIXTURE_ID
from .contracts import (
    CustomerTargetObservationSummary,
    EvidenceTier,
    ScenarioResultReasonCode,
    VerificationResultState,
)
from .sg01 import evaluate_observations as evaluate_normal_control

SG02_DEFINITION_FINGERPRINT = fingerprint_json(
    {
        "scenario": "SG-02",
        "definition_version": 1,
        "fixture_id": CAPTURED_FIXTURE_ID,
        "sequence": "the same captured webhook event is delivered twice sequentially",
        "positive_control": "delivery one satisfies the SG-01 normal lifecycle",
        "invariant": "total exact correlated customer-value target entries are at most one",
        "rules": (
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.WEBHOOK_DUPLICATE_DELIVERY),
        ),
    }
)


def evaluate_sequence(
    first: CustomerTargetObservationSummary,
    second: CustomerTargetObservationSummary,
) -> tuple[VerificationResultState, EvidenceTier | None, ScenarioResultReasonCode]:
    first_result = evaluate_normal_control(first)
    if first_result[0] == VerificationResultState.VERIFIED_FAIL:
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.NORMAL_CONTROL_MULTIPLE_TARGET_ENTRIES,
        )
    if first_result[0] != VerificationResultState.VERIFIED_PASS:
        return first_result
    if len(second.request_received_sequences) != 1:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if second.entered_count > 0:
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.DUPLICATE_DELIVERY_ADDED_TARGET_ENTRY,
        )
    if second.returned_normally_count or second.exception_escaped_count:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.TARGET_TERMINAL_UNPROVEN,
        )
    if len(second.response_completed_sequences) != 1 or second.request_aborted_sequences:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    return (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.DUPLICATE_DELIVERY_ADDED_NO_TARGET_ENTRY,
    )
