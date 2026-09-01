"""Pinned SG-01 input construction and deterministic invariant evaluation."""

from __future__ import annotations

from stateguard.contracts.common import (
    NormalControlId,
    RuntimeRequestId,
    ScenarioExecutionId,
)
from stateguard.contracts.identity import fingerprint_json
from stateguard.rules.razorpay import RazorpayProtocolRuleId, razorpay_rule_fingerprint
from stateguard.runtime.contracts import RuntimeObservationEvent, RuntimeObservationKind

from .captured_webhook import (
    CAPTURED_FIXTURE_ID,
    PreparedCapturedWebhook,
    prepare_captured_webhook,
)
from .contracts import (
    CustomerTargetObservationSummary,
    EvidenceTier,
    ScenarioResultReasonCode,
    VerificationResultState,
)

SG01_DEFINITION_FINGERPRINT = fingerprint_json(
    {
        "scenario": "SG-01",
        "definition_version": 1,
        "fixture_id": CAPTURED_FIXTURE_ID,
        "invariant": "exact correlated customer-value target entry cardinality",
        "terminal_requirement": "one normal Python terminal return for pass",
        "rules": (
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY),
        ),
    }
)


def prepare_sg01_request(
    *,
    execution_id: ScenarioExecutionId,
    path: str,
    secret: str,
) -> PreparedCapturedWebhook:
    return prepare_captured_webhook(
        execution_id=execution_id,
        path=path,
        secret=secret,
    )


def summarize_observations(
    events: tuple[RuntimeObservationEvent, ...],
    *,
    request_id: RuntimeRequestId,
    normal_control_id: NormalControlId,
    http_status_code: int,
) -> CustomerTargetObservationSummary:
    correlated = tuple(item for item in events if item.request_id == request_id)

    def sequences(kind: RuntimeObservationKind, *, exact_control: bool = False) -> tuple[int, ...]:
        return tuple(
            item.sequence
            for item in correlated
            if item.kind == kind
            and (not exact_control or item.normal_control_id == normal_control_id)
        )

    entered = sequences(RuntimeObservationKind.CUSTOMER_VALUE_ENTERED, exact_control=True)
    returned = sequences(
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY, exact_control=True
    )
    escaped = sequences(RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED, exact_control=True)
    return CustomerTargetObservationSummary(
        entered_count=len(entered),
        returned_normally_count=len(returned),
        exception_escaped_count=len(escaped),
        entered_sequences=entered,
        returned_normally_sequences=returned,
        exception_escaped_sequences=escaped,
        request_received_sequences=sequences(RuntimeObservationKind.REQUEST_RECEIVED),
        response_completed_sequences=sequences(RuntimeObservationKind.RESPONSE_COMPLETED),
        request_aborted_sequences=sequences(RuntimeObservationKind.REQUEST_ABORTED),
        http_status_code=http_status_code,
    )


def evaluate_observations(
    summary: CustomerTargetObservationSummary,
) -> tuple[VerificationResultState, EvidenceTier | None, ScenarioResultReasonCode]:
    if len(summary.request_received_sequences) != 1:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if summary.entered_count > 1:
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.EXACT_TARGET_ENTERED_MULTIPLE_TIMES,
        )
    if summary.entered_count == 0:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
        )
    if summary.returned_normally_count != 1 or summary.exception_escaped_count != 0:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.TARGET_TERMINAL_UNPROVEN,
        )
    normally_completed = (
        len(summary.response_completed_sequences) == 1
        and not summary.request_aborted_sequences
        and summary.http_status_code is not None
        and 200 <= summary.http_status_code < 300
    )
    if not normally_completed:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    return (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.EXACT_TARGET_ENTERED_ONCE,
    )
