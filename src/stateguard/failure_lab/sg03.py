"""SG-03 modeled retry after an exact StateGuard-injected acknowledgement failure."""

from __future__ import annotations

from stateguard.contracts.common import GraphNodeId, RuntimeRequestId
from stateguard.contracts.identity import fingerprint_json
from stateguard.rules.razorpay import RazorpayProtocolRuleId, razorpay_rule_fingerprint
from stateguard.runtime.contracts import RuntimeObservationEvent, RuntimeObservationKind

from .captured_webhook import CAPTURED_FIXTURE_ID
from .contracts import (
    AcknowledgementFailureObservation,
    EvidenceTier,
    ScenarioRequestObservation,
    ScenarioResultReasonCode,
    VerificationResultState,
)

SG03_DEFINITION_FINGERPRINT = fingerprint_json(
    {
        "scenario": "SG-03",
        "definition_version": 1,
        "fixture_id": CAPTURED_FIXTURE_ID,
        "sequence": "captured webhook with modeled failed acknowledgement, then modeled retry",
        "acknowledgement_model": "StateGuard forces an exact merchant 2xx to effective 503",
        "invariant": "the modeled retry adds no exact customer-value target entry",
        "rules": (
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.WEBHOOK_RETRY_ON_UNSUCCESSFUL_ACK),
        ),
    }
)


def summarize_acknowledgement_failure(
    events: tuple[RuntimeObservationEvent, ...],
    *,
    request_id: RuntimeRequestId,
    acknowledgement_node_id: GraphNodeId,
) -> AcknowledgementFailureObservation | None:
    matches = tuple(
        item
        for item in events
        if item.request_id == request_id
        and item.kind == RuntimeObservationKind.ACKNOWLEDGEMENT_FAILURE_INJECTED
        and item.acknowledgement_node_id == acknowledgement_node_id
        and item.original_status_code is not None
        and item.status_code == 503
    )
    if len(matches) != 1:
        return None
    event = matches[0]
    assert event.original_status_code is not None
    return AcknowledgementFailureObservation(
        acknowledgement_node_id=acknowledgement_node_id,
        original_status_code=event.original_status_code,
        effective_status_code=503,
        injection_sequence=event.sequence,
    )


def evaluate_sequence(
    first: ScenarioRequestObservation,
    retry: ScenarioRequestObservation,
) -> tuple[VerificationResultState, EvidenceTier | None, ScenarioResultReasonCode]:
    summary = first.observations
    injection = first.acknowledgement_failure
    injection_proven = bool(
        injection is not None
        and retry.acknowledgement_failure is None
        and len(summary.request_received_sequences) == 1
        and summary.response_completed_sequences
        and injection.injection_sequence < min(summary.response_completed_sequences)
        and summary.http_status_code == 503
        and not summary.request_aborted_sequences
    )
    if not injection_proven:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.MODELED_ACK_FAILURE_UNPROVEN,
        )
    assert injection is not None
    if len(retry.observations.request_received_sequences) != 1:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if summary.entered_count > 1:
        if (
            summary.returned_normally_count != summary.entered_count
            or summary.exception_escaped_count
            or max(summary.returned_normally_sequences) >= injection.injection_sequence
        ):
            return (
                VerificationResultState.UNVERIFIED,
                None,
                ScenarioResultReasonCode.TARGET_TERMINAL_UNPROVEN,
            )
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.INITIAL_DELIVERY_MULTIPLE_TARGET_ENTRIES,
        )
    if summary.entered_count == 0:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
        )
    if summary.returned_normally_count != 1 or summary.exception_escaped_count:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.TARGET_TERMINAL_UNPROVEN,
        )
    if max(summary.returned_normally_sequences) >= injection.injection_sequence:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.MODELED_ACK_FAILURE_UNPROVEN,
        )
    retry_summary = retry.observations
    if retry_summary.entered_count > 0:
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.MODELED_RETRY_ADDED_TARGET_ENTRY,
        )
    if retry_summary.returned_normally_count or retry_summary.exception_escaped_count:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.TARGET_TERMINAL_UNPROVEN,
        )
    retry_completed = bool(
        len(retry_summary.response_completed_sequences) == 1
        and not retry_summary.request_aborted_sequences
        and retry_summary.http_status_code is not None
        and 200 <= retry_summary.http_status_code < 300
    )
    if not retry_completed:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    return (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.MODELED_RETRY_ADDED_NO_TARGET_ENTRY,
    )
