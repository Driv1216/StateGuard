"""SG-04 out-of-order webhook construction and deterministic reductions."""

from __future__ import annotations

from dataclasses import dataclass

from stateguard.contracts.common import ScenarioExecutionId
from stateguard.contracts.identity import fingerprint_json
from stateguard.rules.razorpay import RazorpayProtocolRuleId, razorpay_rule_fingerprint

from .captured_webhook import (
    AUTHORIZED_FIXTURE_ID,
    CAPTURED_FIXTURE_ID,
    PreparedCapturedWebhook,
    prepare_payment_webhook_event,
)
from .contracts import (
    CustomerTargetObservationSummary,
    EvidenceTier,
    MutationScenarioRequestObservation,
    ScenarioResultReasonCode,
    VerificationResultState,
    WebhookSequenceEventReference,
    WebhookSequenceInputReference,
)
from .sg01 import evaluate_observations as evaluate_normal_control

SG04_DEFINITION_FINGERPRINT = fingerprint_json(
    {
        "scenario": "SG-04",
        "definition_version": 1,
        "sequence": "payment.captured then stale payment.authorized for one payment/order",
        "customer_invariant": "stale event adds no exact customer-value target entry",
        "optional_state_invariant": "captured merchant state does not regress to authorized",
        "rules": (
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.WEBHOOK_ORDER_NOT_GUARANTEED),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY),
        ),
    }
)


@dataclass(frozen=True, repr=False)
class PreparedSG04Requests:
    captured: PreparedCapturedWebhook
    authorized: PreparedCapturedWebhook
    input_reference: WebhookSequenceInputReference

    def __repr__(self) -> str:
        return "PreparedSG04Requests(<redacted request material>)"


def prepare_sg04_requests(
    *, execution_id: ScenarioExecutionId, path: str, secret: str
) -> PreparedSG04Requests:
    captured = prepare_payment_webhook_event(
        execution_id=execution_id,
        path=path,
        secret=secret,
        event="captured",
        event_id_suffix="c",
    )
    authorized = prepare_payment_webhook_event(
        execution_id=execution_id,
        path=path,
        secret=secret,
        event="authorized",
        event_id_suffix="a",
    )
    context = fingerprint_json(
        {
            "execution_id": execution_id,
            "payment_identity_source": "shared deterministic execution suffix",
        }
    )
    reference = WebhookSequenceInputReference(
        context_fingerprint=context,
        path=path,
        events=(
            WebhookSequenceEventReference(
                role="CAPTURED_CONTROL",
                fixture_id=CAPTURED_FIXTURE_ID,
                fixture_fingerprint=captured.fixture_fingerprint,
                raw_body_fingerprint=captured.raw_body_fingerprint,
                synthetic_event_id=captured.synthetic_event_id,
            ),
            WebhookSequenceEventReference(
                role="STALE_AUTHORIZED",
                fixture_id=AUTHORIZED_FIXTURE_ID,
                fixture_fingerprint=authorized.fixture_fingerprint,
                raw_body_fingerprint=authorized.raw_body_fingerprint,
                synthetic_event_id=authorized.synthetic_event_id,
            ),
        ),
    )
    return PreparedSG04Requests(captured=captured, authorized=authorized, input_reference=reference)


def evaluate_customer_sequence(
    captured: CustomerTargetObservationSummary,
    authorized: CustomerTargetObservationSummary,
) -> tuple[VerificationResultState, EvidenceTier | None, ScenarioResultReasonCode]:
    first = evaluate_normal_control(captured)
    if first[0] == VerificationResultState.VERIFIED_FAIL:
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.OUT_OF_ORDER_CONTROL_MULTIPLE_TARGET_ENTRIES,
        )
    if first[0] != VerificationResultState.VERIFIED_PASS:
        return first
    if len(authorized.request_received_sequences) != 1:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if authorized.entered_count > 0:
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.STALE_AUTHORIZED_ADDED_TARGET_ENTRY,
        )
    if authorized.returned_normally_count or authorized.exception_escaped_count:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.TARGET_TERMINAL_UNPROVEN,
        )
    if len(authorized.response_completed_sequences) != 1 or authorized.request_aborted_sequences:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    return (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.STALE_AUTHORIZED_ADDED_NO_TARGET_ENTRY,
    )


def evaluate_state_sequence(
    captured: MutationScenarioRequestObservation,
    authorized: MutationScenarioRequestObservation,
    *,
    captured_node_id: str,
    authorized_node_id: str,
) -> tuple[VerificationResultState, EvidenceTier | None, ScenarioResultReasonCode]:
    if (
        len(captured.request_received_sequences) != 1
        or len(authorized.request_received_sequences) != 1
    ):
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    first = next(
        (item for item in captured.mutation_targets if item.mutation_node_id == captured_node_id),
        None,
    )
    stale = next(
        (
            item
            for item in authorized.mutation_targets
            if item.mutation_node_id == authorized_node_id
        ),
        None,
    )
    if first is None or stale is None:
        return VerificationResultState.UNVERIFIED, None, ScenarioResultReasonCode.AUTHORITY_MISMATCH
    if (
        first.completed_normally_count < 1
        or first.raised_count
        or first.reached_count != first.completed_normally_count
    ):
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.CAPTURED_STATE_CONTROL_UNPROVEN,
        )
    if stale.completed_normally_count > 0:
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.MERCHANT_STATE_REGRESSED_TO_AUTHORIZED,
        )
    if stale.reached_count or stale.raised_count:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.MUTATION_OUTCOME_UNPROVEN,
        )
    if len(authorized.response_completed_sequences) != 1 or authorized.request_aborted_sequences:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    return (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.MERCHANT_STATE_DID_NOT_REGRESS,
    )
