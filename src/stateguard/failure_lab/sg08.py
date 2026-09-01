"""SG-08 modeled late-authorisation inputs with conservative business-context authority."""

from __future__ import annotations

from dataclasses import dataclass

from stateguard.contracts.common import ScenarioExecutionId, Sha256Digest
from stateguard.contracts.config import FulfilmentPolicy, LateAuthorisationPolicy
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
    LateAuthorisationEventReference,
    LateAuthorisationInputReference,
    LateAuthorisationPolicyReference,
    ScenarioResultReasonCode,
    VerificationResultState,
)

SG08_DEFINITION_FINGERPRINT = fingerprint_json(
    {
        "scenario": "SG-08",
        "definition_version": 1,
        "context_authority": "StateGuard-modeled; merchant late business state is not implied",
        "capture_sequence": "payment.authorized then payment.captured for one payment/order",
        "rules": (
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.PAYMENT_AUTHORIZED_WEBHOOK_EVENT),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.LATE_AUTHORISATION_BUSINESS_POLICY),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY),
        ),
    }
)


@dataclass(frozen=True, repr=False)
class PreparedSG08Requests:
    authorized: PreparedCapturedWebhook
    captured: PreparedCapturedWebhook | None
    input_reference: LateAuthorisationInputReference

    def __repr__(self) -> str:
        return "PreparedSG08Requests(<redacted request material>)"


def prepare_sg08_requests(
    *,
    execution_id: ScenarioExecutionId,
    path: str,
    secret: str,
    fulfilment: FulfilmentPolicy,
    fulfilment_evidence_fingerprint: Sha256Digest,
    late_authorisation: LateAuthorisationPolicy,
    late_authorisation_evidence_fingerprint: Sha256Digest,
    include_capture: bool,
) -> PreparedSG08Requests:
    authorized = prepare_payment_webhook_event(
        execution_id=execution_id,
        path=path,
        secret=secret,
        event="authorized",
        event_id_suffix="a",
    )
    captured = (
        prepare_payment_webhook_event(
            execution_id=execution_id,
            path=path,
            secret=secret,
            event="captured",
            event_id_suffix="c",
        )
        if include_capture
        and fulfilment == FulfilmentPolicy.CAPTURE_REQUIRED
        and late_authorisation == LateAuthorisationPolicy.FULFIL_LATER
        else None
    )
    events = [
        LateAuthorisationEventReference(
            role="MODELED_LATE_AUTHORIZED",
            fixture_id=AUTHORIZED_FIXTURE_ID,
            fixture_fingerprint=authorized.fixture_fingerprint,
            raw_body_fingerprint=authorized.raw_body_fingerprint,
            synthetic_event_id=authorized.synthetic_event_id,
        )
    ]
    if captured is not None:
        events.append(
            LateAuthorisationEventReference(
                role="CAPTURED_THRESHOLD_CONTROL",
                fixture_id=CAPTURED_FIXTURE_ID,
                fixture_fingerprint=captured.fixture_fingerprint,
                raw_body_fingerprint=captured.raw_body_fingerprint,
                synthetic_event_id=captured.synthetic_event_id,
            )
        )
    policy = LateAuthorisationPolicyReference(
        fulfilment=fulfilment,
        fulfilment_evidence_fingerprint=fulfilment_evidence_fingerprint,
        late_authorisation=late_authorisation,
        late_authorisation_evidence_fingerprint=late_authorisation_evidence_fingerprint,
    )
    reference = LateAuthorisationInputReference(
        context_fingerprint=fingerprint_json(
            {
                "execution_id": execution_id,
                "context": "modeled payment.authorized notification; merchant late state unproven",
                "policy": policy,
            }
        ),
        policy=policy,
        path=path,
        events=tuple(events),
    )
    return PreparedSG08Requests(
        authorized=authorized,
        captured=captured,
        input_reference=reference,
    )


def evaluate_precapture(
    authorized: CustomerTargetObservationSummary,
    captured: CustomerTargetObservationSummary | None,
    *,
    late_authorisation: LateAuthorisationPolicy,
) -> tuple[VerificationResultState, EvidenceTier | None, ScenarioResultReasonCode]:
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
            ScenarioResultReasonCode.AUTHORIZED_EXECUTED_BEFORE_CAPTURE,
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
    if late_authorisation == LateAuthorisationPolicy.DO_NOT_FULFIL or captured is None:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.MERCHANT_LATE_CONTEXT_UNPROVEN,
        )
    if (
        captured.entered_count == captured.returned_normally_count == 1
        and captured.exception_escaped_count == 0
        and len(captured.request_received_sequences) == 1
        and len(captured.response_completed_sequences) == 1
        and not captured.request_aborted_sequences
        and captured.http_status_code is not None
        and 200 <= captured.http_status_code < 300
    ):
        return (
            VerificationResultState.VERIFIED_PASS,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.AUTHORIZED_ADDED_NO_TARGET_ENTRY,
        )
    return (
        VerificationResultState.UNVERIFIED,
        None,
        ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
    )


def evaluate_capture_sequence(
    authorized: CustomerTargetObservationSummary,
    captured: CustomerTargetObservationSummary,
) -> tuple[VerificationResultState, EvidenceTier | None, ScenarioResultReasonCode]:
    if len(authorized.request_received_sequences) != 1:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if (
        len(authorized.response_completed_sequences) != 1
        or authorized.request_aborted_sequences
        or authorized.http_status_code is None
        or not 200 <= authorized.http_status_code < 300
    ):
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if authorized.entered_count > 0:
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.AUTHORIZED_EXECUTED_BEFORE_CAPTURE,
        )
    if len(captured.request_received_sequences) != 1:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if captured.entered_count > 1:
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.CAPTURED_THRESHOLD_MULTIPLE_TARGET_ENTRIES,
        )
    if captured.entered_count == 0:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
        )
    if captured.returned_normally_count != 1 or captured.exception_escaped_count:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.TARGET_TERMINAL_UNPROVEN,
        )
    if (
        len(captured.response_completed_sequences) != 1
        or captured.request_aborted_sequences
        or captured.http_status_code is None
        or not 200 <= captured.http_status_code < 300
    ):
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    return (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.CAPTURED_THRESHOLD_TARGET_ENTERED_ONCE,
    )
