"""SG-05 rejected-signature construction and deterministic invariant reduction."""

from __future__ import annotations

from dataclasses import dataclass

from stateguard.contracts.common import GraphNodeId, RuntimeRequestId, ScenarioExecutionId
from stateguard.contracts.identity import fingerprint_json
from stateguard.rules.razorpay import RazorpayProtocolRuleId, razorpay_rule_fingerprint
from stateguard.runtime.contracts import RuntimeObservationEvent, RuntimeObservationKind

from .captured_webhook import CAPTURED_FIXTURE_ID, prepare_captured_webhook
from .contracts import (
    CustomerTargetObservationSummary,
    EvidenceTier,
    MutationScenarioRequestObservation,
    MutationTargetObservationSummary,
    ScenarioInputReference,
    ScenarioResultReasonCode,
    VerificationResultState,
)
from .sg01 import evaluate_observations as evaluate_normal_control

SG05_DEFINITION_FINGERPRINT = fingerprint_json(
    {
        "scenario": "SG-05",
        "definition_version": 1,
        "fixture_id": CAPTURED_FIXTURE_ID,
        "sequence": "rejected signature first, valid signature control second",
        "adversarial_variation": "one deterministic hexadecimal signature nibble",
        "customer_invariant": "rejected request does not enter exact customer target",
        "mutation_invariant": "rejected request completes no exact mutation instruction",
        "rules": (
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY),
        ),
    }
)


@dataclass(frozen=True, repr=False)
class PreparedSG05Requests:
    raw_body: bytes
    rejected_headers: dict[str, str]
    valid_headers: dict[str, str]
    input_reference: ScenarioInputReference

    def __repr__(self) -> str:
        return "PreparedSG05Requests(<redacted request material>)"


def _rejected_signature(valid_signature: str) -> str:
    if len(valid_signature) != 64 or any(
        character not in "0123456789abcdef" for character in valid_signature
    ):
        raise ValueError("valid webhook signature must be a lowercase SHA-256 hex digest")
    replacement = "0" if valid_signature[0] != "0" else "1"
    return f"{replacement}{valid_signature[1:]}"


def prepare_sg05_requests(
    *,
    execution_id: ScenarioExecutionId,
    path: str,
    secret: str,
) -> PreparedSG05Requests:
    prepared = prepare_captured_webhook(
        execution_id=execution_id,
        path=path,
        secret=secret,
    )
    valid_headers = dict(prepared.headers)
    rejected_headers = dict(valid_headers)
    rejected_headers["X-Razorpay-Signature"] = _rejected_signature(
        valid_headers["X-Razorpay-Signature"]
    )
    return PreparedSG05Requests(
        raw_body=prepared.raw_body,
        rejected_headers=rejected_headers,
        valid_headers=valid_headers,
        input_reference=prepared.input_reference(),
    )


def evaluate_customer_sequence(
    rejected: CustomerTargetObservationSummary,
    control: CustomerTargetObservationSummary,
) -> tuple[VerificationResultState, EvidenceTier | None, ScenarioResultReasonCode]:
    if len(rejected.request_received_sequences) != 1:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if rejected.entered_count > 0:
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.REJECTED_SIGNATURE_ADDED_CUSTOMER_TARGET_ENTRY,
        )
    if rejected.returned_normally_count or rejected.exception_escaped_count:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.TARGET_TERMINAL_UNPROVEN,
        )
    if len(rejected.response_completed_sequences) != 1 or rejected.request_aborted_sequences:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if evaluate_normal_control(control)[0] != VerificationResultState.VERIFIED_PASS:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.VALID_SIGNATURE_CONTROL_UNPROVEN,
        )
    return (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.REJECTED_SIGNATURE_ADDED_NO_CUSTOMER_TARGET_ENTRY,
    )


def summarize_mutation_observations(
    events: tuple[RuntimeObservationEvent, ...],
    *,
    request_id: RuntimeRequestId,
    mutation_node_ids: tuple[GraphNodeId, ...],
    http_status_code: int,
) -> MutationScenarioRequestObservation:
    correlated = tuple(item for item in events if item.request_id == request_id)

    def lifecycle_sequences(kind: RuntimeObservationKind) -> tuple[int, ...]:
        return tuple(item.sequence for item in correlated if item.kind == kind)

    def mutation_sequences(
        mutation_node_id: GraphNodeId,
        kind: RuntimeObservationKind,
    ) -> tuple[int, ...]:
        return tuple(
            item.sequence
            for item in correlated
            if item.kind == kind and item.mutation_node_id == mutation_node_id
        )

    targets = []
    for mutation_node_id in mutation_node_ids:
        reached = mutation_sequences(
            mutation_node_id,
            RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_REACHED,
        )
        completed = mutation_sequences(
            mutation_node_id,
            RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_COMPLETED_NORMALLY,
        )
        raised = mutation_sequences(
            mutation_node_id,
            RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_RAISED,
        )
        targets.append(
            MutationTargetObservationSummary(
                mutation_node_id=mutation_node_id,
                reached_count=len(reached),
                completed_normally_count=len(completed),
                raised_count=len(raised),
                reached_sequences=reached,
                completed_normally_sequences=completed,
                raised_sequences=raised,
            )
        )
    return MutationScenarioRequestObservation(
        request_id=request_id,
        mutation_targets=tuple(targets),
        request_received_sequences=lifecycle_sequences(RuntimeObservationKind.REQUEST_RECEIVED),
        response_completed_sequences=lifecycle_sequences(RuntimeObservationKind.RESPONSE_COMPLETED),
        request_aborted_sequences=lifecycle_sequences(RuntimeObservationKind.REQUEST_ABORTED),
        http_status_code=http_status_code,
    )


def evaluate_mutation_sequence(
    rejected: MutationScenarioRequestObservation,
    control: MutationScenarioRequestObservation,
) -> tuple[VerificationResultState, EvidenceTier | None, ScenarioResultReasonCode]:
    rejected_ids = tuple(item.mutation_node_id for item in rejected.mutation_targets)
    control_ids = tuple(item.mutation_node_id for item in control.mutation_targets)
    if rejected_ids != control_ids:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
        )
    if len(rejected.request_received_sequences) != 1:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if any(item.completed_normally_count > 0 for item in rejected.mutation_targets):
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.REJECTED_SIGNATURE_COMPLETED_MUTATION,
        )
    if any(item.reached_count > 0 or item.raised_count > 0 for item in rejected.mutation_targets):
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.MUTATION_OUTCOME_UNPROVEN,
        )
    if len(rejected.response_completed_sequences) != 1 or rejected.request_aborted_sequences:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    control_normal = bool(
        len(control.request_received_sequences) == 1
        and len(control.response_completed_sequences) == 1
        and not control.request_aborted_sequences
        and control.http_status_code is not None
        and 200 <= control.http_status_code < 300
        and all(
            item.reached_count >= 1
            and item.completed_normally_count == item.reached_count
            and item.raised_count == 0
            for item in control.mutation_targets
        )
    )
    if not control_normal:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.VALID_SIGNATURE_CONTROL_UNPROVEN,
        )
    return (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.REJECTED_SIGNATURE_ADDED_NO_MUTATION,
    )
