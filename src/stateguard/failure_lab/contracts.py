"""Minimal, redacted contracts for Step 6 scenario execution results."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from stateguard.applicability.contracts import ScenarioId
from stateguard.contracts.common import (
    ArtifactFields,
    AssertionId,
    GraphNodeId,
    NormalControlId,
    PersistedArtifactModel,
    RuntimeRequestId,
    RuntimeSessionId,
    ScenarioExecutionId,
    ScenarioInstanceId,
    Sha256Digest,
)
from stateguard.contracts.config import FulfilmentPolicy, LateAuthorisationPolicy
from stateguard.contracts.identity import fingerprint_json
from stateguard.runtime.contracts import RuntimeCapabilityReasonCode


class VerificationResultState(StrEnum):
    VERIFIED_PASS = "VERIFIED PASS"
    VERIFIED_FAIL = "VERIFIED FAIL"
    STATIC_WARNING = "STATIC WARNING"
    NEEDS_INPUT = "NEEDS INPUT"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "NOT APPLICABLE"


class EvidenceTier(StrEnum):
    E0_DISCOVERED = "E0 DISCOVERED"
    E1_RESOLVED = "E1 RESOLVED"
    E2_STATIC_VERIFIED = "E2 STATIC VERIFIED"
    E3_DYNAMIC_VERIFIED = "E3 DYNAMIC VERIFIED"
    E4_RAZORPAY_GROUNDED = "E4 RAZORPAY GROUNDED"


class ScenarioInputAuthority(StrEnum):
    STATEGUARD_OFFLINE_SYNTHETIC = "STATEGUARD_OFFLINE_SYNTHETIC"
    STATEGUARD_SYNTHETIC_FROM_RAZORPAY_TEST_RESOURCE = (
        "STATEGUARD_SYNTHETIC_FROM_RAZORPAY_TEST_RESOURCE"
    )


class ScenarioResultReasonCode(StrEnum):
    APPLICABILITY_NOT_APPLICABLE = "APPLICABILITY_NOT_APPLICABLE"
    APPLICABILITY_NEEDS_INPUT = "APPLICABILITY_NEEDS_INPUT"
    APPLICABILITY_INDETERMINATE = "APPLICABILITY_INDETERMINATE"
    STALE_APPLICABILITY_AUTHORITY = "STALE_APPLICABILITY_AUTHORITY"
    AUTHORITY_MISMATCH = "AUTHORITY_MISMATCH"
    RUNTIME_MODE_UNSUPPORTED = "RUNTIME_MODE_UNSUPPORTED"
    RUNTIME_SESSION_UNAVAILABLE = "RUNTIME_SESSION_UNAVAILABLE"
    RUNTIME_CAPABILITY_INSUFFICIENT = "RUNTIME_CAPABILITY_INSUFFICIENT"
    WEBHOOK_SECRET_UNAVAILABLE = "WEBHOOK_SECRET_UNAVAILABLE"
    CHECKOUT_SECRET_UNAVAILABLE = "CHECKOUT_SECRET_UNAVAILABLE"
    SERVER_ORDER_CONTROL_UNAVAILABLE = "SERVER_ORDER_CONTROL_UNAVAILABLE"
    REQUEST_EXECUTION_FAILED = "REQUEST_EXECUTION_FAILED"
    TRANSCRIPT_UNTRUSTWORTHY = "TRANSCRIPT_UNTRUSTWORTHY"
    REQUEST_LIFECYCLE_UNPROVEN = "REQUEST_LIFECYCLE_UNPROVEN"
    NORMAL_INPUT_PRECONDITION_UNPROVEN = "NORMAL_INPUT_PRECONDITION_UNPROVEN"
    TARGET_TERMINAL_UNPROVEN = "TARGET_TERMINAL_UNPROVEN"
    EXACT_TARGET_ENTERED_ONCE = "EXACT_TARGET_ENTERED_ONCE"
    EXACT_TARGET_ENTERED_MULTIPLE_TIMES = "EXACT_TARGET_ENTERED_MULTIPLE_TIMES"
    NORMAL_CONTROL_MULTIPLE_TARGET_ENTRIES = "NORMAL_CONTROL_MULTIPLE_TARGET_ENTRIES"
    DUPLICATE_DELIVERY_ADDED_TARGET_ENTRY = "DUPLICATE_DELIVERY_ADDED_TARGET_ENTRY"
    DUPLICATE_DELIVERY_ADDED_NO_TARGET_ENTRY = "DUPLICATE_DELIVERY_ADDED_NO_TARGET_ENTRY"
    REJECTED_SIGNATURE_ADDED_CUSTOMER_TARGET_ENTRY = (
        "REJECTED_SIGNATURE_ADDED_CUSTOMER_TARGET_ENTRY"
    )
    REJECTED_SIGNATURE_ADDED_NO_CUSTOMER_TARGET_ENTRY = (
        "REJECTED_SIGNATURE_ADDED_NO_CUSTOMER_TARGET_ENTRY"
    )
    REJECTED_SIGNATURE_COMPLETED_MUTATION = "REJECTED_SIGNATURE_COMPLETED_MUTATION"
    REJECTED_SIGNATURE_ADDED_NO_MUTATION = "REJECTED_SIGNATURE_ADDED_NO_MUTATION"
    VALID_SIGNATURE_CONTROL_UNPROVEN = "VALID_SIGNATURE_CONTROL_UNPROVEN"
    MUTATION_OUTCOME_UNPROVEN = "MUTATION_OUTCOME_UNPROVEN"
    OUT_OF_ORDER_CONTROL_MULTIPLE_TARGET_ENTRIES = "OUT_OF_ORDER_CONTROL_MULTIPLE_TARGET_ENTRIES"
    STALE_AUTHORIZED_ADDED_TARGET_ENTRY = "STALE_AUTHORIZED_ADDED_TARGET_ENTRY"
    STALE_AUTHORIZED_ADDED_NO_TARGET_ENTRY = "STALE_AUTHORIZED_ADDED_NO_TARGET_ENTRY"
    MERCHANT_STATE_REGRESSED_TO_AUTHORIZED = "MERCHANT_STATE_REGRESSED_TO_AUTHORIZED"
    MERCHANT_STATE_DID_NOT_REGRESS = "MERCHANT_STATE_DID_NOT_REGRESS"
    CAPTURED_STATE_CONTROL_UNPROVEN = "CAPTURED_STATE_CONTROL_UNPROVEN"
    TAMPERED_CALLBACK_ADDED_CUSTOMER_TARGET_ENTRY = "TAMPERED_CALLBACK_ADDED_CUSTOMER_TARGET_ENTRY"
    TAMPERED_CALLBACK_ADDED_NO_CUSTOMER_TARGET_ENTRY = (
        "TAMPERED_CALLBACK_ADDED_NO_CUSTOMER_TARGET_ENTRY"
    )
    TAMPERED_CALLBACK_COMPLETED_MUTATION = "TAMPERED_CALLBACK_COMPLETED_MUTATION"
    TAMPERED_CALLBACK_ADDED_NO_MUTATION = "TAMPERED_CALLBACK_ADDED_NO_MUTATION"
    VALID_CHECKOUT_CONTROL_UNPROVEN = "VALID_CHECKOUT_CONTROL_UNPROVEN"
    WEBHOOK_ONLY_TARGET_ENTERED_ONCE = "WEBHOOK_ONLY_TARGET_ENTERED_ONCE"
    WEBHOOK_ONLY_TARGET_ENTERED_MULTIPLE_TIMES = "WEBHOOK_ONLY_TARGET_ENTERED_MULTIPLE_TIMES"
    MODELED_ACK_FAILURE_UNPROVEN = "MODELED_ACK_FAILURE_UNPROVEN"
    INITIAL_DELIVERY_MULTIPLE_TARGET_ENTRIES = "INITIAL_DELIVERY_MULTIPLE_TARGET_ENTRIES"
    MODELED_RETRY_ADDED_TARGET_ENTRY = "MODELED_RETRY_ADDED_TARGET_ENTRY"
    MODELED_RETRY_ADDED_NO_TARGET_ENTRY = "MODELED_RETRY_ADDED_NO_TARGET_ENTRY"
    MERCHANT_LATE_CONTEXT_UNPROVEN = "MERCHANT_LATE_CONTEXT_UNPROVEN"
    AUTHORIZED_EXECUTED_BEFORE_CAPTURE = "AUTHORIZED_EXECUTED_BEFORE_CAPTURE"
    AUTHORIZED_ADDED_NO_TARGET_ENTRY = "AUTHORIZED_ADDED_NO_TARGET_ENTRY"
    CAPTURED_THRESHOLD_TARGET_ENTERED_ONCE = "CAPTURED_THRESHOLD_TARGET_ENTERED_ONCE"
    CAPTURED_THRESHOLD_MULTIPLE_TARGET_ENTRIES = "CAPTURED_THRESHOLD_MULTIPLE_TARGET_ENTRIES"


class ScenarioAuthorityReference(PersistedArtifactModel):
    applicability_fingerprint: Sha256Digest
    scenario_instance_id: ScenarioInstanceId
    normal_control_id: NormalControlId | None = None
    runtime_capability_fingerprint: Sha256Digest | None = None
    runtime_session_id: RuntimeSessionId | None = None
    runtime_request_ids: tuple[RuntimeRequestId, ...] = ()
    transcript_fingerprint: Sha256Digest | None = None

    @model_validator(mode="after")
    def validate_runtime_authority(self) -> ScenarioAuthorityReference:
        if self.runtime_request_ids and self.runtime_session_id is None:
            raise ValueError("runtime request authority requires a runtime session")
        if len(set(self.runtime_request_ids)) != len(self.runtime_request_ids):
            raise ValueError("runtime request authority must be unique and ordered")
        if self.transcript_fingerprint is not None and (
            self.runtime_capability_fingerprint is None or self.runtime_session_id is None
        ):
            raise ValueError("transcript authority requires capability and session authority")
        return self


class ScenarioInputReference(PersistedArtifactModel):
    authority: ScenarioInputAuthority = ScenarioInputAuthority.STATEGUARD_OFFLINE_SYNTHETIC
    fixture_id: Literal["RZP_PAYMENT_CAPTURED_SAMPLE_V1"] = "RZP_PAYMENT_CAPTURED_SAMPLE_V1"
    fixture_fingerprint: Sha256Digest
    raw_body_fingerprint: Sha256Digest
    synthetic_event_id: str = Field(pattern=r"^evt_stateguard_[0-9a-f]{20}$")
    method: Literal["POST"] = "POST"
    path: str = Field(min_length=1, max_length=4096)
    header_names: tuple[str, ...] = (
        "Content-Type",
        "X-Razorpay-Signature",
        "x-razorpay-event-id",
    )

    @model_validator(mode="after")
    def validate_safe_headers(self) -> ScenarioInputReference:
        if (
            type(self) is ScenarioInputReference
            and self.authority != ScenarioInputAuthority.STATEGUARD_OFFLINE_SYNTHETIC
        ):
            raise ValueError("offline scenario input requires offline synthetic authority")
        if self.header_names != (
            "Content-Type",
            "X-Razorpay-Signature",
            "x-razorpay-event-id",
        ):
            raise ValueError("scenario input reference may contain only fixed safe header names")
        return self


class GroundedScenarioInputReference(ScenarioInputReference):
    authority: ScenarioInputAuthority = (
        ScenarioInputAuthority.STATEGUARD_SYNTHETIC_FROM_RAZORPAY_TEST_RESOURCE
    )
    grounding_fingerprint: Sha256Digest
    sanitized_projection_fingerprint: Sha256Digest

    @model_validator(mode="after")
    def validate_grounded_authority(self) -> GroundedScenarioInputReference:
        if (
            self.authority
            != ScenarioInputAuthority.STATEGUARD_SYNTHETIC_FROM_RAZORPAY_TEST_RESOURCE
        ):
            raise ValueError("grounded scenario input requires Razorpay Test resource authority")
        return self


class WebhookSequenceEventReference(PersistedArtifactModel):
    role: Literal["CAPTURED_CONTROL", "STALE_AUTHORIZED"]
    fixture_id: Literal[
        "RZP_PAYMENT_CAPTURED_SAMPLE_V1",
        "RZP_PAYMENT_AUTHORIZED_SAMPLE_V1",
    ]
    fixture_fingerprint: Sha256Digest
    raw_body_fingerprint: Sha256Digest
    synthetic_event_id: str = Field(pattern=r"^evt_stateguard_[0-9a-f]{20}_[ca]$")


class WebhookSequenceInputReference(PersistedArtifactModel):
    input_kind: Literal["OUT_OF_ORDER_WEBHOOK_SEQUENCE"] = "OUT_OF_ORDER_WEBHOOK_SEQUENCE"
    context_fingerprint: Sha256Digest
    method: Literal["POST"] = "POST"
    path: str = Field(min_length=1, max_length=4096)
    events: tuple[WebhookSequenceEventReference, WebhookSequenceEventReference]

    @model_validator(mode="after")
    def validate_sequence(self) -> WebhookSequenceInputReference:
        if (
            tuple(item.role for item in self.events)
            != (
                "CAPTURED_CONTROL",
                "STALE_AUTHORIZED",
            )
            or len({item.synthetic_event_id for item in self.events}) != 2
        ):
            raise ValueError("out-of-order input must retain captured/authorized ordering")
        return self


class CheckoutRequestInputReference(PersistedArtifactModel):
    role: Literal["TAMPERED", "VALID_CONTROL"]
    request_material_fingerprint: Sha256Digest


class CheckoutSequenceInputReference(PersistedArtifactModel):
    input_kind: Literal["CHECKOUT_TAMPER_SEQUENCE"] = "CHECKOUT_TAMPER_SEQUENCE"
    transport: Literal["JSON", "FORM_URLENCODED", "QUERY"]
    method: Literal["POST"] = "POST"
    path: str = Field(min_length=1, max_length=4096)
    payment_context_fingerprint: Sha256Digest
    browser_order_mismatch: Literal[True] = True
    requests: tuple[CheckoutRequestInputReference, CheckoutRequestInputReference]

    @model_validator(mode="after")
    def validate_sequence(self) -> CheckoutSequenceInputReference:
        if tuple(item.role for item in self.requests) != ("TAMPERED", "VALID_CONTROL"):
            raise ValueError("Checkout input must retain tampered/control ordering")
        return self


class LateAuthorisationPolicyReference(PersistedArtifactModel):
    fulfilment: FulfilmentPolicy
    fulfilment_evidence_fingerprint: Sha256Digest
    late_authorisation: LateAuthorisationPolicy
    late_authorisation_evidence_fingerprint: Sha256Digest


class LateAuthorisationEventReference(PersistedArtifactModel):
    role: Literal["MODELED_LATE_AUTHORIZED", "CAPTURED_THRESHOLD_CONTROL"]
    fixture_id: Literal[
        "RZP_PAYMENT_AUTHORIZED_SAMPLE_V1",
        "RZP_PAYMENT_CAPTURED_SAMPLE_V1",
    ]
    fixture_fingerprint: Sha256Digest
    raw_body_fingerprint: Sha256Digest
    synthetic_event_id: str = Field(pattern=r"^evt_stateguard_[0-9a-f]{20}_[ca]$")


class LateAuthorisationInputReference(PersistedArtifactModel):
    input_kind: Literal["MODELED_LATE_AUTHORIZATION_SEQUENCE"] = (
        "MODELED_LATE_AUTHORIZATION_SEQUENCE"
    )
    context_authority: Literal["STATEGUARD_MODELED_NOT_MERCHANT_OBSERVED"] = (
        "STATEGUARD_MODELED_NOT_MERCHANT_OBSERVED"
    )
    context_fingerprint: Sha256Digest
    policy: LateAuthorisationPolicyReference
    method: Literal["POST"] = "POST"
    path: str = Field(min_length=1, max_length=4096)
    events: tuple[LateAuthorisationEventReference, ...] = Field(min_length=1, max_length=2)

    @model_validator(mode="after")
    def validate_sequence(self) -> LateAuthorisationInputReference:
        roles = tuple(item.role for item in self.events)
        allowed = (
            {
                ("MODELED_LATE_AUTHORIZED",),
                ("MODELED_LATE_AUTHORIZED", "CAPTURED_THRESHOLD_CONTROL"),
            }
            if self.policy.fulfilment == FulfilmentPolicy.CAPTURE_REQUIRED
            and self.policy.late_authorisation == LateAuthorisationPolicy.FULFIL_LATER
            else {("MODELED_LATE_AUTHORIZED",)}
        )
        if roles not in allowed:
            raise ValueError(
                "modeled late-authorisation input must match the exact policy sequence"
            )
        if self.events[0].fixture_id != "RZP_PAYMENT_AUTHORIZED_SAMPLE_V1":
            raise ValueError("modeled late-authorisation sequence must begin with authorization")
        if len(self.events) == 2 and self.events[1].fixture_id != "RZP_PAYMENT_CAPTURED_SAMPLE_V1":
            raise ValueError("late capture threshold control must use the captured fixture")
        if len({item.synthetic_event_id for item in self.events}) != len(self.events):
            raise ValueError("modeled late-authorisation event identities must be distinct")
        return self


ScenarioSafeInputReference = (
    ScenarioInputReference
    | GroundedScenarioInputReference
    | WebhookSequenceInputReference
    | CheckoutSequenceInputReference
    | LateAuthorisationInputReference
)


class AcknowledgementFailureObservation(PersistedArtifactModel):
    acknowledgement_node_id: GraphNodeId
    original_status_code: int = Field(ge=200, le=299)
    effective_status_code: Literal[503] = 503
    injection_sequence: int = Field(ge=1)


class CustomerTargetObservationSummary(PersistedArtifactModel):
    entered_count: int = Field(ge=0)
    returned_normally_count: int = Field(ge=0)
    exception_escaped_count: int = Field(ge=0)
    entered_sequences: tuple[int, ...] = ()
    returned_normally_sequences: tuple[int, ...] = ()
    exception_escaped_sequences: tuple[int, ...] = ()
    request_received_sequences: tuple[int, ...] = ()
    response_completed_sequences: tuple[int, ...] = ()
    request_aborted_sequences: tuple[int, ...] = ()
    http_status_code: int | None = Field(default=None, ge=100, le=599)

    @model_validator(mode="after")
    def validate_counts(self) -> CustomerTargetObservationSummary:
        if self.entered_count != len(self.entered_sequences):
            raise ValueError("customer entry count must match its sequence references")
        if self.returned_normally_count != len(self.returned_normally_sequences):
            raise ValueError("normal-return count must match its sequence references")
        if self.exception_escaped_count != len(self.exception_escaped_sequences):
            raise ValueError("escaped-exception count must match its sequence references")
        return self


class ScenarioRequestObservation(PersistedArtifactModel):
    request_id: RuntimeRequestId
    observations: CustomerTargetObservationSummary
    acknowledgement_failure: AcknowledgementFailureObservation | None = None


class MutationTargetObservationSummary(PersistedArtifactModel):
    mutation_node_id: GraphNodeId
    reached_count: int = Field(ge=0)
    completed_normally_count: int = Field(ge=0)
    raised_count: int = Field(ge=0)
    reached_sequences: tuple[int, ...] = ()
    completed_normally_sequences: tuple[int, ...] = ()
    raised_sequences: tuple[int, ...] = ()

    @model_validator(mode="after")
    def validate_counts(self) -> MutationTargetObservationSummary:
        if self.reached_count != len(self.reached_sequences):
            raise ValueError("mutation reached count must match its sequence references")
        if self.completed_normally_count != len(self.completed_normally_sequences):
            raise ValueError("mutation completion count must match its sequence references")
        if self.raised_count != len(self.raised_sequences):
            raise ValueError("mutation raised count must match its sequence references")
        return self


class MutationScenarioRequestObservation(PersistedArtifactModel):
    request_id: RuntimeRequestId
    mutation_targets: tuple[MutationTargetObservationSummary, ...] = Field(min_length=1)
    request_received_sequences: tuple[int, ...] = ()
    response_completed_sequences: tuple[int, ...] = ()
    request_aborted_sequences: tuple[int, ...] = ()
    http_status_code: int | None = Field(default=None, ge=100, le=599)

    @model_validator(mode="after")
    def validate_targets(self) -> MutationScenarioRequestObservation:
        node_ids = tuple(item.mutation_node_id for item in self.mutation_targets)
        if len(set(node_ids)) != len(node_ids):
            raise ValueError("mutation request observations require unique exact targets")
        return self


ScenarioObservation = ScenarioRequestObservation | MutationScenarioRequestObservation


def scenario_result_fingerprint_payload(
    *,
    execution_id: ScenarioExecutionId,
    scenario_id: ScenarioId,
    scenario_definition_fingerprint: Sha256Digest,
    assertion_id: AssertionId,
    authority: ScenarioAuthorityReference,
    input_reference: ScenarioSafeInputReference | None,
    request_observations: tuple[ScenarioObservation, ...],
    result: VerificationResultState,
    evidence_tier: EvidenceTier | None,
    reason: ScenarioResultReasonCode,
    runtime_diagnostics: tuple[RuntimeCapabilityReasonCode, ...],
    schema_version: Literal[2, 3] = 3,
) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "execution_id": execution_id,
        "scenario_id": scenario_id,
        "scenario_definition_fingerprint": scenario_definition_fingerprint,
        "assertion_id": assertion_id,
        "authority": authority,
        "input_reference": input_reference,
        "request_observations": request_observations,
        "result": result,
        "evidence_tier": evidence_tier,
        "reason": reason,
        "runtime_diagnostics": runtime_diagnostics,
    }


def _normal_first_delivery(summary: CustomerTargetObservationSummary) -> bool:
    return bool(
        len(summary.request_received_sequences) == 1
        and summary.entered_count == 1
        and summary.returned_normally_count == 1
        and summary.exception_escaped_count == 0
        and len(summary.response_completed_sequences) == 1
        and not summary.request_aborted_sequences
        and summary.http_status_code is not None
        and 200 <= summary.http_status_code < 300
    )


class ScenarioExecutionResult(ArtifactFields):
    artifact_type: Literal["SCENARIO_EXECUTION_RESULT"] = "SCENARIO_EXECUTION_RESULT"
    schema_version: Literal[2, 3] = 3
    execution_id: ScenarioExecutionId
    scenario_id: Literal[
        ScenarioId.SG_01,
        ScenarioId.SG_02,
        ScenarioId.SG_03,
        ScenarioId.SG_04,
        ScenarioId.SG_05,
        ScenarioId.SG_06,
        ScenarioId.SG_07,
        ScenarioId.SG_08,
    ]
    scenario_definition_fingerprint: Sha256Digest
    assertion_id: AssertionId
    authority: ScenarioAuthorityReference
    input_reference: ScenarioSafeInputReference | None = None
    request_observations: tuple[ScenarioObservation, ...] = ()
    result: VerificationResultState
    evidence_tier: EvidenceTier | None = None
    reason: ScenarioResultReasonCode
    runtime_diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = ()
    result_fingerprint: Sha256Digest

    @model_validator(mode="after")
    def validate_result(self) -> ScenarioExecutionResult:
        verified = self.result in {
            VerificationResultState.VERIFIED_PASS,
            VerificationResultState.VERIFIED_FAIL,
        }
        if verified != (self.evidence_tier == EvidenceTier.E3_DYNAMIC_VERIFIED):
            raise ValueError("only verified offline scenario results may carry E3")
        if self.evidence_tier == EvidenceTier.E4_RAZORPAY_GROUNDED:
            raise ValueError("offline scenario execution cannot carry E4")
        if isinstance(self.input_reference, GroundedScenarioInputReference) and (
            self.schema_version != 3 or self.scenario_id != ScenarioId.SG_01
        ):
            raise ValueError("resource-grounded synthetic input is valid only for SG-01 schema v3")
        observation_ids = tuple(item.request_id for item in self.request_observations)
        if observation_ids != self.authority.runtime_request_ids[: len(observation_ids)]:
            raise ValueError("ordered request observations must match runtime request authority")
        if self.request_observations and self.input_reference is None:
            raise ValueError("request observations require one shared event input reference")
        if verified and (
            self.authority.runtime_capability_fingerprint is None
            or self.authority.runtime_session_id is None
            or self.authority.transcript_fingerprint is None
            or self.input_reference is None
            or observation_ids != self.authority.runtime_request_ids
        ):
            raise ValueError("verified results require complete dynamic authority")
        if self.scenario_id != ScenarioId.SG_03 and any(
            isinstance(item, ScenarioRequestObservation)
            and item.acknowledgement_failure is not None
            for item in self.request_observations
        ):
            raise ValueError("acknowledgement failure evidence is valid only for SG-03")

        if self.scenario_id == ScenarioId.SG_01:
            if (verified or self.request_observations) and self.authority.normal_control_id is None:
                raise ValueError("SG-01 requires exact customer-control authority")
            if any(
                not isinstance(item, ScenarioRequestObservation)
                for item in self.request_observations
            ):
                raise ValueError("SG-01 requires exact customer-control observations")
            summaries = tuple(
                item.observations
                for item in self.request_observations
                if isinstance(item, ScenarioRequestObservation)
            )
            self._validate_sg01(verified, summaries)
        elif self.scenario_id == ScenarioId.SG_02:
            if (verified or self.request_observations) and self.authority.normal_control_id is None:
                raise ValueError("SG-02 requires exact customer-control authority")
            if any(
                not isinstance(item, ScenarioRequestObservation)
                for item in self.request_observations
            ):
                raise ValueError("SG-02 requires exact customer-control observations")
            summaries = tuple(
                item.observations
                for item in self.request_observations
                if isinstance(item, ScenarioRequestObservation)
            )
            self._validate_sg02(verified, summaries)
        elif self.scenario_id == ScenarioId.SG_03:
            self._validate_sg03(verified)
        elif self.scenario_id == ScenarioId.SG_05:
            self._validate_sg05(verified)
        elif self.scenario_id == ScenarioId.SG_04:
            self._validate_sg04(verified)
        elif self.scenario_id == ScenarioId.SG_06:
            self._validate_sg06(verified)
        elif self.scenario_id == ScenarioId.SG_07:
            self._validate_sg07(verified)
        else:
            self._validate_sg08(verified)

        payload = scenario_result_fingerprint_payload(
            execution_id=self.execution_id,
            scenario_id=self.scenario_id,
            scenario_definition_fingerprint=self.scenario_definition_fingerprint,
            assertion_id=self.assertion_id,
            authority=self.authority,
            input_reference=self.input_reference,
            request_observations=self.request_observations,
            result=self.result,
            evidence_tier=self.evidence_tier,
            reason=self.reason,
            runtime_diagnostics=self.runtime_diagnostics,
            schema_version=self.schema_version,
        )
        if self.result_fingerprint != fingerprint_json(payload):
            raise ValueError("scenario result fingerprint must match artifact contents")
        return self

    def _validate_sg01(
        self,
        verified: bool,
        summaries: tuple[CustomerTargetObservationSummary, ...],
    ) -> None:
        if verified and len(summaries) != 1:
            raise ValueError("verified SG-01 results require exactly one request")
        if self.result == VerificationResultState.VERIFIED_PASS and (
            self.reason != ScenarioResultReasonCode.EXACT_TARGET_ENTERED_ONCE
            or not summaries
            or not _normal_first_delivery(summaries[0])
        ):
            raise ValueError("verified SG-01 pass must match exact normal lifecycle evidence")
        if self.result == VerificationResultState.VERIFIED_FAIL and (
            self.reason != ScenarioResultReasonCode.EXACT_TARGET_ENTERED_MULTIPLE_TIMES
            or not summaries
            or summaries[0].entered_count <= 1
            or len(summaries[0].request_received_sequences) != 1
        ):
            raise ValueError("verified SG-01 fail requires multiple exact target entries")

    def _validate_sg02(
        self,
        verified: bool,
        summaries: tuple[CustomerTargetObservationSummary, ...],
    ) -> None:
        if verified and len(summaries) != 2:
            raise ValueError("verified SG-02 results require exactly two requests")
        if verified and any(len(item.request_received_sequences) != 1 for item in summaries):
            raise ValueError("verified SG-02 results require both correlated deliveries")
        if self.result == VerificationResultState.VERIFIED_PASS:
            valid_pass = bool(
                len(summaries) == 2
                and _normal_first_delivery(summaries[0])
                and len(summaries[1].request_received_sequences) == 1
                and summaries[1].entered_count == 0
                and len(summaries[1].response_completed_sequences) == 1
                and not summaries[1].request_aborted_sequences
            )
            if (
                self.reason != ScenarioResultReasonCode.DUPLICATE_DELIVERY_ADDED_NO_TARGET_ENTRY
                or not valid_pass
            ):
                raise ValueError("verified SG-02 pass must match the duplicate sequence invariant")
        if self.result == VerificationResultState.VERIFIED_FAIL:
            first_multiple = bool(
                len(summaries) == 2
                and len(summaries[0].request_received_sequences) == 1
                and summaries[0].entered_count > 1
            )
            duplicate_entered = bool(
                len(summaries) == 2
                and _normal_first_delivery(summaries[0])
                and len(summaries[1].request_received_sequences) == 1
                and summaries[1].entered_count > 0
            )
            attributed_failure = bool(
                (
                    self.reason == ScenarioResultReasonCode.NORMAL_CONTROL_MULTIPLE_TARGET_ENTRIES
                    and first_multiple
                )
                or (
                    self.reason == ScenarioResultReasonCode.DUPLICATE_DELIVERY_ADDED_TARGET_ENTRY
                    and duplicate_entered
                )
            )
            if not attributed_failure:
                raise ValueError(
                    "verified SG-02 fail reason must identify the delivery that added entries"
                )

    def _validate_sg03(self, verified: bool) -> None:
        if (verified or self.request_observations) and self.authority.normal_control_id is None:
            raise ValueError("SG-03 requires exact customer-control authority")
        if any(
            not isinstance(item, ScenarioRequestObservation) for item in self.request_observations
        ):
            raise ValueError("SG-03 requires exact customer-control observations")
        observations = tuple(
            item
            for item in self.request_observations
            if isinstance(item, ScenarioRequestObservation)
        )
        if verified and (
            len(observations) != 2 or not isinstance(self.input_reference, ScenarioInputReference)
        ):
            raise ValueError("verified SG-03 requires exact two-delivery authority")
        if not verified or len(observations) != 2:
            return
        first, retry = observations
        injection = first.acknowledgement_failure
        first_summary = first.observations
        retry_summary = retry.observations
        injection_exact = bool(
            injection is not None
            and retry.acknowledgement_failure is None
            and first_summary.http_status_code == 503
            and first_summary.returned_normally_sequences
            and max(first_summary.returned_normally_sequences) < injection.injection_sequence
            and first_summary.response_completed_sequences
            and injection.injection_sequence < min(first_summary.response_completed_sequences)
        )
        if not injection_exact:
            raise ValueError(
                "verified SG-03 requires exact post-processing acknowledgement injection"
            )
        if self.result == VerificationResultState.VERIFIED_PASS and not (
            self.reason == ScenarioResultReasonCode.MODELED_RETRY_ADDED_NO_TARGET_ENTRY
            and first_summary.entered_count == first_summary.returned_normally_count == 1
            and first_summary.exception_escaped_count == 0
            and retry_summary.entered_count == 0
            and len(retry_summary.request_received_sequences) == 1
            and len(retry_summary.response_completed_sequences) == 1
            and not retry_summary.request_aborted_sequences
            and retry_summary.http_status_code is not None
            and 200 <= retry_summary.http_status_code < 300
        ):
            raise ValueError("verified SG-03 pass must match the modeled retry invariant")
        if self.result == VerificationResultState.VERIFIED_FAIL:
            initial = bool(
                self.reason == ScenarioResultReasonCode.INITIAL_DELIVERY_MULTIPLE_TARGET_ENTRIES
                and first_summary.entered_count > 1
            )
            retried = bool(
                self.reason == ScenarioResultReasonCode.MODELED_RETRY_ADDED_TARGET_ENTRY
                and first_summary.entered_count == first_summary.returned_normally_count == 1
                and first_summary.exception_escaped_count == 0
                and retry_summary.entered_count > 0
            )
            if not (initial or retried):
                raise ValueError("verified SG-03 failure must retain exact delivery attribution")

    def _validate_sg05(self, verified: bool) -> None:
        if verified and len(self.request_observations) != 2:
            raise ValueError("verified SG-05 results require rejected and control requests")
        if not verified or not self.request_observations:
            return

        customer_observations = all(
            isinstance(item, ScenarioRequestObservation) for item in self.request_observations
        )
        mutation_observations = all(
            isinstance(item, MutationScenarioRequestObservation)
            for item in self.request_observations
        )
        if customer_observations == mutation_observations:
            raise ValueError(
                "verified SG-05 result must carry one exact assertion observation type"
            )

        if customer_observations:
            if self.authority.normal_control_id is None:
                raise ValueError("verified SG-05 customer result requires a normal control")
            rejected, control = (
                item.observations
                for item in self.request_observations
                if isinstance(item, ScenarioRequestObservation)
            )
            rejected_received = len(rejected.request_received_sequences) == 1
            if self.result == VerificationResultState.VERIFIED_FAIL:
                if (
                    self.reason
                    != ScenarioResultReasonCode.REJECTED_SIGNATURE_ADDED_CUSTOMER_TARGET_ENTRY
                    or not rejected_received
                    or rejected.entered_count == 0
                ):
                    raise ValueError("verified SG-05 customer fail requires rejected-request entry")
            elif self.result == VerificationResultState.VERIFIED_PASS:
                rejected_completed = bool(
                    rejected_received
                    and rejected.entered_count == 0
                    and rejected.returned_normally_count == 0
                    and rejected.exception_escaped_count == 0
                    and len(rejected.response_completed_sequences) == 1
                    and not rejected.request_aborted_sequences
                )
                if (
                    self.reason
                    != ScenarioResultReasonCode.REJECTED_SIGNATURE_ADDED_NO_CUSTOMER_TARGET_ENTRY
                    or not rejected_completed
                    or not _normal_first_delivery(control)
                ):
                    raise ValueError("verified SG-05 customer pass requires differential control")
            return

        if self.authority.normal_control_id is not None:
            raise ValueError("verified SG-05 mutation result cannot borrow a normal control")
        mutation_rejected, mutation_control = (
            item
            for item in self.request_observations
            if isinstance(item, MutationScenarioRequestObservation)
        )
        rejected_ids = tuple(item.mutation_node_id for item in mutation_rejected.mutation_targets)
        control_ids = tuple(item.mutation_node_id for item in mutation_control.mutation_targets)
        if rejected_ids != control_ids:
            raise ValueError("SG-05 mutation observations must retain exact ordered targets")
        rejected_completed = any(
            item.completed_normally_count > 0 for item in mutation_rejected.mutation_targets
        )
        if self.result == VerificationResultState.VERIFIED_FAIL:
            if (
                self.reason != ScenarioResultReasonCode.REJECTED_SIGNATURE_COMPLETED_MUTATION
                or len(mutation_rejected.request_received_sequences) != 1
                or not rejected_completed
            ):
                raise ValueError("verified SG-05 mutation fail requires exact completion")
            return
        rejected_clean = bool(
            len(mutation_rejected.request_received_sequences) == 1
            and all(
                item.reached_count == 0
                and item.completed_normally_count == 0
                and item.raised_count == 0
                for item in mutation_rejected.mutation_targets
            )
            and len(mutation_rejected.response_completed_sequences) == 1
            and not mutation_rejected.request_aborted_sequences
        )
        control_normal = bool(
            len(mutation_control.request_received_sequences) == 1
            and len(mutation_control.response_completed_sequences) == 1
            and not mutation_control.request_aborted_sequences
            and mutation_control.http_status_code is not None
            and 200 <= mutation_control.http_status_code < 300
            and all(
                item.reached_count >= 1
                and item.completed_normally_count == item.reached_count
                and item.raised_count == 0
                for item in mutation_control.mutation_targets
            )
        )
        if (
            self.reason != ScenarioResultReasonCode.REJECTED_SIGNATURE_ADDED_NO_MUTATION
            or not rejected_clean
            or not control_normal
        ):
            raise ValueError("verified SG-05 mutation pass requires differential control")

    def _validate_sg04(self, verified: bool) -> None:
        if verified and (
            len(self.request_observations) != 2
            or not isinstance(self.input_reference, WebhookSequenceInputReference)
            or self.authority.normal_control_id is None
        ):
            raise ValueError("verified SG-04 requires exact two-request sequence authority")
        if not verified or not self.request_observations:
            return
        customer = all(
            isinstance(item, ScenarioRequestObservation) for item in self.request_observations
        )
        mutation = all(
            isinstance(item, MutationScenarioRequestObservation)
            for item in self.request_observations
        )
        if customer == mutation:
            raise ValueError("verified SG-04 requires one assertion observation type")
        if customer:
            first, second = (
                item.observations
                for item in self.request_observations
                if isinstance(item, ScenarioRequestObservation)
            )
            if self.result == VerificationResultState.VERIFIED_PASS and not (
                self.reason == ScenarioResultReasonCode.STALE_AUTHORIZED_ADDED_NO_TARGET_ENTRY
                and _normal_first_delivery(first)
                and len(second.request_received_sequences) == 1
                and second.entered_count == 0
                and len(second.response_completed_sequences) == 1
                and not second.request_aborted_sequences
            ):
                raise ValueError("verified SG-04 pass must prove the stale event added no value")
            if self.result == VerificationResultState.VERIFIED_FAIL and not (
                (
                    self.reason
                    == ScenarioResultReasonCode.OUT_OF_ORDER_CONTROL_MULTIPLE_TARGET_ENTRIES
                    and first.entered_count > 1
                )
                or (
                    self.reason == ScenarioResultReasonCode.STALE_AUTHORIZED_ADDED_TARGET_ENTRY
                    and _normal_first_delivery(first)
                    and second.entered_count > 0
                )
            ):
                raise ValueError("verified SG-04 fail must retain delivery attribution")
            return
        first_mutation, second_mutation = (
            item
            for item in self.request_observations
            if isinstance(item, MutationScenarioRequestObservation)
        )
        if self.result == VerificationResultState.VERIFIED_FAIL and not (
            self.reason == ScenarioResultReasonCode.MERCHANT_STATE_REGRESSED_TO_AUTHORIZED
            and any(item.completed_normally_count > 0 for item in second_mutation.mutation_targets)
        ):
            raise ValueError("verified SG-04 regression requires a completed stale transition")
        if self.result == VerificationResultState.VERIFIED_PASS and not (
            self.reason == ScenarioResultReasonCode.MERCHANT_STATE_DID_NOT_REGRESS
            and any(item.completed_normally_count > 0 for item in first_mutation.mutation_targets)
            and all(
                item.reached_count == item.completed_normally_count == item.raised_count == 0
                for item in second_mutation.mutation_targets
            )
        ):
            raise ValueError("verified SG-04 state pass requires a differential control")

    def _validate_sg06(self, verified: bool) -> None:
        if verified and (
            len(self.request_observations) != 2
            or not isinstance(self.input_reference, CheckoutSequenceInputReference)
        ):
            raise ValueError("verified SG-06 requires tampered/control sequence authority")
        if not verified or not self.request_observations:
            return
        customer = all(
            isinstance(item, ScenarioRequestObservation) for item in self.request_observations
        )
        mutation = all(
            isinstance(item, MutationScenarioRequestObservation)
            for item in self.request_observations
        )
        if customer == mutation:
            raise ValueError("verified SG-06 requires one assertion observation type")
        if customer:
            if self.authority.normal_control_id is None:
                raise ValueError("verified SG-06 customer result requires exact control")
            tampered, control = (
                item.observations
                for item in self.request_observations
                if isinstance(item, ScenarioRequestObservation)
            )
            if self.result == VerificationResultState.VERIFIED_FAIL and not (
                self.reason
                == ScenarioResultReasonCode.TAMPERED_CALLBACK_ADDED_CUSTOMER_TARGET_ENTRY
                and tampered.entered_count > 0
            ):
                raise ValueError("verified SG-06 fail requires tampered-request entry")
            if self.result == VerificationResultState.VERIFIED_PASS and not (
                self.reason
                == ScenarioResultReasonCode.TAMPERED_CALLBACK_ADDED_NO_CUSTOMER_TARGET_ENTRY
                and tampered.entered_count == 0
                and len(tampered.response_completed_sequences) == 1
                and _normal_first_delivery(control)
            ):
                raise ValueError("verified SG-06 pass requires a valid differential control")
            return
        tampered_mutation, control_mutation = (
            item
            for item in self.request_observations
            if isinstance(item, MutationScenarioRequestObservation)
        )
        if self.result == VerificationResultState.VERIFIED_FAIL and not (
            self.reason == ScenarioResultReasonCode.TAMPERED_CALLBACK_COMPLETED_MUTATION
            and any(
                item.completed_normally_count > 0 for item in tampered_mutation.mutation_targets
            )
        ):
            raise ValueError("verified SG-06 mutation fail requires exact completion")
        if self.result == VerificationResultState.VERIFIED_PASS and not (
            self.reason == ScenarioResultReasonCode.TAMPERED_CALLBACK_ADDED_NO_MUTATION
            and all(
                item.reached_count == item.completed_normally_count == item.raised_count == 0
                for item in tampered_mutation.mutation_targets
            )
            and all(
                item.reached_count >= 1
                and item.completed_normally_count == item.reached_count
                and item.raised_count == 0
                for item in control_mutation.mutation_targets
            )
        ):
            raise ValueError("verified SG-06 mutation pass requires a valid control")

    def _validate_sg07(self, verified: bool) -> None:
        if verified and (
            len(self.request_observations) != 1
            or not isinstance(self.input_reference, ScenarioInputReference)
            or self.authority.normal_control_id is None
        ):
            raise ValueError("verified SG-07 requires one exact webhook request")
        if not verified or not self.request_observations:
            return
        if not all(
            isinstance(item, ScenarioRequestObservation) for item in self.request_observations
        ):
            raise ValueError("SG-07 requires customer-value observations")
        summary = next(
            item.observations
            for item in self.request_observations
            if isinstance(item, ScenarioRequestObservation)
        )
        if self.result == VerificationResultState.VERIFIED_PASS and not (
            self.reason == ScenarioResultReasonCode.WEBHOOK_ONLY_TARGET_ENTERED_ONCE
            and _normal_first_delivery(summary)
        ):
            raise ValueError("verified SG-07 pass requires one normal webhook-only outcome")
        if self.result == VerificationResultState.VERIFIED_FAIL and not (
            self.reason == ScenarioResultReasonCode.WEBHOOK_ONLY_TARGET_ENTERED_MULTIPLE_TIMES
            and summary.entered_count > 1
        ):
            raise ValueError("verified SG-07 fail requires multiple exact entries")

    def _validate_sg08(self, verified: bool) -> None:
        if (verified or self.request_observations) and self.authority.normal_control_id is None:
            raise ValueError("SG-08 requires exact customer-control authority")
        if any(
            not isinstance(item, ScenarioRequestObservation) for item in self.request_observations
        ):
            raise ValueError("SG-08 requires customer-value observations")
        if not verified:
            return
        if not isinstance(self.input_reference, LateAuthorisationInputReference):
            raise ValueError("verified SG-08 requires modeled late-authorisation input authority")
        if self.input_reference.policy.fulfilment != FulfilmentPolicy.CAPTURE_REQUIRED:
            raise ValueError(
                "authorized-allowed late assertions require merchant late-context authority"
            )
        summaries = tuple(
            item.observations
            for item in self.request_observations
            if isinstance(item, ScenarioRequestObservation)
        )
        expected_count = 2 if len(self.input_reference.events) == 2 else 1
        if len(summaries) != expected_count:
            raise ValueError("verified SG-08 observations must match the policy input sequence")
        authorized = summaries[0]
        if self.result == VerificationResultState.VERIFIED_FAIL:
            early = bool(
                self.reason == ScenarioResultReasonCode.AUTHORIZED_EXECUTED_BEFORE_CAPTURE
                and authorized.entered_count > 0
            )
            captured_multiple = bool(
                self.reason == ScenarioResultReasonCode.CAPTURED_THRESHOLD_MULTIPLE_TARGET_ENTRIES
                and len(summaries) == 2
                and summaries[1].entered_count > 1
            )
            if not (early or captured_multiple):
                raise ValueError(
                    "verified SG-08 fail must retain authorization/capture attribution"
                )
            return
        if len(summaries) != 2:
            raise ValueError("verified SG-08 pass requires the captured differential control")
        captured = summaries[1]
        captured_normal = bool(
            captured.entered_count == captured.returned_normally_count == 1
            and captured.exception_escaped_count == 0
            and len(captured.request_received_sequences) == 1
            and len(captured.response_completed_sequences) == 1
            and not captured.request_aborted_sequences
            and captured.http_status_code is not None
            and 200 <= captured.http_status_code < 300
        )
        if not (
            authorized.entered_count == 0
            and captured_normal
            and self.reason
            in {
                ScenarioResultReasonCode.AUTHORIZED_ADDED_NO_TARGET_ENTRY,
                ScenarioResultReasonCode.CAPTURED_THRESHOLD_TARGET_ENTERED_ONCE,
            }
        ):
            raise ValueError("verified SG-08 pass requires the captured differential control")
