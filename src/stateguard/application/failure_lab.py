"""Application orchestration for deterministic managed Failure Lab slices."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from stateguard import __version__
from stateguard.applicability.contracts import (
    SG01_ASSERTION_KEY,
    SG02_ASSERTION_KEY,
    SG03_ASSERTION_KEY,
    SG04_CUSTOMER_VALUE_ASSERTION_KEY,
    SG04_STATE_REGRESSION_ASSERTION_KEY,
    SG05_CUSTOMER_VALUE_ASSERTION_KEY,
    SG05_MUTATION_ASSERTION_KEY,
    SG06_CUSTOMER_VALUE_ASSERTION_KEY,
    SG06_MUTATION_ASSERTION_KEY,
    SG07_CUSTOMER_VALUE_ASSERTION_KEY,
    SG08_CAPTURE_ASSERTION_KEY,
    SG08_LATE_POLICY_ASSERTION_KEY,
    SG08_PRECAPTURE_ASSERTION_KEY,
    ApplicabilityReasonCode,
    ApplicabilityState,
    EvidenceReferenceKind,
    ScenarioApplicabilityArtifact,
    ScenarioId,
    ScenarioInstance,
)
from stateguard.application.applicability import analyze_applicability
from stateguard.application.runtime import RuntimeSessionOpenResult, open_runtime_session
from stateguard.contracts.common import (
    AssertionId,
    GraphNodeId,
    NormalControlId,
    RuntimeRequestId,
    RuntimeSessionId,
    ScenarioExecutionId,
    ScenarioInstanceId,
    Sha256Digest,
)
from stateguard.contracts.config import (
    FulfilmentPolicy,
    ManagedRuntimeConfig,
)
from stateguard.contracts.identity import (
    assertion_id,
    fingerprint_json,
    new_scenario_execution_id,
)
from stateguard.failure_lab.captured_webhook import prepare_captured_webhook
from stateguard.failure_lab.contracts import (
    EvidenceTier,
    MutationScenarioRequestObservation,
    ScenarioAuthorityReference,
    ScenarioExecutionResult,
    ScenarioInputReference,
    ScenarioObservation,
    ScenarioRequestObservation,
    ScenarioResultReasonCode,
    ScenarioSafeInputReference,
    VerificationResultState,
    scenario_result_fingerprint_payload,
)
from stateguard.failure_lab.sg01 import (
    SG01_DEFINITION_FINGERPRINT,
    evaluate_observations,
    summarize_observations,
)
from stateguard.failure_lab.sg02 import SG02_DEFINITION_FINGERPRINT, evaluate_sequence
from stateguard.failure_lab.sg03 import (
    SG03_DEFINITION_FINGERPRINT,
    summarize_acknowledgement_failure,
)
from stateguard.failure_lab.sg03 import (
    evaluate_sequence as evaluate_sg03_sequence,
)
from stateguard.failure_lab.sg04 import (
    SG04_DEFINITION_FINGERPRINT,
    prepare_sg04_requests,
)
from stateguard.failure_lab.sg04 import (
    evaluate_customer_sequence as evaluate_sg04_customer_sequence,
)
from stateguard.failure_lab.sg04 import (
    evaluate_state_sequence as evaluate_sg04_state_sequence,
)
from stateguard.failure_lab.sg05 import (
    SG05_DEFINITION_FINGERPRINT,
    prepare_sg05_requests,
    summarize_mutation_observations,
)
from stateguard.failure_lab.sg05 import (
    evaluate_customer_sequence as evaluate_sg05_customer_sequence,
)
from stateguard.failure_lab.sg05 import (
    evaluate_mutation_sequence as evaluate_sg05_mutation_sequence,
)
from stateguard.failure_lab.sg06 import (
    SG06_DEFINITION_FINGERPRINT,
    prepare_sg06_requests,
)
from stateguard.failure_lab.sg06 import (
    evaluate_customer_sequence as evaluate_sg06_customer_sequence,
)
from stateguard.failure_lab.sg06 import (
    evaluate_mutation_sequence as evaluate_sg06_mutation_sequence,
)
from stateguard.failure_lab.sg07 import (
    SG07_DEFINITION_FINGERPRINT,
    evaluate_webhook_only,
)
from stateguard.failure_lab.sg08 import (
    SG08_DEFINITION_FINGERPRINT,
    prepare_sg08_requests,
)
from stateguard.failure_lab.sg08 import (
    evaluate_capture_sequence as evaluate_sg08_capture_sequence,
)
from stateguard.failure_lab.sg08 import (
    evaluate_precapture as evaluate_sg08_precapture,
)
from stateguard.graph.contracts import AcknowledgementOutcome
from stateguard.grounding.razorpay import GroundingAcquisitionResult
from stateguard.runtime.contracts import (
    CustomerValueLifecycleStrength,
    IngressRuntimeBinding,
    ManagedAcknowledgementFailureMode,
    MutationObservationStrength,
    RuntimeCapabilityReasonCode,
    RuntimeCapabilityState,
    RuntimeLifecycleState,
    RuntimeObservationKind,
    RuntimeObservationTranscript,
    RuntimeTranscriptMismatchError,
    validate_observation_transcript,
)
from stateguard.runtime.session import (
    ManagedRuntimeSession,
    RuntimeRequestResult,
    RuntimeSessionError,
)
from stateguard.workspace.config import load_config

_SECRET_CHILD_NAME = "STATEGUARD_TEST_WEBHOOK_SECRET"
_CHECKOUT_SECRET_CHILD_NAME = "STATEGUARD_TEST_RAZORPAY_KEY_SECRET"
_SERVER_ORDER_CHILD_NAME = "STATEGUARD_TEST_SERVER_ORDER_ID"


def _make_result(
    *,
    generated_at: datetime,
    execution_id: ScenarioExecutionId,
    scenario_id: ScenarioId = ScenarioId.SG_01,
    scenario_definition_fingerprint: Sha256Digest = SG01_DEFINITION_FINGERPRINT,
    assertion: AssertionId,
    authority: ScenarioAuthorityReference,
    result: VerificationResultState,
    reason: ScenarioResultReasonCode,
    evidence_tier: EvidenceTier | None = None,
    input_reference: ScenarioSafeInputReference | None = None,
    request_observations: tuple[ScenarioObservation, ...] = (),
    runtime_diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = (),
) -> ScenarioExecutionResult:
    diagnostics = tuple(sorted(set(runtime_diagnostics)))
    payload = scenario_result_fingerprint_payload(
        execution_id=execution_id,
        scenario_id=scenario_id,
        scenario_definition_fingerprint=scenario_definition_fingerprint,
        assertion_id=assertion,
        authority=authority,
        input_reference=input_reference,
        request_observations=request_observations,
        result=result,
        evidence_tier=evidence_tier,
        reason=reason,
        runtime_diagnostics=diagnostics,
    )
    return ScenarioExecutionResult(
        producer_version=__version__,
        generated_at=generated_at,
        **payload,
        result_fingerprint=fingerprint_json(payload),
    )


def _make_sg02_result(
    *,
    generated_at: datetime,
    execution_id: ScenarioExecutionId,
    assertion: AssertionId,
    authority: ScenarioAuthorityReference,
    result: VerificationResultState,
    reason: ScenarioResultReasonCode,
    evidence_tier: EvidenceTier | None = None,
    input_reference: ScenarioInputReference | None = None,
    request_observations: tuple[ScenarioRequestObservation, ...] = (),
    runtime_diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = (),
) -> ScenarioExecutionResult:
    return _make_result(
        generated_at=generated_at,
        execution_id=execution_id,
        scenario_id=ScenarioId.SG_02,
        scenario_definition_fingerprint=SG02_DEFINITION_FINGERPRINT,
        assertion=assertion,
        authority=authority,
        result=result,
        reason=reason,
        evidence_tier=evidence_tier,
        input_reference=input_reference,
        request_observations=request_observations,
        runtime_diagnostics=runtime_diagnostics,
    )


def _make_sg05_result(
    *,
    generated_at: datetime,
    execution_id: ScenarioExecutionId,
    assertion: AssertionId,
    authority: ScenarioAuthorityReference,
    result: VerificationResultState,
    reason: ScenarioResultReasonCode,
    evidence_tier: EvidenceTier | None = None,
    input_reference: ScenarioInputReference | None = None,
    request_observations: tuple[ScenarioObservation, ...] = (),
    runtime_diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = (),
) -> ScenarioExecutionResult:
    return _make_result(
        generated_at=generated_at,
        execution_id=execution_id,
        scenario_id=ScenarioId.SG_05,
        scenario_definition_fingerprint=SG05_DEFINITION_FINGERPRINT,
        assertion=assertion,
        authority=authority,
        result=result,
        reason=reason,
        evidence_tier=evidence_tier,
        input_reference=input_reference,
        request_observations=request_observations,
        runtime_diagnostics=runtime_diagnostics,
    )


def _sg01_instance(
    applicability: ScenarioApplicabilityArtifact,
    instance_id: ScenarioInstanceId,
) -> ScenarioInstance | None:
    scenario = next(
        (item for item in applicability.scenarios if item.scenario_id == ScenarioId.SG_01),
        None,
    )
    if scenario is None:
        return None
    return next((item for item in scenario.instances if item.instance_id == instance_id), None)


def _sg02_instance(
    applicability: ScenarioApplicabilityArtifact,
    instance_id: ScenarioInstanceId,
) -> ScenarioInstance | None:
    scenario = next(
        (item for item in applicability.scenarios if item.scenario_id == ScenarioId.SG_02),
        None,
    )
    if scenario is None:
        return None
    return next((item for item in scenario.instances if item.instance_id == instance_id), None)


def _sg05_instance(
    applicability: ScenarioApplicabilityArtifact,
    instance_id: ScenarioInstanceId,
) -> ScenarioInstance | None:
    scenario = next(
        (item for item in applicability.scenarios if item.scenario_id == ScenarioId.SG_05),
        None,
    )
    if scenario is None:
        return None
    return next((item for item in scenario.instances if item.instance_id == instance_id), None)


def _scenario_instance(
    applicability: ScenarioApplicabilityArtifact,
    scenario_id: ScenarioId,
    instance_id: ScenarioInstanceId,
) -> ScenarioInstance | None:
    scenario = next(
        (item for item in applicability.scenarios if item.scenario_id == scenario_id),
        None,
    )
    if scenario is None:
        return None
    return next((item for item in scenario.instances if item.instance_id == instance_id), None)


@dataclass(frozen=True)
class _ManagedRequestSpec:
    headers: dict[str, str]
    content: bytes | None
    params: dict[str, str] | None = None
    acknowledgement_failure: ManagedAcknowledgementFailureMode | None = None
    acknowledgement_node_id: GraphNodeId | None = None


def _dispatch_managed_sequence(
    session: ManagedRuntimeSession,
    capability_fingerprint: Sha256Digest,
    ingress: IngressRuntimeBinding | None,
    requests: tuple[_ManagedRequestSpec, ...],
) -> tuple[
    tuple[RuntimeRequestResult, ...],
    RuntimeObservationTranscript | None,
    RuntimeCapabilityReasonCode | None,
    bool,
]:
    request_results: list[RuntimeRequestResult] = []
    request_failure: RuntimeCapabilityReasonCode | None = None
    transcript: RuntimeObservationTranscript | None = None
    close_failed = False
    try:
        for request in requests:
            if ingress is None:
                request_failure = RuntimeCapabilityReasonCode.RUNTIME_ROUTE_NOT_FOUND
                break
            try:
                if request.params is None and request.acknowledgement_failure is None:
                    result = session.request(
                        ingress,
                        headers=request.headers,
                        content=request.content,
                    )
                elif request.params is not None and request.acknowledgement_failure is None:
                    result = session.request(
                        ingress,
                        headers=request.headers,
                        content=request.content,
                        params=request.params,
                    )
                else:
                    result = session.request(
                        ingress,
                        headers=request.headers,
                        content=request.content,
                        params=request.params,
                        acknowledgement_failure=request.acknowledgement_failure,
                        acknowledgement_node_id=request.acknowledgement_node_id,
                    )
                request_results.append(result)
            except RuntimeSessionError as exc:
                request_failure = exc.reason
                break
    finally:
        try:
            transcript = session.close(capability_fingerprint)
        except (OSError, ValueError):
            close_failed = True
    return tuple(request_results), transcript, request_failure, close_failed


def _sequence_authority_is_exact(
    transcript: RuntimeObservationTranscript,
    request_results: tuple[RuntimeRequestResult, ...],
) -> bool:
    expected = tuple(item.request_id for item in request_results)
    if len(set(expected)) != len(expected):
        return False
    transcript_ids = {item.request_id for item in transcript.events}
    received = tuple(
        item.request_id
        for item in transcript.events
        if item.kind == RuntimeObservationKind.REQUEST_RECEIVED
    )
    binding = request_results[0].binding if request_results else None
    return bool(
        binding is not None
        and transcript_ids == set(expected)
        and received == expected
        and all(item.binding == binding for item in request_results)
        and all(
            item.ingress_node_id == binding.ingress_node_id
            and item.route_registration_id == binding.route_registration_id
            for item in transcript.events
            if item.request_id in expected
        )
    )


def _assertion_for(
    instance: ScenarioInstance | None,
    instance_id: ScenarioInstanceId,
    assertion_key: str = SG01_ASSERTION_KEY,
) -> AssertionId:
    if instance is not None:
        selected = tuple(item for item in instance.assertions if item.key == assertion_key)
        if len(selected) == 1:
            return selected[0].assertion_id
    return assertion_id(instance_id, assertion_key)


def _base_authority(
    applicability_fingerprint: Sha256Digest,
    instance_id: ScenarioInstanceId,
    normal_control_id: NormalControlId | None,
    *,
    capability_fingerprint: Sha256Digest | None = None,
    session_id: RuntimeSessionId | None = None,
    request_ids: tuple[RuntimeRequestId, ...] = (),
    transcript_fingerprint: Sha256Digest | None = None,
) -> ScenarioAuthorityReference:
    return ScenarioAuthorityReference(
        applicability_fingerprint=applicability_fingerprint,
        scenario_instance_id=instance_id,
        normal_control_id=normal_control_id,
        runtime_capability_fingerprint=capability_fingerprint,
        runtime_session_id=session_id,
        runtime_request_ids=request_ids,
        transcript_fingerprint=transcript_fingerprint,
    )


def _early_applicability_result(
    state: ApplicabilityState,
) -> tuple[VerificationResultState, ScenarioResultReasonCode] | None:
    if state == ApplicabilityState.NOT_APPLICABLE:
        return (
            VerificationResultState.NOT_APPLICABLE,
            ScenarioResultReasonCode.APPLICABILITY_NOT_APPLICABLE,
        )
    if state == ApplicabilityState.NEEDS_INPUT:
        return (
            VerificationResultState.NEEDS_INPUT,
            ScenarioResultReasonCode.APPLICABILITY_NEEDS_INPUT,
        )
    if state == ApplicabilityState.INDETERMINATE:
        return (
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.APPLICABILITY_INDETERMINATE,
        )
    return None


def _capability_is_sufficient(
    opened: RuntimeSessionOpenResult,
    normal_control_id: NormalControlId,
) -> bool:
    artifact = opened.artifact
    customers = tuple(
        item
        for item in artifact.customer_values
        if item.target.normal_control_id == normal_control_id
    )
    if len(customers) != 1:
        return False
    customer = customers[0]
    ingresses = tuple(
        item for item in artifact.ingresses if item.binding == customer.target.ingress
    )
    return bool(
        artifact.mode == "managed"
        and artifact.lifecycle == RuntimeLifecycleState.READY
        and len(ingresses) == 1
        and ingresses[0].addressability.state == RuntimeCapabilityState.COMPLETE
        and ingresses[0].request_correlation.state == RuntimeCapabilityState.COMPLETE
        and customer.lifecycle.state == RuntimeCapabilityState.COMPLETE
        and customer.strength == CustomerValueLifecycleStrength.ENTRY_AND_TERMINAL
        and artifact.isolation.fresh_process.state == RuntimeCapabilityState.COMPLETE
        and artifact.isolation.observation_reset.state == RuntimeCapabilityState.COMPLETE
    )


def execute_sg01(
    repository_root: Path,
    config_path: Path,
    *,
    scenario_instance_id: ScenarioInstanceId,
    expected_applicability_fingerprint: Sha256Digest,
    generated_at: datetime | None = None,
    grounding: GroundingAcquisitionResult | None = None,
) -> ScenarioExecutionResult:
    """Execute one exact managed SG-01 instance without persisting scenario evidence."""

    timestamp = generated_at or datetime.now(UTC)
    execution_id = new_scenario_execution_id()
    preflight = analyze_applicability(repository_root, config_path, generated_at=timestamp)
    applicability = preflight.artifact
    instance = _sg01_instance(applicability, scenario_instance_id)
    selected_assertion = _assertion_for(instance, scenario_instance_id)
    normal_control_id = instance.normal_control_id if instance is not None else None
    authority = _base_authority(
        applicability.applicability_fingerprint,
        scenario_instance_id,
        normal_control_id,
    )
    if applicability.applicability_fingerprint != expected_applicability_fingerprint:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
        )
    if instance is None:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.AUTHORITY_MISMATCH,
        )
    early = _early_applicability_result(instance.state)
    if early is not None:
        result, reason = early
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=result,
            reason=reason,
        )
    if normal_control_id is None:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.AUTHORITY_MISMATCH,
        )

    config = load_config(config_path)
    if not isinstance(config.runtime, ManagedRuntimeConfig):
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.RUNTIME_MODE_UNSUPPORTED,
        )
    expected_runtime_config_fingerprint = fingerprint_json(config.runtime)
    host_secret_name = config.runtime.env_from_host.get(_SECRET_CHILD_NAME)
    secret = os.environ.get(host_secret_name, "") if host_secret_name is not None else ""
    if not secret:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.WEBHOOK_SECRET_UNAVAILABLE,
        )

    try:
        opened = open_runtime_session(repository_root, config_path, generated_at=timestamp)
    except (OSError, ValueError):
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
        )

    runtime_authority = _base_authority(
        applicability.applicability_fingerprint,
        scenario_instance_id,
        normal_control_id,
        capability_fingerprint=opened.artifact.capability_fingerprint,
        session_id=opened.artifact.assessment_session_id,
    )
    if (
        opened.applicability.artifact.applicability_fingerprint
        != applicability.applicability_fingerprint
        or opened.artifact.runtime_config_fingerprint != expected_runtime_config_fingerprint
    ):
        if opened.session is not None:
            opened.session.close(opened.artifact.capability_fingerprint)
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=runtime_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
            runtime_diagnostics=tuple(item.code for item in opened.artifact.diagnostics),
        )
    reopened_instance = _sg01_instance(opened.applicability.artifact, scenario_instance_id)
    if reopened_instance != instance:
        if opened.session is not None:
            opened.session.close(opened.artifact.capability_fingerprint)
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=runtime_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.AUTHORITY_MISMATCH,
        )
    if not isinstance(opened.session, ManagedRuntimeSession):
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=runtime_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
            runtime_diagnostics=tuple(item.code for item in opened.artifact.diagnostics),
        )

    session = opened.session
    request_result = None
    prepared = None
    request_failure: RuntimeCapabilityReasonCode | None = None
    transcript: RuntimeObservationTranscript | None = None
    close_failed = False
    capability_sufficient = _capability_is_sufficient(opened, normal_control_id)
    try:
        if capability_sufficient:
            target = next(
                item
                for item in opened.artifact.customer_values
                if item.target.normal_control_id == normal_control_id
            )
            prepared = prepare_captured_webhook(
                execution_id=execution_id,
                path=target.target.ingress.effective_path,
                secret=secret,
                grounded_profile=(grounding.profile if grounding is not None else None),
                grounding_fingerprint=(
                    grounding.snapshot.grounding_fingerprint
                    if grounding is not None and grounding.profile is not None
                    else None
                ),
                sanitized_projection_fingerprint=(
                    grounding.snapshot.sanitized_projection_fingerprint
                    if grounding is not None and grounding.profile is not None
                    else None
                ),
            )
            try:
                request_result = session.request(
                    target.target.ingress,
                    headers=prepared.headers,
                    content=prepared.raw_body,
                )
            except RuntimeSessionError as exc:
                request_failure = exc.reason
    finally:
        try:
            transcript = session.close(opened.artifact.capability_fingerprint)
        except (OSError, ValueError):
            close_failed = True
    if close_failed or transcript is None:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=runtime_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
        )

    runtime_diagnostics = tuple(
        {
            *(item.code for item in opened.artifact.diagnostics),
            *transcript.diagnostics,
            *((request_failure,) if request_failure is not None else ()),
        }
    )
    sealed_authority = _base_authority(
        applicability.applicability_fingerprint,
        scenario_instance_id,
        normal_control_id,
        capability_fingerprint=opened.artifact.capability_fingerprint,
        session_id=opened.artifact.assessment_session_id,
        request_ids=((request_result.request_id,) if request_result is not None else ()),
        transcript_fingerprint=transcript.transcript_fingerprint,
    )
    if not capability_sufficient:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=sealed_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
            runtime_diagnostics=runtime_diagnostics,
        )
    if request_result is None or prepared is None:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=sealed_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.REQUEST_EXECUTION_FAILED,
            runtime_diagnostics=runtime_diagnostics,
        )
    try:
        validate_observation_transcript(opened.artifact, transcript)
    except RuntimeTranscriptMismatchError:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=sealed_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            input_reference=prepared.input_reference(),
            runtime_diagnostics=runtime_diagnostics,
        )
    if transcript.diagnostics:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=sealed_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            input_reference=prepared.input_reference(),
            runtime_diagnostics=runtime_diagnostics,
        )

    request_ids = {item.request_id for item in transcript.events}
    customer_kinds = {
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED,
    }
    cross_control = any(
        item.request_id == request_result.request_id
        and item.kind in customer_kinds
        and item.normal_control_id != normal_control_id
        for item in transcript.events
    )
    if request_ids != {request_result.request_id} or cross_control:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=sealed_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            input_reference=prepared.input_reference(),
            runtime_diagnostics=runtime_diagnostics,
        )

    summary = summarize_observations(
        transcript.events,
        request_id=request_result.request_id,
        normal_control_id=normal_control_id,
        http_status_code=request_result.response.status_code,
    )
    result, evidence_tier, reason = evaluate_observations(summary)
    return _make_result(
        generated_at=timestamp,
        execution_id=execution_id,
        assertion=selected_assertion,
        authority=sealed_authority,
        result=result,
        evidence_tier=evidence_tier,
        reason=reason,
        input_reference=prepared.input_reference(),
        request_observations=(
            ScenarioRequestObservation(
                request_id=request_result.request_id,
                observations=summary,
            ),
        ),
        runtime_diagnostics=runtime_diagnostics,
    )


def execute_sg02(
    repository_root: Path,
    config_path: Path,
    *,
    scenario_instance_id: ScenarioInstanceId,
    expected_applicability_fingerprint: Sha256Digest,
    generated_at: datetime | None = None,
) -> ScenarioExecutionResult:
    """Execute one exact managed SG-02 instance without persisting scenario evidence."""

    timestamp = generated_at or datetime.now(UTC)
    execution_id = new_scenario_execution_id()
    preflight = analyze_applicability(repository_root, config_path, generated_at=timestamp)
    applicability = preflight.artifact
    instance = _sg02_instance(applicability, scenario_instance_id)
    selected_assertion = _assertion_for(
        instance,
        scenario_instance_id,
        SG02_ASSERTION_KEY,
    )
    normal_control_id = instance.normal_control_id if instance is not None else None
    authority = _base_authority(
        applicability.applicability_fingerprint,
        scenario_instance_id,
        normal_control_id,
    )
    if applicability.applicability_fingerprint != expected_applicability_fingerprint:
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
        )
    if instance is None:
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.AUTHORITY_MISMATCH,
        )
    early = _early_applicability_result(instance.state)
    if early is not None:
        result, reason = early
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=result,
            reason=reason,
        )
    if normal_control_id is None:
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.AUTHORITY_MISMATCH,
        )

    config = load_config(config_path)
    if not isinstance(config.runtime, ManagedRuntimeConfig):
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.RUNTIME_MODE_UNSUPPORTED,
        )
    expected_runtime_config_fingerprint = fingerprint_json(config.runtime)
    host_secret_name = config.runtime.env_from_host.get(_SECRET_CHILD_NAME)
    secret = os.environ.get(host_secret_name, "") if host_secret_name is not None else ""
    if not secret:
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.WEBHOOK_SECRET_UNAVAILABLE,
        )

    try:
        opened = open_runtime_session(repository_root, config_path, generated_at=timestamp)
    except (OSError, ValueError):
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
        )

    runtime_authority = _base_authority(
        applicability.applicability_fingerprint,
        scenario_instance_id,
        normal_control_id,
        capability_fingerprint=opened.artifact.capability_fingerprint,
        session_id=opened.artifact.assessment_session_id,
    )
    if (
        opened.applicability.artifact.applicability_fingerprint
        != applicability.applicability_fingerprint
        or opened.artifact.runtime_config_fingerprint != expected_runtime_config_fingerprint
    ):
        if opened.session is not None:
            opened.session.close(opened.artifact.capability_fingerprint)
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=runtime_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
            runtime_diagnostics=tuple(item.code for item in opened.artifact.diagnostics),
        )
    reopened_instance = _sg02_instance(opened.applicability.artifact, scenario_instance_id)
    if reopened_instance != instance:
        if opened.session is not None:
            opened.session.close(opened.artifact.capability_fingerprint)
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=runtime_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.AUTHORITY_MISMATCH,
        )
    if not isinstance(opened.session, ManagedRuntimeSession):
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=runtime_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
            runtime_diagnostics=tuple(item.code for item in opened.artifact.diagnostics),
        )

    prepared = None
    capability_sufficient = _capability_is_sufficient(opened, normal_control_id)
    target = (
        next(
            item
            for item in opened.artifact.customer_values
            if item.target.normal_control_id == normal_control_id
        )
        if capability_sufficient
        else None
    )
    if target is not None:
        prepared = prepare_captured_webhook(
            execution_id=execution_id,
            path=target.target.ingress.effective_path,
            secret=secret,
        )
    request_specs = (
        (
            _ManagedRequestSpec(prepared.headers, prepared.raw_body),
            _ManagedRequestSpec(prepared.headers, prepared.raw_body),
        )
        if prepared is not None
        else ()
    )
    request_results, transcript, request_failure, close_failed = _dispatch_managed_sequence(
        opened.session,
        opened.artifact.capability_fingerprint,
        target.target.ingress if target is not None else None,
        request_specs,
    )
    if close_failed or transcript is None:
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=runtime_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
        )

    runtime_diagnostics = tuple(
        {
            *(item.code for item in opened.artifact.diagnostics),
            *transcript.diagnostics,
            *((request_failure,) if request_failure is not None else ()),
        }
    )
    request_ids = tuple(item.request_id for item in request_results)
    sealed_authority = _base_authority(
        applicability.applicability_fingerprint,
        scenario_instance_id,
        normal_control_id,
        capability_fingerprint=opened.artifact.capability_fingerprint,
        session_id=opened.artifact.assessment_session_id,
        request_ids=request_ids,
        transcript_fingerprint=transcript.transcript_fingerprint,
    )
    input_reference = prepared.input_reference() if prepared is not None else None
    if not capability_sufficient:
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=sealed_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
            runtime_diagnostics=runtime_diagnostics,
        )
    if prepared is None:
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=sealed_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.REQUEST_EXECUTION_FAILED,
            runtime_diagnostics=runtime_diagnostics,
        )
    try:
        validate_observation_transcript(opened.artifact, transcript)
    except RuntimeTranscriptMismatchError:
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=sealed_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            input_reference=input_reference,
            runtime_diagnostics=runtime_diagnostics,
        )
    if transcript.diagnostics:
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=sealed_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            input_reference=input_reference,
            runtime_diagnostics=runtime_diagnostics,
        )
    if len(request_results) != 2:
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=sealed_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.REQUEST_EXECUTION_FAILED,
            input_reference=input_reference,
            runtime_diagnostics=runtime_diagnostics,
        )

    expected_request_ids = tuple(item.request_id for item in request_results)
    customer_kinds = {
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED,
    }
    cross_control = any(
        item.request_id in expected_request_ids
        and item.kind in customer_kinds
        and item.normal_control_id != normal_control_id
        for item in transcript.events
    )
    if not _sequence_authority_is_exact(transcript, request_results) or cross_control:
        return _make_sg02_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion,
            authority=sealed_authority,
            result=VerificationResultState.UNVERIFIED,
            reason=ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            input_reference=input_reference,
            runtime_diagnostics=runtime_diagnostics,
        )

    request_observations = tuple(
        ScenarioRequestObservation(
            request_id=request_result.request_id,
            observations=summarize_observations(
                transcript.events,
                request_id=request_result.request_id,
                normal_control_id=normal_control_id,
                http_status_code=request_result.response.status_code,
            ),
        )
        for request_result in request_results
    )
    result, evidence_tier, reason = evaluate_sequence(
        request_observations[0].observations,
        request_observations[1].observations,
    )
    return _make_sg02_result(
        generated_at=timestamp,
        execution_id=execution_id,
        assertion=selected_assertion,
        authority=sealed_authority,
        result=result,
        evidence_tier=evidence_tier,
        reason=reason,
        input_reference=input_reference,
        request_observations=request_observations,
        runtime_diagnostics=runtime_diagnostics,
    )


def execute_sg05(
    repository_root: Path,
    config_path: Path,
    *,
    scenario_instance_id: ScenarioInstanceId,
    expected_applicability_fingerprint: Sha256Digest,
    generated_at: datetime | None = None,
) -> tuple[ScenarioExecutionResult, ...]:
    """Execute both exact managed SG-05 assertions without persisting evidence."""

    timestamp = generated_at or datetime.now(UTC)
    execution_id = new_scenario_execution_id()
    preflight = analyze_applicability(repository_root, config_path, generated_at=timestamp)
    applicability = preflight.artifact
    instance = _sg05_instance(applicability, scenario_instance_id)
    catalog_assertion_keys = (
        SG05_MUTATION_ASSERTION_KEY,
        SG05_CUSTOMER_VALUE_ASSERTION_KEY,
    )
    assertions = {
        item.key: item
        for item in (instance.assertions if instance is not None else ())
        if item.key in catalog_assertion_keys
    }
    assertion_keys = (
        tuple(key for key in catalog_assertion_keys if key in assertions)
        if instance is not None
        else catalog_assertion_keys
    )

    def selected_assertion(key: str) -> AssertionId:
        assertion = assertions.get(key)
        return (
            assertion.assertion_id
            if assertion is not None
            else assertion_id(scenario_instance_id, key)
        )

    def authority_for(
        key: str,
        *,
        capability_fingerprint: Sha256Digest | None = None,
        session_id: RuntimeSessionId | None = None,
        request_ids: tuple[RuntimeRequestId, ...] = (),
        transcript_fingerprint: Sha256Digest | None = None,
    ) -> ScenarioAuthorityReference:
        assertion = assertions.get(key)
        normal_control_id = (
            assertion.normal_control_id
            if key == SG05_CUSTOMER_VALUE_ASSERTION_KEY and assertion is not None
            else None
        )
        return _base_authority(
            applicability.applicability_fingerprint,
            scenario_instance_id,
            normal_control_id,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fingerprint=transcript_fingerprint,
        )

    results: dict[str, ScenarioExecutionResult] = {}

    def add_result(
        key: str,
        *,
        result: VerificationResultState,
        reason: ScenarioResultReasonCode,
        authority: ScenarioAuthorityReference | None = None,
        evidence_tier: EvidenceTier | None = None,
        input_reference: ScenarioInputReference | None = None,
        request_observations: tuple[ScenarioObservation, ...] = (),
        runtime_diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = (),
    ) -> None:
        results[key] = _make_sg05_result(
            generated_at=timestamp,
            execution_id=execution_id,
            assertion=selected_assertion(key),
            authority=authority or authority_for(key),
            result=result,
            reason=reason,
            evidence_tier=evidence_tier,
            input_reference=input_reference,
            request_observations=request_observations,
            runtime_diagnostics=runtime_diagnostics,
        )

    def ordered_results() -> tuple[ScenarioExecutionResult, ...]:
        return tuple(results[key] for key in assertion_keys)

    if applicability.applicability_fingerprint != expected_applicability_fingerprint:
        for key in assertion_keys:
            add_result(
                key,
                result=VerificationResultState.UNVERIFIED,
                reason=ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
            )
        return ordered_results()
    if instance is None or set(assertions) != set(assertion_keys):
        for key in assertion_keys:
            add_result(
                key,
                result=VerificationResultState.UNVERIFIED,
                reason=ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            )
        return ordered_results()

    applicable_keys: list[str] = []
    for key in assertion_keys:
        assertion = assertions[key]
        early = _early_applicability_result(assertion.state)
        if early is None:
            applicable_keys.append(key)
            continue
        result, reason = early
        add_result(key, result=result, reason=reason)
    if not applicable_keys:
        return ordered_results()

    def add_unverified_for_applicable(
        reason: ScenarioResultReasonCode,
        *,
        capability_fingerprint: Sha256Digest | None = None,
        session_id: RuntimeSessionId | None = None,
        request_ids: tuple[RuntimeRequestId, ...] = (),
        transcript_fingerprint: Sha256Digest | None = None,
        input_reference: ScenarioInputReference | None = None,
        runtime_diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = (),
    ) -> tuple[ScenarioExecutionResult, ...]:
        for key in applicable_keys:
            add_result(
                key,
                authority=authority_for(
                    key,
                    capability_fingerprint=capability_fingerprint,
                    session_id=session_id,
                    request_ids=request_ids,
                    transcript_fingerprint=transcript_fingerprint,
                ),
                result=VerificationResultState.UNVERIFIED,
                reason=reason,
                input_reference=input_reference,
                runtime_diagnostics=runtime_diagnostics,
            )
        return ordered_results()

    config = load_config(config_path)
    if not isinstance(config.runtime, ManagedRuntimeConfig):
        return add_unverified_for_applicable(ScenarioResultReasonCode.RUNTIME_MODE_UNSUPPORTED)
    expected_runtime_config_fingerprint = fingerprint_json(config.runtime)
    host_secret_name = config.runtime.env_from_host.get(_SECRET_CHILD_NAME)
    secret = os.environ.get(host_secret_name, "") if host_secret_name is not None else ""
    if not secret:
        return add_unverified_for_applicable(ScenarioResultReasonCode.WEBHOOK_SECRET_UNAVAILABLE)

    try:
        opened = open_runtime_session(repository_root, config_path, generated_at=timestamp)
    except (OSError, ValueError):
        return add_unverified_for_applicable(ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE)

    capability_fingerprint = opened.artifact.capability_fingerprint
    session_id = opened.artifact.assessment_session_id
    opened_diagnostics = tuple(item.code for item in opened.artifact.diagnostics)
    if (
        opened.applicability.artifact.applicability_fingerprint
        != applicability.applicability_fingerprint
        or opened.artifact.runtime_config_fingerprint != expected_runtime_config_fingerprint
    ):
        if opened.session is not None:
            opened.session.close(capability_fingerprint)
        return add_unverified_for_applicable(
            ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
            runtime_diagnostics=opened_diagnostics,
        )
    reopened_instance = _sg05_instance(opened.applicability.artifact, scenario_instance_id)
    if reopened_instance != instance:
        if opened.session is not None:
            opened.session.close(capability_fingerprint)
        return add_unverified_for_applicable(
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
        )
    if not isinstance(opened.session, ManagedRuntimeSession):
        return add_unverified_for_applicable(
            ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
            runtime_diagnostics=opened_diagnostics,
        )

    ingress_bindings = tuple(
        item for item in opened.plan.ingresses if item.ingress_node_id == instance.ingress_node_id
    )
    if len(ingress_bindings) != 1:
        opened.session.close(capability_fingerprint)
        return add_unverified_for_applicable(
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
        )
    ingress = ingress_bindings[0]
    ingress_capabilities = tuple(
        item for item in opened.artifact.ingresses if item.binding == ingress
    )
    common_capability = bool(
        opened.artifact.mode == "managed"
        and opened.artifact.lifecycle == RuntimeLifecycleState.READY
        and len(ingress_capabilities) == 1
        and ingress_capabilities[0].addressability.state == RuntimeCapabilityState.COMPLETE
        and ingress_capabilities[0].request_correlation.state == RuntimeCapabilityState.COMPLETE
        and opened.artifact.isolation.fresh_process.state == RuntimeCapabilityState.COMPLETE
        and opened.artifact.isolation.observation_reset.state == RuntimeCapabilityState.COMPLETE
    )

    mutation_assertion = assertions[SG05_MUTATION_ASSERTION_KEY]
    mutation_node_ids = tuple(
        sorted(
            {
                evidence.reference
                for reason in mutation_assertion.reasons
                if reason.code == ApplicabilityReasonCode.MUTATION_TARGET_AVAILABLE
                for evidence in reason.evidence
                if evidence.kind == EvidenceReferenceKind.GRAPH_NODE
            }
        )
    )
    mutation_capabilities = tuple(
        item
        for item in opened.artifact.mutations
        if item.target.mutation_node_id in mutation_node_ids and item.target.ingress == ingress
    )
    mutation_capability = bool(
        common_capability
        and mutation_node_ids
        and {item.target.mutation_node_id for item in mutation_capabilities}
        == set(mutation_node_ids)
        and all(
            item.assignment.state == RuntimeCapabilityState.COMPLETE
            and item.strength
            == MutationObservationStrength.PYTHON_ASSIGNMENT_INSTRUCTION_COMPLETION
            for item in mutation_capabilities
        )
    )

    customer_assertion = assertions[SG05_CUSTOMER_VALUE_ASSERTION_KEY]
    normal_control_id = customer_assertion.normal_control_id
    customer_capabilities = tuple(
        item
        for item in opened.artifact.customer_values
        if normal_control_id is not None
        and item.target.normal_control_id == normal_control_id
        and item.target.ingress == ingress
    )
    customer_observable = bool(
        common_capability
        and len(customer_capabilities) == 1
        and customer_capabilities[0].lifecycle.state != RuntimeCapabilityState.UNAVAILABLE
    )
    customer_pass_capability = bool(
        customer_observable
        and customer_capabilities[0].lifecycle.state == RuntimeCapabilityState.COMPLETE
        and customer_capabilities[0].strength == CustomerValueLifecycleStrength.ENTRY_AND_TERMINAL
    )
    should_execute = bool(
        (SG05_MUTATION_ASSERTION_KEY in applicable_keys and mutation_capability)
        or (SG05_CUSTOMER_VALUE_ASSERTION_KEY in applicable_keys and customer_observable)
    )

    prepared = None
    if should_execute:
        prepared = prepare_sg05_requests(
            execution_id=execution_id,
            path=ingress.effective_path,
            secret=secret,
        )
    request_specs = (
        (
            _ManagedRequestSpec(prepared.rejected_headers, prepared.raw_body),
            _ManagedRequestSpec(prepared.valid_headers, prepared.raw_body),
        )
        if prepared is not None
        else ()
    )
    request_results, transcript, request_failure, close_failed = _dispatch_managed_sequence(
        opened.session,
        capability_fingerprint,
        ingress,
        request_specs,
    )

    if close_failed or transcript is None:
        return add_unverified_for_applicable(
            ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
        )
    runtime_diagnostics = tuple(
        {
            *opened_diagnostics,
            *transcript.diagnostics,
            *((request_failure,) if request_failure is not None else ()),
        }
    )
    request_ids = tuple(item.request_id for item in request_results)
    input_reference = prepared.input_reference if prepared is not None else None
    if not should_execute:
        return add_unverified_for_applicable(
            ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fingerprint=transcript.transcript_fingerprint,
            runtime_diagnostics=runtime_diagnostics,
        )
    if prepared is None or len(request_results) != 2:
        return add_unverified_for_applicable(
            ScenarioResultReasonCode.REQUEST_EXECUTION_FAILED,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fingerprint=transcript.transcript_fingerprint,
            input_reference=input_reference,
            runtime_diagnostics=runtime_diagnostics,
        )
    try:
        validate_observation_transcript(opened.artifact, transcript)
    except RuntimeTranscriptMismatchError:
        return add_unverified_for_applicable(
            ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fingerprint=transcript.transcript_fingerprint,
            input_reference=input_reference,
            runtime_diagnostics=runtime_diagnostics,
        )
    if transcript.diagnostics:
        return add_unverified_for_applicable(
            ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fingerprint=transcript.transcript_fingerprint,
            input_reference=input_reference,
            runtime_diagnostics=runtime_diagnostics,
        )

    expected_request_ids = tuple(item.request_id for item in request_results)
    customer_kinds = {
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED,
    }
    mutation_kinds = {
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_REACHED,
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_COMPLETED_NORMALLY,
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_RAISED,
    }
    cross_customer = bool(
        SG05_CUSTOMER_VALUE_ASSERTION_KEY in applicable_keys
        and any(
            item.request_id in expected_request_ids
            and item.kind in customer_kinds
            and item.normal_control_id != normal_control_id
            for item in transcript.events
        )
    )
    cross_mutation = bool(
        SG05_MUTATION_ASSERTION_KEY in applicable_keys
        and any(
            item.request_id in expected_request_ids
            and item.kind in mutation_kinds
            and item.mutation_node_id not in mutation_node_ids
            for item in transcript.events
        )
    )
    if (
        not _sequence_authority_is_exact(transcript, request_results)
        or cross_customer
        or cross_mutation
    ):
        return add_unverified_for_applicable(
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fingerprint=transcript.transcript_fingerprint,
            input_reference=input_reference,
            runtime_diagnostics=runtime_diagnostics,
        )

    def sealed_authority_for(key: str) -> ScenarioAuthorityReference:
        return authority_for(
            key,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fingerprint=transcript.transcript_fingerprint,
        )

    if SG05_MUTATION_ASSERTION_KEY in applicable_keys:
        if not mutation_capability:
            add_result(
                SG05_MUTATION_ASSERTION_KEY,
                authority=sealed_authority_for(SG05_MUTATION_ASSERTION_KEY),
                result=VerificationResultState.UNVERIFIED,
                reason=ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
                input_reference=input_reference,
                runtime_diagnostics=runtime_diagnostics,
            )
        else:
            mutation_observations: tuple[MutationScenarioRequestObservation, ...] = tuple(
                summarize_mutation_observations(
                    transcript.events,
                    request_id=request_result.request_id,
                    mutation_node_ids=mutation_node_ids,
                    http_status_code=request_result.response.status_code,
                )
                for request_result in request_results
            )
            result, tier, reason = evaluate_sg05_mutation_sequence(*mutation_observations)
            add_result(
                SG05_MUTATION_ASSERTION_KEY,
                authority=sealed_authority_for(SG05_MUTATION_ASSERTION_KEY),
                result=result,
                evidence_tier=tier,
                reason=reason,
                input_reference=input_reference,
                request_observations=mutation_observations,
                runtime_diagnostics=runtime_diagnostics,
            )

    if SG05_CUSTOMER_VALUE_ASSERTION_KEY in applicable_keys:
        if not customer_observable or normal_control_id is None:
            add_result(
                SG05_CUSTOMER_VALUE_ASSERTION_KEY,
                authority=sealed_authority_for(SG05_CUSTOMER_VALUE_ASSERTION_KEY),
                result=VerificationResultState.UNVERIFIED,
                reason=ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
                input_reference=input_reference,
                runtime_diagnostics=runtime_diagnostics,
            )
        else:
            customer_observations = tuple(
                ScenarioRequestObservation(
                    request_id=request_result.request_id,
                    observations=summarize_observations(
                        transcript.events,
                        request_id=request_result.request_id,
                        normal_control_id=normal_control_id,
                        http_status_code=request_result.response.status_code,
                    ),
                )
                for request_result in request_results
            )
            result, tier, reason = evaluate_sg05_customer_sequence(
                customer_observations[0].observations,
                customer_observations[1].observations,
            )
            if result == VerificationResultState.VERIFIED_PASS and not customer_pass_capability:
                result = VerificationResultState.UNVERIFIED
                tier = None
                reason = ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT
            add_result(
                SG05_CUSTOMER_VALUE_ASSERTION_KEY,
                authority=sealed_authority_for(SG05_CUSTOMER_VALUE_ASSERTION_KEY),
                result=result,
                evidence_tier=tier,
                reason=reason,
                input_reference=input_reference,
                request_observations=customer_observations,
                runtime_diagnostics=runtime_diagnostics,
            )
    return ordered_results()


def execute_sg07(
    repository_root: Path,
    config_path: Path,
    *,
    scenario_instance_id: ScenarioInstanceId,
    expected_applicability_fingerprint: Sha256Digest,
    generated_at: datetime | None = None,
) -> ScenarioExecutionResult:
    """Execute one webhook request while the linked Checkout callback remains absent."""

    timestamp = generated_at or datetime.now(UTC)
    execution_id = new_scenario_execution_id()
    preflight = analyze_applicability(repository_root, config_path, generated_at=timestamp)
    applicability = preflight.artifact
    instance = _scenario_instance(applicability, ScenarioId.SG_07, scenario_instance_id)
    assertion = _assertion_for(instance, scenario_instance_id, SG07_CUSTOMER_VALUE_ASSERTION_KEY)
    normal_control_id = instance.normal_control_id if instance is not None else None
    authority = _base_authority(
        applicability.applicability_fingerprint, scenario_instance_id, normal_control_id
    )

    def result(
        state: VerificationResultState,
        reason: ScenarioResultReasonCode,
        *,
        selected_authority: ScenarioAuthorityReference = authority,
        tier: EvidenceTier | None = None,
        input_reference: ScenarioInputReference | None = None,
        observations: tuple[ScenarioRequestObservation, ...] = (),
        diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = (),
    ) -> ScenarioExecutionResult:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            scenario_id=ScenarioId.SG_07,
            scenario_definition_fingerprint=SG07_DEFINITION_FINGERPRINT,
            assertion=assertion,
            authority=selected_authority,
            result=state,
            reason=reason,
            evidence_tier=tier,
            input_reference=input_reference,
            request_observations=observations,
            runtime_diagnostics=diagnostics,
        )

    if applicability.applicability_fingerprint != expected_applicability_fingerprint:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
        )
    if instance is None or normal_control_id is None:
        return result(
            VerificationResultState.UNVERIFIED, ScenarioResultReasonCode.AUTHORITY_MISMATCH
        )
    early = _early_applicability_result(instance.assertions[0].state)
    if early is not None:
        return result(*early)
    config = load_config(config_path)
    if not isinstance(config.runtime, ManagedRuntimeConfig):
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.RUNTIME_MODE_UNSUPPORTED,
        )
    expected_runtime_config_fingerprint = fingerprint_json(config.runtime)
    host_secret_name = config.runtime.env_from_host.get(_SECRET_CHILD_NAME)
    secret = os.environ.get(host_secret_name, "") if host_secret_name else ""
    if not secret:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.WEBHOOK_SECRET_UNAVAILABLE,
        )
    try:
        opened = open_runtime_session(repository_root, config_path, generated_at=timestamp)
    except (OSError, ValueError):
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
        )
    capability_fp = opened.artifact.capability_fingerprint
    session_id = opened.artifact.assessment_session_id
    runtime_authority = _base_authority(
        applicability.applicability_fingerprint,
        scenario_instance_id,
        normal_control_id,
        capability_fingerprint=capability_fp,
        session_id=session_id,
    )
    if (
        opened.applicability.artifact.applicability_fingerprint
        != applicability.applicability_fingerprint
        or opened.artifact.runtime_config_fingerprint != expected_runtime_config_fingerprint
        or _scenario_instance(opened.applicability.artifact, ScenarioId.SG_07, scenario_instance_id)
        != instance
    ):
        if opened.session is not None:
            opened.session.close(capability_fp)
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
            selected_authority=runtime_authority,
        )
    if not isinstance(opened.session, ManagedRuntimeSession):
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
            selected_authority=runtime_authority,
        )
    targets = tuple(
        item
        for item in opened.artifact.customer_values
        if item.target.normal_control_id == normal_control_id
    )
    capability_sufficient = _capability_is_sufficient(opened, normal_control_id)
    requests: tuple[_ManagedRequestSpec, ...] = ()
    prepared = None
    if capability_sufficient and len(targets) == 1:
        prepared = prepare_captured_webhook(
            execution_id=execution_id,
            path=targets[0].target.ingress.effective_path,
            secret=secret,
        )
        requests = (_ManagedRequestSpec(prepared.headers, prepared.raw_body),)
    request_results, transcript, request_failure, close_failed = _dispatch_managed_sequence(
        opened.session,
        capability_fp,
        targets[0].target.ingress if targets else opened.plan.ingresses[0],
        requests,
    )
    diagnostics = tuple(
        {
            *(item.code for item in opened.artifact.diagnostics),
            *((transcript.diagnostics) if transcript is not None else ()),
            *((request_failure,) if request_failure is not None else ()),
        }
    )
    sealed = _base_authority(
        applicability.applicability_fingerprint,
        scenario_instance_id,
        normal_control_id,
        capability_fingerprint=capability_fp,
        session_id=session_id,
        request_ids=tuple(item.request_id for item in request_results),
        transcript_fingerprint=(transcript.transcript_fingerprint if transcript else None),
    )
    if close_failed or transcript is None:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            selected_authority=runtime_authority,
        )
    if not capability_sufficient:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
            selected_authority=sealed,
            diagnostics=diagnostics,
        )
    if prepared is None or len(request_results) != 1:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.REQUEST_EXECUTION_FAILED,
            selected_authority=sealed,
            diagnostics=diagnostics,
        )
    try:
        validate_observation_transcript(opened.artifact, transcript)
    except RuntimeTranscriptMismatchError:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            selected_authority=sealed,
            input_reference=prepared.input_reference(),
            diagnostics=diagnostics,
        )
    customer_kinds = {
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED,
    }
    cross_control = any(
        item.kind in customer_kinds and item.normal_control_id != normal_control_id
        for item in transcript.events
    )
    if (
        transcript.diagnostics
        or not _sequence_authority_is_exact(transcript, request_results)
        or cross_control
    ):
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            selected_authority=sealed,
            input_reference=prepared.input_reference(),
            diagnostics=diagnostics,
        )
    summary = summarize_observations(
        transcript.events,
        request_id=request_results[0].request_id,
        normal_control_id=normal_control_id,
        http_status_code=request_results[0].response.status_code,
    )
    state, tier, reason = evaluate_webhook_only(summary)
    return result(
        state,
        reason,
        selected_authority=sealed,
        tier=tier,
        input_reference=prepared.input_reference(),
        observations=(
            ScenarioRequestObservation(
                request_id=request_results[0].request_id, observations=summary
            ),
        ),
        diagnostics=diagnostics,
    )


def execute_sg04(
    repository_root: Path,
    config_path: Path,
    *,
    scenario_instance_id: ScenarioInstanceId,
    expected_applicability_fingerprint: Sha256Digest,
    generated_at: datetime | None = None,
) -> tuple[ScenarioExecutionResult, ...]:
    """Execute captured then stale-authorized requests for one exact webhook control."""

    timestamp = generated_at or datetime.now(UTC)
    execution_id = new_scenario_execution_id()
    preflight = analyze_applicability(repository_root, config_path, generated_at=timestamp)
    applicability = preflight.artifact
    instance = _scenario_instance(applicability, ScenarioId.SG_04, scenario_instance_id)
    catalog_keys = (SG04_CUSTOMER_VALUE_ASSERTION_KEY, SG04_STATE_REGRESSION_ASSERTION_KEY)
    assertions = {
        item.key: item
        for item in (instance.assertions if instance is not None else ())
        if item.key in catalog_keys
    }
    keys = (
        tuple(key for key in catalog_keys if key in assertions)
        if instance is not None
        else catalog_keys
    )
    normal_control_id = instance.normal_control_id if instance is not None else None
    results: dict[str, ScenarioExecutionResult] = {}

    def authority_for(
        *,
        capability_fp: Sha256Digest | None = None,
        session_id: RuntimeSessionId | None = None,
        request_ids: tuple[RuntimeRequestId, ...] = (),
        transcript_fp: Sha256Digest | None = None,
    ) -> ScenarioAuthorityReference:
        return _base_authority(
            applicability.applicability_fingerprint,
            scenario_instance_id,
            normal_control_id,
            capability_fingerprint=capability_fp,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fingerprint=transcript_fp,
        )

    def add(
        key: str,
        state: VerificationResultState,
        reason: ScenarioResultReasonCode,
        *,
        authority: ScenarioAuthorityReference | None = None,
        tier: EvidenceTier | None = None,
        input_reference: ScenarioSafeInputReference | None = None,
        observations: tuple[ScenarioObservation, ...] = (),
        diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = (),
    ) -> None:
        assertion = assertions.get(key)
        selected = assertion.assertion_id if assertion else assertion_id(scenario_instance_id, key)
        results[key] = _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            scenario_id=ScenarioId.SG_04,
            scenario_definition_fingerprint=SG04_DEFINITION_FINGERPRINT,
            assertion=selected,
            authority=authority or authority_for(),
            result=state,
            reason=reason,
            evidence_tier=tier,
            input_reference=input_reference,
            request_observations=observations,
            runtime_diagnostics=diagnostics,
        )

    def ordered() -> tuple[ScenarioExecutionResult, ...]:
        return tuple(results[key] for key in keys if key in results)

    if applicability.applicability_fingerprint != expected_applicability_fingerprint:
        for key in keys:
            add(
                key,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
            )
        return ordered()
    if instance is None or set(assertions) != set(keys):
        for key in keys:
            add(
                key,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            )
        return ordered()
    applicable: list[str] = []
    for key in keys:
        early = _early_applicability_result(assertions[key].state)
        if early is None:
            applicable.append(key)
        else:
            add(key, *early)
    if not applicable:
        return ordered()
    if normal_control_id is None:
        for key in applicable:
            add(
                key,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            )
        return ordered()
    config = load_config(config_path)

    def unverified(
        reason: ScenarioResultReasonCode,
        *,
        authority: ScenarioAuthorityReference | None = None,
        input_reference: ScenarioSafeInputReference | None = None,
        diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = (),
    ) -> tuple[ScenarioExecutionResult, ...]:
        for key in applicable:
            add(
                key,
                VerificationResultState.UNVERIFIED,
                reason,
                authority=authority,
                input_reference=input_reference,
                diagnostics=diagnostics,
            )
        return ordered()

    if not isinstance(config.runtime, ManagedRuntimeConfig):
        return unverified(ScenarioResultReasonCode.RUNTIME_MODE_UNSUPPORTED)
    expected_runtime_config_fingerprint = fingerprint_json(config.runtime)
    host_secret_name = config.runtime.env_from_host.get(_SECRET_CHILD_NAME)
    secret = os.environ.get(host_secret_name, "") if host_secret_name else ""
    if not secret:
        return unverified(ScenarioResultReasonCode.WEBHOOK_SECRET_UNAVAILABLE)
    try:
        opened = open_runtime_session(repository_root, config_path, generated_at=timestamp)
    except (OSError, ValueError):
        return unverified(ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE)
    capability_fp = opened.artifact.capability_fingerprint
    session_id = opened.artifact.assessment_session_id
    runtime_authority = authority_for(capability_fp=capability_fp, session_id=session_id)
    if (
        opened.applicability.artifact.applicability_fingerprint
        != applicability.applicability_fingerprint
        or opened.artifact.runtime_config_fingerprint != expected_runtime_config_fingerprint
        or _scenario_instance(opened.applicability.artifact, ScenarioId.SG_04, scenario_instance_id)
        != instance
    ):
        if opened.session is not None:
            opened.session.close(capability_fp)
        return unverified(
            ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
            authority=runtime_authority,
        )
    if not isinstance(opened.session, ManagedRuntimeSession):
        return unverified(
            ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
            authority=runtime_authority,
        )
    ingress_bindings = tuple(
        item for item in opened.plan.ingresses if item.ingress_node_id == instance.ingress_node_id
    )
    if len(ingress_bindings) != 1:
        opened.session.close(capability_fp)
        return unverified(ScenarioResultReasonCode.AUTHORITY_MISMATCH, authority=runtime_authority)
    ingress = ingress_bindings[0]
    ingress_capabilities = tuple(
        item for item in opened.artifact.ingresses if item.binding == ingress
    )
    common = bool(
        opened.artifact.mode == "managed"
        and opened.artifact.lifecycle == RuntimeLifecycleState.READY
        and len(ingress_capabilities) == 1
        and ingress_capabilities[0].addressability.state == RuntimeCapabilityState.COMPLETE
        and ingress_capabilities[0].request_correlation.state == RuntimeCapabilityState.COMPLETE
        and opened.artifact.isolation.fresh_process.state == RuntimeCapabilityState.COMPLETE
        and opened.artifact.isolation.observation_reset.state == RuntimeCapabilityState.COMPLETE
    )
    customer_caps = tuple(
        item
        for item in opened.artifact.customer_values
        if item.target.normal_control_id == normal_control_id and item.target.ingress == ingress
    )
    customer_observable = bool(
        common
        and len(customer_caps) == 1
        and customer_caps[0].lifecycle.state != RuntimeCapabilityState.UNAVAILABLE
    )
    customer_pass_capability = bool(
        customer_observable
        and customer_caps[0].lifecycle.state == RuntimeCapabilityState.COMPLETE
        and customer_caps[0].strength == CustomerValueLifecycleStrength.ENTRY_AND_TERMINAL
    )
    mutation_ids = tuple(
        sorted(
            {
                evidence.reference
                for reason in assertions[SG04_STATE_REGRESSION_ASSERTION_KEY].reasons
                for evidence in reason.evidence
                if evidence.kind == EvidenceReferenceKind.GRAPH_NODE
            }
        )
    )
    mutation_caps = tuple(
        item
        for item in opened.artifact.mutations
        if item.target.mutation_node_id in mutation_ids and item.target.ingress == ingress
    )
    mutation_capability = bool(
        common
        and mutation_ids
        and {item.target.mutation_node_id for item in mutation_caps} == set(mutation_ids)
        and all(
            item.assignment.state == RuntimeCapabilityState.COMPLETE
            and item.strength
            == MutationObservationStrength.PYTHON_ASSIGNMENT_INSTRUCTION_COMPLETION
            for item in mutation_caps
        )
    )
    should_execute = bool(
        (SG04_CUSTOMER_VALUE_ASSERTION_KEY in applicable and customer_observable)
        or (SG04_STATE_REGRESSION_ASSERTION_KEY in applicable and mutation_capability)
    )
    prepared = (
        prepare_sg04_requests(execution_id=execution_id, path=ingress.effective_path, secret=secret)
        if should_execute
        else None
    )
    specs = (
        (
            _ManagedRequestSpec(prepared.captured.headers, prepared.captured.raw_body),
            _ManagedRequestSpec(prepared.authorized.headers, prepared.authorized.raw_body),
        )
        if prepared is not None
        else ()
    )
    request_results, transcript, request_failure, close_failed = _dispatch_managed_sequence(
        opened.session, capability_fp, ingress, specs
    )
    diagnostics = tuple(
        {
            *(item.code for item in opened.artifact.diagnostics),
            *((transcript.diagnostics) if transcript else ()),
            *((request_failure,) if request_failure else ()),
        }
    )
    sealed = authority_for(
        capability_fp=capability_fp,
        session_id=session_id,
        request_ids=tuple(item.request_id for item in request_results),
        transcript_fp=(transcript.transcript_fingerprint if transcript else None),
    )
    input_reference = prepared.input_reference if prepared else None
    if close_failed or transcript is None:
        return unverified(
            ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            authority=runtime_authority,
        )
    if not should_execute:
        return unverified(
            ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
            authority=sealed,
            diagnostics=diagnostics,
        )
    if prepared is None or len(request_results) != 2:
        return unverified(
            ScenarioResultReasonCode.REQUEST_EXECUTION_FAILED,
            authority=sealed,
            input_reference=input_reference,
            diagnostics=diagnostics,
        )
    try:
        validate_observation_transcript(opened.artifact, transcript)
    except RuntimeTranscriptMismatchError:
        return unverified(
            ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            authority=sealed,
            input_reference=input_reference,
            diagnostics=diagnostics,
        )
    customer_kinds = {
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED,
    }
    cross_customer = any(
        item.kind in customer_kinds and item.normal_control_id != normal_control_id
        for item in transcript.events
    )
    if (
        transcript.diagnostics
        or not _sequence_authority_is_exact(transcript, request_results)
        or cross_customer
    ):
        return unverified(
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            authority=sealed,
            input_reference=input_reference,
            diagnostics=diagnostics,
        )
    if SG04_CUSTOMER_VALUE_ASSERTION_KEY in applicable:
        if not customer_observable:
            add(
                SG04_CUSTOMER_VALUE_ASSERTION_KEY,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
                authority=sealed,
                input_reference=input_reference,
                diagnostics=diagnostics,
            )
        else:
            customer_observations = tuple(
                ScenarioRequestObservation(
                    request_id=request.request_id,
                    observations=summarize_observations(
                        transcript.events,
                        request_id=request.request_id,
                        normal_control_id=normal_control_id,
                        http_status_code=request.response.status_code,
                    ),
                )
                for request in request_results
            )
            state, tier, reason = evaluate_sg04_customer_sequence(
                customer_observations[0].observations,
                customer_observations[1].observations,
            )
            if state == VerificationResultState.VERIFIED_PASS and not customer_pass_capability:
                state, tier, reason = (
                    VerificationResultState.UNVERIFIED,
                    None,
                    ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
                )
            add(
                SG04_CUSTOMER_VALUE_ASSERTION_KEY,
                state,
                reason,
                authority=sealed,
                tier=tier,
                input_reference=input_reference,
                observations=customer_observations,
                diagnostics=diagnostics,
            )
    if SG04_STATE_REGRESSION_ASSERTION_KEY in applicable:
        if not mutation_capability:
            add(
                SG04_STATE_REGRESSION_ASSERTION_KEY,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
                authority=sealed,
                input_reference=input_reference,
                diagnostics=diagnostics,
            )
        else:
            mutation_observations = tuple(
                summarize_mutation_observations(
                    transcript.events,
                    request_id=request.request_id,
                    mutation_node_ids=mutation_ids,
                    http_status_code=request.response.status_code,
                )
                for request in request_results
            )
            graph_nodes = {item.node_id: item for item in preflight.snapshot.graph.nodes}
            captured_ids = tuple(
                node_id
                for node_id in mutation_ids
                if getattr(graph_nodes[node_id].details, "assigned_payment_state", None)
                == "captured"
            )
            authorized_ids = tuple(
                node_id
                for node_id in mutation_ids
                if getattr(graph_nodes[node_id].details, "assigned_payment_state", None)
                == "authorized"
            )
            if len(captured_ids) != 1 or len(authorized_ids) != 1:
                state, tier, reason = (
                    VerificationResultState.UNVERIFIED,
                    None,
                    ScenarioResultReasonCode.AUTHORITY_MISMATCH,
                )
            else:
                state, tier, reason = evaluate_sg04_state_sequence(
                    mutation_observations[0],
                    mutation_observations[1],
                    captured_node_id=captured_ids[0],
                    authorized_node_id=authorized_ids[0],
                )
            add(
                SG04_STATE_REGRESSION_ASSERTION_KEY,
                state,
                reason,
                authority=sealed,
                tier=tier,
                input_reference=input_reference,
                observations=mutation_observations,
                diagnostics=diagnostics,
            )
    return ordered()


def execute_sg03(
    repository_root: Path,
    config_path: Path,
    *,
    scenario_instance_id: ScenarioInstanceId,
    expected_applicability_fingerprint: Sha256Digest,
    generated_at: datetime | None = None,
) -> ScenarioExecutionResult:
    """Execute a StateGuard-modeled failed acknowledgement and modeled retry."""

    timestamp = generated_at or datetime.now(UTC)
    execution_id = new_scenario_execution_id()
    applicability = analyze_applicability(
        repository_root, config_path, generated_at=timestamp
    ).artifact
    instance = _scenario_instance(applicability, ScenarioId.SG_03, scenario_instance_id)
    selected_assertion = _assertion_for(instance, scenario_instance_id, SG03_ASSERTION_KEY)
    normal_control_id = instance.normal_control_id if instance is not None else None
    authority = _base_authority(
        applicability.applicability_fingerprint,
        scenario_instance_id,
        normal_control_id,
    )

    def result(
        state: VerificationResultState,
        reason: ScenarioResultReasonCode,
        *,
        selected_authority: ScenarioAuthorityReference = authority,
        tier: EvidenceTier | None = None,
        input_reference: ScenarioInputReference | None = None,
        observations: tuple[ScenarioRequestObservation, ...] = (),
        diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = (),
    ) -> ScenarioExecutionResult:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            scenario_id=ScenarioId.SG_03,
            scenario_definition_fingerprint=SG03_DEFINITION_FINGERPRINT,
            assertion=selected_assertion,
            authority=selected_authority,
            result=state,
            reason=reason,
            evidence_tier=tier,
            input_reference=input_reference,
            request_observations=observations,
            runtime_diagnostics=diagnostics,
        )

    if applicability.applicability_fingerprint != expected_applicability_fingerprint:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
        )
    if instance is None or normal_control_id is None:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
        )
    assertion = next((item for item in instance.assertions if item.key == SG03_ASSERTION_KEY), None)
    if assertion is None:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
        )
    early = _early_applicability_result(assertion.state)
    if early is not None:
        return result(*early)

    config = load_config(config_path)
    if not isinstance(config.runtime, ManagedRuntimeConfig):
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.RUNTIME_MODE_UNSUPPORTED,
        )
    expected_runtime_config_fingerprint = fingerprint_json(config.runtime)
    host_secret_name = config.runtime.env_from_host.get(_SECRET_CHILD_NAME)
    secret = os.environ.get(host_secret_name, "") if host_secret_name else ""
    if not secret:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.WEBHOOK_SECRET_UNAVAILABLE,
        )
    try:
        opened = open_runtime_session(repository_root, config_path, generated_at=timestamp)
    except (OSError, ValueError):
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
        )

    capability_fp = opened.artifact.capability_fingerprint
    session_id = opened.artifact.assessment_session_id
    runtime_authority = _base_authority(
        applicability.applicability_fingerprint,
        scenario_instance_id,
        normal_control_id,
        capability_fingerprint=capability_fp,
        session_id=session_id,
    )
    reopened = _scenario_instance(
        opened.applicability.artifact, ScenarioId.SG_03, scenario_instance_id
    )
    if (
        opened.applicability.artifact.applicability_fingerprint
        != applicability.applicability_fingerprint
        or opened.artifact.runtime_config_fingerprint != expected_runtime_config_fingerprint
        or reopened != instance
    ):
        if opened.session is not None:
            opened.session.close(capability_fp)
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
            selected_authority=runtime_authority,
        )
    if not isinstance(opened.session, ManagedRuntimeSession):
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
            selected_authority=runtime_authority,
            diagnostics=tuple(item.code for item in opened.artifact.diagnostics),
        )

    targets = tuple(
        item
        for item in opened.artifact.customer_values
        if item.target.normal_control_id == normal_control_id
    )
    acknowledged_node_ids = {
        evidence.reference
        for reason in assertion.reasons
        for evidence in reason.evidence
        if evidence.kind == EvidenceReferenceKind.GRAPH_NODE
    }
    acknowledgements = tuple(
        item
        for item in opened.artifact.acknowledgements
        if item.target.acknowledgement_node_id in acknowledged_node_ids
        and item.target.status_code is not None
        and 200 <= item.target.status_code < 300
        and item.target.outcome == AcknowledgementOutcome.SUCCESS_2XX
        and item.timeline.state == RuntimeCapabilityState.COMPLETE
    )
    capability_sufficient = bool(
        _capability_is_sufficient(opened, normal_control_id)
        and len(targets) == 1
        and len(acknowledgements) == 1
        and acknowledgements[0].target.ingress == targets[0].target.ingress
    )
    prepared = (
        prepare_captured_webhook(
            execution_id=execution_id,
            path=targets[0].target.ingress.effective_path,
            secret=secret,
        )
        if capability_sufficient
        else None
    )
    requests = (
        (
            _ManagedRequestSpec(
                prepared.headers,
                prepared.raw_body,
                acknowledgement_failure=(
                    ManagedAcknowledgementFailureMode.FORCE_NON_2XX_AFTER_SUCCESS
                ),
                acknowledgement_node_id=(acknowledgements[0].target.acknowledgement_node_id),
            ),
            _ManagedRequestSpec(prepared.headers, prepared.raw_body),
        )
        if prepared is not None
        else ()
    )
    request_results, transcript, request_failure, close_failed = _dispatch_managed_sequence(
        opened.session,
        capability_fp,
        targets[0].target.ingress if targets else None,
        requests,
    )
    diagnostics = tuple(
        {
            *(item.code for item in opened.artifact.diagnostics),
            *((transcript.diagnostics) if transcript else ()),
            *((request_failure,) if request_failure else ()),
        }
    )
    request_ids = tuple(item.request_id for item in request_results)
    sealed = _base_authority(
        applicability.applicability_fingerprint,
        scenario_instance_id,
        normal_control_id,
        capability_fingerprint=capability_fp,
        session_id=session_id,
        request_ids=request_ids,
        transcript_fingerprint=(transcript.transcript_fingerprint if transcript else None),
    )
    input_reference = prepared.input_reference() if prepared else None
    if close_failed or transcript is None:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            selected_authority=runtime_authority,
        )
    if not capability_sufficient:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
            selected_authority=sealed,
            diagnostics=diagnostics,
        )
    if prepared is None or len(request_results) != 2:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.REQUEST_EXECUTION_FAILED,
            selected_authority=sealed,
            input_reference=input_reference,
            diagnostics=diagnostics,
        )
    try:
        validate_observation_transcript(opened.artifact, transcript)
    except RuntimeTranscriptMismatchError:
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            selected_authority=sealed,
            input_reference=input_reference,
            diagnostics=diagnostics,
        )
    customer_kinds = {
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED,
    }
    cross_control = any(
        event.kind in customer_kinds and event.normal_control_id != normal_control_id
        for event in transcript.events
    )
    if (
        transcript.diagnostics
        or not _sequence_authority_is_exact(transcript, request_results)
        or cross_control
    ):
        return result(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            selected_authority=sealed,
            input_reference=input_reference,
            diagnostics=diagnostics,
        )

    first, retry = request_results
    acknowledgement = summarize_acknowledgement_failure(
        transcript.events,
        request_id=first.request_id,
        acknowledgement_node_id=acknowledgements[0].target.acknowledgement_node_id,
    )
    observations = (
        ScenarioRequestObservation(
            request_id=first.request_id,
            observations=summarize_observations(
                transcript.events,
                request_id=first.request_id,
                normal_control_id=normal_control_id,
                http_status_code=first.response.status_code,
            ),
            acknowledgement_failure=acknowledgement,
        ),
        ScenarioRequestObservation(
            request_id=retry.request_id,
            observations=summarize_observations(
                transcript.events,
                request_id=retry.request_id,
                normal_control_id=normal_control_id,
                http_status_code=retry.response.status_code,
            ),
        ),
    )
    state, tier, reason = evaluate_sg03_sequence(*observations)
    return result(
        state,
        reason,
        selected_authority=sealed,
        tier=tier,
        input_reference=input_reference,
        observations=observations,
        diagnostics=diagnostics,
    )


def execute_sg08(
    repository_root: Path,
    config_path: Path,
    *,
    scenario_instance_id: ScenarioInstanceId,
    expected_applicability_fingerprint: Sha256Digest,
    generated_at: datetime | None = None,
) -> tuple[ScenarioExecutionResult, ...]:
    """Execute only SG-08 invariants that do not require unproved merchant late state."""

    timestamp = generated_at or datetime.now(UTC)
    execution_id = new_scenario_execution_id()
    applicability = analyze_applicability(
        repository_root, config_path, generated_at=timestamp
    ).artifact
    instance = _scenario_instance(applicability, ScenarioId.SG_08, scenario_instance_id)
    assertions = {item.key: item for item in (instance.assertions if instance is not None else ())}
    keys = tuple(assertions) or (SG08_LATE_POLICY_ASSERTION_KEY,)
    normal_control_id = instance.normal_control_id if instance is not None else None

    def authority_for(
        *,
        capability_fingerprint: Sha256Digest | None = None,
        session_id: RuntimeSessionId | None = None,
        request_ids: tuple[RuntimeRequestId, ...] = (),
        transcript_fingerprint: Sha256Digest | None = None,
    ) -> ScenarioAuthorityReference:
        return _base_authority(
            applicability.applicability_fingerprint,
            scenario_instance_id,
            normal_control_id,
            capability_fingerprint=capability_fingerprint,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fingerprint=transcript_fingerprint,
        )

    def result(
        key: str,
        state: VerificationResultState,
        reason: ScenarioResultReasonCode,
        *,
        selected_authority: ScenarioAuthorityReference | None = None,
        tier: EvidenceTier | None = None,
        input_reference: ScenarioSafeInputReference | None = None,
        observations: tuple[ScenarioRequestObservation, ...] = (),
        diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = (),
    ) -> ScenarioExecutionResult:
        return _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            scenario_id=ScenarioId.SG_08,
            scenario_definition_fingerprint=SG08_DEFINITION_FINGERPRINT,
            assertion=_assertion_for(instance, scenario_instance_id, key),
            authority=selected_authority or authority_for(),
            result=state,
            reason=reason,
            evidence_tier=tier,
            input_reference=input_reference,
            request_observations=observations,
            runtime_diagnostics=diagnostics,
        )

    def all_results(
        state: VerificationResultState, reason: ScenarioResultReasonCode
    ) -> tuple[ScenarioExecutionResult, ...]:
        return tuple(result(key, state, reason) for key in keys)

    if applicability.applicability_fingerprint != expected_applicability_fingerprint:
        return all_results(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
        )
    if instance is None:
        return all_results(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
        )
    if normal_control_id is None:
        early = tuple(_early_applicability_result(item.state) for item in assertions.values())
        if early and all(item is not None for item in early):
            return tuple(
                result(key, *selected)
                for key, selected in zip(keys, early, strict=True)
                if selected is not None
            )
        return all_results(
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
        )

    policy = applicability.policy
    fulfilment = policy.fulfilment.confirmed_policy
    late_authorisation = policy.late_authorisation.confirmed_policy
    if fulfilment is None or late_authorisation is None:
        return tuple(
            result(
                key,
                *(
                    _early_applicability_result(assertions[key].state)
                    or (
                        VerificationResultState.UNVERIFIED,
                        ScenarioResultReasonCode.AUTHORITY_MISMATCH,
                    )
                ),
            )
            for key in keys
        )
    if (
        policy.fulfilment.evidence_current is not True
        or policy.late_authorisation.evidence_current is not True
    ):
        return tuple(
            result(
                key,
                *(
                    _early_applicability_result(assertions[key].state)
                    or (
                        VerificationResultState.UNVERIFIED,
                        ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
                    )
                ),
            )
            for key in keys
        )
    if fulfilment == FulfilmentPolicy.AUTHORIZED_ALLOWED:
        return tuple(
            result(
                key,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.MERCHANT_LATE_CONTEXT_UNPROVEN,
            )
            for key in keys
        )

    applicable = {
        key for key, item in assertions.items() if item.state == ApplicabilityState.APPLICABLE
    }
    early_results = {
        key: result(
            key,
            *(
                early
                or (
                    VerificationResultState.UNVERIFIED,
                    ScenarioResultReasonCode.AUTHORITY_MISMATCH,
                )
            ),
        )
        for key, item in assertions.items()
        if item.state != ApplicabilityState.APPLICABLE
        for early in (_early_applicability_result(item.state),)
    }
    if not applicable:
        return tuple(early_results[key] for key in keys)

    config = load_config(config_path)
    if not isinstance(config.runtime, ManagedRuntimeConfig):
        return tuple(
            early_results.get(key)
            or result(
                key,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.RUNTIME_MODE_UNSUPPORTED,
            )
            for key in keys
        )
    expected_runtime_config_fingerprint = fingerprint_json(config.runtime)
    host_secret_name = config.runtime.env_from_host.get(_SECRET_CHILD_NAME)
    secret = os.environ.get(host_secret_name, "") if host_secret_name else ""
    if not secret:
        return tuple(
            early_results.get(key)
            or result(
                key,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.WEBHOOK_SECRET_UNAVAILABLE,
            )
            for key in keys
        )
    try:
        opened = open_runtime_session(repository_root, config_path, generated_at=timestamp)
    except (OSError, ValueError):
        return tuple(
            early_results.get(key)
            or result(
                key,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
            )
            for key in keys
        )

    capability_fp = opened.artifact.capability_fingerprint
    session_id = opened.artifact.assessment_session_id
    runtime_authority = authority_for(capability_fingerprint=capability_fp, session_id=session_id)
    reopened = _scenario_instance(
        opened.applicability.artifact, ScenarioId.SG_08, scenario_instance_id
    )
    if (
        opened.applicability.artifact.applicability_fingerprint
        != applicability.applicability_fingerprint
        or opened.artifact.runtime_config_fingerprint != expected_runtime_config_fingerprint
        or reopened != instance
    ):
        if opened.session is not None:
            opened.session.close(capability_fp)
        return tuple(
            early_results.get(key)
            or result(
                key,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
                selected_authority=runtime_authority,
            )
            for key in keys
        )
    if not isinstance(opened.session, ManagedRuntimeSession):
        return tuple(
            early_results.get(key)
            or result(
                key,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
                selected_authority=runtime_authority,
            )
            for key in keys
        )

    targets = tuple(
        item
        for item in opened.artifact.customer_values
        if item.target.normal_control_id == normal_control_id
    )
    capability_sufficient = bool(
        _capability_is_sufficient(opened, normal_control_id) and len(targets) == 1
    )
    include_capture = SG08_CAPTURE_ASSERTION_KEY in applicable
    prepared = (
        prepare_sg08_requests(
            execution_id=execution_id,
            path=targets[0].target.ingress.effective_path,
            secret=secret,
            fulfilment=fulfilment,
            fulfilment_evidence_fingerprint=policy.fulfilment.evidence_fingerprint,
            late_authorisation=late_authorisation,
            late_authorisation_evidence_fingerprint=(
                policy.late_authorisation.evidence_fingerprint
            ),
            include_capture=include_capture,
        )
        if capability_sufficient
        else None
    )
    prepared_requests = (
        (prepared.authorized,) + ((prepared.captured,) if prepared.captured else ())
        if prepared is not None
        else ()
    )
    specs = tuple(_ManagedRequestSpec(item.headers, item.raw_body) for item in prepared_requests)
    request_results, transcript, request_failure, close_failed = _dispatch_managed_sequence(
        opened.session,
        capability_fp,
        targets[0].target.ingress if targets else None,
        specs,
    )
    diagnostics = tuple(
        {
            *(item.code for item in opened.artifact.diagnostics),
            *((transcript.diagnostics) if transcript else ()),
            *((request_failure,) if request_failure else ()),
        }
    )
    request_ids = tuple(item.request_id for item in request_results)
    sealed = authority_for(
        capability_fingerprint=capability_fp,
        session_id=session_id,
        request_ids=request_ids,
        transcript_fingerprint=(transcript.transcript_fingerprint if transcript else None),
    )
    input_reference = prepared.input_reference if prepared else None

    def active_unverified(
        reason: ScenarioResultReasonCode,
        *,
        selected_authority: ScenarioAuthorityReference = sealed,
    ) -> tuple[ScenarioExecutionResult, ...]:
        return tuple(
            early_results.get(key)
            or result(
                key,
                VerificationResultState.UNVERIFIED,
                reason,
                selected_authority=selected_authority,
                input_reference=input_reference,
                diagnostics=diagnostics,
            )
            for key in keys
        )

    if close_failed or transcript is None:
        return active_unverified(
            ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            selected_authority=runtime_authority,
        )
    if not capability_sufficient:
        return active_unverified(ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT)
    if prepared is None or len(request_results) != len(prepared_requests):
        return active_unverified(ScenarioResultReasonCode.REQUEST_EXECUTION_FAILED)
    try:
        validate_observation_transcript(opened.artifact, transcript)
    except RuntimeTranscriptMismatchError:
        return active_unverified(ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY)
    customer_kinds = {
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED,
    }
    cross_control = any(
        event.kind in customer_kinds and event.normal_control_id != normal_control_id
        for event in transcript.events
    )
    if (
        transcript.diagnostics
        or not _sequence_authority_is_exact(transcript, request_results)
        or cross_control
    ):
        return active_unverified(ScenarioResultReasonCode.AUTHORITY_MISMATCH)

    observations = tuple(
        ScenarioRequestObservation(
            request_id=request.request_id,
            observations=summarize_observations(
                transcript.events,
                request_id=request.request_id,
                normal_control_id=normal_control_id,
                http_status_code=request.response.status_code,
            ),
        )
        for request in request_results
    )
    evaluated: dict[str, ScenarioExecutionResult] = dict(early_results)
    if SG08_PRECAPTURE_ASSERTION_KEY in applicable:
        state, tier, reason = evaluate_sg08_precapture(
            observations[0].observations,
            observations[1].observations if len(observations) == 2 else None,
            late_authorisation=late_authorisation,
        )
        evaluated[SG08_PRECAPTURE_ASSERTION_KEY] = result(
            SG08_PRECAPTURE_ASSERTION_KEY,
            state,
            reason,
            selected_authority=sealed,
            tier=tier,
            input_reference=input_reference,
            observations=observations,
            diagnostics=diagnostics,
        )
    if SG08_CAPTURE_ASSERTION_KEY in applicable:
        if len(observations) != 2:
            evaluated[SG08_CAPTURE_ASSERTION_KEY] = result(
                SG08_CAPTURE_ASSERTION_KEY,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.REQUEST_EXECUTION_FAILED,
                selected_authority=sealed,
                input_reference=input_reference,
                observations=observations,
                diagnostics=diagnostics,
            )
        else:
            state, tier, reason = evaluate_sg08_capture_sequence(
                observations[0].observations, observations[1].observations
            )
            evaluated[SG08_CAPTURE_ASSERTION_KEY] = result(
                SG08_CAPTURE_ASSERTION_KEY,
                state,
                reason,
                selected_authority=sealed,
                tier=tier,
                input_reference=input_reference,
                observations=observations,
                diagnostics=diagnostics,
            )
    return tuple(evaluated[key] for key in keys)


def execute_sg06(
    repository_root: Path,
    config_path: Path,
    *,
    scenario_instance_id: ScenarioInstanceId,
    expected_applicability_fingerprint: Sha256Digest,
    generated_at: datetime | None = None,
) -> tuple[ScenarioExecutionResult, ...]:
    """Execute a tampered Checkout callback followed by a valid local control."""

    timestamp = generated_at or datetime.now(UTC)
    execution_id = new_scenario_execution_id()
    preflight = analyze_applicability(repository_root, config_path, generated_at=timestamp)
    applicability = preflight.artifact
    instance = _scenario_instance(applicability, ScenarioId.SG_06, scenario_instance_id)
    catalog_keys = (SG06_MUTATION_ASSERTION_KEY, SG06_CUSTOMER_VALUE_ASSERTION_KEY)
    assertions = {
        item.key: item
        for item in (instance.assertions if instance is not None else ())
        if item.key in catalog_keys
    }
    keys = (
        tuple(key for key in catalog_keys if key in assertions)
        if instance is not None
        else catalog_keys
    )
    results: dict[str, ScenarioExecutionResult] = {}

    def authority_for(
        key: str,
        *,
        capability_fp: Sha256Digest | None = None,
        session_id: RuntimeSessionId | None = None,
        request_ids: tuple[RuntimeRequestId, ...] = (),
        transcript_fp: Sha256Digest | None = None,
    ) -> ScenarioAuthorityReference:
        normal_control = (
            assertions[key].normal_control_id
            if key == SG06_CUSTOMER_VALUE_ASSERTION_KEY and key in assertions
            else None
        )
        return _base_authority(
            applicability.applicability_fingerprint,
            scenario_instance_id,
            normal_control,
            capability_fingerprint=capability_fp,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fingerprint=transcript_fp,
        )

    def add(
        key: str,
        state: VerificationResultState,
        reason: ScenarioResultReasonCode,
        *,
        authority: ScenarioAuthorityReference | None = None,
        tier: EvidenceTier | None = None,
        input_reference: ScenarioSafeInputReference | None = None,
        observations: tuple[ScenarioObservation, ...] = (),
        diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = (),
    ) -> None:
        assertion = assertions.get(key)
        selected = assertion.assertion_id if assertion else assertion_id(scenario_instance_id, key)
        results[key] = _make_result(
            generated_at=timestamp,
            execution_id=execution_id,
            scenario_id=ScenarioId.SG_06,
            scenario_definition_fingerprint=SG06_DEFINITION_FINGERPRINT,
            assertion=selected,
            authority=authority or authority_for(key),
            result=state,
            reason=reason,
            evidence_tier=tier,
            input_reference=input_reference,
            request_observations=observations,
            runtime_diagnostics=diagnostics,
        )

    def ordered() -> tuple[ScenarioExecutionResult, ...]:
        return tuple(results[key] for key in keys if key in results)

    if applicability.applicability_fingerprint != expected_applicability_fingerprint:
        for key in keys:
            add(
                key,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
            )
        return ordered()
    if instance is None or set(assertions) != set(keys):
        for key in keys:
            add(
                key,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            )
        return ordered()
    applicable: list[str] = []
    for key in keys:
        early = _early_applicability_result(assertions[key].state)
        if early is None:
            applicable.append(key)
        else:
            add(key, *early)
    if not applicable:
        return ordered()

    def unverified(
        reason: ScenarioResultReasonCode,
        *,
        capability_fp: Sha256Digest | None = None,
        session_id: RuntimeSessionId | None = None,
        request_ids: tuple[RuntimeRequestId, ...] = (),
        transcript_fp: Sha256Digest | None = None,
        input_reference: ScenarioSafeInputReference | None = None,
        diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = (),
    ) -> tuple[ScenarioExecutionResult, ...]:
        for key in applicable:
            add(
                key,
                VerificationResultState.UNVERIFIED,
                reason,
                authority=authority_for(
                    key,
                    capability_fp=capability_fp,
                    session_id=session_id,
                    request_ids=request_ids,
                    transcript_fp=transcript_fp,
                ),
                input_reference=input_reference,
                diagnostics=diagnostics,
            )
        return ordered()

    config = load_config(config_path)
    if not isinstance(config.runtime, ManagedRuntimeConfig):
        return unverified(ScenarioResultReasonCode.RUNTIME_MODE_UNSUPPORTED)
    expected_runtime_config_fingerprint = fingerprint_json(config.runtime)
    secret_host = config.runtime.env_from_host.get(_CHECKOUT_SECRET_CHILD_NAME)
    order_host = config.runtime.env_from_host.get(_SERVER_ORDER_CHILD_NAME)
    secret = os.environ.get(secret_host, "") if secret_host else ""
    server_order = os.environ.get(order_host, "") if order_host else ""
    if not secret:
        return unverified(ScenarioResultReasonCode.CHECKOUT_SECRET_UNAVAILABLE)
    if not server_order:
        return unverified(ScenarioResultReasonCode.SERVER_ORDER_CONTROL_UNAVAILABLE)
    try:
        opened = open_runtime_session(repository_root, config_path, generated_at=timestamp)
    except (OSError, ValueError):
        return unverified(ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE)
    capability_fp = opened.artifact.capability_fingerprint
    session_id = opened.artifact.assessment_session_id
    opened_diagnostics = tuple(item.code for item in opened.artifact.diagnostics)
    if (
        opened.applicability.artifact.applicability_fingerprint
        != applicability.applicability_fingerprint
        or opened.artifact.runtime_config_fingerprint != expected_runtime_config_fingerprint
        or _scenario_instance(opened.applicability.artifact, ScenarioId.SG_06, scenario_instance_id)
        != instance
    ):
        if opened.session is not None:
            opened.session.close(capability_fp)
        return unverified(
            ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY,
            capability_fp=capability_fp,
            session_id=session_id,
            diagnostics=opened_diagnostics,
        )
    if not isinstance(opened.session, ManagedRuntimeSession):
        return unverified(
            ScenarioResultReasonCode.RUNTIME_SESSION_UNAVAILABLE,
            capability_fp=capability_fp,
            session_id=session_id,
            diagnostics=opened_diagnostics,
        )
    ingress_bindings = tuple(
        item for item in opened.plan.ingresses if item.ingress_node_id == instance.ingress_node_id
    )
    if len(ingress_bindings) != 1:
        opened.session.close(capability_fp)
        return unverified(
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            capability_fp=capability_fp,
            session_id=session_id,
        )
    ingress = ingress_bindings[0]
    if ingress.checkout_request_binding is None:
        opened.session.close(capability_fp)
        return unverified(
            ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
            capability_fp=capability_fp,
            session_id=session_id,
        )
    ingress_caps = tuple(item for item in opened.artifact.ingresses if item.binding == ingress)
    common = bool(
        opened.artifact.mode == "managed"
        and opened.artifact.lifecycle == RuntimeLifecycleState.READY
        and len(ingress_caps) == 1
        and ingress_caps[0].addressability.state == RuntimeCapabilityState.COMPLETE
        and ingress_caps[0].request_correlation.state == RuntimeCapabilityState.COMPLETE
        and opened.artifact.isolation.fresh_process.state == RuntimeCapabilityState.COMPLETE
        and opened.artifact.isolation.observation_reset.state == RuntimeCapabilityState.COMPLETE
    )
    mutation_ids = tuple(
        sorted(
            {
                evidence.reference
                for reason in assertions[SG06_MUTATION_ASSERTION_KEY].reasons
                for evidence in reason.evidence
                if evidence.kind == EvidenceReferenceKind.GRAPH_NODE
            }
        )
    )
    mutation_caps = tuple(
        item
        for item in opened.artifact.mutations
        if item.target.mutation_node_id in mutation_ids and item.target.ingress == ingress
    )
    mutation_capability = bool(
        common
        and mutation_ids
        and {item.target.mutation_node_id for item in mutation_caps} == set(mutation_ids)
        and all(
            item.assignment.state == RuntimeCapabilityState.COMPLETE
            and item.strength
            == MutationObservationStrength.PYTHON_ASSIGNMENT_INSTRUCTION_COMPLETION
            for item in mutation_caps
        )
    )
    normal_control_id = assertions[SG06_CUSTOMER_VALUE_ASSERTION_KEY].normal_control_id
    customer_caps = tuple(
        item
        for item in opened.artifact.customer_values
        if normal_control_id is not None
        and item.target.normal_control_id == normal_control_id
        and item.target.ingress == ingress
    )
    customer_observable = bool(
        common
        and len(customer_caps) == 1
        and customer_caps[0].lifecycle.state != RuntimeCapabilityState.UNAVAILABLE
    )
    customer_pass_capability = bool(
        customer_observable
        and customer_caps[0].lifecycle.state == RuntimeCapabilityState.COMPLETE
        and customer_caps[0].strength == CustomerValueLifecycleStrength.ENTRY_AND_TERMINAL
    )
    should_execute = bool(
        (SG06_MUTATION_ASSERTION_KEY in applicable and mutation_capability)
        or (SG06_CUSTOMER_VALUE_ASSERTION_KEY in applicable and customer_observable)
    )
    prepared = (
        prepare_sg06_requests(
            execution_id=execution_id,
            path=ingress.effective_path,
            binding=ingress.checkout_request_binding,
            secret=secret,
            server_order_id=server_order,
        )
        if should_execute
        else None
    )
    specs = (
        tuple(
            _ManagedRequestSpec(item.headers, item.content, item.params)
            for item in (prepared.tampered, prepared.valid)
        )
        if prepared is not None
        else ()
    )
    request_results, transcript, request_failure, close_failed = _dispatch_managed_sequence(
        opened.session, capability_fp, ingress, specs
    )
    diagnostics = tuple(
        {
            *opened_diagnostics,
            *((transcript.diagnostics) if transcript else ()),
            *((request_failure,) if request_failure else ()),
        }
    )
    request_ids = tuple(item.request_id for item in request_results)
    transcript_fp = transcript.transcript_fingerprint if transcript else None
    input_reference = prepared.input_reference if prepared else None
    if close_failed or transcript is None:
        return unverified(
            ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            capability_fp=capability_fp,
            session_id=session_id,
        )
    if not should_execute:
        return unverified(
            ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
            capability_fp=capability_fp,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fp=transcript_fp,
            diagnostics=diagnostics,
        )
    if prepared is None or len(request_results) != 2:
        return unverified(
            ScenarioResultReasonCode.REQUEST_EXECUTION_FAILED,
            capability_fp=capability_fp,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fp=transcript_fp,
            input_reference=input_reference,
            diagnostics=diagnostics,
        )
    try:
        validate_observation_transcript(opened.artifact, transcript)
    except RuntimeTranscriptMismatchError:
        return unverified(
            ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY,
            capability_fp=capability_fp,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fp=transcript_fp,
            input_reference=input_reference,
            diagnostics=diagnostics,
        )
    customer_kinds = {
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED,
    }
    mutation_kinds = {
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_REACHED,
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_COMPLETED_NORMALLY,
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_RAISED,
    }
    cross_customer = any(
        item.kind in customer_kinds
        and normal_control_id is not None
        and item.normal_control_id != normal_control_id
        for item in transcript.events
    )
    cross_mutation = (
        any(
            item.kind in mutation_kinds and item.mutation_node_id not in mutation_ids
            for item in transcript.events
        )
        if SG06_MUTATION_ASSERTION_KEY in applicable
        else False
    )
    if (
        transcript.diagnostics
        or not _sequence_authority_is_exact(transcript, request_results)
        or cross_customer
        or cross_mutation
    ):
        return unverified(
            ScenarioResultReasonCode.AUTHORITY_MISMATCH,
            capability_fp=capability_fp,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fp=transcript_fp,
            input_reference=input_reference,
            diagnostics=diagnostics,
        )

    def sealed(key: str) -> ScenarioAuthorityReference:
        return authority_for(
            key,
            capability_fp=capability_fp,
            session_id=session_id,
            request_ids=request_ids,
            transcript_fp=transcript_fp,
        )

    if SG06_MUTATION_ASSERTION_KEY in applicable:
        if not mutation_capability:
            add(
                SG06_MUTATION_ASSERTION_KEY,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
                authority=sealed(SG06_MUTATION_ASSERTION_KEY),
                input_reference=input_reference,
                diagnostics=diagnostics,
            )
        else:
            mutation_observations = tuple(
                summarize_mutation_observations(
                    transcript.events,
                    request_id=request.request_id,
                    mutation_node_ids=mutation_ids,
                    http_status_code=request.response.status_code,
                )
                for request in request_results
            )
            state, tier, reason = evaluate_sg06_mutation_sequence(*mutation_observations)
            add(
                SG06_MUTATION_ASSERTION_KEY,
                state,
                reason,
                authority=sealed(SG06_MUTATION_ASSERTION_KEY),
                tier=tier,
                input_reference=input_reference,
                observations=mutation_observations,
                diagnostics=diagnostics,
            )
    if SG06_CUSTOMER_VALUE_ASSERTION_KEY in applicable:
        if not customer_observable or normal_control_id is None:
            add(
                SG06_CUSTOMER_VALUE_ASSERTION_KEY,
                VerificationResultState.UNVERIFIED,
                ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
                authority=sealed(SG06_CUSTOMER_VALUE_ASSERTION_KEY),
                input_reference=input_reference,
                diagnostics=diagnostics,
            )
        else:
            customer_observations = tuple(
                ScenarioRequestObservation(
                    request_id=request.request_id,
                    observations=summarize_observations(
                        transcript.events,
                        request_id=request.request_id,
                        normal_control_id=normal_control_id,
                        http_status_code=request.response.status_code,
                    ),
                )
                for request in request_results
            )
            state, tier, reason = evaluate_sg06_customer_sequence(
                customer_observations[0].observations,
                customer_observations[1].observations,
            )
            if state == VerificationResultState.VERIFIED_PASS and not customer_pass_capability:
                state, tier, reason = (
                    VerificationResultState.UNVERIFIED,
                    None,
                    ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT,
                )
            add(
                SG06_CUSTOMER_VALUE_ASSERTION_KEY,
                state,
                reason,
                authority=sealed(SG06_CUSTOMER_VALUE_ASSERTION_KEY),
                tier=tier,
                input_reference=input_reference,
                observations=customer_observations,
                diagnostics=diagnostics,
            )
    return ordered()
