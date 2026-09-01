"""Persisted contracts for merchant-policy evidence and scenario applicability."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from stateguard.contracts.common import (
    ArtifactFields,
    AssertionId,
    GraphEdgeId,
    GraphNodeId,
    NormalControlId,
    PersistedArtifactModel,
    ProjectId,
    RouteRegistrationId,
    ScenarioInstanceId,
    Sha256Digest,
    SymbolId,
)
from stateguard.contracts.config import FulfilmentPolicy, LateAuthorisationPolicy
from stateguard.contracts.identity import canonical_json, fingerprint_json
from stateguard.graph.contracts import PaymentIngressKind


class PolicyEvidenceStatus(StrEnum):
    CONSISTENT_SUGGESTION = "CONSISTENT_SUGGESTION"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class ApplicabilityState(StrEnum):
    """Internal Step 4 state; this is not a public verification result."""

    APPLICABLE = "APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NEEDS_INPUT = "NEEDS_INPUT"
    INDETERMINATE = "INDETERMINATE"


class AssertionRole(StrEnum):
    CORE = "CORE"
    OPTIONAL = "OPTIONAL"


class ScenarioId(StrEnum):
    SG_01 = "SG-01"
    SG_02 = "SG-02"
    SG_03 = "SG-03"
    SG_04 = "SG-04"
    SG_05 = "SG-05"
    SG_06 = "SG-06"
    SG_07 = "SG-07"
    SG_08 = "SG-08"


SG01_ASSERTION_KEY = "VALUE_EXACTLY_ONCE_AT_POLICY_THRESHOLD"
SG02_ASSERTION_KEY = "DUPLICATE_VALUE_AT_MOST_ONCE"
SG03_ASSERTION_KEY = "RETRY_VALUE_AT_MOST_ONCE"
SG04_CUSTOMER_VALUE_ASSERTION_KEY = "OUT_OF_ORDER_VALUE_AT_MOST_ONCE"
SG04_STATE_REGRESSION_ASSERTION_KEY = "MERCHANT_STATE_DOES_NOT_REGRESS"
SG05_CUSTOMER_VALUE_ASSERTION_KEY = "FORGED_WEBHOOK_NO_CUSTOMER_VALUE"
SG05_MUTATION_ASSERTION_KEY = "FORGED_WEBHOOK_NO_TRUSTED_MUTATION"
SG06_CUSTOMER_VALUE_ASSERTION_KEY = "TAMPERED_CALLBACK_NO_CUSTOMER_VALUE"
SG06_MUTATION_ASSERTION_KEY = "TAMPERED_CALLBACK_NO_TRUSTED_MUTATION"
SG07_CUSTOMER_VALUE_ASSERTION_KEY = "WEBHOOK_OUTCOME_WITHOUT_CALLBACK"
SG08_PRECAPTURE_ASSERTION_KEY = "LATE_AUTHORIZATION_PROVIDES_NO_VALUE"
SG08_CAPTURE_ASSERTION_KEY = "LATE_PAYMENT_VALUE_ONCE_AFTER_CAPTURE"
SG08_LATE_POLICY_ASSERTION_KEY = "LATE_PAYMENT_POLICY_OUTCOME"


class EvidenceReferenceKind(StrEnum):
    GRAPH_NODE = "GRAPH_NODE"
    GRAPH_EDGE = "GRAPH_EDGE"
    GRAPH_DIAGNOSTIC = "GRAPH_DIAGNOSTIC"
    SEMANTIC_RESOLUTION = "SEMANTIC_RESOLUTION"
    MERCHANT_POLICY = "MERCHANT_POLICY"
    RAZORPAY_RULE = "RAZORPAY_RULE"
    NORMAL_CONTROL = "NORMAL_CONTROL"


class ApplicabilityReasonCode(StrEnum):
    EXACT_CONTROL_AVAILABLE = "EXACT_CONTROL_AVAILABLE"
    INGRESS_ABSENT = "INGRESS_ABSENT"
    CUSTOMER_VALUE_UNRESOLVED = "CUSTOMER_VALUE_UNRESOLVED"
    CUSTOMER_VALUE_PATH_ABSENT = "CUSTOMER_VALUE_PATH_ABSENT"
    GRAPH_COVERAGE_INSUFFICIENT = "GRAPH_COVERAGE_INSUFFICIENT"
    FULFILMENT_POLICY_REQUIRED = "FULFILMENT_POLICY_REQUIRED"
    FULFILMENT_POLICY_STALE = "FULFILMENT_POLICY_STALE"
    NORMAL_CAPTURE_THRESHOLD_AVAILABLE = "NORMAL_CAPTURE_THRESHOLD_AVAILABLE"
    NORMAL_CAPTURE_THRESHOLD_UNPROVEN = "NORMAL_CAPTURE_THRESHOLD_UNPROVEN"
    CAPTURED_EVENT_TARGET_AVAILABLE = "CAPTURED_EVENT_TARGET_AVAILABLE"
    CAPTURED_EVENT_TARGET_UNPROVEN = "CAPTURED_EVENT_TARGET_UNPROVEN"
    LATE_AUTHORISATION_POLICY_REQUIRED = "LATE_AUTHORISATION_POLICY_REQUIRED"
    LATE_AUTHORISATION_POLICY_STALE = "LATE_AUTHORISATION_POLICY_STALE"
    MERCHANT_LATE_CONTEXT_UNPROVEN = "MERCHANT_LATE_CONTEXT_UNPROVEN"
    VALUE_BEFORE_ACK_PROVEN = "VALUE_BEFORE_ACK_PROVEN"
    VALUE_BEFORE_ACK_NOT_PRESENT = "VALUE_BEFORE_ACK_NOT_PRESENT"
    ACK_ORDER_UNRESOLVED = "ACK_ORDER_UNRESOLVED"
    MUTATION_TARGET_AVAILABLE = "MUTATION_TARGET_AVAILABLE"
    MUTATION_TARGET_ABSENT = "MUTATION_TARGET_ABSENT"
    CHECKOUT_SURFACE_REQUIRED = "CHECKOUT_SURFACE_REQUIRED"
    CHECKOUT_REQUEST_BINDING_AVAILABLE = "CHECKOUT_REQUEST_BINDING_AVAILABLE"
    CHECKOUT_REQUEST_BINDING_UNRESOLVED = "CHECKOUT_REQUEST_BINDING_UNRESOLVED"
    CHECKOUT_TARGET_LINK_AVAILABLE = "CHECKOUT_TARGET_LINK_AVAILABLE"
    CHECKOUT_TARGET_LINK_UNRESOLVED = "CHECKOUT_TARGET_LINK_UNRESOLVED"
    STATE_REGRESSION_TARGET_AVAILABLE = "STATE_REGRESSION_TARGET_AVAILABLE"
    STATE_REGRESSION_TARGET_ABSENT = "STATE_REGRESSION_TARGET_ABSENT"
    STATE_REGRESSION_TARGET_UNRESOLVED = "STATE_REGRESSION_TARGET_UNRESOLVED"
    POLICY_MATRIX_SELECTED = "POLICY_MATRIX_SELECTED"
    LATE_SEQUENCE_NOT_SUPPORTED = "LATE_SEQUENCE_NOT_SUPPORTED"
    LATE_SEQUENCE_UNRESOLVED = "LATE_SEQUENCE_UNRESOLVED"


class EvidenceReference(PersistedArtifactModel):
    kind: EvidenceReferenceKind
    reference: str = Field(min_length=1, max_length=2048)


class ApplicabilityReason(PersistedArtifactModel):
    code: ApplicabilityReasonCode
    evidence: tuple[EvidenceReference, ...] = ()


class NormalControlInstance(PersistedArtifactModel):
    control_id: NormalControlId
    ingress_node_id: GraphNodeId
    route_registration_id: RouteRegistrationId
    ingress_kind: PaymentIngressKind
    customer_value_node_id: GraphNodeId
    customer_value_symbol_id: SymbolId
    connectivity_edge_id: GraphEdgeId
    call_path_references: tuple[str, ...] = Field(min_length=1)
    semantic_resolution_fingerprint: Sha256Digest


class FulfilmentPolicyAssessment(PersistedArtifactModel):
    evidence_status: PolicyEvidenceStatus
    evidence_fingerprint: Sha256Digest
    observed_states: tuple[str, ...] = ()
    suggested_policy: FulfilmentPolicy | None = None
    confirmed_policy: FulfilmentPolicy | None = None
    evidence_current: bool | None = None
    implementation_mismatch: bool = False

    @model_validator(mode="after")
    def validate_assessment(self) -> FulfilmentPolicyAssessment:
        if (self.evidence_status == PolicyEvidenceStatus.CONSISTENT_SUGGESTION) != (
            self.suggested_policy is not None
        ):
            raise ValueError("only consistent evidence may carry a policy suggestion")
        if self.confirmed_policy is None:
            if self.evidence_current is not None or self.implementation_mismatch:
                raise ValueError("unconfirmed policy cannot have confirmation status")
        elif self.evidence_current is None:
            raise ValueError("confirmed policy requires evidence-current status")
        expected_mismatch = (
            self.confirmed_policy is not None
            and self.suggested_policy is not None
            and self.confirmed_policy != self.suggested_policy
        )
        if self.implementation_mismatch != expected_mismatch:
            raise ValueError("implementation mismatch must match evidence and declaration")
        return self


class LateAuthorisationPolicyAssessment(PersistedArtifactModel):
    evidence_fingerprint: Sha256Digest
    confirmed_policy: LateAuthorisationPolicy | None = None
    evidence_current: bool | None = None

    @model_validator(mode="after")
    def validate_confirmation(self) -> LateAuthorisationPolicyAssessment:
        if (self.confirmed_policy is None) != (self.evidence_current is None):
            raise ValueError("late-authorisation confirmation status must accompany policy")
        return self


class MerchantPolicyAssessment(PersistedArtifactModel):
    fulfilment: FulfilmentPolicyAssessment
    late_authorisation: LateAuthorisationPolicyAssessment


class AssertionApplicability(PersistedArtifactModel):
    assertion_id: AssertionId
    key: str = Field(min_length=1, max_length=128)
    role: AssertionRole
    state: ApplicabilityState
    reasons: tuple[ApplicabilityReason, ...] = Field(min_length=1)
    normal_control_id: NormalControlId | None = None


def roll_up_assertions(
    assertions: Iterable[AssertionApplicability],
) -> ApplicabilityState:
    core = tuple(item for item in assertions if item.role == AssertionRole.CORE)
    if not core:
        raise ValueError("scenario applicability requires at least one core assertion")
    states = {item.state for item in core}
    for candidate in (
        ApplicabilityState.APPLICABLE,
        ApplicabilityState.NEEDS_INPUT,
        ApplicabilityState.INDETERMINATE,
        ApplicabilityState.NOT_APPLICABLE,
    ):
        if candidate in states:
            return candidate
    raise AssertionError("unreachable applicability state")


class ScenarioInstance(PersistedArtifactModel):
    instance_id: ScenarioInstanceId
    state: ApplicabilityState
    ingress_node_id: GraphNodeId | None = None
    normal_control_id: NormalControlId | None = None
    route_registration_id: RouteRegistrationId | None = None
    customer_value_node_id: GraphNodeId | None = None
    customer_value_symbol_id: SymbolId | None = None
    assertions: tuple[AssertionApplicability, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_rollup(self) -> ScenarioInstance:
        if self.state != roll_up_assertions(self.assertions):
            raise ValueError("scenario-instance state must roll up from core assertions")
        return self


class ScenarioApplicability(PersistedArtifactModel):
    scenario_id: ScenarioId
    state: ApplicabilityState
    instances: tuple[ScenarioInstance, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_rollup(self) -> ScenarioApplicability:
        assertions = tuple(
            assertion for instance in self.instances for assertion in instance.assertions
        )
        if self.state != roll_up_assertions(assertions):
            raise ValueError("scenario state must roll up from all core assertions")
        if len({item.instance_id for item in self.instances}) != len(self.instances):
            raise ValueError("scenario instance IDs must be unique")
        return self


def applicability_fingerprint(
    *,
    project_id: ProjectId,
    project_source_fingerprint: Sha256Digest,
    source_index_fingerprint: Sha256Digest,
    structural_graph_fingerprint: Sha256Digest,
    projected_graph_fingerprint: Sha256Digest,
    semantic_resolution_fingerprint: Sha256Digest | None,
    policy: MerchantPolicyAssessment,
    normal_controls: Iterable[NormalControlInstance],
    scenarios: Iterable[ScenarioApplicability],
) -> Sha256Digest:
    return fingerprint_json(
        {
            "schema_version": 2,
            "project_id": project_id,
            "project_source_fingerprint": project_source_fingerprint,
            "source_index_fingerprint": source_index_fingerprint,
            "structural_graph_fingerprint": structural_graph_fingerprint,
            "projected_graph_fingerprint": projected_graph_fingerprint,
            "semantic_resolution_fingerprint": semantic_resolution_fingerprint,
            "policy": policy,
            "normal_controls": sorted(normal_controls, key=canonical_json),
            "scenarios": sorted(scenarios, key=canonical_json),
        }
    )


class ScenarioApplicabilityArtifact(ArtifactFields):
    artifact_type: Literal["SCENARIO_APPLICABILITY"] = "SCENARIO_APPLICABILITY"
    schema_version: Literal[2] = 2
    project_id: ProjectId
    project_source_fingerprint: Sha256Digest
    source_index_fingerprint: Sha256Digest
    structural_graph_fingerprint: Sha256Digest
    projected_graph_fingerprint: Sha256Digest
    semantic_resolution_fingerprint: Sha256Digest | None = None
    policy: MerchantPolicyAssessment
    normal_controls: tuple[NormalControlInstance, ...] = ()
    scenarios: tuple[ScenarioApplicability, ...] = Field(min_length=8, max_length=8)
    applicability_fingerprint: Sha256Digest

    @model_validator(mode="after")
    def validate_artifact(self) -> ScenarioApplicabilityArtifact:
        controls = {item.control_id: item for item in self.normal_controls}
        if len(controls) != len(self.normal_controls):
            raise ValueError("normal-control IDs must be unique")
        if {item.scenario_id for item in self.scenarios} != set(ScenarioId):
            raise ValueError("applicability artifact must contain the fixed scenario catalog")
        for scenario in self.scenarios:
            for instance in scenario.instances:
                if (
                    instance.normal_control_id is not None
                    and instance.normal_control_id not in controls
                ):
                    raise ValueError("scenario instance refers to an unknown normal control")
                if instance.normal_control_id is not None:
                    control = controls[instance.normal_control_id]
                    if instance.ingress_node_id != control.ingress_node_id:
                        raise ValueError(
                            "scenario instance ingress must match exact normal control"
                        )
                    if instance.route_registration_id != control.route_registration_id:
                        raise ValueError("scenario instance route must match exact normal control")
                    if instance.customer_value_node_id != control.customer_value_node_id:
                        raise ValueError(
                            "scenario instance customer-value node must match exact normal control"
                        )
                    if instance.customer_value_symbol_id != control.customer_value_symbol_id:
                        raise ValueError(
                            "scenario instance customer-value symbol must match "
                            "exact normal control"
                        )
                elif any(
                    value is not None
                    for value in (
                        instance.route_registration_id,
                        instance.customer_value_node_id,
                        instance.customer_value_symbol_id,
                    )
                ):
                    raise ValueError("control identity fields require a normal control")
                for assertion in instance.assertions:
                    if (
                        assertion.normal_control_id is not None
                        and assertion.normal_control_id not in controls
                    ):
                        raise ValueError("assertion refers to an unknown normal control")
                    if (
                        instance.normal_control_id is not None
                        and assertion.normal_control_id is not None
                        and assertion.normal_control_id != instance.normal_control_id
                    ):
                        raise ValueError("assertion dependency must match exact instance control")
        expected = applicability_fingerprint(
            project_id=self.project_id,
            project_source_fingerprint=self.project_source_fingerprint,
            source_index_fingerprint=self.source_index_fingerprint,
            structural_graph_fingerprint=self.structural_graph_fingerprint,
            projected_graph_fingerprint=self.projected_graph_fingerprint,
            semantic_resolution_fingerprint=self.semantic_resolution_fingerprint,
            policy=self.policy,
            normal_controls=self.normal_controls,
            scenarios=self.scenarios,
        )
        if self.applicability_fingerprint != expected:
            raise ValueError("applicability fingerprint must match artifact contents")
        return self
