"""Immutable Step 7 verification-run, check, evidence, and finding contracts."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from stateguard.applicability.contracts import (
    ApplicabilityReasonCode,
    ApplicabilityState,
    AssertionRole,
    ScenarioId,
)
from stateguard.contracts.common import (
    ArtifactFields,
    AssertionId,
    FindingKey,
    FindingOccurrenceId,
    GraphEdgeId,
    GraphNodeId,
    NormalControlId,
    PersistedArtifactModel,
    ProjectId,
    ProvenanceKind,
    RouteRegistrationId,
    RuntimeRequestId,
    RuntimeSessionId,
    ScenarioExecutionId,
    ScenarioInstanceId,
    Sha256Digest,
    SourceFileId,
    SourceLocation,
    SymbolId,
    VerificationCheckId,
    VerificationCheckKey,
    VerificationRunId,
    normalize_relative_path,
)
from stateguard.contracts.config import FulfilmentPolicy, LateAuthorisationPolicy
from stateguard.contracts.identity import (
    assertion_id,
    canonical_json,
    finding_key,
    finding_occurrence_id,
    fingerprint_json,
    verification_check_id,
    verification_check_key,
)
from stateguard.failure_lab.contracts import (
    EvidenceTier,
    GroundedScenarioInputReference,
    ScenarioResultReasonCode,
    ScenarioSafeInputReference,
    VerificationResultState,
)
from stateguard.grounding.contracts import (
    CheckGroundingEvidence,
    RazorpayGroundingSnapshot,
    RazorpayGroundingStatus,
)
from stateguard.rules.razorpay import RazorpayProtocolRuleId
from stateguard.runtime.contracts import RuntimeCapabilityReasonCode
from stateguard.semantics.contracts import ResolutionBasis, ResolutionState

from .catalog import PolicyDimension, RequestRole


class VerificationRunStatus(StrEnum):
    COMPLETED = "COMPLETED"


class FindingKind(StrEnum):
    VERIFIED_FAILURE = "VERIFIED_FAILURE"
    STATIC_WARNING = "STATIC_WARNING"
    RESOLUTION_REQUIRED = "RESOLUTION_REQUIRED"
    VERIFICATION_COVERAGE = "VERIFICATION_COVERAGE"


class ReverificationMode(StrEnum):
    REVERIFY_CURRENT_AUTHORITY = "REVERIFY_CURRENT_AUTHORITY"


class ComponentSchemaVersions(PersistedArtifactModel):
    source_index: Literal[2] = 2
    structural_graph: Literal[2] = 2
    projected_graph: Literal[2] = 2
    semantics: Literal[2] = 2
    applicability: Literal[2] = 2
    runtime_capability: Literal[1] = 1
    scenario_execution_result: Literal[2, 3] = 3
    razorpay_rule_catalog: Literal[1] = 1
    razorpay_grounding: Literal[1] | None = None


class SemanticProvenanceSnapshot(PersistedArtifactModel):
    kind: ProvenanceKind
    source_location: SourceLocation | None = None
    supporting_fingerprint: Sha256Digest | None = None


class SemanticAuthoritySnapshot(PersistedArtifactModel):
    state: ResolutionState | None = None
    basis: ResolutionBasis | None = None
    selected_symbol_id: SymbolId | None = None
    resolution_fingerprint: Sha256Digest | None = None
    semantic_context_fingerprint: Sha256Digest | None = None
    selected_target_provenance: tuple[SemanticProvenanceSnapshot, ...] = ()

    @model_validator(mode="after")
    def validate_resolution(self) -> SemanticAuthoritySnapshot:
        if self.state == ResolutionState.UNIQUE:
            if (
                self.basis is None
                or self.basis == ResolutionBasis.UNRESOLVED
                or self.selected_symbol_id is None
                or self.resolution_fingerprint is None
            ):
                raise ValueError("unique semantic authority requires selected resolved evidence")
        elif self.selected_symbol_id is not None:
            raise ValueError("unresolved semantic authority cannot select a target")
        return self


class PolicyAuthoritySnapshot(PersistedArtifactModel):
    fulfilment: FulfilmentPolicy | None = None
    fulfilment_evidence_fingerprint: Sha256Digest
    fulfilment_evidence_current: bool | None = None
    late_authorisation: LateAuthorisationPolicy | None = None
    late_authorisation_evidence_fingerprint: Sha256Digest
    late_authorisation_evidence_current: bool | None = None


class RazorpayRuleSnapshot(PersistedArtifactModel):
    rule_id: RazorpayProtocolRuleId
    fact: str = Field(min_length=1, max_length=1024)
    source_url: str = Field(pattern=r"^https://")
    verified_on: date
    rule_fingerprint: Sha256Digest


class RazorpayRuleAuthoritySnapshot(PersistedArtifactModel):
    catalog_version: Literal[1] = 1
    catalog_fingerprint: Sha256Digest
    referenced_rules: tuple[RazorpayRuleSnapshot, ...]

    @model_validator(mode="after")
    def validate_rules(self) -> RazorpayRuleAuthoritySnapshot:
        ids = tuple(item.rule_id for item in self.referenced_rules)
        if len(ids) != len(set(ids)) or ids != tuple(sorted(ids, key=str)):
            raise ValueError("referenced Razorpay rules must be unique and ordered")
        return self


class VerificationAuthoritySnapshot(PersistedArtifactModel):
    project_id: ProjectId
    config_fingerprint: Sha256Digest
    project_source_fingerprint: Sha256Digest
    source_index_fingerprint: Sha256Digest
    structural_graph_fingerprint: Sha256Digest
    projected_graph_fingerprint: Sha256Digest
    applicability_fingerprint: Sha256Digest
    runtime_config_fingerprint: Sha256Digest
    runtime_capability_fingerprints: tuple[Sha256Digest, ...] = ()
    semantic: SemanticAuthoritySnapshot
    policy: PolicyAuthoritySnapshot
    razorpay_rules: RazorpayRuleAuthoritySnapshot
    razorpay_grounding: RazorpayGroundingSnapshot | None = None
    schema_versions: ComponentSchemaVersions = ComponentSchemaVersions()

    @model_validator(mode="after")
    def validate_capabilities(self) -> VerificationAuthoritySnapshot:
        if self.runtime_capability_fingerprints != tuple(
            sorted(set(self.runtime_capability_fingerprints))
        ):
            raise ValueError("runtime capability fingerprints must be unique and ordered")
        return self


class ApplicabilityEvidenceSnapshot(PersistedArtifactModel):
    state: ApplicabilityState
    role: AssertionRole
    reasons: tuple[ApplicabilityReasonCode, ...] = Field(min_length=1)
    graph_node_ids: tuple[GraphNodeId, ...] = ()
    graph_edge_ids: tuple[GraphEdgeId, ...] = ()
    normal_control_ids: tuple[NormalControlId, ...] = ()

    @model_validator(mode="after")
    def validate_collections(self) -> ApplicabilityEvidenceSnapshot:
        for collection in (
            self.reasons,
            self.graph_node_ids,
            self.graph_edge_ids,
            self.normal_control_ids,
        ):
            if len(collection) != len(set(collection)):
                raise ValueError("applicability evidence collections must be unique")
        return self


class CheckTargetReference(PersistedArtifactModel):
    ingress_node_id: GraphNodeId | None = None
    route_registration_id: RouteRegistrationId | None = None
    ingress_symbol_id: SymbolId | None = None
    normal_control_id: NormalControlId | None = None
    customer_value_node_id: GraphNodeId | None = None
    customer_value_symbol_id: SymbolId | None = None
    connectivity_edge_id: GraphEdgeId | None = None
    mutation_node_ids: tuple[GraphNodeId, ...] = ()
    acknowledgement_node_ids: tuple[GraphNodeId, ...] = ()

    @model_validator(mode="after")
    def validate_targets(self) -> CheckTargetReference:
        if self.mutation_node_ids != tuple(sorted(set(self.mutation_node_ids))):
            raise ValueError("mutation target identities must be unique and ordered")
        if self.acknowledgement_node_ids != tuple(sorted(set(self.acknowledgement_node_ids))):
            raise ValueError("acknowledgement identities must be unique and ordered")
        return self


class SourceEvidenceReference(PersistedArtifactModel):
    symbol_id: SymbolId
    source_location: SourceLocation


class RelevantSourceFileAuthority(PersistedArtifactModel):
    """Confidentiality-safe authority for one source file used by a check."""

    file_id: SourceFileId
    path: str
    content_fingerprint: Sha256Digest

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return normalize_relative_path(value)


class RelevantFactAuthority(PersistedArtifactModel):
    """Stable identity and content fingerprint for an exact indexed/graph fact."""

    fact_id: str = Field(min_length=1, max_length=2048)
    fact_fingerprint: Sha256Digest


class CustomerRuntimeEvidence(PersistedArtifactModel):
    entered_count: int = Field(ge=0)
    returned_normally_count: int = Field(ge=0)
    exception_escaped_count: int = Field(ge=0)
    entered_sequences: tuple[int, ...] = ()
    returned_normally_sequences: tuple[int, ...] = ()
    exception_escaped_sequences: tuple[int, ...] = ()

    @model_validator(mode="after")
    def validate_counts(self) -> CustomerRuntimeEvidence:
        if self.entered_count != len(self.entered_sequences):
            raise ValueError("customer entry evidence count is inconsistent")
        if self.returned_normally_count != len(self.returned_normally_sequences):
            raise ValueError("customer return evidence count is inconsistent")
        if self.exception_escaped_count != len(self.exception_escaped_sequences):
            raise ValueError("customer exception evidence count is inconsistent")
        return self


class MutationRuntimeEvidence(PersistedArtifactModel):
    mutation_node_id: GraphNodeId
    observation_strength: Literal["PYTHON_ASSIGNMENT_INSTRUCTION_COMPLETION"] = (
        "PYTHON_ASSIGNMENT_INSTRUCTION_COMPLETION"
    )
    reached_count: int = Field(ge=0)
    completed_normally_count: int = Field(ge=0)
    raised_count: int = Field(ge=0)
    reached_sequences: tuple[int, ...] = ()
    completed_normally_sequences: tuple[int, ...] = ()
    raised_sequences: tuple[int, ...] = ()

    @model_validator(mode="after")
    def validate_counts(self) -> MutationRuntimeEvidence:
        if self.reached_count != len(self.reached_sequences):
            raise ValueError("mutation reach evidence count is inconsistent")
        if self.completed_normally_count != len(self.completed_normally_sequences):
            raise ValueError("mutation completion evidence count is inconsistent")
        if self.raised_count != len(self.raised_sequences):
            raise ValueError("mutation raised evidence count is inconsistent")
        return self


class AcknowledgementInjectionEvidence(PersistedArtifactModel):
    acknowledgement_node_id: GraphNodeId
    original_status_code: int = Field(ge=200, le=299)
    effective_status_code: Literal[503] = 503
    injection_sequence: int = Field(ge=1)


class RuntimeRequestEvidence(PersistedArtifactModel):
    request_id: RuntimeRequestId
    ordinal: int = Field(ge=0)
    role: RequestRole
    request_received_sequences: tuple[int, ...] = ()
    response_completed_sequences: tuple[int, ...] = ()
    request_aborted_sequences: tuple[int, ...] = ()
    http_status_code: int | None = Field(default=None, ge=100, le=599)
    customer: CustomerRuntimeEvidence | None = None
    mutations: tuple[MutationRuntimeEvidence, ...] = ()
    acknowledgement_injection: AcknowledgementInjectionEvidence | None = None

    @model_validator(mode="after")
    def validate_projection(self) -> RuntimeRequestEvidence:
        if (self.customer is None) == (not self.mutations):
            raise ValueError("request evidence requires exactly one target observation shape")
        ids = tuple(item.mutation_node_id for item in self.mutations)
        if len(ids) != len(set(ids)):
            raise ValueError("request mutation evidence must have unique targets")
        return self


class RuntimeEvidenceProjection(PersistedArtifactModel):
    scenario_execution_id: ScenarioExecutionId
    runtime_session_id: RuntimeSessionId | None = None
    runtime_capability_fingerprint: Sha256Digest | None = None
    transcript_fingerprint: Sha256Digest | None = None
    requests: tuple[RuntimeRequestEvidence, ...] = ()
    diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = ()

    @model_validator(mode="after")
    def validate_runtime(self) -> RuntimeEvidenceProjection:
        request_ids = tuple(item.request_id for item in self.requests)
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("runtime request evidence must be unique")
        if tuple(item.ordinal for item in self.requests) != tuple(range(len(self.requests))):
            raise ValueError("runtime request evidence must preserve exact order")
        if self.requests and self.runtime_session_id is None:
            raise ValueError("runtime requests require session authority")
        if self.transcript_fingerprint is not None and (
            self.runtime_session_id is None or self.runtime_capability_fingerprint is None
        ):
            raise ValueError("transcript evidence requires session and capability authority")
        if len(self.diagnostics) != len(set(self.diagnostics)):
            raise ValueError("runtime diagnostic codes must be unique")
        return self


class CheckPolicyAuthority(PersistedArtifactModel):
    dimensions: tuple[PolicyDimension, ...] = ()
    fulfilment: FulfilmentPolicy | None = None
    fulfilment_evidence_fingerprint: Sha256Digest | None = None
    late_authorisation: LateAuthorisationPolicy | None = None
    late_authorisation_evidence_fingerprint: Sha256Digest | None = None

    @model_validator(mode="after")
    def validate_dimensions(self) -> CheckPolicyAuthority:
        dimensions = set(self.dimensions)
        if (PolicyDimension.FULFILMENT in dimensions) != (
            self.fulfilment_evidence_fingerprint is not None
        ):
            raise ValueError("fulfilment policy evidence must match declared usage")
        if (PolicyDimension.LATE_AUTHORISATION in dimensions) != (
            self.late_authorisation_evidence_fingerprint is not None
        ):
            raise ValueError("late policy evidence must match declared usage")
        return self


class FindingRelevantAuthoritySnapshot(PersistedArtifactModel):
    """Smallest persisted authority that materially supports one normalized check."""

    source_files: tuple[RelevantSourceFileAuthority, ...] = ()
    symbols: tuple[RelevantFactAuthority, ...] = ()
    call_sites: tuple[RelevantFactAuthority, ...] = ()
    call_path_references: tuple[str, ...] = ()
    graph_nodes: tuple[RelevantFactAuthority, ...] = ()
    graph_edges: tuple[RelevantFactAuthority, ...] = ()
    applicability_assertion_fingerprint: Sha256Digest
    selected_semantic_symbol_id: SymbolId | None = None
    semantic_resolution_fingerprint: Sha256Digest | None = None
    semantic_context_fingerprint: Sha256Digest | None = None
    key_policy_authority: CheckPolicyAuthority
    invariant_id: str = Field(min_length=1, max_length=128)
    invariant_version: int = Field(ge=1)
    scenario_definition_fingerprint: Sha256Digest
    razorpay_rules: tuple[RelevantFactAuthority, ...] = ()
    razorpay_rule_catalog_fingerprint: Sha256Digest
    relevant_authority_fingerprint: Sha256Digest

    @model_validator(mode="after")
    def validate_snapshot(self) -> FindingRelevantAuthoritySnapshot:
        for collection in (
            self.source_files,
            self.symbols,
            self.call_sites,
            self.graph_nodes,
            self.graph_edges,
            self.razorpay_rules,
        ):
            canonical = tuple(sorted(collection, key=lambda item: canonical_json(item)))
            if tuple(collection) != canonical:
                raise ValueError("finding-relevant authority facts must be canonically ordered")
            if len(collection) != len(set(collection)):
                raise ValueError("finding-relevant authority facts must be unique")
        if self.call_path_references != tuple(sorted(set(self.call_path_references))):
            raise ValueError("call-path references must be unique and ordered")
        expected = fingerprint_json(finding_relevant_authority_fingerprint_payload(self))
        if self.relevant_authority_fingerprint != expected:
            raise ValueError("finding-relevant authority fingerprint must match exact facts")
        return self


def finding_relevant_authority_fingerprint_payload(
    snapshot: FindingRelevantAuthoritySnapshot,
) -> dict[str, object]:
    return snapshot.model_dump(
        mode="json",
        exclude={"relevant_authority_fingerprint"},
    )


def build_verification_check_key(
    *,
    project_id: ProjectId,
    scenario_id: ScenarioId,
    assertion_key: str,
    invariant_id: str,
    invariant_version: int,
    targets: CheckTargetReference,
    key_policy_dimensions: tuple[PolicyDimension, ...],
    policy: PolicyAuthoritySnapshot,
) -> VerificationCheckKey:
    """Build a stable logical key without volatile execution or fingerprint authority."""

    policy_values: list[tuple[str, str]] = []
    if PolicyDimension.FULFILMENT in key_policy_dimensions:
        policy_values.append(
            (
                PolicyDimension.FULFILMENT.value,
                policy.fulfilment.value if policy.fulfilment is not None else "UNRESOLVED",
            )
        )
    if PolicyDimension.LATE_AUTHORISATION in key_policy_dimensions:
        policy_values.append(
            (
                PolicyDimension.LATE_AUTHORISATION.value,
                (
                    policy.late_authorisation.value
                    if policy.late_authorisation is not None
                    else "UNRESOLVED"
                ),
            )
        )
    return verification_check_key(
        "VERIFICATION_CHECK_KEY_V1",
        project_id,
        scenario_id.value,
        assertion_key,
        invariant_id,
        invariant_version,
        targets.ingress_node_id or "NO_INGRESS",
        targets.route_registration_id or "NO_ROUTE",
        targets.ingress_symbol_id or "NO_INGRESS_SYMBOL",
        targets.customer_value_node_id or "NO_CUSTOMER_NODE",
        targets.customer_value_symbol_id or "NO_CUSTOMER_SYMBOL",
        targets.connectivity_edge_id or "NO_CONNECTIVITY_EDGE",
        *targets.mutation_node_ids,
        *targets.acknowledgement_node_ids,
        *policy_values,
    )


class ReverificationReference(PersistedArtifactModel):
    mode: Literal[ReverificationMode.REVERIFY_CURRENT_AUTHORITY] = (
        ReverificationMode.REVERIFY_CURRENT_AUTHORITY
    )
    scenario_id: ScenarioId
    assertion_key: str = Field(min_length=1, max_length=128)
    invariant_id: str = Field(min_length=1, max_length=128)
    invariant_version: int = Field(ge=1)
    targets: CheckTargetReference
    input_reference: ScenarioSafeInputReference | None = None
    config_fingerprint: Sha256Digest
    project_source_fingerprint: Sha256Digest
    projected_graph_fingerprint: Sha256Digest
    applicability_fingerprint: Sha256Digest
    razorpay_rule_catalog_fingerprint: Sha256Digest


class VerificationCheck(PersistedArtifactModel):
    check_id: VerificationCheckId
    check_key: VerificationCheckKey
    scenario_id: ScenarioId
    scenario_instance_id: ScenarioInstanceId
    assertion_id: AssertionId
    assertion_key: str = Field(min_length=1, max_length=128)
    invariant_id: str = Field(min_length=1, max_length=128)
    invariant_version: int = Field(ge=1)
    expected_invariant: str = Field(min_length=1, max_length=512)
    scenario_definition_fingerprint: Sha256Digest
    scenario_result_fingerprint: Sha256Digest
    applicability: ApplicabilityEvidenceSnapshot
    targets: CheckTargetReference
    policy_authority: CheckPolicyAuthority
    key_policy_dimensions: tuple[PolicyDimension, ...] = ()
    razorpay_rule_ids: tuple[RazorpayProtocolRuleId, ...]
    source_references: tuple[SourceEvidenceReference, ...] = ()
    graph_node_ids: tuple[GraphNodeId, ...] = ()
    graph_edge_ids: tuple[GraphEdgeId, ...] = ()
    input_reference: ScenarioSafeInputReference | None = None
    runtime_evidence: RuntimeEvidenceProjection
    result: VerificationResultState
    evidence_tier: EvidenceTier | None = None
    grounding: CheckGroundingEvidence | None = None
    reason: ScenarioResultReasonCode
    reverification: ReverificationReference
    relevant_authority: FindingRelevantAuthoritySnapshot | None = None

    @model_validator(mode="after")
    def validate_check(self) -> VerificationCheck:
        if self.result in {
            VerificationResultState.VERIFIED_PASS,
            VerificationResultState.VERIFIED_FAIL,
        }:
            if self.evidence_tier not in {
                EvidenceTier.E3_DYNAMIC_VERIFIED,
                EvidenceTier.E4_RAZORPAY_GROUNDED,
            }:
                raise ValueError("verified checks require dynamic evidence")
            if (
                self.input_reference is None
                or not self.runtime_evidence.requests
                or self.runtime_evidence.runtime_session_id is None
                or self.runtime_evidence.runtime_capability_fingerprint is None
                or self.runtime_evidence.transcript_fingerprint is None
            ):
                raise ValueError("verified checks require complete safe runtime authority")
        elif self.evidence_tier == EvidenceTier.E3_DYNAMIC_VERIFIED:
            raise ValueError("non-verified checks cannot claim E3")
        elif self.evidence_tier == EvidenceTier.E4_RAZORPAY_GROUNDED:
            raise ValueError("non-verified checks cannot claim E4")
        if self.evidence_tier == EvidenceTier.E4_RAZORPAY_GROUNDED:
            if (
                self.scenario_id != ScenarioId.SG_01
                or self.grounding is None
                or not isinstance(self.input_reference, GroundedScenarioInputReference)
                or self.grounding.grounding_fingerprint
                != self.input_reference.grounding_fingerprint
                or self.grounding.sanitized_projection_fingerprint
                != self.input_reference.sanitized_projection_fingerprint
            ):
                raise ValueError("E4 requires exact SG-01 resource-profile grounding")
        elif self.grounding is not None:
            raise ValueError("per-check grounding is valid only for E4")
        if self.input_reference != self.reverification.input_reference:
            raise ValueError("re-verification input reference must match recorded evidence")
        if len(self.razorpay_rule_ids) != len(set(self.razorpay_rule_ids)):
            raise ValueError("check Razorpay rule references must be unique")
        if not set(self.key_policy_dimensions) <= set(self.policy_authority.dimensions):
            raise ValueError("check-key policy dimensions must be used check authority")
        if self.graph_node_ids != tuple(sorted(set(self.graph_node_ids))):
            raise ValueError("check graph node references must be unique and ordered")
        if self.graph_edge_ids != tuple(sorted(set(self.graph_edge_ids))):
            raise ValueError("check graph edge references must be unique and ordered")
        source_keys = tuple(
            (item.symbol_id, item.source_location.model_dump_json())
            for item in self.source_references
        )
        if len(source_keys) != len(set(source_keys)):
            raise ValueError("check source references must be unique")
        return self


class Finding(PersistedArtifactModel):
    occurrence_id: FindingOccurrenceId
    finding_key: FindingKey
    check_id: VerificationCheckId
    check_key: VerificationCheckKey
    kind: FindingKind
    critical: bool

    @model_validator(mode="after")
    def validate_critical(self) -> Finding:
        if self.critical != (self.kind == FindingKind.VERIFIED_FAILURE):
            raise ValueError("only verified-failure findings are critical")
        return self


class EvidenceTierDistribution(PersistedArtifactModel):
    no_tier: int = Field(ge=0)
    e0_discovered: int = Field(ge=0)
    e1_resolved: int = Field(ge=0)
    e2_static_verified: int = Field(ge=0)
    e3_dynamic_verified: int = Field(ge=0)
    e4_razorpay_grounded: int = Field(ge=0)


class VerificationRunSummary(PersistedArtifactModel):
    verified_pass: int = Field(ge=0)
    verified_fail: int = Field(ge=0)
    static_warning: int = Field(ge=0)
    needs_input: int = Field(ge=0)
    unverified: int = Field(ge=0)
    not_applicable: int = Field(ge=0)
    dynamic_coverage_numerator: int = Field(ge=0)
    dynamic_coverage_denominator: int = Field(ge=0)
    evidence_tiers: EvidenceTierDistribution


_FINDING_KIND_BY_RESULT = {
    VerificationResultState.VERIFIED_FAIL: FindingKind.VERIFIED_FAILURE,
    VerificationResultState.STATIC_WARNING: FindingKind.STATIC_WARNING,
    VerificationResultState.NEEDS_INPUT: FindingKind.RESOLUTION_REQUIRED,
    VerificationResultState.UNVERIFIED: FindingKind.VERIFICATION_COVERAGE,
}


def derive_findings(
    run_id: VerificationRunId,
    checks: tuple[VerificationCheck, ...],
) -> tuple[Finding, ...]:
    return tuple(
        Finding(
            occurrence_id=finding_occurrence_id(run_id, check.check_id),
            finding_key=finding_key(check.check_key),
            check_id=check.check_id,
            check_key=check.check_key,
            kind=kind,
            critical=kind == FindingKind.VERIFIED_FAILURE,
        )
        for check in checks
        if (kind := _FINDING_KIND_BY_RESULT.get(check.result)) is not None
    )


def summarize_checks(checks: tuple[VerificationCheck, ...]) -> VerificationRunSummary:
    counts = {state: 0 for state in VerificationResultState}
    tiers: dict[EvidenceTier | None, int] = {None: 0, **{tier: 0 for tier in EvidenceTier}}
    for check in checks:
        counts[check.result] += 1
        tiers[check.evidence_tier] += 1
    numerator = tiers[EvidenceTier.E3_DYNAMIC_VERIFIED] + tiers[EvidenceTier.E4_RAZORPAY_GROUNDED]
    denominator = len(checks) - counts[VerificationResultState.NOT_APPLICABLE]
    return VerificationRunSummary(
        verified_pass=counts[VerificationResultState.VERIFIED_PASS],
        verified_fail=counts[VerificationResultState.VERIFIED_FAIL],
        static_warning=counts[VerificationResultState.STATIC_WARNING],
        needs_input=counts[VerificationResultState.NEEDS_INPUT],
        unverified=counts[VerificationResultState.UNVERIFIED],
        not_applicable=counts[VerificationResultState.NOT_APPLICABLE],
        dynamic_coverage_numerator=numerator,
        dynamic_coverage_denominator=denominator,
        evidence_tiers=EvidenceTierDistribution(
            no_tier=tiers[None],
            e0_discovered=tiers[EvidenceTier.E0_DISCOVERED],
            e1_resolved=tiers[EvidenceTier.E1_RESOLVED],
            e2_static_verified=tiers[EvidenceTier.E2_STATIC_VERIFIED],
            e3_dynamic_verified=tiers[EvidenceTier.E3_DYNAMIC_VERIFIED],
            e4_razorpay_grounded=tiers[EvidenceTier.E4_RAZORPAY_GROUNDED],
        ),
    )


def verification_run_fingerprint_payload(
    *,
    schema_version: Literal[1, 2, 3],
    producer_version: str,
    generated_at: datetime,
    run_id: VerificationRunId,
    status: VerificationRunStatus,
    created_at: datetime,
    completed_at: datetime,
    authority: VerificationAuthoritySnapshot,
    checks: tuple[VerificationCheck, ...],
    findings: tuple[Finding, ...],
    summary: VerificationRunSummary,
) -> dict[str, object]:
    serialized_checks: object
    serialized_authority: object
    if schema_version == 1:
        serialized_checks = tuple(
            check.model_dump(
                mode="json",
                exclude={"relevant_authority", "grounding"},
            )
            for check in checks
        )
        serialized_authority = authority.model_dump(
            mode="json",
            exclude={
                "razorpay_grounding": True,
                "schema_versions": {"razorpay_grounding"},
            },
        )
    elif schema_version == 2:
        serialized_checks = tuple(
            check.model_dump(mode="json", exclude={"grounding"}) for check in checks
        )
        serialized_authority = authority.model_dump(
            mode="json",
            exclude={
                "razorpay_grounding": True,
                "schema_versions": {"razorpay_grounding"},
            },
        )
    else:
        serialized_checks = checks
        serialized_authority = authority
    return {
        "artifact_type": "VERIFICATION_RUN",
        "schema_version": schema_version,
        "producer_version": producer_version,
        "generated_at": generated_at.isoformat(),
        "run_id": run_id,
        "status": status,
        "created_at": created_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "authority": serialized_authority,
        "checks": serialized_checks,
        "findings": findings,
        "summary": summary,
    }


class VerificationRun(ArtifactFields):
    artifact_type: Literal["VERIFICATION_RUN"] = "VERIFICATION_RUN"
    schema_version: Literal[1, 2, 3] = 3
    run_id: VerificationRunId
    status: Literal[VerificationRunStatus.COMPLETED] = VerificationRunStatus.COMPLETED
    created_at: datetime
    completed_at: datetime
    authority: VerificationAuthoritySnapshot
    checks: tuple[VerificationCheck, ...] = Field(min_length=1)
    findings: tuple[Finding, ...] = ()
    summary: VerificationRunSummary
    run_fingerprint: Sha256Digest

    @field_validator("created_at", "completed_at")
    @classmethod
    def require_run_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("verification-run timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_run(self) -> VerificationRun:
        if self.completed_at < self.created_at:
            raise ValueError("verification run completion cannot precede creation")
        check_ids = tuple(item.check_id for item in self.checks)
        check_keys = tuple(item.check_key for item in self.checks)
        if len(check_ids) != len(set(check_ids)):
            raise ValueError("verification check occurrence IDs must be unique")
        if len(check_keys) != len(set(check_keys)):
            raise ValueError("verification check keys must be unique within one run")
        if self.schema_version == 1 and any(
            check.relevant_authority is not None for check in self.checks
        ):
            raise ValueError("schema-v1 verification checks cannot carry v2 authority")
        if self.schema_version in {2, 3} and any(
            check.relevant_authority is None for check in self.checks
        ):
            raise ValueError("current verification checks require relevant authority")
        if self.schema_version in {1, 2} and (
            self.authority.razorpay_grounding is not None
            or any(check.grounding is not None for check in self.checks)
        ):
            raise ValueError("legacy verification runs cannot carry Razorpay grounding")
        if (
            self.schema_version == 3
            and self.authority.schema_versions.scenario_execution_result != 3
        ):
            raise ValueError("schema-v3 verification requires scenario result schema v3")
        grounding = self.authority.razorpay_grounding
        if grounding is not None:
            if (
                grounding.run_id != self.run_id
                or not self.created_at <= grounding.acquired_at <= self.completed_at
                or self.authority.schema_versions.razorpay_grounding != 1
            ):
                raise ValueError("run grounding must be current and bound to the exact run")
        elif self.authority.schema_versions.razorpay_grounding is not None:
            raise ValueError("grounding schema authority requires a grounding attempt")
        e4_checks = tuple(
            check
            for check in self.checks
            if check.evidence_tier == EvidenceTier.E4_RAZORPAY_GROUNDED
        )
        if len(e4_checks) > 1:
            raise ValueError("bounded grounding may promote at most one SG-01 check")
        if e4_checks and (
            grounding is None or grounding.status != RazorpayGroundingStatus.GROUNDED
        ):
            raise ValueError("E4 checks require a successful run grounding snapshot")
        if e4_checks:
            assert grounding is not None
        for check in e4_checks:
            assert grounding is not None
            if (
                check.grounding is None
                or check.grounding.grounding_fingerprint != grounding.grounding_fingerprint
                or check.grounding.sanitized_projection_fingerprint
                != grounding.sanitized_projection_fingerprint
            ):
                raise ValueError("E4 check grounding must match exact run authority")
        runtime_fingerprints = tuple(
            sorted(
                {
                    check.runtime_evidence.runtime_capability_fingerprint
                    for check in self.checks
                    if check.runtime_evidence.runtime_capability_fingerprint is not None
                }
            )
        )
        if runtime_fingerprints != self.authority.runtime_capability_fingerprints:
            raise ValueError("run runtime authority must match check evidence")
        for check in self.checks:
            if check.assertion_id != assertion_id(check.scenario_instance_id, check.assertion_key):
                raise ValueError("verification assertion identity is not canonical")
            if check.check_id != verification_check_id(
                self.run_id, check.scenario_instance_id, check.assertion_id
            ):
                raise ValueError("verification check occurrence identity is not canonical")
            expected_key = build_verification_check_key(
                project_id=self.authority.project_id,
                scenario_id=check.scenario_id,
                assertion_key=check.assertion_key,
                invariant_id=check.invariant_id,
                invariant_version=check.invariant_version,
                targets=check.targets,
                key_policy_dimensions=check.key_policy_dimensions,
                policy=self.authority.policy,
            )
            if check.check_key != expected_key:
                raise ValueError("verification check key is not canonical")
            reference = check.reverification
            if (
                reference.scenario_id != check.scenario_id
                or reference.assertion_key != check.assertion_key
                or reference.invariant_id != check.invariant_id
                or reference.invariant_version != check.invariant_version
                or reference.targets != check.targets
                or reference.config_fingerprint != self.authority.config_fingerprint
                or reference.project_source_fingerprint != self.authority.project_source_fingerprint
                or reference.projected_graph_fingerprint
                != self.authority.projected_graph_fingerprint
                or reference.applicability_fingerprint != self.authority.applicability_fingerprint
                or reference.razorpay_rule_catalog_fingerprint
                != self.authority.razorpay_rules.catalog_fingerprint
            ):
                raise ValueError("check re-verification authority is inconsistent with its run")
            dimensions = set(check.policy_authority.dimensions)
            if PolicyDimension.FULFILMENT in dimensions and (
                check.policy_authority.fulfilment != self.authority.policy.fulfilment
                or check.policy_authority.fulfilment_evidence_fingerprint
                != self.authority.policy.fulfilment_evidence_fingerprint
            ):
                raise ValueError("check fulfilment authority is inconsistent with its run")
            if PolicyDimension.LATE_AUTHORISATION in dimensions and (
                check.policy_authority.late_authorisation
                != self.authority.policy.late_authorisation
                or check.policy_authority.late_authorisation_evidence_fingerprint
                != self.authority.policy.late_authorisation_evidence_fingerprint
            ):
                raise ValueError("check late-policy authority is inconsistent with its run")
        if self.findings != derive_findings(self.run_id, self.checks):
            raise ValueError("findings must be derived exactly from normalized checks")
        if self.summary != summarize_checks(self.checks):
            raise ValueError("run summary must be derived exactly from normalized checks")
        referenced_rules = {rule_id for check in self.checks for rule_id in check.razorpay_rule_ids}
        if referenced_rules != {
            item.rule_id for item in self.authority.razorpay_rules.referenced_rules
        }:
            raise ValueError("run rule snapshot must match check rule references")
        payload = verification_run_fingerprint_payload(
            schema_version=self.schema_version,
            producer_version=self.producer_version,
            generated_at=self.generated_at,
            run_id=self.run_id,
            status=VerificationRunStatus(self.status),
            created_at=self.created_at,
            completed_at=self.completed_at,
            authority=self.authority,
            checks=self.checks,
            findings=self.findings,
            summary=self.summary,
        )
        if self.run_fingerprint != fingerprint_json(payload):
            raise ValueError("verification-run fingerprint must match artifact contents")
        return self
