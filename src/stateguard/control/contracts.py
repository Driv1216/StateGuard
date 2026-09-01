"""Bounded safe contracts shared by stable non-UI control adapters."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from stateguard.applicability.contracts import (
    MerchantPolicyAssessment,
    ScenarioApplicabilityArtifact,
    ScenarioId,
)
from stateguard.contracts.common import (
    AssertionId,
    GraphEdgeId,
    GraphNodeId,
    ProjectId,
    ProvenanceKind,
    ScenarioInstanceId,
    Sha256Digest,
    SourceLocation,
    SymbolId,
    VerificationCheckId,
    VerificationCheckKey,
    VerificationRunId,
)
from stateguard.contracts.config import (
    FulfilmentPolicy,
    LateAuthorisationPolicy,
    RuntimeMode,
    RuntimeTargetKind,
)
from stateguard.discovery.contracts import (
    AnalysisDiagnosticCode,
    ArtifactCompleteness,
    DiagnosticImpact,
    SymbolKind,
)
from stateguard.evidence.contracts import (
    ApplicabilityEvidenceSnapshot,
    CheckPolicyAuthority,
    CheckTargetReference,
    Finding,
    SourceEvidenceReference,
    VerificationRun,
    VerificationRunStatus,
    VerificationRunSummary,
)
from stateguard.failure_lab.contracts import (
    EvidenceTier,
    ScenarioResultReasonCode,
    VerificationResultState,
)
from stateguard.graph.contracts import (
    GraphCompleteness,
    GraphDiagnosticCode,
    GraphDiagnosticImpact,
    GraphEdgeKind,
    GraphNodeKind,
)
from stateguard.model_providers.protocol import ProviderFailureCode
from stateguard.rules.razorpay import RazorpayProtocolRuleId
from stateguard.semantics.contracts import (
    BundleCompleteness,
    CustomerValueSemanticArtifact,
    ResolutionBasis,
    ResolutionState,
)


class ControlModel(BaseModel):
    """Immutable non-persisted adapter contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ConfigValidationV1(ControlModel):
    schema_version: Literal[1] = 1
    valid: Literal[True] = True
    config_schema_version: Literal[2] = 2
    project_id: ProjectId


class RuntimeEnvironmentBindingV1(ControlModel):
    schema_version: Literal[1] = 1
    child_name: str = Field(min_length=1)
    host_name: str = Field(min_length=1)


class RuntimeTargetSetupV1(ControlModel):
    schema_version: Literal[1] = 1
    kind: RuntimeTargetKind
    base_url: str = Field(min_length=1)
    non_production_declaration: bool


class RuntimeReadinessSetupV1(ControlModel):
    schema_version: Literal[1] = 1
    path: str = Field(min_length=1)
    accepted_statuses: tuple[int, ...]


class RuntimeSetupV1(ControlModel):
    schema_version: Literal[1] = 1
    mode: RuntimeMode
    working_directory: str | None = None
    environment_bindings: tuple[RuntimeEnvironmentBindingV1, ...] = ()
    startup_timeout_seconds: float | None = None
    request_timeout_seconds: float | None = None
    shutdown_timeout_seconds: float | None = None
    target: RuntimeTargetSetupV1 | None = None
    readiness: RuntimeReadinessSetupV1 | None = None
    launch_configured: bool = False


class ProjectSetupV1(ControlModel):
    schema_version: Literal[1] = 1
    project_id: ProjectId
    config_schema_version: Literal[2] = 2
    configured_app_target: str | None = None
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_api_key_env: str | None = None
    ai_base_url: str | None = None
    runtime_configured: bool
    runtime_mode: RuntimeMode
    runtime: RuntimeSetupV1 | None = None
    configured_customer_value_symbol_id: SymbolId | None = None
    configured_fulfilment_policy: FulfilmentPolicy | None = None
    configured_late_authorisation_policy: LateAuthorisationPolicy | None = None


class DiagnosticCountV1(ControlModel):
    schema_version: Literal[1] = 1
    code: AnalysisDiagnosticCode | GraphDiagnosticCode
    impact: DiagnosticImpact | GraphDiagnosticImpact
    count: int = Field(ge=1)


class GraphNodeKindCountV1(ControlModel):
    schema_version: Literal[1] = 1
    kind: GraphNodeKind
    count: int = Field(ge=1)


class GraphEdgeKindCountV1(ControlModel):
    schema_version: Literal[1] = 1
    kind: GraphEdgeKind
    count: int = Field(ge=1)


class SemanticAuthorityV1(ControlModel):
    schema_version: Literal[1] = 1
    state: ResolutionState | None = None
    basis: ResolutionBasis | None = None
    selected_symbol_id: SymbolId | None = None
    resolution_fingerprint: Sha256Digest | None = None
    selected_target_provenance: tuple[ProvenanceKind, ...] = ()
    matching_artifact_current: bool


class SemanticSourceCurrentness(StrEnum):
    NOT_CHECKED = "NOT_CHECKED"


class RecordedSemanticCandidateKind(StrEnum):
    VALID = "VALID"
    PARTIAL_SUGGESTION = "PARTIAL_SUGGESTION"


class SemanticSelectionKind(StrEnum):
    VALID = "VALID"
    PARTIAL_SUGGESTION = "PARTIAL_SUGGESTION"
    PRESENTED = "PRESENTED"


class RecordedSemanticCandidateV1(ControlModel):
    schema_version: Literal[1] = 1
    kind: RecordedSemanticCandidateKind
    symbol_id: SymbolId
    rationale: str = Field(min_length=1, max_length=512)
    provider_confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class SemanticSelectionOptionV1(ControlModel):
    schema_version: Literal[1] = 1
    kind: SemanticSelectionKind
    symbol_id: SymbolId
    qualified_name: str = Field(min_length=1, max_length=512)
    symbol_kind: SymbolKind
    source_location: SourceLocation
    rationale: str | None = Field(default=None, min_length=1, max_length=512)
    provider_confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class SemanticSnapshotV1(ControlModel):
    """Persistence-only semantic view that never claims current source authority."""

    schema_version: Literal[1] = 1
    source_currentness: Literal[SemanticSourceCurrentness.NOT_CHECKED] = (
        SemanticSourceCurrentness.NOT_CHECKED
    )
    project_id: ProjectId
    recorded: bool
    recorded_at: datetime | None = None
    state: ResolutionState | None = None
    basis: ResolutionBasis | None = None
    selected_symbol_id: SymbolId | None = None
    semantic_context_fingerprint: Sha256Digest | None = None
    resolution_fingerprint: Sha256Digest | None = None
    bundle_completeness: BundleCompleteness | None = None
    provider_id: str | None = None
    model: str | None = None
    provider_failure_code: ProviderFailureCode | None = None
    provider_failure_status_code: int | None = Field(default=None, ge=100, le=599)
    presented_symbol_ids: tuple[SymbolId, ...] = ()
    candidates: tuple[RecordedSemanticCandidateV1, ...] = ()
    human_basis: ResolutionBasis | None = None
    human_acted_at: datetime | None = None


class ProjectAnalysisV1(ControlModel):
    schema_version: Literal[1] = 1
    producer_version: str = Field(min_length=1)
    generated_at: datetime
    project_id: ProjectId
    project_source_fingerprint: Sha256Digest
    source_index_fingerprint: Sha256Digest
    source_completeness: ArtifactCompleteness
    indexed_file_count: int = Field(ge=0)
    indexed_symbol_count: int = Field(ge=0)
    source_diagnostics: tuple[DiagnosticCountV1, ...] = ()
    graph_fingerprint: Sha256Digest
    graph_completeness: GraphCompleteness
    graph_nodes: tuple[GraphNodeKindCountV1, ...] = ()
    graph_edges: tuple[GraphEdgeKindCountV1, ...] = ()
    graph_diagnostics: tuple[DiagnosticCountV1, ...] = ()
    semantics: SemanticAuthorityV1
    policy: MerchantPolicyAssessment
    applicability: ScenarioApplicabilityArtifact


class SemanticOperationV1(ControlModel):
    schema_version: Literal[1] = 1
    artifact: CustomerValueSemanticArtifact
    graph_fingerprint: Sha256Digest
    selection_options: tuple[SemanticSelectionOptionV1, ...] = ()


class RunListItemV1(ControlModel):
    schema_version: Literal[1] = 1
    run_id: VerificationRunId
    status: VerificationRunStatus
    created_at: datetime
    completed_at: datetime
    run_fingerprint: Sha256Digest
    summary: VerificationRunSummary
    finding_count: int = Field(ge=0)


class RunListV1(ControlModel):
    schema_version: Literal[1] = 1
    runs: tuple[RunListItemV1, ...] = ()


class RunCheckReportV1(ControlModel):
    schema_version: Literal[1] = 1
    check_id: VerificationCheckId
    check_key: VerificationCheckKey
    scenario_id: ScenarioId
    scenario_instance_id: ScenarioInstanceId
    assertion_id: AssertionId
    assertion_key: str
    invariant_id: str
    invariant_version: int = Field(ge=1)
    expected_invariant: str
    applicability: ApplicabilityEvidenceSnapshot
    targets: CheckTargetReference
    policy_authority: CheckPolicyAuthority
    razorpay_rule_ids: tuple[RazorpayProtocolRuleId, ...]
    source_references: tuple[SourceEvidenceReference, ...] = ()
    graph_node_ids: tuple[GraphNodeId, ...] = ()
    graph_edge_ids: tuple[GraphEdgeId, ...] = ()
    result: VerificationResultState
    evidence_tier: EvidenceTier | None = None
    reason: ScenarioResultReasonCode


class RunReportV1(ControlModel):
    schema_version: Literal[1] = 1
    run_id: VerificationRunId
    status: VerificationRunStatus
    created_at: datetime
    completed_at: datetime
    run_fingerprint: Sha256Digest
    summary: VerificationRunSummary
    checks: tuple[RunCheckReportV1, ...]
    findings: tuple[Finding, ...] = ()


class ControlErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    REQUEST_SCHEMA_INVALID = "REQUEST_SCHEMA_INVALID"
    ROUTE_NOT_FOUND = "ROUTE_NOT_FOUND"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    HOST_NOT_ALLOWED = "HOST_NOT_ALLOWED"
    ORIGIN_NOT_ALLOWED = "ORIGIN_NOT_ALLOWED"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    PROJECT_INVALID = "PROJECT_INVALID"
    CONFIG_INVALID = "CONFIG_INVALID"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    CONCURRENT_CONFIGURATION_CHANGE = "CONCURRENT_CONFIGURATION_CHANGE"
    AUTHORITY_CHANGED = "AUTHORITY_CHANGED"
    INVALID_SEMANTIC_SELECTION = "INVALID_SEMANTIC_SELECTION"
    INVALID_POLICY_CONFIRMATION = "INVALID_POLICY_CONFIRMATION"
    INVALID_RUN_ID = "INVALID_RUN_ID"
    RUN_NOT_FOUND = "RUN_NOT_FOUND"
    RUN_ARTIFACT_INVALID = "RUN_ARTIFACT_INVALID"
    SEMANTIC_ARTIFACT_INVALID = "SEMANTIC_ARTIFACT_INVALID"
    REMEDIATION_NOT_ELIGIBLE = "REMEDIATION_NOT_ELIGIBLE"
    MODEL_PROVIDER_FAILED = "MODEL_PROVIDER_FAILED"
    OPERATION_FAILED = "OPERATION_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ControlErrorV1(ControlModel):
    schema_version: Literal[1] = 1
    code: ControlErrorCode
    message: str = Field(min_length=1, max_length=256)


_SAFE_ERROR_MESSAGES: dict[ControlErrorCode, str] = {
    ControlErrorCode.INVALID_REQUEST: "the requested control operation is invalid",
    ControlErrorCode.REQUEST_SCHEMA_INVALID: "the request does not match the required schema",
    ControlErrorCode.ROUTE_NOT_FOUND: "the requested control API route does not exist",
    ControlErrorCode.METHOD_NOT_ALLOWED: "the HTTP method is not allowed for this route",
    ControlErrorCode.HOST_NOT_ALLOWED: "the HTTP Host is not allowed",
    ControlErrorCode.ORIGIN_NOT_ALLOWED: "the HTTP Origin is not allowed",
    ControlErrorCode.UNSUPPORTED_MEDIA_TYPE: "the HTTP content type is not supported",
    ControlErrorCode.REQUEST_TOO_LARGE: "the HTTP request body is too large",
    ControlErrorCode.PROJECT_INVALID: "the StateGuard project root is unavailable",
    ControlErrorCode.CONFIG_INVALID: "the StateGuard configuration is invalid",
    ControlErrorCode.ANALYSIS_UNAVAILABLE: "project analysis could not be completed",
    ControlErrorCode.CONCURRENT_CONFIGURATION_CHANGE: (
        "the configuration changed during the requested update"
    ),
    ControlErrorCode.AUTHORITY_CHANGED: "StateGuard authority changed during the operation",
    ControlErrorCode.INVALID_SEMANTIC_SELECTION: (
        "the selected customer-value symbol is not eligible"
    ),
    ControlErrorCode.INVALID_POLICY_CONFIRMATION: (
        "policy confirmation requires at least one explicit value"
    ),
    ControlErrorCode.INVALID_RUN_ID: "the verification run ID is invalid",
    ControlErrorCode.RUN_NOT_FOUND: "the requested verification run does not exist",
    ControlErrorCode.RUN_ARTIFACT_INVALID: "stored verification-run history is invalid",
    ControlErrorCode.SEMANTIC_ARTIFACT_INVALID: "stored semantic history is invalid",
    ControlErrorCode.REMEDIATION_NOT_ELIGIBLE: (
        "only an exact critical VERIFIED FAIL finding is eligible for assistance"
    ),
    ControlErrorCode.MODEL_PROVIDER_FAILED: "the configured model provider failed safely",
    ControlErrorCode.OPERATION_FAILED: "the requested StateGuard operation failed",
    ControlErrorCode.INTERNAL_ERROR: "StateGuard encountered an internal control error",
}


def control_error(code: ControlErrorCode) -> ControlErrorV1:
    """Build one fixed safe adapter error without exception-derived content."""

    return ControlErrorV1(code=code, message=_SAFE_ERROR_MESSAGES[code])


def run_list_item(run: VerificationRun) -> RunListItemV1:
    return RunListItemV1(
        run_id=run.run_id,
        status=VerificationRunStatus(run.status),
        created_at=run.created_at,
        completed_at=run.completed_at,
        run_fingerprint=run.run_fingerprint,
        summary=run.summary,
        finding_count=len(run.findings),
    )


def run_report(run: VerificationRun) -> RunReportV1:
    return RunReportV1(
        run_id=run.run_id,
        status=VerificationRunStatus(run.status),
        created_at=run.created_at,
        completed_at=run.completed_at,
        run_fingerprint=run.run_fingerprint,
        summary=run.summary,
        checks=tuple(
            RunCheckReportV1(
                check_id=check.check_id,
                check_key=check.check_key,
                scenario_id=check.scenario_id,
                scenario_instance_id=check.scenario_instance_id,
                assertion_id=check.assertion_id,
                assertion_key=check.assertion_key,
                invariant_id=check.invariant_id,
                invariant_version=check.invariant_version,
                expected_invariant=check.expected_invariant,
                applicability=check.applicability,
                targets=check.targets,
                policy_authority=check.policy_authority,
                razorpay_rule_ids=check.razorpay_rule_ids,
                source_references=check.source_references,
                graph_node_ids=check.graph_node_ids,
                graph_edge_ids=check.graph_edge_ids,
                result=check.result,
                evidence_tier=check.evidence_tier,
                reason=check.reason,
            )
            for check in run.checks
        ),
        findings=run.findings,
    )
