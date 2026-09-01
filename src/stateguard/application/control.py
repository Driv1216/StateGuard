"""Stable project-bound control operations shared by non-UI adapters."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Never

from stateguard import __version__
from stateguard.applicability.contracts import ScenarioApplicabilityArtifact
from stateguard.application.applicability import (
    analyze_applicability,
    confirm_merchant_policy,
    inspect_applicability,
)
from stateguard.application.remediation import (
    generate_remediation_assistance,
    verify_current_finding,
)
from stateguard.application.runtime import assess_runtime_capability
from stateguard.application.semantics import (
    SemanticSelectionError,
    SemanticUseCaseResult,
    confirm_customer_value,
    resolve_customer_value,
)
from stateguard.application.verification import (
    VerificationAuthorityChangedError,
    create_verification_run,
)
from stateguard.contracts.config import (
    AIConfig,
    BringYourOwnRuntimeConfig,
    FulfilmentPolicy,
    LateAuthorisationPolicy,
    ManagedRuntimeConfig,
    RuntimeConfig,
    RuntimeMode,
)
from stateguard.control.contracts import (
    ConfigValidationV1,
    ControlErrorCode,
    DiagnosticCountV1,
    GraphEdgeKindCountV1,
    GraphNodeKindCountV1,
    ProjectAnalysisV1,
    ProjectSetupV1,
    RecordedSemanticCandidateKind,
    RecordedSemanticCandidateV1,
    RunListV1,
    RunReportV1,
    RuntimeEnvironmentBindingV1,
    RuntimeReadinessSetupV1,
    RuntimeSetupV1,
    RuntimeTargetSetupV1,
    SemanticAuthorityV1,
    SemanticOperationV1,
    SemanticSelectionKind,
    SemanticSelectionOptionV1,
    SemanticSnapshotV1,
    control_error,
    run_list_item,
    run_report,
)
from stateguard.discovery.files import ProjectDiscoveryError
from stateguard.discovery.service import StaleSourceIndexError
from stateguard.evidence.contracts import VerificationRun
from stateguard.graph.contracts import GraphNodeKind, PaymentSafetyGraphArtifact
from stateguard.grounding.contracts import RazorpayTestGroundingRequest
from stateguard.model_providers.protocol import ModelProviderError
from stateguard.remediation.context_builder import RemediationNotEligibleError
from stateguard.remediation.contracts import RemediationAssistance, ReverificationResult
from stateguard.runtime.contracts import RuntimeCapabilityArtifact
from stateguard.workspace.config import ConfigLoadError, load_config
from stateguard.workspace.config_edit import (
    ConcurrentConfigEditError,
    write_ai_configuration,
    write_runtime_configuration,
)
from stateguard.workspace.run_artifacts import (
    InvalidVerificationRunIdError,
    VerificationRunArtifactError,
    VerificationRunNotFoundError,
    list_verification_runs,
    load_latest_verification_run,
    load_verification_run,
)
from stateguard.workspace.semantic_artifacts import load_semantic_artifact


class ControlOperationError(Exception):
    """Safe adapter-facing operation failure with no raw exception payload."""

    def __init__(self, code: ControlErrorCode) -> None:
        self.error = control_error(code)
        super().__init__(self.error.message)


def _raise_control(code: ControlErrorCode) -> Never:
    raise ControlOperationError(code)


def _translate_error(exc: Exception) -> Never:
    if isinstance(exc, ConcurrentConfigEditError):
        _raise_control(ControlErrorCode.CONCURRENT_CONFIGURATION_CHANGE)
    if isinstance(exc, ConfigLoadError):
        _raise_control(ControlErrorCode.CONFIG_INVALID)
    if isinstance(exc, ProjectDiscoveryError):
        _raise_control(ControlErrorCode.ANALYSIS_UNAVAILABLE)
    if isinstance(exc, (StaleSourceIndexError, VerificationAuthorityChangedError)):
        _raise_control(ControlErrorCode.AUTHORITY_CHANGED)
    if isinstance(exc, InvalidVerificationRunIdError):
        _raise_control(ControlErrorCode.INVALID_RUN_ID)
    if isinstance(exc, VerificationRunNotFoundError):
        _raise_control(ControlErrorCode.RUN_NOT_FOUND)
    if isinstance(exc, VerificationRunArtifactError):
        _raise_control(ControlErrorCode.RUN_ARTIFACT_INVALID)
    if isinstance(exc, RemediationNotEligibleError):
        _raise_control(ControlErrorCode.REMEDIATION_NOT_ELIGIBLE)
    if isinstance(exc, ModelProviderError):
        _raise_control(ControlErrorCode.MODEL_PROVIDER_FAILED)
    if isinstance(exc, (ValueError, OSError)):
        _raise_control(ControlErrorCode.OPERATION_FAILED)
    _raise_control(ControlErrorCode.INTERNAL_ERROR)


def validate_configuration(path: Path) -> ConfigValidationV1:
    """Validate one explicit configuration without exposing its sensitive fields."""

    try:
        config = load_config(path)
    except Exception as exc:
        _translate_error(exc)
    return ConfigValidationV1(project_id=config.project.id)


def _runtime_setup(runtime: RuntimeConfig | None) -> RuntimeSetupV1 | None:
    if runtime is None:
        return None
    if not isinstance(runtime, (ManagedRuntimeConfig, BringYourOwnRuntimeConfig)):
        return RuntimeSetupV1(mode=runtime.mode)
    bindings = tuple(
        RuntimeEnvironmentBindingV1(child_name=child, host_name=host)
        for child, host in sorted(runtime.env_from_host.items())
    )
    if isinstance(runtime, ManagedRuntimeConfig):
        return RuntimeSetupV1(
            mode=runtime.mode,
            working_directory=runtime.working_directory,
            environment_bindings=bindings,
            startup_timeout_seconds=runtime.startup_timeout_seconds,
            request_timeout_seconds=runtime.request_timeout_seconds,
            shutdown_timeout_seconds=runtime.shutdown_timeout_seconds,
        )
    return RuntimeSetupV1(
        mode=runtime.mode,
        working_directory=runtime.working_directory,
        environment_bindings=bindings,
        startup_timeout_seconds=runtime.startup_timeout_seconds,
        request_timeout_seconds=runtime.request_timeout_seconds,
        shutdown_timeout_seconds=runtime.shutdown_timeout_seconds,
        target=RuntimeTargetSetupV1(
            kind=runtime.target.kind,
            base_url=runtime.target.base_url,
            non_production_declaration=runtime.target.kind.value == "declared_test",
        ),
        readiness=RuntimeReadinessSetupV1(
            path=runtime.readiness.path,
            accepted_statuses=runtime.readiness.accepted_statuses,
        ),
        launch_configured=runtime.launch_argv is not None,
    )


class StateGuardControl:
    """One canonical project/config binding over existing StateGuard use cases."""

    def __init__(
        self,
        project_root: Path,
        config_path: Path = Path("stateguard.yaml"),
    ) -> None:
        try:
            canonical_root = project_root.resolve(strict=True)
        except OSError:
            _raise_control(ControlErrorCode.PROJECT_INVALID)
        if not canonical_root.is_dir():
            _raise_control(ControlErrorCode.PROJECT_INVALID)
        selected_config = config_path if config_path.is_absolute() else canonical_root / config_path
        self._project_root = canonical_root
        self._config_path = selected_config.resolve(strict=False)

    @property
    def project_root(self) -> Path:
        return self._project_root

    @property
    def config_path(self) -> Path:
        return self._config_path

    def project_setup(self) -> ProjectSetupV1:
        try:
            config = load_config(self._config_path)
        except Exception as exc:
            _translate_error(exc)
        semantic = config.semantics.customer_value if config.semantics is not None else None
        policy = config.policy
        runtime = config.runtime
        return ProjectSetupV1(
            project_id=config.project.id,
            configured_app_target=config.project.app_target,
            ai_provider=config.ai.provider if config.ai is not None else None,
            ai_model=config.ai.model if config.ai is not None else None,
            ai_api_key_env=config.ai.api_key_env if config.ai is not None else None,
            ai_base_url=config.ai.base_url if config.ai is not None else None,
            runtime_configured=runtime is not None,
            runtime_mode=runtime.mode if runtime is not None else RuntimeMode.STATIC,
            runtime=_runtime_setup(runtime),
            configured_customer_value_symbol_id=(
                semantic.symbol_id if semantic is not None else None
            ),
            configured_fulfilment_policy=(
                policy.fulfilment.value
                if policy is not None and policy.fulfilment is not None
                else None
            ),
            configured_late_authorisation_policy=(
                policy.late_authorisation.value
                if policy is not None and policy.late_authorisation is not None
                else None
            ),
        )

    def configure_ai(self, config: AIConfig) -> ProjectSetupV1:
        """Persist only validated non-secret provider configuration metadata."""

        try:
            write_ai_configuration(self._config_path, config)
        except Exception as exc:
            _translate_error(exc)
        return self.project_setup()

    def configure_runtime(self, config: RuntimeConfig) -> ProjectSetupV1:
        """Persist only the bounded runtime contract without assessing capability."""

        try:
            write_runtime_configuration(self._config_path, config)
        except Exception as exc:
            _translate_error(exc)
        return self.project_setup()

    def analyze_project(self) -> ProjectAnalysisV1:
        """Inspect current static/semantic/policy authority without persistence."""

        try:
            result = inspect_applicability(self._project_root, self._config_path)
        except Exception as exc:
            _translate_error(exc)
        snapshot = result.snapshot
        source = snapshot.source_index
        graph = snapshot.graph

        source_counts = Counter((item.code, item.impact) for item in source.diagnostics)
        graph_diagnostic_counts = Counter((item.code, item.impact) for item in graph.diagnostics)
        node_counts = Counter(item.kind for item in graph.nodes)
        edge_counts = Counter(item.kind for item in graph.edges)
        resolution = snapshot.resolution
        selected_provenance = tuple(
            sorted(
                {
                    provenance.kind
                    for node in graph.nodes
                    if node.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
                    and resolution is not None
                    and node.backing_symbol_id == resolution.selected_symbol_id
                    for provenance in node.provenance
                },
                key=str,
            )
        )
        return ProjectAnalysisV1(
            producer_version=__version__,
            generated_at=result.artifact.generated_at,
            project_id=source.project_id,
            project_source_fingerprint=source.project_source_fingerprint,
            source_index_fingerprint=source.source_index_fingerprint,
            source_completeness=source.completeness,
            indexed_file_count=len(source.indexed_files),
            indexed_symbol_count=len(source.symbols),
            source_diagnostics=tuple(
                DiagnosticCountV1(code=code, impact=impact, count=count)
                for (code, impact), count in sorted(
                    source_counts.items(), key=lambda item: (str(item[0][0]), str(item[0][1]))
                )
            ),
            graph_fingerprint=graph.graph_fingerprint,
            graph_completeness=graph.completeness,
            graph_nodes=tuple(
                GraphNodeKindCountV1(kind=kind, count=count)
                for kind, count in sorted(node_counts.items(), key=lambda item: str(item[0]))
            ),
            graph_edges=tuple(
                GraphEdgeKindCountV1(kind=kind, count=count)
                for kind, count in sorted(edge_counts.items(), key=lambda item: str(item[0]))
            ),
            graph_diagnostics=tuple(
                DiagnosticCountV1(code=code, impact=impact, count=count)
                for (code, impact), count in sorted(
                    graph_diagnostic_counts.items(),
                    key=lambda item: (str(item[0][0]), str(item[0][1])),
                )
            ),
            semantics=SemanticAuthorityV1(
                state=resolution.state if resolution is not None else None,
                basis=resolution.basis if resolution is not None else None,
                selected_symbol_id=(
                    resolution.selected_symbol_id if resolution is not None else None
                ),
                resolution_fingerprint=snapshot.resolution_fingerprint,
                selected_target_provenance=selected_provenance,
                matching_artifact_current=snapshot.artifact is not None,
            ),
            policy=result.artifact.policy,
            applicability=result.artifact,
        )

    def current_graph(self) -> PaymentSafetyGraphArtifact:
        try:
            return inspect_applicability(self._project_root, self._config_path).snapshot.graph
        except Exception as exc:
            _translate_error(exc)

    def semantic_snapshot(self) -> SemanticSnapshotV1:
        """Read only already-recorded safe semantics without rebuilding source authority."""

        try:
            config = load_config(self._config_path)
            artifact = load_semantic_artifact(self._project_root)
        except ConfigLoadError:
            _raise_control(ControlErrorCode.CONFIG_INVALID)
        except (OSError, ValueError):
            _raise_control(ControlErrorCode.SEMANTIC_ARTIFACT_INVALID)
        if artifact is None:
            return SemanticSnapshotV1(project_id=config.project.id, recorded=False)
        if artifact.project_id != config.project.id:
            _raise_control(ControlErrorCode.SEMANTIC_ARTIFACT_INVALID)

        candidates = tuple(
            RecordedSemanticCandidateV1(
                kind=kind,
                symbol_id=candidate.symbol_id,
                rationale=candidate.rationale,
                provider_confidence=candidate.provider_confidence,
            )
            for kind, records in (
                (RecordedSemanticCandidateKind.VALID, artifact.valid_candidates),
                (
                    RecordedSemanticCandidateKind.PARTIAL_SUGGESTION,
                    artifact.partial_bundle_suggestions,
                ),
            )
            for candidate in records
        )
        resolution = artifact.resolution
        attempt = artifact.model_attempt
        failure = artifact.provider_failure
        human = artifact.human_audit
        return SemanticSnapshotV1(
            project_id=config.project.id,
            recorded=True,
            recorded_at=artifact.generated_at,
            state=resolution.state if resolution is not None else None,
            basis=resolution.basis if resolution is not None else None,
            selected_symbol_id=(resolution.selected_symbol_id if resolution is not None else None),
            semantic_context_fingerprint=artifact.semantic_context_fingerprint,
            resolution_fingerprint=artifact.resolution_fingerprint,
            bundle_completeness=artifact.context.bundle_completeness,
            provider_id=attempt.provider_id if attempt is not None else None,
            model=attempt.model if attempt is not None else None,
            provider_failure_code=failure.code if failure is not None else None,
            provider_failure_status_code=(failure.status_code if failure is not None else None),
            presented_symbol_ids=artifact.context.presented_symbol_ids,
            candidates=candidates,
            human_basis=human.basis if human is not None else None,
            human_acted_at=human.acted_at if human is not None else None,
        )

    @staticmethod
    def _semantic_selection_options(
        result: SemanticUseCaseResult,
    ) -> tuple[SemanticSelectionOptionV1, ...]:
        artifact = result.artifact
        by_symbol = {item.symbol_id: item for item in result.source_index.symbols}
        valid = {item.symbol_id: item for item in artifact.valid_candidates}
        partial = {item.symbol_id: item for item in artifact.partial_bundle_suggestions}
        ordered_ids = list(artifact.context.presented_symbol_ids)
        if (
            artifact.resolution is not None
            and artifact.resolution.selected_symbol_id is not None
            and artifact.resolution.selected_symbol_id not in ordered_ids
        ):
            ordered_ids.append(artifact.resolution.selected_symbol_id)
        options: list[SemanticSelectionOptionV1] = []
        for symbol_id in ordered_ids:
            symbol = by_symbol.get(symbol_id)
            if symbol is None:
                continue
            candidate = valid.get(symbol_id) or partial.get(symbol_id)
            kind = (
                SemanticSelectionKind.VALID
                if symbol_id in valid
                else (
                    SemanticSelectionKind.PARTIAL_SUGGESTION
                    if symbol_id in partial
                    else SemanticSelectionKind.PRESENTED
                )
            )
            options.append(
                SemanticSelectionOptionV1(
                    kind=kind,
                    symbol_id=symbol.symbol_id,
                    qualified_name=symbol.qualified_name,
                    symbol_kind=symbol.kind,
                    source_location=symbol.source_location,
                    rationale=candidate.rationale if candidate is not None else None,
                    provider_confidence=(
                        candidate.provider_confidence if candidate is not None else None
                    ),
                )
            )
        return tuple(options)

    async def resolve_semantics(self) -> SemanticOperationV1:
        try:
            result = await resolve_customer_value(self._project_root, self._config_path)
        except Exception as exc:
            _translate_error(exc)
        return SemanticOperationV1(
            artifact=result.artifact,
            graph_fingerprint=result.graph.graph_fingerprint,
            selection_options=self._semantic_selection_options(result),
        )

    async def confirm_semantics(self, symbol_id: str) -> SemanticOperationV1:
        try:
            result = await confirm_customer_value(
                self._project_root,
                self._config_path,
                symbol_id,
            )
        except SemanticSelectionError:
            _raise_control(ControlErrorCode.INVALID_SEMANTIC_SELECTION)
        except Exception as exc:
            _translate_error(exc)
        return SemanticOperationV1(
            artifact=result.artifact,
            graph_fingerprint=result.graph.graph_fingerprint,
            selection_options=self._semantic_selection_options(result),
        )

    def analyze_applicability(self) -> ScenarioApplicabilityArtifact:
        try:
            return analyze_applicability(self._project_root, self._config_path).artifact
        except Exception as exc:
            _translate_error(exc)

    def confirm_policy(
        self,
        *,
        fulfilment: FulfilmentPolicy | None = None,
        late_authorisation: LateAuthorisationPolicy | None = None,
    ) -> ScenarioApplicabilityArtifact:
        if fulfilment is None and late_authorisation is None:
            _raise_control(ControlErrorCode.INVALID_POLICY_CONFIRMATION)
        try:
            return confirm_merchant_policy(
                self._project_root,
                self._config_path,
                fulfilment=fulfilment,
                late_authorisation=late_authorisation,
            ).artifact
        except Exception as exc:
            _translate_error(exc)

    def assess_runtime(self) -> RuntimeCapabilityArtifact:
        try:
            return assess_runtime_capability(self._project_root, self._config_path).artifact
        except Exception as exc:
            _translate_error(exc)

    def verify(
        self,
        *,
        razorpay_grounding_request: RazorpayTestGroundingRequest | None = None,
    ) -> VerificationRun:
        try:
            if razorpay_grounding_request is None:
                return create_verification_run(
                    self._project_root,
                    self._config_path,
                ).artifact
            return create_verification_run(
                self._project_root,
                self._config_path,
                razorpay_grounding_request=razorpay_grounding_request,
            ).artifact
        except Exception as exc:
            _translate_error(exc)

    async def remediation_assistance(
        self,
        run_id: str,
        occurrence_id: str,
    ) -> RemediationAssistance:
        try:
            return await generate_remediation_assistance(
                self._project_root,
                self._config_path,
                run_id,
                occurrence_id,
            )
        except Exception as exc:
            _translate_error(exc)

    def reverify_finding(
        self,
        run_id: str,
        occurrence_id: str,
    ) -> ReverificationResult:
        try:
            return verify_current_finding(
                self._project_root,
                self._config_path,
                run_id,
                occurrence_id,
            )
        except Exception as exc:
            _translate_error(exc)

    def list_runs(self) -> RunListV1:
        try:
            runs = list_verification_runs(self._project_root)
        except Exception as exc:
            _translate_error(exc)
        return RunListV1(runs=tuple(run_list_item(run) for run in runs))

    def latest_run(self) -> VerificationRun:
        try:
            run = load_latest_verification_run(self._project_root)
        except Exception as exc:
            _translate_error(exc)
        if run is None:
            _raise_control(ControlErrorCode.RUN_NOT_FOUND)
        return run

    def load_run(self, run_id: str) -> VerificationRun:
        try:
            return load_verification_run(self._project_root, run_id)
        except Exception as exc:
            _translate_error(exc)

    def report_run(self, run_id: str) -> RunReportV1:
        return run_report(self.load_run(run_id))

    def report_latest_run(self) -> RunReportV1:
        return run_report(self.latest_run())
