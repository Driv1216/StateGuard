"""Step 5 runtime capability assessment without scenario or verdict semantics."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from stateguard.application.applicability import ApplicabilityUseCaseResult, analyze_applicability
from stateguard.contracts.config import (
    BringYourOwnRuntimeConfig,
    ManagedRuntimeConfig,
    RuntimeMode,
    StaticRuntimeConfig,
)
from stateguard.contracts.identity import fingerprint_json, new_runtime_session_id
from stateguard.runtime.capability import (
    PreparedInstrumentation,
    build_capability_artifact,
    prepare_instrumentation,
)
from stateguard.runtime.compatibility import (
    detect_runtime_compatibility,
    managed_compatibility_reason,
)
from stateguard.runtime.contracts import (
    RuntimeCapabilityArtifact,
    RuntimeCapabilityReasonCode,
    RuntimeDiagnostic,
    RuntimeDiagnosticStage,
    RuntimeLifecycleState,
    RuntimeProcessOwnership,
)
from stateguard.runtime.planning import RuntimeTargetPlan, build_runtime_target_plan
from stateguard.runtime.routes import RouteAttachment
from stateguard.runtime.session import (
    BringYourOwnRuntimeSession,
    ManagedRuntimeSession,
    RuntimeSessionError,
)
from stateguard.workspace.config import load_config
from stateguard.workspace.runtime_artifacts import write_runtime_artifact


@dataclass(frozen=True)
class RuntimeAssessmentResult:
    applicability: ApplicabilityUseCaseResult
    artifact: RuntimeCapabilityArtifact


RuntimeSession = ManagedRuntimeSession | BringYourOwnRuntimeSession


@dataclass(frozen=True)
class RuntimeSessionOpenResult:
    """Fresh capability authority and its active value-free stream, if available."""

    applicability: ApplicabilityUseCaseResult
    artifact: RuntimeCapabilityArtifact
    plan: RuntimeTargetPlan
    session: RuntimeSession | None
    runtime_config: ManagedRuntimeConfig | BringYourOwnRuntimeConfig | StaticRuntimeConfig
    prepared: PreparedInstrumentation
    attachments: tuple[RouteAttachment, ...]
    generated_at: datetime


def open_runtime_session(
    repository_root: Path,
    config_path: Path,
    *,
    generated_at: datetime | None = None,
) -> RuntimeSessionOpenResult:
    """Open a freshly assessed session for Step 6 without persisting observations."""

    timestamp = generated_at or datetime.now(UTC)
    config = load_config(config_path)
    applicability_result = analyze_applicability(
        repository_root,
        config_path,
        generated_at=timestamp,
    )
    snapshot = applicability_result.snapshot
    applicability = applicability_result.artifact
    plan = build_runtime_target_plan(snapshot.source_index, snapshot.graph, applicability)
    prepared = prepare_instrumentation(
        repository_root,
        snapshot.source_index,
        snapshot.graph,
        plan,
    )
    session_id = new_runtime_session_id()
    runtime_config = config.runtime or StaticRuntimeConfig()
    attachments: tuple[RouteAttachment, ...] = ()
    diagnostics: list[RuntimeDiagnostic] = []
    ownership = RuntimeProcessOwnership.NONE
    session: RuntimeSession | None = None

    if runtime_config.mode == RuntimeMode.MANAGED:
        assert isinstance(runtime_config, ManagedRuntimeConfig)
        compatibility_reason = managed_compatibility_reason(detect_runtime_compatibility())
        if compatibility_reason != RuntimeCapabilityReasonCode.AVAILABLE:
            diagnostics.append(
                RuntimeDiagnostic(
                    code=compatibility_reason,
                    stage=RuntimeDiagnosticStage.PREFLIGHT,
                )
            )
        else:
            try:
                started = ManagedRuntimeSession.start(
                    repository_root=repository_root,
                    config_path=config_path,
                    config=runtime_config,
                    source_root=config.project.source_root,
                    session_id=session_id,
                    source_index=snapshot.source_index,
                    structural_graph=snapshot.structural_graph,
                    graph=snapshot.graph,
                    applicability=applicability,
                    plan=plan,
                )
                session = started.session
                attachments = started.attachments
                prepared = started.prepared
                ownership = RuntimeProcessOwnership.STATEGUARD
            except RuntimeSessionError as exc:
                diagnostics.append(
                    RuntimeDiagnostic(
                        code=exc.reason,
                        stage=RuntimeDiagnosticStage.STARTUP,
                        reference=exc.reference,
                    )
                )
    elif runtime_config.mode == RuntimeMode.BYO:
        assert isinstance(runtime_config, BringYourOwnRuntimeConfig)
        ownership = (
            RuntimeProcessOwnership.STATEGUARD
            if runtime_config.launch_argv is not None
            else RuntimeProcessOwnership.EXTERNAL
        )
        try:
            session = BringYourOwnRuntimeSession.start(
                repository_root=repository_root,
                config=runtime_config,
                session_id=session_id,
            )
        except RuntimeSessionError as exc:
            diagnostics.append(
                RuntimeDiagnostic(
                    code=exc.reason,
                    stage=RuntimeDiagnosticStage.READINESS,
                    reference=exc.reference,
                )
            )

    try:
        artifact = build_capability_artifact(
            generated_at=timestamp,
            session_id=session_id,
            runtime_config=runtime_config,
            source_index=snapshot.source_index,
            structural_graph=snapshot.structural_graph,
            graph=snapshot.graph,
            applicability=applicability,
            plan=plan,
            prepared=prepared,
            attachments=attachments,
            lifecycle=(
                RuntimeLifecycleState.READY
                if session is not None
                else RuntimeLifecycleState.UNAVAILABLE
            ),
            ownership=ownership,
            diagnostics=tuple(diagnostics),
        )
    except BaseException:
        if session is not None:
            with contextlib.suppress(BaseException):
                session.close(fingerprint_json("failed runtime capability construction"))
        raise
    return RuntimeSessionOpenResult(
        applicability=applicability_result,
        artifact=artifact,
        plan=plan,
        session=session,
        runtime_config=runtime_config,
        prepared=prepared,
        attachments=attachments,
        generated_at=timestamp,
    )


def assess_runtime_capability(
    repository_root: Path,
    config_path: Path,
    *,
    generated_at: datetime | None = None,
) -> RuntimeAssessmentResult:
    """Explicitly assess runtime capability; never evaluate a payment invariant."""

    opened = open_runtime_session(
        repository_root,
        config_path,
        generated_at=generated_at,
    )
    snapshot = opened.applicability.snapshot
    applicability = opened.applicability.artifact
    diagnostics = list(opened.artifact.diagnostics)
    lifecycle = opened.artifact.lifecycle
    if opened.session is not None:
        transcript = opened.session.close(opened.artifact.capability_fingerprint)
        for code in transcript.diagnostics:
            diagnostics.append(
                RuntimeDiagnostic(
                    code=code,
                    stage=(
                        RuntimeDiagnosticStage.CLEANUP
                        if code == RuntimeCapabilityReasonCode.CLEANUP_FAILED
                        else RuntimeDiagnosticStage.OBSERVATION
                    ),
                )
            )
        if not transcript.complete and not transcript.diagnostics:
            diagnostics.append(
                RuntimeDiagnostic(
                    code=RuntimeCapabilityReasonCode.OBSERVATION_CHANNEL_FAILED,
                    stage=RuntimeDiagnosticStage.OBSERVATION,
                )
            )
        lifecycle = RuntimeLifecycleState.HISTORICAL

    artifact = build_capability_artifact(
        generated_at=opened.generated_at,
        session_id=opened.artifact.assessment_session_id,
        runtime_config=opened.runtime_config,
        source_index=snapshot.source_index,
        structural_graph=snapshot.structural_graph,
        graph=snapshot.graph,
        applicability=applicability,
        plan=opened.plan,
        prepared=opened.prepared,
        attachments=opened.attachments,
        lifecycle=lifecycle,
        ownership=opened.artifact.ownership,
        diagnostics=tuple(diagnostics),
    )
    write_runtime_artifact(repository_root, artifact)
    return RuntimeAssessmentResult(applicability=opened.applicability, artifact=artifact)
