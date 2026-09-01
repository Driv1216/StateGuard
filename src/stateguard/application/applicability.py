"""Step 4 application use cases without model-provider execution."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from stateguard.applicability.contracts import ScenarioApplicabilityArtifact
from stateguard.applicability.engine import evaluate_applicability
from stateguard.application.semantics import (
    CurrentSemanticSnapshot,
    rebuild_current_semantic_snapshot,
)
from stateguard.contracts.config import (
    ConfirmedFulfilmentPolicyConfig,
    ConfirmedLateAuthorisationPolicyConfig,
    FulfilmentPolicy,
    LateAuthorisationPolicy,
    MerchantPolicyConfig,
)
from stateguard.workspace.applicability_artifacts import write_applicability_artifact
from stateguard.workspace.config import load_config
from stateguard.workspace.config_edit import write_merchant_policy_confirmation


@dataclass(frozen=True)
class ApplicabilityUseCaseResult:
    snapshot: CurrentSemanticSnapshot
    artifact: ScenarioApplicabilityArtifact


def _analyze(
    repository_root: Path,
    config_path: Path,
    timestamp: datetime,
    *,
    persist: bool,
) -> ApplicabilityUseCaseResult:
    config = load_config(config_path)
    snapshot = rebuild_current_semantic_snapshot(
        repository_root,
        config,
        generated_at=timestamp,
    )
    artifact = evaluate_applicability(
        generated_at=timestamp,
        config=config,
        source_index=snapshot.source_index,
        structural_graph=snapshot.structural_graph,
        projected_graph=snapshot.graph,
        resolution=snapshot.resolution,
        resolution_fingerprint=snapshot.resolution_fingerprint,
    )
    if persist:
        write_applicability_artifact(repository_root, artifact)
    return ApplicabilityUseCaseResult(snapshot=snapshot, artifact=artifact)


def analyze_applicability(
    repository_root: Path,
    config_path: Path,
    *,
    generated_at: datetime | None = None,
) -> ApplicabilityUseCaseResult:
    """Rebuild and persist deterministic Step 4 analysis without any AI request."""

    timestamp = generated_at or datetime.now(UTC)
    return _analyze(repository_root, config_path, timestamp, persist=True)


def inspect_applicability(
    repository_root: Path,
    config_path: Path,
    *,
    generated_at: datetime | None = None,
) -> ApplicabilityUseCaseResult:
    """Rebuild current Step 4 authority without changing persisted artifacts."""

    timestamp = generated_at or datetime.now(UTC)
    return _analyze(repository_root, config_path, timestamp, persist=False)


def confirm_merchant_policy(
    repository_root: Path,
    config_path: Path,
    *,
    fulfilment: FulfilmentPolicy | None = None,
    late_authorisation: LateAuthorisationPolicy | None = None,
    generated_at: datetime | None = None,
) -> ApplicabilityUseCaseResult:
    """Persist only explicit policy values against current deterministic evidence."""

    if fulfilment is None and late_authorisation is None:
        raise ValueError("policy confirmation requires an explicit policy value")
    timestamp = generated_at or datetime.now(UTC)
    current = _analyze(repository_root, config_path, timestamp, persist=False)
    update = MerchantPolicyConfig(
        fulfilment=(
            ConfirmedFulfilmentPolicyConfig(
                value=fulfilment,
                evidence_fingerprint=current.artifact.policy.fulfilment.evidence_fingerprint,
            )
            if fulfilment is not None
            else None
        ),
        late_authorisation=(
            ConfirmedLateAuthorisationPolicyConfig(
                value=late_authorisation,
                evidence_fingerprint=(
                    current.artifact.policy.late_authorisation.evidence_fingerprint
                ),
            )
            if late_authorisation is not None
            else None
        ),
    )
    write_merchant_policy_confirmation(config_path, update)
    return _analyze(repository_root, config_path, timestamp, persist=True)
