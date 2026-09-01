"""Step 7 application orchestration for one complete durable verification run."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from stateguard.applicability.contracts import ApplicabilityState, ScenarioId, ScenarioInstance
from stateguard.application.applicability import ApplicabilityUseCaseResult, analyze_applicability
from stateguard.application.failure_lab import (
    execute_sg01,
    execute_sg02,
    execute_sg03,
    execute_sg04,
    execute_sg05,
    execute_sg06,
    execute_sg07,
    execute_sg08,
)
from stateguard.contracts.common import Sha256Digest
from stateguard.contracts.config import StateGuardConfig
from stateguard.contracts.identity import (
    fingerprint_json,
    new_verification_run_id,
)
from stateguard.evidence.contracts import VerificationRun
from stateguard.evidence.normalization import build_verification_run
from stateguard.failure_lab.contracts import ScenarioExecutionResult
from stateguard.grounding.contracts import RazorpayTestGroundingRequest
from stateguard.grounding.razorpay import (
    GroundingAcquisitionResult,
    acquire_razorpay_test_grounding,
)
from stateguard.rules.razorpay import razorpay_rule_catalog_fingerprint
from stateguard.workspace.config import load_config
from stateguard.workspace.run_artifacts import write_verification_run


@dataclass(frozen=True)
class VerificationRunUseCaseResult:
    artifact: VerificationRun
    path: Path


class VerificationAuthorityChangedError(ValueError):
    """Current verification authority drifted before a run could be published."""


def _execute_instance(
    repository_root: Path,
    config_path: Path,
    scenario_id: ScenarioId,
    instance: ScenarioInstance,
    applicability_fingerprint: Sha256Digest,
    grounding: GroundingAcquisitionResult | None = None,
) -> tuple[ScenarioExecutionResult, ...]:
    timestamp = datetime.now(UTC)
    if scenario_id == ScenarioId.SG_01:
        return (
            execute_sg01(
                repository_root,
                config_path,
                scenario_instance_id=instance.instance_id,
                expected_applicability_fingerprint=applicability_fingerprint,
                generated_at=timestamp,
                grounding=grounding,
            ),
        )
    if scenario_id == ScenarioId.SG_02:
        return (
            execute_sg02(
                repository_root,
                config_path,
                scenario_instance_id=instance.instance_id,
                expected_applicability_fingerprint=applicability_fingerprint,
                generated_at=timestamp,
            ),
        )
    if scenario_id == ScenarioId.SG_03:
        return (
            execute_sg03(
                repository_root,
                config_path,
                scenario_instance_id=instance.instance_id,
                expected_applicability_fingerprint=applicability_fingerprint,
                generated_at=timestamp,
            ),
        )
    if scenario_id == ScenarioId.SG_04:
        return execute_sg04(
            repository_root,
            config_path,
            scenario_instance_id=instance.instance_id,
            expected_applicability_fingerprint=applicability_fingerprint,
            generated_at=timestamp,
        )
    if scenario_id == ScenarioId.SG_05:
        return execute_sg05(
            repository_root,
            config_path,
            scenario_instance_id=instance.instance_id,
            expected_applicability_fingerprint=applicability_fingerprint,
            generated_at=timestamp,
        )
    if scenario_id == ScenarioId.SG_06:
        return execute_sg06(
            repository_root,
            config_path,
            scenario_instance_id=instance.instance_id,
            expected_applicability_fingerprint=applicability_fingerprint,
            generated_at=timestamp,
        )
    if scenario_id == ScenarioId.SG_07:
        return (
            execute_sg07(
                repository_root,
                config_path,
                scenario_instance_id=instance.instance_id,
                expected_applicability_fingerprint=applicability_fingerprint,
                generated_at=timestamp,
            ),
        )
    return execute_sg08(
        repository_root,
        config_path,
        scenario_instance_id=instance.instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=timestamp,
    )


def _validate_unchanged_authority(
    initial_config: StateGuardConfig,
    initial: ApplicabilityUseCaseResult,
    final_config: StateGuardConfig,
    final: ApplicabilityUseCaseResult,
    initial_rule_catalog_fingerprint: str,
) -> None:
    initial_snapshot = initial.snapshot
    final_snapshot = final.snapshot
    unchanged = bool(
        fingerprint_json(initial_config) == fingerprint_json(final_config)
        and initial.artifact.applicability_fingerprint == final.artifact.applicability_fingerprint
        and initial_snapshot.source_index.project_source_fingerprint
        == final_snapshot.source_index.project_source_fingerprint
        and initial_snapshot.source_index.source_index_fingerprint
        == final_snapshot.source_index.source_index_fingerprint
        and initial_snapshot.structural_graph.graph_fingerprint
        == final_snapshot.structural_graph.graph_fingerprint
        and initial_snapshot.graph.graph_fingerprint == final_snapshot.graph.graph_fingerprint
        and initial_snapshot.resolution == final_snapshot.resolution
        and initial_snapshot.resolution_fingerprint == final_snapshot.resolution_fingerprint
        and initial_rule_catalog_fingerprint == razorpay_rule_catalog_fingerprint()
    )
    if not unchanged:
        raise VerificationAuthorityChangedError(
            "verification authority changed before run completion"
        )


def create_verification_run(
    repository_root: Path,
    config_path: Path,
    *,
    created_at: datetime | None = None,
    razorpay_grounding_request: RazorpayTestGroundingRequest | None = None,
) -> VerificationRunUseCaseResult:
    """Execute all current Failure Lab assertions and publish one immutable run."""

    started = created_at or datetime.now(UTC)
    run_id = new_verification_run_id()
    initial_config = load_config(config_path)
    initial = analyze_applicability(repository_root, config_path, generated_at=started)
    applicability = initial.artifact
    initial_rules = razorpay_rule_catalog_fingerprint()

    results: list[ScenarioExecutionResult] = []
    scenarios = sorted(
        applicability.scenarios,
        key=lambda item: int(item.scenario_id.value.removeprefix("SG-")),
    )
    grounding: GroundingAcquisitionResult | None = None
    grounded_instance_id = None
    sg01 = next(
        (scenario for scenario in scenarios if scenario.scenario_id == ScenarioId.SG_01),
        None,
    )
    if razorpay_grounding_request is not None and sg01 is not None:
        grounded_instance_id = next(
            (
                instance.instance_id
                for instance in sorted(sg01.instances, key=lambda item: item.instance_id)
                if instance.state == ApplicabilityState.APPLICABLE
            ),
            None,
        )
        grounding = acquire_razorpay_test_grounding(
            razorpay_grounding_request,
            run_id,
            acquired_at=max(datetime.now(UTC), started),
        )
    for scenario in scenarios:
        for instance in sorted(scenario.instances, key=lambda item: item.instance_id):
            results.extend(
                _execute_instance(
                    repository_root,
                    config_path,
                    scenario.scenario_id,
                    instance,
                    applicability.applicability_fingerprint,
                    grounding=(
                        grounding
                        if scenario.scenario_id == ScenarioId.SG_01
                        and instance.instance_id == grounded_instance_id
                        and grounding is not None
                        and grounding.profile is not None
                        else None
                    ),
                )
            )

    completed = max(
        datetime.now(UTC),
        started,
        *(tuple([grounding.snapshot.acquired_at]) if grounding is not None else ()),
    )
    final_config = load_config(config_path)
    final = analyze_applicability(repository_root, config_path, generated_at=completed)
    _validate_unchanged_authority(
        initial_config,
        initial,
        final_config,
        final,
        initial_rules,
    )
    snapshot = initial.snapshot
    artifact = build_verification_run(
        repository_root=repository_root,
        run_id=run_id,
        created_at=started,
        completed_at=completed,
        config=initial_config,
        source_index=snapshot.source_index,
        structural_graph=snapshot.structural_graph,
        projected_graph=snapshot.graph,
        semantic_artifact=snapshot.artifact,
        resolution=snapshot.resolution,
        resolution_fingerprint=snapshot.resolution_fingerprint,
        applicability=applicability,
        results=results,
        razorpay_grounding=(grounding.snapshot if grounding is not None else None),
    )
    path = write_verification_run(repository_root, artifact)
    return VerificationRunUseCaseResult(artifact=artifact, path=path)
