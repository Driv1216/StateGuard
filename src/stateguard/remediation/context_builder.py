"""Eligibility, historical grounding, and relevance-scoped current authority."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stateguard.applicability.contracts import AssertionApplicability
from stateguard.application.applicability import ApplicabilityUseCaseResult, inspect_applicability
from stateguard.contracts.config import StateGuardConfig
from stateguard.contracts.identity import canonical_json
from stateguard.evidence.catalog import PolicyDimension
from stateguard.evidence.contracts import (
    CheckPolicyAuthority,
    Finding,
    FindingKind,
    FindingRelevantAuthoritySnapshot,
    SemanticAuthoritySnapshot,
    VerificationCheck,
    VerificationRun,
)
from stateguard.evidence.normalization import (
    build_finding_relevant_authority_snapshot,
    current_scenario_definition_fingerprint,
)
from stateguard.failure_lab.contracts import EvidenceTier, VerificationResultState
from stateguard.rules.razorpay import razorpay_rule_catalog_fingerprint
from stateguard.workspace.config import load_config
from stateguard.workspace.run_artifacts import load_verification_run

from .contracts import AssistanceMode, DriftDiagnostic, EditableRegion, GroundingReference
from .patch_validation import UnsafePatchError, build_symbol_regions


class RemediationNotEligibleError(ValueError):
    """The selected finding is not an exact proven-failure occurrence."""


@dataclass(frozen=True)
class RemediationContext:
    run: VerificationRun
    finding: Finding
    check: VerificationCheck
    config: StateGuardConfig
    mode: AssistanceMode
    mode_label: str
    references: tuple[GroundingReference, ...]
    provider_input: str
    allowed_reference_ids: frozenset[str]
    editable_regions: tuple[EditableRegion, ...]
    historical_relevant_fingerprint: str | None
    current_relevant_fingerprint: str | None
    drift: tuple[DriftDiagnostic, ...]


def _select_verified_failure(
    run: VerificationRun,
    occurrence_id: str,
) -> tuple[Finding, VerificationCheck]:
    findings = [item for item in run.findings if item.occurrence_id == occurrence_id]
    if len(findings) != 1:
        raise RemediationNotEligibleError("finding occurrence is not present in the run")
    finding = findings[0]
    checks = [item for item in run.checks if item.check_id == finding.check_id]
    if len(checks) != 1:
        raise RemediationNotEligibleError("finding check is unavailable")
    check = checks[0]
    if (
        finding.kind != FindingKind.VERIFIED_FAILURE
        or not finding.critical
        or check.result != VerificationResultState.VERIFIED_FAIL
        or check.evidence_tier
        not in {EvidenceTier.E3_DYNAMIC_VERIFIED, EvidenceTier.E4_RAZORPAY_GROUNDED}
    ):
        raise RemediationNotEligibleError("only critical VERIFIED FAIL findings are eligible")
    return finding, check


def _keyed_policy(
    check: VerificationCheck,
    current: ApplicabilityUseCaseResult,
) -> CheckPolicyAuthority:
    dimensions = check.key_policy_dimensions
    policy = current.artifact.policy
    return CheckPolicyAuthority(
        dimensions=dimensions,
        fulfilment=(
            policy.fulfilment.confirmed_policy if PolicyDimension.FULFILMENT in dimensions else None
        ),
        fulfilment_evidence_fingerprint=(
            policy.fulfilment.evidence_fingerprint
            if PolicyDimension.FULFILMENT in dimensions
            else None
        ),
        late_authorisation=(
            policy.late_authorisation.confirmed_policy
            if PolicyDimension.LATE_AUTHORISATION in dimensions
            else None
        ),
        late_authorisation_evidence_fingerprint=(
            policy.late_authorisation.evidence_fingerprint
            if PolicyDimension.LATE_AUTHORISATION in dimensions
            else None
        ),
    )


def _current_assertion(
    check: VerificationCheck,
    current: ApplicabilityUseCaseResult,
) -> AssertionApplicability:
    matches = tuple(
        assertion
        for scenario in current.artifact.scenarios
        if scenario.scenario_id == check.scenario_id
        for instance in scenario.instances
        if instance.instance_id == check.scenario_instance_id
        for assertion in instance.assertions
        if assertion.assertion_id == check.assertion_id and assertion.key == check.assertion_key
    )
    if len(matches) != 1:
        raise ValueError("exact current applicability assertion is unavailable")
    return matches[0]


def _semantic_authority(
    config: StateGuardConfig,
    current: ApplicabilityUseCaseResult,
) -> SemanticAuthoritySnapshot:
    snapshot = current.snapshot
    resolution = snapshot.resolution
    configured = (
        config.semantics.customer_value
        if config.semantics is not None and config.semantics.customer_value is not None
        else None
    )
    return SemanticAuthoritySnapshot(
        state=resolution.state if resolution is not None else None,
        basis=resolution.basis if resolution is not None else None,
        selected_symbol_id=(resolution.selected_symbol_id if resolution is not None else None),
        resolution_fingerprint=snapshot.resolution_fingerprint,
        semantic_context_fingerprint=(
            snapshot.artifact.semantic_context_fingerprint
            if snapshot.artifact is not None
            else (configured.semantic_context_fingerprint if configured is not None else None)
        ),
    )


def rebuild_current_finding_authority(
    repository_root: Path,
    config: StateGuardConfig,
    check: VerificationCheck,
    current: ApplicabilityUseCaseResult,
) -> FindingRelevantAuthoritySnapshot:
    historical = check.relevant_authority
    if historical is None:
        raise ValueError("legacy run has no finding-relevant authority")
    return build_finding_relevant_authority_snapshot(
        repository_root=repository_root,
        source_index=current.snapshot.source_index,
        graph=current.snapshot.graph,
        applicability=current.artifact,
        assertion=_current_assertion(check, current),
        targets=check.targets,
        source_references=check.source_references,
        graph_node_ids=check.graph_node_ids,
        graph_edge_ids=check.graph_edge_ids,
        key_policy_dimensions=check.key_policy_dimensions,
        policy_authority=_keyed_policy(check, current),
        invariant_id=check.invariant_id,
        invariant_version=check.invariant_version,
        scenario_definition_fingerprint=current_scenario_definition_fingerprint(check.scenario_id),
        rule_ids=check.razorpay_rule_ids,
        semantic=_semantic_authority(config, current),
    )


def _whole_drift(
    run: VerificationRun,
    current: ApplicabilityUseCaseResult,
) -> tuple[DriftDiagnostic, ...]:
    old = run.authority
    pairs = (
        (
            "PROJECT_SOURCE",
            old.project_source_fingerprint,
            current.snapshot.source_index.project_source_fingerprint,
        ),
        (
            "SOURCE_INDEX",
            old.source_index_fingerprint,
            current.snapshot.source_index.source_index_fingerprint,
        ),
        (
            "STRUCTURAL_GRAPH",
            old.structural_graph_fingerprint,
            current.snapshot.structural_graph.graph_fingerprint,
        ),
        (
            "PROJECTED_GRAPH",
            old.projected_graph_fingerprint,
            current.snapshot.graph.graph_fingerprint,
        ),
        (
            "APPLICABILITY",
            old.applicability_fingerprint,
            current.artifact.applicability_fingerprint,
        ),
    )
    return tuple(
        DriftDiagnostic(
            dimension=name,
            historical_fingerprint=historical,
            current_fingerprint=now,
            blocking=False,
        )
        for name, historical, now in pairs
        if historical != now
    )


def relevant_authority_blockers(
    historical: FindingRelevantAuthoritySnapshot,
    current: FindingRelevantAuthoritySnapshot,
) -> tuple[str, ...]:
    # Whole referenced-file bytes are diagnostic. Exact definition/call-site/edit-region
    # authority below decides whether an unrelated change in that file is material.
    fields = (
        "symbols",
        "call_sites",
        "call_path_references",
        "graph_nodes",
        "graph_edges",
        "applicability_assertion_fingerprint",
        "selected_semantic_symbol_id",
        "semantic_resolution_fingerprint",
        "semantic_context_fingerprint",
        "key_policy_authority",
        "invariant_id",
        "invariant_version",
        "scenario_definition_fingerprint",
        "razorpay_rules",
        "razorpay_rule_catalog_fingerprint",
    )
    return tuple(name for name in fields if getattr(historical, name) != getattr(current, name))


def _historical_references(
    run: VerificationRun,
    check: VerificationCheck,
) -> tuple[GroundingReference, ...]:
    references = [
        GroundingReference(
            reference="historical-invariant",
            description=check.expected_invariant,
        ),
        GroundingReference(
            reference="historical-result",
            description=(
                f"{check.result.value}; reason {check.reason.value}; "
                f"evidence tier {check.evidence_tier.value if check.evidence_tier else 'NONE'}"
            ),
        ),
        GroundingReference(
            reference="historical-assertion",
            description=(
                f"{check.scenario_id.value} / {check.assertion_key} / "
                f"{check.invariant_id} v{check.invariant_version}"
            ),
        ),
    ]
    for index, request in enumerate(check.runtime_evidence.requests, start=1):
        references.append(
            GroundingReference(
                reference=f"historical-request-{index}",
                description=(
                    f"{request.role.value}: received {len(request.request_received_sequences)}; "
                    "customer entries "
                    f"{request.customer.entered_count if request.customer else 0}; "
                    f"HTTP status {request.http_status_code}"
                ),
            )
        )
    for index, source in enumerate(check.source_references, start=1):
        references.append(
            GroundingReference(
                reference=f"historical-target-{index}",
                description=(
                    f"Historical symbol {source.symbol_id} at project-relative "
                    f"{source.source_location.path}"
                ),
            )
        )
    rules = {item.rule_id: item for item in run.authority.razorpay_rules.referenced_rules}
    for index, rule_id in enumerate(check.razorpay_rule_ids, start=1):
        rule = rules[rule_id]
        references.append(
            GroundingReference(
                reference=f"historical-rule-{index}",
                description=f"{rule.fact} (verified {rule.verified_on.isoformat()})",
            )
        )
    return tuple(references)


def build_remediation_context(
    repository_root: Path,
    config_path: Path,
    run_id: str,
    occurrence_id: str,
) -> RemediationContext:
    run = load_verification_run(repository_root, run_id)
    finding, check = _select_verified_failure(run, occurrence_id)
    config = load_config(config_path)
    references = _historical_references(run, check)
    drift: tuple[DriftDiagnostic, ...] = ()
    current_relevant: FindingRelevantAuthoritySnapshot | None = None
    editable_regions: tuple[EditableRegion, ...] = ()
    blockers: tuple[str, ...] = ("CURRENT_AUTHORITY_UNAVAILABLE",)
    try:
        current = inspect_applicability(repository_root, config_path)
        drift = _whole_drift(run, current)
        if run.schema_version == 2 and check.relevant_authority is not None:
            current_relevant = rebuild_current_finding_authority(
                repository_root, config, check, current
            )
            blockers = relevant_authority_blockers(check.relevant_authority, current_relevant)
        else:
            whole_matches = not drift and (
                run.authority.semantic.selected_symbol_id
                == _semantic_authority(config, current).selected_symbol_id
                and run.authority.semantic.resolution_fingerprint
                == _semantic_authority(config, current).resolution_fingerprint
                and run.authority.razorpay_rules.catalog_fingerprint
                == razorpay_rule_catalog_fingerprint()
            )
            blockers = () if whole_matches else ("LEGACY_WHOLE_AUTHORITY_DRIFT",)
        if not blockers:
            symbol_ids = {item.symbol_id for item in check.source_references}
            editable_regions = build_symbol_regions(
                repository_root, current.snapshot.source_index, symbol_ids
            )
            if not editable_regions:
                blockers = ("NO_SUPPORTED_EDITABLE_REGION",)
    except (OSError, ValueError, UnsafePatchError):
        blockers = ("CURRENT_AUTHORITY_UNAVAILABLE",)

    if blockers:
        mode = AssistanceMode.HISTORICAL_EXPLANATION_ONLY
        mode_label = f"HISTORICAL EXPLANATION — REFERS TO RUN {run.run_id}; CURRENT SOURCE NOT USED"
        provider_payload = {
            "mode": mode.value,
            "run_id": run.run_id,
            "references": [item.model_dump(mode="json") for item in references],
            "limitations": list(blockers),
        }
        editable_regions = ()
    else:
        mode = AssistanceMode.CURRENT_SOURCE_REMEDIATION
        mode_label = "CURRENT SOURCE REMEDIATION — AI-GENERATED AND NOT VERIFIED"
        provider_payload = {
            "mode": mode.value,
            "run_id": run.run_id,
            "references": [item.model_dump(mode="json") for item in references],
            "editable_regions": [
                {
                    "region_reference": item.region_reference,
                    "kind": item.kind.value,
                    "merchant_source": item.content,
                }
                for item in editable_regions
            ],
        }
    return RemediationContext(
        run=run,
        finding=finding,
        check=check,
        config=config,
        mode=mode,
        mode_label=mode_label,
        references=references,
        provider_input=canonical_json(provider_payload),
        allowed_reference_ids=frozenset(
            (
                *[item.reference for item in references],
                *[item.region_reference for item in editable_regions],
            )
        ),
        editable_regions=editable_regions,
        historical_relevant_fingerprint=(
            check.relevant_authority.relevant_authority_fingerprint
            if check.relevant_authority is not None
            else None
        ),
        current_relevant_fingerprint=(
            current_relevant.relevant_authority_fingerprint
            if current_relevant is not None
            else None
        ),
        drift=tuple(
            (*drift, *(DriftDiagnostic(dimension=item, blocking=True) for item in blockers))
        ),
    )
