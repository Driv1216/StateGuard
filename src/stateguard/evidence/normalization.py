"""Pure normalization from current authority and Step 6 results into Step 7 evidence."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from stateguard import __version__
from stateguard.applicability.contracts import (
    AssertionApplicability,
    EvidenceReferenceKind,
    ScenarioApplicabilityArtifact,
    ScenarioId,
    ScenarioInstance,
)
from stateguard.contracts.common import (
    GraphEdgeId,
    GraphNodeId,
    PersistedArtifactModel,
    SymbolId,
    VerificationRunId,
)
from stateguard.contracts.config import StateGuardConfig, StaticRuntimeConfig
from stateguard.contracts.identity import (
    assertion_id as expected_assertion_id,
)
from stateguard.contracts.identity import (
    canonical_json,
    fingerprint_json,
    sha256_digest,
    verification_check_id,
)
from stateguard.discovery.contracts import SourceIndexArtifact
from stateguard.failure_lab.contracts import (
    EvidenceTier,
    GroundedScenarioInputReference,
    MutationScenarioRequestObservation,
    ScenarioExecutionResult,
    ScenarioRequestObservation,
)
from stateguard.failure_lab.sg01 import SG01_DEFINITION_FINGERPRINT
from stateguard.failure_lab.sg02 import SG02_DEFINITION_FINGERPRINT
from stateguard.failure_lab.sg03 import SG03_DEFINITION_FINGERPRINT
from stateguard.failure_lab.sg04 import SG04_DEFINITION_FINGERPRINT
from stateguard.failure_lab.sg05 import SG05_DEFINITION_FINGERPRINT
from stateguard.failure_lab.sg06 import SG06_DEFINITION_FINGERPRINT
from stateguard.failure_lab.sg07 import SG07_DEFINITION_FINGERPRINT
from stateguard.failure_lab.sg08 import SG08_DEFINITION_FINGERPRINT
from stateguard.graph.contracts import GraphNodeKind, PaymentSafetyGraphArtifact
from stateguard.grounding.contracts import (
    CheckGroundingEvidence,
    RazorpayGroundingSnapshot,
    RazorpayGroundingStatus,
)
from stateguard.rules.razorpay import (
    RAZORPAY_PROTOCOL_FACTS,
    RAZORPAY_RULE_CATALOG_VERSION,
    RazorpayProtocolRuleId,
    razorpay_rule_catalog_fingerprint,
    razorpay_rule_fingerprint,
)
from stateguard.semantics.contracts import CustomerValueResolution, CustomerValueSemanticArtifact

from .catalog import (
    PolicyDimension,
    assertion_definition,
    assertion_order,
)
from .contracts import (
    AcknowledgementInjectionEvidence,
    ApplicabilityEvidenceSnapshot,
    CheckPolicyAuthority,
    CheckTargetReference,
    ComponentSchemaVersions,
    CustomerRuntimeEvidence,
    FindingRelevantAuthoritySnapshot,
    MutationRuntimeEvidence,
    PolicyAuthoritySnapshot,
    RazorpayRuleAuthoritySnapshot,
    RazorpayRuleSnapshot,
    RelevantFactAuthority,
    RelevantSourceFileAuthority,
    ReverificationReference,
    RuntimeEvidenceProjection,
    RuntimeRequestEvidence,
    SemanticAuthoritySnapshot,
    SemanticProvenanceSnapshot,
    SourceEvidenceReference,
    VerificationAuthoritySnapshot,
    VerificationCheck,
    VerificationRun,
    VerificationRunStatus,
    build_verification_check_key,
    derive_findings,
    summarize_checks,
    verification_run_fingerprint_payload,
)

_SCENARIO_DEFINITION_FINGERPRINTS = {
    ScenarioId.SG_01: SG01_DEFINITION_FINGERPRINT,
    ScenarioId.SG_02: SG02_DEFINITION_FINGERPRINT,
    ScenarioId.SG_03: SG03_DEFINITION_FINGERPRINT,
    ScenarioId.SG_04: SG04_DEFINITION_FINGERPRINT,
    ScenarioId.SG_05: SG05_DEFINITION_FINGERPRINT,
    ScenarioId.SG_06: SG06_DEFINITION_FINGERPRINT,
    ScenarioId.SG_07: SG07_DEFINITION_FINGERPRINT,
    ScenarioId.SG_08: SG08_DEFINITION_FINGERPRINT,
}


def _assertion_authorities(
    applicability: ScenarioApplicabilityArtifact,
) -> dict[tuple[ScenarioId, str, str], tuple[ScenarioInstance, AssertionApplicability]]:
    authorities: dict[
        tuple[ScenarioId, str, str], tuple[ScenarioInstance, AssertionApplicability]
    ] = {}
    for scenario in applicability.scenarios:
        for instance in scenario.instances:
            for assertion in instance.assertions:
                if assertion.assertion_id != expected_assertion_id(
                    instance.instance_id, assertion.key
                ):
                    raise ValueError("applicability assertion identity is not canonical")
                key = (scenario.scenario_id, instance.instance_id, assertion.assertion_id)
                if key in authorities:
                    raise ValueError("duplicate applicability assertion authority")
                authorities[key] = (instance, assertion)
    return authorities


def _execution_results(
    results: Iterable[ScenarioExecutionResult],
) -> dict[tuple[ScenarioId, str, str], ScenarioExecutionResult]:
    mapped: dict[tuple[ScenarioId, str, str], ScenarioExecutionResult] = {}
    for candidate in results:
        result = ScenarioExecutionResult.model_validate(candidate.model_dump(mode="python"))
        key = (
            result.scenario_id,
            result.authority.scenario_instance_id,
            result.assertion_id,
        )
        if key in mapped:
            raise ValueError("duplicate scenario execution assertion authority")
        mapped[key] = result
    return mapped


def _applicability_projection(
    assertion: AssertionApplicability,
) -> ApplicabilityEvidenceSnapshot:
    node_ids: list[str] = []
    edge_ids: list[str] = []
    controls: list[str] = []
    reasons = []
    for reason in assertion.reasons:
        if reason.code not in reasons:
            reasons.append(reason.code)
        for evidence in reason.evidence:
            if evidence.kind == EvidenceReferenceKind.GRAPH_NODE:
                node_ids.append(evidence.reference)
            elif evidence.kind == EvidenceReferenceKind.GRAPH_EDGE:
                edge_ids.append(evidence.reference)
            elif evidence.kind == EvidenceReferenceKind.NORMAL_CONTROL:
                controls.append(evidence.reference)
            else:
                raise ValueError("unsupported free-form applicability evidence reference")
    return ApplicabilityEvidenceSnapshot(
        state=assertion.state,
        role=assertion.role,
        reasons=tuple(reasons),
        graph_node_ids=tuple(dict.fromkeys(node_ids)),
        graph_edge_ids=tuple(dict.fromkeys(edge_ids)),
        normal_control_ids=tuple(dict.fromkeys(controls)),
    )


def _target_reference(
    *,
    applicability: ScenarioApplicabilityArtifact,
    instance: ScenarioInstance,
    assertion: AssertionApplicability,
    result: ScenarioExecutionResult,
    graph: PaymentSafetyGraphArtifact,
) -> CheckTargetReference:
    nodes = {item.node_id: item for item in graph.nodes}
    controls = {item.control_id: item for item in applicability.normal_controls}
    if result.authority.normal_control_id != assertion.normal_control_id:
        raise ValueError("scenario result substituted assertion normal-control authority")
    result_control = (
        controls.get(result.authority.normal_control_id)
        if result.authority.normal_control_id is not None
        else None
    )
    if result.authority.normal_control_id is not None and result_control is None:
        raise ValueError("scenario result refers to an unknown normal control")
    identity_control = (
        controls.get(instance.normal_control_id)
        if instance.normal_control_id is not None
        else result_control
    )

    evidence_node_ids = {
        evidence.reference
        for reason in assertion.reasons
        for evidence in reason.evidence
        if evidence.kind == EvidenceReferenceKind.GRAPH_NODE
    }
    observed_mutations = {
        target.mutation_node_id
        for observation in result.request_observations
        if isinstance(observation, MutationScenarioRequestObservation)
        for target in observation.mutation_targets
    }
    mutation_ids = {
        node_id
        for node_id in evidence_node_ids | observed_mutations
        if (node := nodes.get(node_id)) is not None
        and node.kind == GraphNodeKind.MERCHANT_STATE_MUTATION
    }
    acknowledgement_ids = {
        node_id
        for node_id in evidence_node_ids
        if (node := nodes.get(node_id)) is not None
        and node.kind == GraphNodeKind.ACKNOWLEDGEMENT_BOUNDARY
    }
    acknowledgement_ids.update(
        observation.acknowledgement_failure.acknowledgement_node_id
        for observation in result.request_observations
        if isinstance(observation, ScenarioRequestObservation)
        and observation.acknowledgement_failure is not None
    )
    ingress = nodes.get(instance.ingress_node_id) if instance.ingress_node_id is not None else None
    return CheckTargetReference(
        ingress_node_id=instance.ingress_node_id,
        route_registration_id=instance.route_registration_id,
        ingress_symbol_id=ingress.backing_symbol_id if ingress is not None else None,
        normal_control_id=result.authority.normal_control_id,
        customer_value_node_id=(
            identity_control.customer_value_node_id if identity_control is not None else None
        ),
        customer_value_symbol_id=(
            identity_control.customer_value_symbol_id if identity_control is not None else None
        ),
        connectivity_edge_id=(
            identity_control.connectivity_edge_id if identity_control is not None else None
        ),
        mutation_node_ids=tuple(sorted(mutation_ids)),
        acknowledgement_node_ids=tuple(sorted(acknowledgement_ids)),
    )


def _source_references(
    source_index: SourceIndexArtifact,
    graph: PaymentSafetyGraphArtifact,
    node_ids: set[GraphNodeId],
) -> tuple[SourceEvidenceReference, ...]:
    nodes = {item.node_id: item for item in graph.nodes}
    symbols = {item.symbol_id: item for item in source_index.symbols}
    symbol_ids: set[SymbolId] = {
        node.backing_symbol_id
        for node_id in node_ids
        if (node := nodes.get(node_id)) is not None and node.backing_symbol_id is not None
    }
    result = tuple(
        SourceEvidenceReference(
            symbol_id=symbol_id, source_location=symbols[symbol_id].source_location
        )
        for symbol_id in symbol_ids
        if symbol_id in symbols
    )
    return tuple(sorted(result, key=canonical_json))


def build_finding_relevant_authority_snapshot(
    *,
    repository_root: Path,
    source_index: SourceIndexArtifact,
    graph: PaymentSafetyGraphArtifact,
    applicability: ScenarioApplicabilityArtifact,
    assertion: AssertionApplicability,
    targets: CheckTargetReference,
    source_references: tuple[SourceEvidenceReference, ...],
    graph_node_ids: tuple[GraphNodeId, ...],
    graph_edge_ids: tuple[GraphEdgeId, ...],
    key_policy_dimensions: tuple[PolicyDimension, ...],
    policy_authority: CheckPolicyAuthority,
    invariant_id: str,
    invariant_version: int,
    scenario_definition_fingerprint: str,
    rule_ids: tuple[RazorpayProtocolRuleId, ...],
    semantic: SemanticAuthoritySnapshot,
) -> FindingRelevantAuthoritySnapshot:
    """Capture exact check facts without persisting merchant source content."""

    files = {item.file_id: item for item in source_index.indexed_files}
    symbols = {item.symbol_id: item for item in source_index.symbols}
    referenced_symbol_ids = {item.symbol_id for item in source_references}
    referenced_symbol_ids.update(
        symbol_id
        for symbol_id in (targets.ingress_symbol_id, targets.customer_value_symbol_id)
        if symbol_id is not None
    )
    source_file_ids = {
        symbols[symbol_id].source_file_id
        for symbol_id in referenced_symbol_ids
        if symbol_id in symbols
    }
    relevant_call_sites = tuple(
        item
        for item in source_index.call_sites
        if item.caller_symbol_id in referenced_symbol_ids
        or item.callee_symbol_id in referenced_symbol_ids
    )

    def source_span_fingerprint(path: str, line_start: int, line_end: int) -> str:
        raw = (repository_root / path).read_bytes()
        lines = raw.splitlines(keepends=True)
        if line_start < 1 or line_end < line_start or line_end > len(lines):
            raise ValueError("finding-relevant source span is unavailable")
        return sha256_digest(b"".join(lines[line_start - 1 : line_end]))

    symbol_fact_fingerprints = {
        symbol_id: fingerprint_json(
            {
                "symbol_id": symbol.symbol_id,
                "source_file_id": symbol.source_file_id,
                "qualified_name": symbol.qualified_name,
                "kind": symbol.kind,
                "signature": symbol.signature,
                "definition_ordinal": symbol.definition_ordinal,
                "definition_content_fingerprint": source_span_fingerprint(
                    symbol.source_location.path,
                    symbol.source_location.line_start,
                    symbol.source_location.line_end,
                ),
            }
        )
        for symbol_id, symbol in symbols.items()
        if symbol_id in referenced_symbol_ids
    }
    nodes = {item.node_id: item for item in graph.nodes}
    edges = {item.edge_id: item for item in graph.edges}

    def graph_fact_fingerprint(record: PersistedArtifactModel) -> str:
        payload = record.model_dump(mode="json")
        for provenance in payload.get("provenance", []):
            # Full Source Index fingerprints and line positions are upstream drift
            # diagnostics, not graph-fact semantics. Exact source facts are captured
            # independently by this same relevance snapshot.
            provenance.pop("source_location", None)
            provenance.pop("supporting_fingerprint", None)
        return fingerprint_json(payload)

    control = next(
        (
            item
            for item in applicability.normal_controls
            if item.control_id == targets.normal_control_id
        ),
        None,
    )
    keyed_policy = CheckPolicyAuthority(
        dimensions=key_policy_dimensions,
        fulfilment=(
            policy_authority.fulfilment
            if PolicyDimension.FULFILMENT in key_policy_dimensions
            else None
        ),
        fulfilment_evidence_fingerprint=(
            policy_authority.fulfilment_evidence_fingerprint
            if PolicyDimension.FULFILMENT in key_policy_dimensions
            else None
        ),
        late_authorisation=(
            policy_authority.late_authorisation
            if PolicyDimension.LATE_AUTHORISATION in key_policy_dimensions
            else None
        ),
        late_authorisation_evidence_fingerprint=(
            policy_authority.late_authorisation_evidence_fingerprint
            if PolicyDimension.LATE_AUTHORISATION in key_policy_dimensions
            else None
        ),
    )
    payload: dict[str, object] = {
        "source_files": tuple(
            sorted(
                (
                    RelevantSourceFileAuthority(
                        file_id=files[file_id].file_id,
                        path=files[file_id].path,
                        content_fingerprint=files[file_id].content_fingerprint,
                    )
                    for file_id in source_file_ids
                    if file_id in files
                ),
                key=canonical_json,
            )
        ),
        "symbols": tuple(
            sorted(
                (
                    RelevantFactAuthority(
                        fact_id=symbol_id,
                        fact_fingerprint=symbol_fact_fingerprints[symbol_id],
                    )
                    for symbol_id in referenced_symbol_ids
                    if symbol_id in symbols
                ),
                key=canonical_json,
            )
        ),
        "call_sites": tuple(
            sorted(
                {
                    RelevantFactAuthority(
                        fact_id=fingerprint_json(
                            {
                                "caller_symbol_id": item.caller_symbol_id,
                                "callee_symbol_id": item.callee_symbol_id,
                                "callee_reference": item.callee_reference,
                                "content_fingerprint": source_span_fingerprint(
                                    item.source_location.path,
                                    item.source_location.line_start,
                                    item.source_location.line_end,
                                ),
                            }
                        ),
                        fact_fingerprint=fingerprint_json(
                            {
                                "caller_symbol_id": item.caller_symbol_id,
                                "callee_symbol_id": item.callee_symbol_id,
                                "callee_reference": item.callee_reference,
                                "content_fingerprint": source_span_fingerprint(
                                    item.source_location.path,
                                    item.source_location.line_start,
                                    item.source_location.line_end,
                                ),
                            }
                        ),
                    )
                    for item in relevant_call_sites
                },
                key=canonical_json,
            )
        ),
        "call_path_references": (
            tuple(sorted(set(control.call_path_references))) if control is not None else ()
        ),
        "graph_nodes": tuple(
            sorted(
                (
                    RelevantFactAuthority(
                        fact_id=node_id,
                        fact_fingerprint=graph_fact_fingerprint(nodes[node_id]),
                    )
                    for node_id in graph_node_ids
                    if node_id in nodes
                ),
                key=canonical_json,
            )
        ),
        "graph_edges": tuple(
            sorted(
                (
                    RelevantFactAuthority(
                        fact_id=edge_id,
                        fact_fingerprint=graph_fact_fingerprint(edges[edge_id]),
                    )
                    for edge_id in graph_edge_ids
                    if edge_id in edges
                ),
                key=canonical_json,
            )
        ),
        "applicability_assertion_fingerprint": fingerprint_json(assertion),
        "selected_semantic_symbol_id": semantic.selected_symbol_id,
        "semantic_resolution_fingerprint": semantic.resolution_fingerprint,
        "semantic_context_fingerprint": semantic.semantic_context_fingerprint,
        "key_policy_authority": keyed_policy,
        "invariant_id": invariant_id,
        "invariant_version": invariant_version,
        "scenario_definition_fingerprint": scenario_definition_fingerprint,
        "razorpay_rules": tuple(
            sorted(
                (
                    RelevantFactAuthority(
                        fact_id=rule_id.value,
                        fact_fingerprint=razorpay_rule_fingerprint(rule_id),
                    )
                    for rule_id in rule_ids
                ),
                key=canonical_json,
            )
        ),
        "razorpay_rule_catalog_fingerprint": razorpay_rule_catalog_fingerprint(),
    }
    return FindingRelevantAuthoritySnapshot(
        **payload,
        relevant_authority_fingerprint=fingerprint_json(payload),
    )


def current_scenario_definition_fingerprint(scenario_id: ScenarioId) -> str:
    """Return the canonical implementation fingerprint used by current verification."""

    return _SCENARIO_DEFINITION_FINGERPRINTS[scenario_id]


def _request_projection(
    result: ScenarioExecutionResult,
    roles: tuple[object, ...],
) -> tuple[RuntimeRequestEvidence, ...]:
    if len(result.request_observations) > len(roles):
        raise ValueError("scenario result has more requests than its assertion definition")
    projected: list[RuntimeRequestEvidence] = []
    for ordinal, observation in enumerate(result.request_observations):
        role = roles[ordinal]
        if isinstance(observation, ScenarioRequestObservation):
            summary = observation.observations
            customer = CustomerRuntimeEvidence(
                entered_count=summary.entered_count,
                returned_normally_count=summary.returned_normally_count,
                exception_escaped_count=summary.exception_escaped_count,
                entered_sequences=summary.entered_sequences,
                returned_normally_sequences=summary.returned_normally_sequences,
                exception_escaped_sequences=summary.exception_escaped_sequences,
            )
            acknowledgement = (
                AcknowledgementInjectionEvidence(
                    acknowledgement_node_id=(
                        observation.acknowledgement_failure.acknowledgement_node_id
                    ),
                    original_status_code=observation.acknowledgement_failure.original_status_code,
                    effective_status_code=observation.acknowledgement_failure.effective_status_code,
                    injection_sequence=observation.acknowledgement_failure.injection_sequence,
                )
                if observation.acknowledgement_failure is not None
                else None
            )
            projected.append(
                RuntimeRequestEvidence(
                    request_id=observation.request_id,
                    ordinal=ordinal,
                    role=role,
                    request_received_sequences=summary.request_received_sequences,
                    response_completed_sequences=summary.response_completed_sequences,
                    request_aborted_sequences=summary.request_aborted_sequences,
                    http_status_code=summary.http_status_code,
                    customer=customer,
                    acknowledgement_injection=acknowledgement,
                )
            )
        else:
            projected.append(
                RuntimeRequestEvidence(
                    request_id=observation.request_id,
                    ordinal=ordinal,
                    role=role,
                    request_received_sequences=observation.request_received_sequences,
                    response_completed_sequences=observation.response_completed_sequences,
                    request_aborted_sequences=observation.request_aborted_sequences,
                    http_status_code=observation.http_status_code,
                    mutations=tuple(
                        MutationRuntimeEvidence(
                            mutation_node_id=item.mutation_node_id,
                            reached_count=item.reached_count,
                            completed_normally_count=item.completed_normally_count,
                            raised_count=item.raised_count,
                            reached_sequences=item.reached_sequences,
                            completed_normally_sequences=item.completed_normally_sequences,
                            raised_sequences=item.raised_sequences,
                        )
                        for item in observation.mutation_targets
                    ),
                )
            )
    return tuple(projected)


def _check_policy(
    definition_dimensions: tuple[PolicyDimension, ...],
    applicability: ScenarioApplicabilityArtifact,
) -> CheckPolicyAuthority:
    policy = applicability.policy
    return CheckPolicyAuthority(
        dimensions=definition_dimensions,
        fulfilment=(
            policy.fulfilment.confirmed_policy
            if PolicyDimension.FULFILMENT in definition_dimensions
            else None
        ),
        fulfilment_evidence_fingerprint=(
            policy.fulfilment.evidence_fingerprint
            if PolicyDimension.FULFILMENT in definition_dimensions
            else None
        ),
        late_authorisation=(
            policy.late_authorisation.confirmed_policy
            if PolicyDimension.LATE_AUTHORISATION in definition_dimensions
            else None
        ),
        late_authorisation_evidence_fingerprint=(
            policy.late_authorisation.evidence_fingerprint
            if PolicyDimension.LATE_AUTHORISATION in definition_dimensions
            else None
        ),
    )


def _policy_snapshot(applicability: ScenarioApplicabilityArtifact) -> PolicyAuthoritySnapshot:
    policy = applicability.policy
    return PolicyAuthoritySnapshot(
        fulfilment=policy.fulfilment.confirmed_policy,
        fulfilment_evidence_fingerprint=policy.fulfilment.evidence_fingerprint,
        fulfilment_evidence_current=policy.fulfilment.evidence_current,
        late_authorisation=policy.late_authorisation.confirmed_policy,
        late_authorisation_evidence_fingerprint=(policy.late_authorisation.evidence_fingerprint),
        late_authorisation_evidence_current=policy.late_authorisation.evidence_current,
    )


def _semantic_snapshot(
    resolution: CustomerValueResolution | None,
    resolution_fingerprint: str | None,
    semantic_artifact: CustomerValueSemanticArtifact | None,
    config: StateGuardConfig,
    graph: PaymentSafetyGraphArtifact,
) -> SemanticAuthoritySnapshot:
    selected = resolution.selected_symbol_id if resolution is not None else None
    selected_nodes = tuple(
        node
        for node in graph.nodes
        if node.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION and node.backing_symbol_id == selected
    )
    provenance = tuple(
        SemanticProvenanceSnapshot(
            kind=record.kind,
            source_location=record.source_location,
            supporting_fingerprint=record.supporting_fingerprint,
        )
        for node in selected_nodes
        for record in node.provenance
    )
    configured_context = (
        config.semantics.customer_value.semantic_context_fingerprint
        if config.semantics is not None and config.semantics.customer_value is not None
        else None
    )
    return SemanticAuthoritySnapshot(
        state=resolution.state if resolution is not None else None,
        basis=resolution.basis if resolution is not None else None,
        selected_symbol_id=selected,
        resolution_fingerprint=resolution_fingerprint,
        semantic_context_fingerprint=(
            semantic_artifact.semantic_context_fingerprint
            if semantic_artifact is not None
            else configured_context
        ),
        selected_target_provenance=provenance,
    )


def _rule_snapshot(
    rule_ids: set[RazorpayProtocolRuleId],
) -> RazorpayRuleAuthoritySnapshot:
    facts = {item.rule_id: item for item in RAZORPAY_PROTOCOL_FACTS}
    selected = tuple(sorted(rule_ids, key=str))
    return RazorpayRuleAuthoritySnapshot(
        catalog_version=RAZORPAY_RULE_CATALOG_VERSION,
        catalog_fingerprint=razorpay_rule_catalog_fingerprint(),
        referenced_rules=tuple(
            RazorpayRuleSnapshot(
                rule_id=rule_id,
                fact=facts[rule_id].fact,
                source_url=facts[rule_id].source_url,
                verified_on=facts[rule_id].verified_on,
                rule_fingerprint=razorpay_rule_fingerprint(rule_id),
            )
            for rule_id in selected
        ),
    )


def build_verification_run(
    *,
    repository_root: Path,
    run_id: VerificationRunId,
    created_at: datetime,
    completed_at: datetime,
    config: StateGuardConfig,
    source_index: SourceIndexArtifact,
    structural_graph: PaymentSafetyGraphArtifact,
    projected_graph: PaymentSafetyGraphArtifact,
    semantic_artifact: CustomerValueSemanticArtifact | None,
    resolution: CustomerValueResolution | None,
    resolution_fingerprint: str | None,
    applicability: ScenarioApplicabilityArtifact,
    results: Iterable[ScenarioExecutionResult],
    razorpay_grounding: RazorpayGroundingSnapshot | None = None,
) -> VerificationRun:
    """Normalize exact Step 4/6 authority without recalculating any verdict."""

    if source_index.project_id != applicability.project_id:
        raise ValueError("verification authority refers to different projects")
    if source_index.source_index_fingerprint != applicability.source_index_fingerprint:
        raise ValueError("verification applicability has stale source authority")
    if structural_graph.graph_fingerprint != applicability.structural_graph_fingerprint:
        raise ValueError("verification applicability has stale structural graph authority")
    if projected_graph.graph_fingerprint != applicability.projected_graph_fingerprint:
        raise ValueError("verification applicability has stale projected graph authority")

    assertion_authorities = _assertion_authorities(applicability)
    result_authorities = _execution_results(results)
    if set(assertion_authorities) != set(result_authorities):
        missing = set(assertion_authorities) - set(result_authorities)
        foreign = set(result_authorities) - set(assertion_authorities)
        raise ValueError(
            f"scenario results must map one-to-one to applicability assertions "
            f"(missing={len(missing)}, foreign={len(foreign)})"
        )

    policy_snapshot = _policy_snapshot(applicability)
    semantic_snapshot = _semantic_snapshot(
        resolution,
        resolution_fingerprint,
        semantic_artifact,
        config,
        projected_graph,
    )
    checks: list[VerificationCheck] = []
    for key, (instance, assertion) in assertion_authorities.items():
        scenario_id, instance_id, _ = key
        result = result_authorities[key]
        if result.authority.applicability_fingerprint != applicability.applicability_fingerprint:
            raise ValueError("scenario result has foreign applicability authority")
        if result.scenario_definition_fingerprint != _SCENARIO_DEFINITION_FINGERPRINTS[scenario_id]:
            raise ValueError("scenario result has foreign invariant-definition authority")
        definition = assertion_definition(scenario_id, assertion.key)
        targets = _target_reference(
            applicability=applicability,
            instance=instance,
            assertion=assertion,
            result=result,
            graph=projected_graph,
        )
        applicability_evidence = _applicability_projection(assertion)
        graph_node_ids = {
            *applicability_evidence.graph_node_ids,
            *targets.mutation_node_ids,
            *targets.acknowledgement_node_ids,
        }
        for node_id in (
            targets.ingress_node_id,
            targets.customer_value_node_id,
        ):
            if node_id is not None:
                graph_node_ids.add(node_id)
        graph_edge_ids = set(applicability_evidence.graph_edge_ids)
        if targets.connectivity_edge_id is not None:
            graph_edge_ids.add(targets.connectivity_edge_id)
        runtime_requests = _request_projection(result, definition.request_roles)
        if tuple(item.request_id for item in runtime_requests) != tuple(
            item.request_id for item in result.request_observations
        ):
            raise ValueError("runtime evidence projection changed request identity")
        policy_authority = _check_policy(definition.policy_authority, applicability)
        stable_key = build_verification_check_key(
            project_id=applicability.project_id,
            scenario_id=scenario_id,
            assertion_key=assertion.key,
            invariant_id=definition.invariant_id,
            invariant_version=definition.invariant_version,
            targets=targets,
            key_policy_dimensions=definition.key_policy_dimensions,
            policy=policy_snapshot,
        )
        input_reference = result.input_reference
        check_grounding = None
        evidence_tier = result.evidence_tier
        if isinstance(input_reference, GroundedScenarioInputReference):
            if (
                scenario_id != ScenarioId.SG_01
                or razorpay_grounding is None
                or razorpay_grounding.status != RazorpayGroundingStatus.GROUNDED
                or razorpay_grounding.grounding_fingerprint != input_reference.grounding_fingerprint
                or razorpay_grounding.sanitized_projection_fingerprint
                != input_reference.sanitized_projection_fingerprint
            ):
                raise ValueError("grounded scenario input has no matching run grounding authority")
            if result.evidence_tier == EvidenceTier.E3_DYNAMIC_VERIFIED:
                evidence_tier = EvidenceTier.E4_RAZORPAY_GROUNDED
                check_grounding = CheckGroundingEvidence(
                    grounding_fingerprint=razorpay_grounding.grounding_fingerprint,
                    sanitized_projection_fingerprint=(
                        input_reference.sanitized_projection_fingerprint
                    ),
                )
        source_references = _source_references(source_index, projected_graph, graph_node_ids)
        ordered_graph_node_ids = tuple(sorted(graph_node_ids))
        ordered_graph_edge_ids = tuple(sorted(graph_edge_ids))
        checks.append(
            VerificationCheck(
                check_id=verification_check_id(run_id, instance_id, assertion.assertion_id),
                check_key=stable_key,
                scenario_id=scenario_id,
                scenario_instance_id=instance_id,
                assertion_id=assertion.assertion_id,
                assertion_key=assertion.key,
                invariant_id=definition.invariant_id,
                invariant_version=definition.invariant_version,
                expected_invariant=definition.expected_invariant,
                scenario_definition_fingerprint=result.scenario_definition_fingerprint,
                scenario_result_fingerprint=result.result_fingerprint,
                applicability=applicability_evidence,
                targets=targets,
                policy_authority=policy_authority,
                key_policy_dimensions=definition.key_policy_dimensions,
                razorpay_rule_ids=definition.razorpay_rule_ids,
                source_references=source_references,
                graph_node_ids=ordered_graph_node_ids,
                graph_edge_ids=ordered_graph_edge_ids,
                input_reference=input_reference,
                runtime_evidence=RuntimeEvidenceProjection(
                    scenario_execution_id=result.execution_id,
                    runtime_session_id=result.authority.runtime_session_id,
                    runtime_capability_fingerprint=(
                        result.authority.runtime_capability_fingerprint
                    ),
                    transcript_fingerprint=result.authority.transcript_fingerprint,
                    requests=runtime_requests,
                    diagnostics=result.runtime_diagnostics,
                ),
                result=result.result,
                evidence_tier=evidence_tier,
                grounding=check_grounding,
                reason=result.reason,
                reverification=ReverificationReference(
                    scenario_id=scenario_id,
                    assertion_key=assertion.key,
                    invariant_id=definition.invariant_id,
                    invariant_version=definition.invariant_version,
                    targets=targets,
                    input_reference=input_reference,
                    config_fingerprint=fingerprint_json(config),
                    project_source_fingerprint=source_index.project_source_fingerprint,
                    projected_graph_fingerprint=projected_graph.graph_fingerprint,
                    applicability_fingerprint=applicability.applicability_fingerprint,
                    razorpay_rule_catalog_fingerprint=razorpay_rule_catalog_fingerprint(),
                ),
                relevant_authority=build_finding_relevant_authority_snapshot(
                    repository_root=repository_root,
                    source_index=source_index,
                    graph=projected_graph,
                    applicability=applicability,
                    assertion=assertion,
                    targets=targets,
                    source_references=source_references,
                    graph_node_ids=ordered_graph_node_ids,
                    graph_edge_ids=ordered_graph_edge_ids,
                    key_policy_dimensions=definition.key_policy_dimensions,
                    policy_authority=policy_authority,
                    invariant_id=definition.invariant_id,
                    invariant_version=definition.invariant_version,
                    scenario_definition_fingerprint=result.scenario_definition_fingerprint,
                    rule_ids=definition.razorpay_rule_ids,
                    semantic=semantic_snapshot,
                ),
            )
        )

    checks_tuple = tuple(
        sorted(
            checks,
            key=lambda item: (
                int(item.scenario_id.value.removeprefix("SG-")),
                item.scenario_instance_id,
                assertion_order(item.scenario_id, item.assertion_key),
            ),
        )
    )
    runtime_fingerprints = tuple(
        sorted(
            {
                item.runtime_evidence.runtime_capability_fingerprint
                for item in checks_tuple
                if item.runtime_evidence.runtime_capability_fingerprint is not None
            }
        )
    )
    rule_ids = {rule for check in checks_tuple for rule in check.razorpay_rule_ids}
    runtime_config = config.runtime or StaticRuntimeConfig()
    authority = VerificationAuthoritySnapshot(
        project_id=source_index.project_id,
        config_fingerprint=fingerprint_json(config),
        project_source_fingerprint=source_index.project_source_fingerprint,
        source_index_fingerprint=source_index.source_index_fingerprint,
        structural_graph_fingerprint=structural_graph.graph_fingerprint,
        projected_graph_fingerprint=projected_graph.graph_fingerprint,
        applicability_fingerprint=applicability.applicability_fingerprint,
        runtime_config_fingerprint=fingerprint_json(runtime_config),
        runtime_capability_fingerprints=runtime_fingerprints,
        semantic=semantic_snapshot,
        policy=policy_snapshot,
        razorpay_rules=_rule_snapshot(rule_ids),
        razorpay_grounding=razorpay_grounding,
        schema_versions=ComponentSchemaVersions(
            razorpay_grounding=1 if razorpay_grounding is not None else None
        ),
    )
    findings = derive_findings(run_id, checks_tuple)
    summary = summarize_checks(checks_tuple)
    payload = verification_run_fingerprint_payload(
        schema_version=3,
        producer_version=__version__,
        generated_at=completed_at,
        run_id=run_id,
        status=VerificationRunStatus.COMPLETED,
        created_at=created_at,
        completed_at=completed_at,
        authority=authority,
        checks=checks_tuple,
        findings=findings,
        summary=summary,
    )
    return VerificationRun(
        **payload,
        run_fingerprint=fingerprint_json(payload),
    )
