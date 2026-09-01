"""Application service for deterministic Payment Safety Graph construction."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TypeAlias, TypeVar

from stateguard import __version__
from stateguard.contracts.common import ProvenanceKind, ProvenanceRecord, SourceLocation, SymbolId
from stateguard.contracts.identity import (
    canonical_json,
    graph_edge_id,
    graph_node_id,
    structural_anchor,
)
from stateguard.discovery.contracts import ArtifactCompleteness, CallSiteRecord, SourceIndexArtifact
from stateguard.discovery.service import validate_indexed_source_snapshot
from stateguard.graph.contracts import (
    AcknowledgementBoundaryDetails,
    BranchDisposition,
    EventIdentityGuardDetails,
    GraphBranchDetails,
    GraphCandidateKind,
    GraphDiagnosticCode,
    GraphDiagnosticImpact,
    GraphDiagnosticReason,
    GraphDiagnosticRecord,
    GraphEdge,
    GraphEdgeKind,
    GraphNode,
    GraphNodeKind,
    MerchantStateMutationDetails,
    PaymentIngressDetails,
    PaymentSafetyGraphArtifact,
    PaymentStateGateDetails,
    TrustGateDetails,
    graph_completeness_for,
    graph_fingerprint,
)
from stateguard.graph.control_flow import (
    StatementContext,
    branch_controls,
    context_dominates,
    parse_indexed_functions,
)
from stateguard.graph.reachability import ReachableRoute, compose_effective_routes
from stateguard.graph.recognizers import (
    AcknowledgementFact,
    EventIdentityFact,
    MutationFact,
    RouteConceptAnalysis,
    StateGateFact,
    TrustFact,
    analyze_route_concepts,
    unselected_route_candidate_diagnostics,
)

T = TypeVar("T")
RecognizedFact: TypeAlias = (
    TrustFact | EventIdentityFact | StateGateFact | MutationFact | AcknowledgementFact
)


def _ordered(records: list[T] | tuple[T, ...]) -> tuple[T, ...]:
    return tuple(sorted(records, key=canonical_json))


def _provenance(
    source_index: SourceIndexArtifact,
    reference: str,
    location: SourceLocation | None,
) -> ProvenanceRecord:
    return ProvenanceRecord(
        kind=ProvenanceKind.STATIC,
        reference=reference,
        source_location=location,
        supporting_fingerprint=source_index.source_index_fingerprint,
    )


def _node_provenance(
    source_index: SourceIndexArtifact,
    route: ReachableRoute,
    symbol_id: SymbolId,
    location: SourceLocation,
    rule_id: str,
    anchor: str,
    call_path: tuple[CallSiteRecord, ...] = (),
) -> tuple[ProvenanceRecord, ...]:
    records = [
        _provenance(
            source_index,
            f"route-registration:{route.registration.route_registration_id}",
            route.route_location,
        ),
        _provenance(source_index, f"symbol:{symbol_id}", location),
        _provenance(source_index, f"ast-fact:{rule_id}:node:{anchor}", location),
    ]
    records.extend(
        _provenance(
            source_index,
            _call_site_reference(source_index, item),
            item.source_location,
        )
        for item in call_path
    )
    return _ordered(records)


def _call_site_reference(
    source_index: SourceIndexArtifact,
    call_site: CallSiteRecord,
) -> str:
    peers = sorted(
        (
            item
            for item in source_index.call_sites
            if item.caller_symbol_id == call_site.caller_symbol_id
            and item.callee_symbol_id == call_site.callee_symbol_id
            and item.callee_reference == call_site.callee_reference
        ),
        key=lambda item: canonical_json(item.source_location),
    )
    ordinal = next(
        index
        for index, item in enumerate(peers)
        if item.source_location == call_site.source_location
    )
    return f"call-site:{call_site.caller_symbol_id}:{ordinal}"


def _ingress_node(
    source_index: SourceIndexArtifact,
    route: ReachableRoute,
    analysis: RouteConceptAnalysis,
) -> GraphNode:
    assert analysis.ingress_kind is not None
    node_id = graph_node_id(
        GraphNodeKind.PAYMENT_INGRESS.value,
        route.owner_symbol_id,
        f"{route.registration.route_registration_id}:{analysis.ingress_kind.value}",
    )
    provenance = [
        _provenance(
            source_index,
            f"route-registration:{route.registration.route_registration_id}",
            route.route_location,
        ),
        _provenance(source_index, f"symbol:{route.owner_symbol_id}", route.route_location),
    ]
    provenance.extend(
        _provenance(
            source_index,
            (
                "ast-fact:FASTAPI_ROUTER_INCLUDE:registration:"
                f"{structural_anchor(route.registration.route_registration_id, anchor, ordinal)}"
            ),
            location,
        )
        for ordinal, (location, anchor) in enumerate(
            zip(route.include_locations, route.include_anchors, strict=True)
        )
    )
    provenance.extend(
        _provenance(
            source_index,
            f"source-reference:ingress-evidence:{family}",
            route.route_location,
        )
        for family in analysis.evidence_families
    )
    return GraphNode(
        node_id=node_id,
        kind=GraphNodeKind.PAYMENT_INGRESS,
        label=(
            f"{analysis.ingress_kind.value} {route.registration.method} "
            f"{route.registration.effective_path}"
        ),
        backing_symbol_id=route.owner_symbol_id,
        details=PaymentIngressDetails(
            ingress_kind=analysis.ingress_kind,
            registration=route.registration,
            evidence_families=analysis.evidence_families,
            checkout_request_binding=analysis.checkout_request_binding,
        ),
        provenance=_ordered(provenance),
    )


def _trust_node(
    source_index: SourceIndexArtifact,
    route: ReachableRoute,
    fact: TrustFact,
    call_path: tuple[CallSiteRecord, ...],
) -> GraphNode:
    discriminator = (
        f"{route.registration.route_registration_id}:{fact.context.anchor}:{fact.trust_kind.value}"
    )
    rule_id = {
        "WEBHOOK_SIGNATURE_VERIFICATION": "SG-AST-WEBHOOK-SIGNATURE-001",
        "CHECKOUT_SIGNATURE_VERIFICATION": "SG-AST-CHECKOUT-SIGNATURE-001",
        "SERVER_ORDER_IDENTITY_BINDING": "SG-AST-SERVER-ORDER-BINDING-001",
    }[fact.trust_kind.value]
    return GraphNode(
        node_id=graph_node_id(GraphNodeKind.TRUST_GATE.value, fact.symbol_id, discriminator),
        kind=GraphNodeKind.TRUST_GATE,
        label=fact.trust_kind.value,
        backing_symbol_id=fact.symbol_id,
        details=TrustGateDetails(
            trust_kind=fact.trust_kind,
            route_registration_id=route.registration.route_registration_id,
            structural_anchor=fact.context.anchor,
            webhook_body_origin=fact.webhook_body_origin,
            order_identity_origin=fact.order_identity_origin,
        ),
        provenance=_node_provenance(
            source_index,
            route,
            fact.symbol_id,
            fact.location,
            rule_id,
            fact.context.anchor,
            call_path,
        ),
    )


def _event_node(
    source_index: SourceIndexArtifact,
    route: ReachableRoute,
    fact: EventIdentityFact,
    call_path: tuple[CallSiteRecord, ...],
) -> GraphNode:
    discriminator = f"{route.registration.route_registration_id}:{fact.context.anchor}"
    return GraphNode(
        node_id=graph_node_id(
            GraphNodeKind.EVENT_IDENTITY_GUARD.value, fact.symbol_id, discriminator
        ),
        kind=GraphNodeKind.EVENT_IDENTITY_GUARD,
        label="Webhook event identity guard",
        backing_symbol_id=fact.symbol_id,
        details=EventIdentityGuardDetails(
            route_registration_id=route.registration.route_registration_id,
            structural_anchor=fact.context.anchor,
            strategy=fact.strategy,
        ),
        provenance=_node_provenance(
            source_index,
            route,
            fact.symbol_id,
            fact.location,
            "SG-AST-EVENT-IDENTITY-GUARD-001",
            fact.context.anchor,
            call_path,
        ),
    )


def _state_node(
    source_index: SourceIndexArtifact,
    route: ReachableRoute,
    fact: StateGateFact,
    call_path: tuple[CallSiteRecord, ...],
) -> GraphNode:
    discriminator = f"{route.registration.route_registration_id}:{fact.context.anchor}"
    return GraphNode(
        node_id=graph_node_id(
            GraphNodeKind.PAYMENT_STATE_GATE.value, fact.symbol_id, discriminator
        ),
        kind=GraphNodeKind.PAYMENT_STATE_GATE,
        label=f"Payment state {fact.operator.value}: {', '.join(fact.states)}",
        backing_symbol_id=fact.symbol_id,
        details=PaymentStateGateDetails(
            route_registration_id=route.registration.route_registration_id,
            structural_anchor=fact.context.anchor,
            operator=fact.operator,
            states=fact.states,
        ),
        provenance=_node_provenance(
            source_index,
            route,
            fact.symbol_id,
            fact.location,
            "SG-AST-PAYMENT-STATE-GATE-001",
            fact.context.anchor,
            call_path,
        ),
    )


def _mutation_node(
    source_index: SourceIndexArtifact,
    route: ReachableRoute,
    fact: MutationFact,
    call_path: tuple[CallSiteRecord, ...],
) -> GraphNode:
    discriminator = (
        f"{route.registration.route_registration_id}:{fact.context.anchor}:{fact.carrier_reference}"
    )
    provenance = _node_provenance(
        source_index,
        route,
        fact.symbol_id,
        fact.location,
        "SG-AST-MERCHANT-MUTATION-001",
        fact.context.anchor,
        call_path,
    )
    return GraphNode(
        node_id=graph_node_id(
            GraphNodeKind.MERCHANT_STATE_MUTATION.value, fact.symbol_id, discriminator
        ),
        kind=GraphNodeKind.MERCHANT_STATE_MUTATION,
        label=f"Merchant payment state {fact.mutation_kind.value}",
        backing_symbol_id=fact.symbol_id,
        details=MerchantStateMutationDetails(
            route_registration_id=route.registration.route_registration_id,
            structural_anchor=fact.context.anchor,
            mutation_kind=fact.mutation_kind,
            carrier_reference=fact.carrier_reference,
            assigned_payment_state=fact.assigned_payment_state,
        ),
        provenance=_ordered(
            (
                *provenance,
                _provenance(
                    source_index,
                    (f"ast-fact:SG-AST-MERCHANT-CARRIER-001:carrier:{fact.carrier_reference}"),
                    fact.location,
                ),
            )
        ),
    )


def _ack_node(
    source_index: SourceIndexArtifact,
    route: ReachableRoute,
    fact: AcknowledgementFact,
) -> GraphNode:
    discriminator = f"{route.registration.route_registration_id}:{fact.anchor}"
    return GraphNode(
        node_id=graph_node_id(
            GraphNodeKind.ACKNOWLEDGEMENT_BOUNDARY.value,
            fact.symbol_id,
            discriminator,
        ),
        kind=GraphNodeKind.ACKNOWLEDGEMENT_BOUNDARY,
        label=f"Webhook acknowledgement {fact.outcome.value}",
        backing_symbol_id=fact.symbol_id,
        details=AcknowledgementBoundaryDetails(
            route_registration_id=route.registration.route_registration_id,
            structural_anchor=fact.anchor,
            exit_kind=fact.exit_kind,
            status_code=fact.status_code,
            outcome=fact.outcome,
        ),
        provenance=_node_provenance(
            source_index,
            route,
            fact.symbol_id,
            fact.location,
            "SG-AST-ACKNOWLEDGEMENT-001",
            fact.anchor,
        ),
    )


def _fact_context(fact: object) -> StatementContext | None:
    return getattr(fact, "context", None)


def _edge_provenance(
    source_index: SourceIndexArtifact,
    reference: str,
    location: SourceLocation,
    call_path: tuple[CallSiteRecord, ...] = (),
) -> tuple[ProvenanceRecord, ...]:
    result = [_provenance(source_index, reference, location)]
    result.extend(
        _provenance(
            source_index,
            _call_site_reference(source_index, item),
            item.source_location,
        )
        for item in call_path
    )
    return _ordered(result)


def _append_edge(
    edges: list[GraphEdge],
    *,
    source_index: SourceIndexArtifact,
    kind: GraphEdgeKind,
    source_node: GraphNode,
    target_node: GraphNode,
    reference: str,
    location: SourceLocation,
    call_path: tuple[CallSiteRecord, ...] = (),
    branch: GraphBranchDetails | None = None,
) -> None:
    discriminator = canonical_json(branch) if branch is not None else ""
    relationship_anchor = structural_anchor(
        kind.value,
        source_node.node_id,
        target_node.node_id,
        reference,
        discriminator,
    )
    bounded_reference = f"{reference}:relationship:{relationship_anchor}"
    edge = GraphEdge(
        edge_id=graph_edge_id(
            kind.value,
            source_node.node_id,
            target_node.node_id,
            discriminator=discriminator,
        ),
        source_node_id=source_node.node_id,
        target_node_id=target_node.node_id,
        kind=kind,
        branch=branch,
        provenance=_edge_provenance(source_index, bounded_reference, location, call_path),
    )
    if edge.edge_id not in {item.edge_id for item in edges}:
        edges.append(edge)


def _construct_route_graph(
    source_index: SourceIndexArtifact,
    route: ReachableRoute,
    analysis: RouteConceptAnalysis,
) -> tuple[list[GraphNode], list[GraphEdge], list[GraphDiagnosticRecord]]:
    if analysis.ingress_kind is None:
        return [], [], list(analysis.diagnostics)
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    diagnostics = list(analysis.diagnostics)
    ingress = _ingress_node(source_index, route, analysis)
    nodes.append(ingress)

    fact_nodes: list[tuple[RecognizedFact, GraphNode]] = []
    for trust_fact in analysis.trust:
        node = _trust_node(
            source_index,
            route,
            trust_fact,
            analysis.call_paths[trust_fact.symbol_id],
        )
        nodes.append(node)
        fact_nodes.append((trust_fact, node))
    for identity_fact in analysis.event_identity:
        node = _event_node(
            source_index,
            route,
            identity_fact,
            analysis.call_paths[identity_fact.symbol_id],
        )
        nodes.append(node)
        fact_nodes.append((identity_fact, node))
    for state_fact in analysis.state_gates:
        node = _state_node(
            source_index,
            route,
            state_fact,
            analysis.call_paths[state_fact.symbol_id],
        )
        nodes.append(node)
        fact_nodes.append((state_fact, node))
    for mutation_fact in analysis.mutations:
        node = _mutation_node(
            source_index,
            route,
            mutation_fact,
            analysis.call_paths[mutation_fact.symbol_id],
        )
        nodes.append(node)
        fact_nodes.append((mutation_fact, node))
    for ack_fact in analysis.acknowledgements:
        node = _ack_node(source_index, route, ack_fact)
        nodes.append(node)
        fact_nodes.append((ack_fact, node))

    # Interprocedural orientation: ingress/caller concept -> reached concept.
    for fact, target_node in fact_nodes:
        symbol_id = fact.symbol_id
        call_path = analysis.call_paths.get(symbol_id, ())
        if symbol_id != route.owner_symbol_id and call_path:
            _append_edge(
                edges,
                source_index=source_index,
                kind=GraphEdgeKind.CALLS,
                source_node=ingress,
                target_node=target_node,
                reference="ast-fact:RESOLVED_MERCHANT_CALL_PATH",
                location=call_path[0].source_location,
                call_path=call_path,
            )

    guards = [
        (fact, node)
        for fact, node in fact_nodes
        if isinstance(fact, (TrustFact, EventIdentityFact))
    ]
    guarded_targets = [
        (fact, node)
        for fact, node in fact_nodes
        if isinstance(fact, (TrustFact, EventIdentityFact, StateGateFact, MutationFact))
    ]
    for guard_fact, guard_node in guards:
        for guard_target_fact, target_node in guarded_targets:
            if guard_node.node_id == target_node.node_id:
                continue
            guard_context = _fact_context(guard_fact)
            interprocedural = False
            if (
                isinstance(guard_fact, TrustFact)
                and guard_fact.symbol_id != guard_target_fact.symbol_id
                and guard_fact.route_guard_context is not None
                and guard_target_fact.symbol_id == route.owner_symbol_id
            ):
                guard_context = guard_fact.route_guard_context
                interprocedural = True
            target_context = _fact_context(guard_target_fact)
            if guard_context is None or target_context is None:
                continue
            if context_dominates(guard_context, target_context):
                _append_edge(
                    edges,
                    source_index=source_index,
                    kind=GraphEdgeKind.GUARDS,
                    source_node=guard_node,
                    target_node=target_node,
                    reference="ast-fact:CONTROL_DOMINANCE",
                    location=guard_fact.location,
                    call_path=(
                        analysis.call_paths.get(guard_fact.symbol_id, ()) if interprocedural else ()
                    ),
                )

    state_nodes = [(fact, node) for fact, node in fact_nodes if isinstance(fact, StateGateFact)]
    branch_targets = [
        (fact, node)
        for fact, node in fact_nodes
        if isinstance(
            fact,
            (TrustFact, EventIdentityFact, StateGateFact, MutationFact, AcknowledgementFact),
        )
    ]
    for state_fact, state_node in state_nodes:
        for branch_target_fact, target_node in branch_targets:
            if state_node.node_id == target_node.node_id:
                continue
            target_context = _fact_context(branch_target_fact)
            if target_context is None:
                continue
            branch = branch_controls(state_fact.context, target_context)
            if branch is None:
                continue
            details = GraphBranchDetails(
                disposition=branch.disposition,
                states=state_fact.states if branch.disposition == BranchDisposition.MATCHED else (),
            )
            _append_edge(
                edges,
                source_index=source_index,
                kind=GraphEdgeKind.BRANCHES_TO,
                source_node=state_node,
                target_node=target_node,
                reference="ast-fact:PAYMENT_STATE_BRANCH_CONTROL",
                location=state_fact.location,
                branch=details,
            )

    ack_nodes = [(fact, node) for fact, node in fact_nodes if isinstance(fact, AcknowledgementFact)]
    before_ack = [
        (fact, node)
        for fact, node in fact_nodes
        if isinstance(fact, (TrustFact, EventIdentityFact, StateGateFact, MutationFact))
    ]
    for ack_fact, ack_node in ack_nodes:
        for ack_target_fact, target_node in before_ack:
            target_context = _fact_context(ack_target_fact)
            if target_context is None:
                continue
            dominated = (
                ack_fact.context is not None and context_dominates(target_context, ack_fact.context)
            ) or (
                ack_fact.context is None
                and target_context.symbol_id == route.owner_symbol_id
                and not target_context.ancestors
            )
            if dominated:
                _append_edge(
                    edges,
                    source_index=source_index,
                    kind=GraphEdgeKind.ACKNOWLEDGES_AFTER,
                    source_node=ack_node,
                    target_node=target_node,
                    reference="ast-fact:EXIT_DOMINANCE",
                    location=ack_fact.location,
                )

    for guard_candidate_fact, _ in guards:
        if not isinstance(guard_candidate_fact, TrustFact):
            continue
        earlier_mutation = next(
            (
                mutation
                for mutation in analysis.mutations
                if mutation.symbol_id == guard_candidate_fact.symbol_id
                and mutation.location.line_start < guard_candidate_fact.location.line_start
            ),
            None,
        )
        if earlier_mutation is not None:
            diagnostics.append(
                GraphDiagnosticRecord(
                    code=GraphDiagnosticCode.UNRESOLVED_STRUCTURAL_CANDIDATE,
                    impact=GraphDiagnosticImpact.NOTICE,
                    candidate_kind=GraphCandidateKind.WEBHOOK_SIGNATURE,
                    reason=GraphDiagnosticReason.VALIDATION_AFTER_MUTATION,
                    symbol_id=guard_candidate_fact.symbol_id,
                    route_registration_id=route.registration.route_registration_id,
                    source_location=guard_candidate_fact.location,
                )
            )

    if any(
        context.in_loop for fact, _ in fact_nodes if (context := _fact_context(fact)) is not None
    ):
        diagnostics.append(
            GraphDiagnosticRecord(
                code=GraphDiagnosticCode.CONTROL_FLOW_UNSUPPORTED,
                impact=GraphDiagnosticImpact.COVERAGE_REDUCED,
                source_location=route.route_location,
            )
        )
    return nodes, edges, diagnostics


def _reachable_symbol_ids(
    source_index: SourceIndexArtifact,
    roots: set[SymbolId],
) -> set[SymbolId]:
    graph: dict[SymbolId, list[SymbolId]] = {}
    for call in source_index.call_sites:
        if call.callee_symbol_id is not None:
            graph.setdefault(call.caller_symbol_id, []).append(call.callee_symbol_id)
    result = set(roots)
    pending = list(roots)
    while pending:
        current = pending.pop()
        for callee in graph.get(current, []):
            if callee not in result:
                result.add(callee)
                pending.append(callee)
    return result


def construct_payment_safety_graph(
    repository_root: Path,
    source_index: SourceIndexArtifact,
    *,
    generated_at: datetime | None = None,
) -> PaymentSafetyGraphArtifact:
    timestamp = generated_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")
    validate_indexed_source_snapshot(repository_root, source_index)
    reachability = compose_effective_routes(source_index)
    diagnostics = list(reachability.diagnostics)
    if source_index.completeness == ArtifactCompleteness.PARTIAL:
        diagnostics.append(
            GraphDiagnosticRecord(
                code=GraphDiagnosticCode.UPSTREAM_SOURCE_INDEX_PARTIAL,
                impact=GraphDiagnosticImpact.COVERAGE_REDUCED,
            )
        )

    roots = {item.owner_symbol_id for item in reachability.routes}
    app_unselected = any(
        item.code == GraphDiagnosticCode.APP_TARGET_UNSELECTED for item in reachability.diagnostics
    )
    candidate_roots = (
        {item.owner_symbol_id for item in source_index.routes} if app_unselected else set()
    )
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    if roots or candidate_roots:
        parsed = parse_indexed_functions(
            repository_root,
            source_index,
            _reachable_symbol_ids(source_index, roots | candidate_roots),
        )
        for route in reachability.routes:
            analysis = analyze_route_concepts(route, source_index, parsed)
            route_nodes, route_edges, route_diagnostics = _construct_route_graph(
                source_index, route, analysis
            )
            nodes.extend(route_nodes)
            edges.extend(route_edges)
            diagnostics.extend(route_diagnostics)
        if app_unselected:
            diagnostics.extend(
                unselected_route_candidate_diagnostics(
                    source_index.routes,
                    source_index,
                    parsed,
                )
            )

    ordered_nodes = _ordered(nodes)
    ordered_edges = _ordered(edges)
    ordered_diagnostics = _ordered(diagnostics)
    completeness = graph_completeness_for(ordered_diagnostics)
    fingerprint = graph_fingerprint(
        project_id=source_index.project_id,
        source_index_fingerprint=source_index.source_index_fingerprint,
        completeness=completeness,
        diagnostics=ordered_diagnostics,
        nodes=ordered_nodes,
        edges=ordered_edges,
    )
    return PaymentSafetyGraphArtifact(
        producer_version=__version__,
        generated_at=timestamp,
        project_id=source_index.project_id,
        source_index_fingerprint=source_index.source_index_fingerprint,
        graph_fingerprint=fingerprint,
        completeness=completeness,
        diagnostics=ordered_diagnostics,
        nodes=ordered_nodes,
        edges=ordered_edges,
    )
