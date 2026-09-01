"""Deterministic projection of semantic identity onto the structural graph."""

from __future__ import annotations

import ast
from collections import defaultdict, deque
from pathlib import Path

from stateguard.contracts.common import ProvenanceKind, ProvenanceRecord, Sha256Digest, SymbolId
from stateguard.contracts.identity import canonical_json, graph_edge_id, graph_node_id
from stateguard.discovery.contracts import CallSiteRecord, SourceIndexArtifact, SymbolKind
from stateguard.semantics.contracts import (
    CustomerValueResolution,
    ResolutionBasis,
    ResolutionState,
)

from .contracts import (
    AcknowledgementBoundaryDetails,
    BranchDisposition,
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
    PaymentIngressDetails,
    PaymentSafetyGraphArtifact,
    PaymentStateGateDetails,
    graph_completeness_for,
    graph_fingerprint,
)
from .control_flow import (
    ParsedProject,
    StatementContext,
    branch_controls,
    context_dominates,
    parse_indexed_functions,
    source_location,
)
from .reachability import compose_effective_routes
from .recognizers import AcknowledgementFact, StateGateFact, analyze_route_concepts


def _semantic_call_edge_discriminator(
    provenance: tuple[ProvenanceRecord, ...],
) -> str:
    """Identify the exact resolved call-site path without semantic authority."""

    return canonical_json(tuple(record.reference for record in provenance))


def project_customer_value(
    structural_graph: PaymentSafetyGraphArtifact,
    source_index: SourceIndexArtifact,
    resolution: CustomerValueResolution,
    resolution_fingerprint: Sha256Digest,
    *,
    repository_root: Path | None = None,
) -> PaymentSafetyGraphArtifact:
    """Add semantic identity and only statically proven ingress connectivity."""

    if resolution.state != ResolutionState.UNIQUE or resolution.selected_symbol_id is None:
        return structural_graph
    selected = resolution.selected_symbol_id
    symbol = next((item for item in source_index.symbols if item.symbol_id == selected), None)
    if symbol is None:
        raise ValueError("semantic target does not exist in the current Source Index")
    route_owners = {item.owner_symbol_id for item in source_index.routes}
    eligible_kinds = {
        SymbolKind.FUNCTION,
        SymbolKind.ASYNC_FUNCTION,
        SymbolKind.METHOD,
        SymbolKind.ASYNC_METHOD,
    }
    if symbol.symbol_id in route_owners or symbol.kind not in eligible_kinds:
        raise ValueError("semantic target must be a non-route function or method")
    provenance_kind = (
        ProvenanceKind.AI_INFERRED
        if resolution.basis == ResolutionBasis.MODEL_UNIQUE
        else ProvenanceKind.HUMAN_CONFIRMED
    )
    node = GraphNode(
        node_id=graph_node_id(GraphNodeKind.CUSTOMER_VALUE_ACTION.value, selected),
        kind=GraphNodeKind.CUSTOMER_VALUE_ACTION,
        label=symbol.qualified_name,
        backing_symbol_id=selected,
        provenance=(
            ProvenanceRecord(
                kind=provenance_kind,
                reference=f"customer-value-resolution:{resolution.basis.value}",
                source_location=symbol.source_location,
                supporting_fingerprint=resolution_fingerprint,
            ),
        ),
    )
    nodes = tuple(
        item for item in structural_graph.nodes if item.kind != GraphNodeKind.CUSTOMER_VALUE_ACTION
    ) + (node,)
    retained_node_ids = {item.node_id for item in nodes}
    edges = [
        item
        for item in structural_graph.edges
        if item.source_node_id in retained_node_ids and item.target_node_id in retained_node_ids
    ]
    ingress_nodes = sorted(
        (item for item in nodes if item.kind == GraphNodeKind.PAYMENT_INGRESS),
        key=lambda item: item.node_id,
    )
    for ingress in ingress_nodes:
        assert ingress.backing_symbol_id is not None
        path = _resolved_path(source_index, ingress.backing_symbol_id, selected)
        if path is None:
            continue
        provenance = tuple(
            ProvenanceRecord(
                kind=ProvenanceKind.STATIC,
                reference=_call_site_reference(source_index, item),
                source_location=item.source_location,
                supporting_fingerprint=source_index.source_index_fingerprint,
            )
            for item in path
        )
        if not provenance:
            continue
        edges.append(
            GraphEdge(
                edge_id=graph_edge_id(
                    GraphEdgeKind.CALLS.value,
                    ingress.node_id,
                    node.node_id,
                    # Structural identity is the stable ingress, selected
                    # symbol, and exact resolved call-site path. Semantic
                    # authority remains in node provenance and therefore in
                    # the projected graph fingerprint/currentness contract.
                    discriminator=_semantic_call_edge_discriminator(provenance),
                ),
                source_node_id=ingress.node_id,
                target_node_id=node.node_id,
                kind=GraphEdgeKind.CALLS,
                provenance=provenance,
            )
        )
    ordered_nodes = tuple(sorted(nodes, key=canonical_json))
    ordered_edges = tuple(sorted(edges, key=canonical_json))
    diagnostics = structural_graph.diagnostics
    if repository_root is not None:
        ordered_edges, diagnostics = _project_control_relationships(
            repository_root,
            source_index,
            ordered_nodes,
            ordered_edges,
            diagnostics,
            node,
            selected,
        )
    completeness = graph_completeness_for(diagnostics)
    fingerprint = graph_fingerprint(
        project_id=structural_graph.project_id,
        source_index_fingerprint=structural_graph.source_index_fingerprint,
        completeness=completeness,
        diagnostics=diagnostics,
        nodes=ordered_nodes,
        edges=ordered_edges,
    )
    return PaymentSafetyGraphArtifact(
        producer_version=structural_graph.producer_version,
        generated_at=structural_graph.generated_at,
        project_id=structural_graph.project_id,
        source_index_fingerprint=structural_graph.source_index_fingerprint,
        graph_fingerprint=fingerprint,
        completeness=completeness,
        diagnostics=diagnostics,
        nodes=ordered_nodes,
        edges=ordered_edges,
    )


def _call_context(
    parsed: ParsedProject,
    call_site: CallSiteRecord,
) -> StatementContext | None:
    model = parsed.functions.get(call_site.caller_symbol_id)
    if model is None:
        return None
    node = next(
        (
            item
            for item in ast.walk(model.function)
            if isinstance(item, ast.Call)
            and max(getattr(item, "lineno", 1), 1) == call_site.source_location.line_start
            and max(getattr(item, "col_offset", 0), 0) == call_site.source_location.column_start
        ),
        None,
    )
    return model.context_for(node) if node is not None else None


def _call_node(parsed: ParsedProject, call_site: CallSiteRecord) -> ast.Call | None:
    model = parsed.functions.get(call_site.caller_symbol_id)
    if model is None:
        return None
    return next(
        (
            item
            for item in ast.walk(model.function)
            if isinstance(item, ast.Call)
            and max(getattr(item, "lineno", 1), 1) == call_site.source_location.line_start
            and max(getattr(item, "col_offset", 0), 0) == call_site.source_location.column_start
        ),
        None,
    )


def _direct_execution_proven(
    source_index: SourceIndexArtifact,
    parsed: ParsedProject,
    call_site: CallSiteRecord,
) -> bool:
    """Recognize only direct sync calls and directly awaited async calls."""

    if call_site.callee_symbol_id is None:
        return False
    symbol = next(
        (item for item in source_index.symbols if item.symbol_id == call_site.callee_symbol_id),
        None,
    )
    model = parsed.functions.get(call_site.caller_symbol_id)
    call = _call_node(parsed, call_site)
    if symbol is None or model is None or call is None:
        return False
    parents = {
        child: parent
        for parent in ast.walk(model.function)
        for child in ast.iter_child_nodes(parent)
    }
    parent = parents.get(call)
    is_async = symbol.kind in {SymbolKind.ASYNC_FUNCTION, SymbolKind.ASYNC_METHOD}
    expression: ast.AST = call
    if is_async:
        if not isinstance(parent, ast.Await) or parent.value is not call:
            return False
        expression = parent
        parent = parents.get(parent)
    elif symbol.kind not in {SymbolKind.FUNCTION, SymbolKind.METHOD}:
        return False

    direct_owners = (ast.Expr, ast.Assign, ast.AnnAssign, ast.Return)
    if not isinstance(parent, direct_owners):
        return False
    if isinstance(parent, ast.Expr):
        return parent.value is expression
    if isinstance(parent, (ast.Assign, ast.AnnAssign)):
        return parent.value is expression
    return isinstance(parent, ast.Return) and parent.value is expression


def _path_execution_gap(
    source_index: SourceIndexArtifact,
    parsed: ParsedProject,
    path: tuple[CallSiteRecord, ...],
) -> CallSiteRecord | None:
    return next(
        (
            call_site
            for call_site in path
            if not _direct_execution_proven(source_index, parsed, call_site)
        ),
        None,
    )


def _controlled_path_context(
    fact: StateGateFact,
    path: tuple[CallSiteRecord, ...],
    parsed: ParsedProject,
) -> tuple[StatementContext, BranchDisposition] | None:
    for call_site in path:
        if call_site.caller_symbol_id != fact.symbol_id:
            continue
        context = _call_context(parsed, call_site)
        if context is None:
            return None
        branch = branch_controls(fact.context, context)
        if branch is not None:
            return context, branch.disposition
    return None


def _route_call_context(
    route_owner: SymbolId,
    path: tuple[CallSiteRecord, ...],
    parsed: ParsedProject,
) -> StatementContext | None:
    call_site = next(
        (item for item in path if item.caller_symbol_id == route_owner),
        None,
    )
    return _call_context(parsed, call_site) if call_site is not None else None


def _work_precedes_ack(
    work: StatementContext,
    ack: AcknowledgementFact,
    route_owner: SymbolId,
) -> bool:
    if ack.context is not None:
        return context_dominates(work, ack.context)
    return work.symbol_id == route_owner and not work.ancestors


def _static_relationship_provenance(
    source_index: SourceIndexArtifact,
    reference: str,
    context: StatementContext | None,
    path: tuple[CallSiteRecord, ...],
) -> tuple[ProvenanceRecord, ...]:
    records = [
        ProvenanceRecord(
            kind=ProvenanceKind.STATIC,
            reference=reference,
            source_location=(
                None
                if context is None
                else source_location(
                    next(
                        item.source_location.path
                        for item in source_index.symbols
                        if item.symbol_id == context.symbol_id
                    ),
                    context.node,
                )
            ),
            supporting_fingerprint=source_index.source_index_fingerprint,
        )
    ]
    records.extend(
        ProvenanceRecord(
            kind=ProvenanceKind.STATIC,
            reference=_call_site_reference(source_index, call_site),
            source_location=call_site.source_location,
            supporting_fingerprint=source_index.source_index_fingerprint,
        )
        for call_site in path
    )
    return tuple(sorted(records, key=canonical_json))


def _project_control_relationships(
    repository_root: Path,
    source_index: SourceIndexArtifact,
    nodes: tuple[GraphNode, ...],
    edges: tuple[GraphEdge, ...],
    diagnostics: tuple[GraphDiagnosticRecord, ...],
    customer_node: GraphNode,
    selected: SymbolId,
) -> tuple[tuple[GraphEdge, ...], tuple[GraphDiagnosticRecord, ...]]:
    """Project only exact branch-control and pre-acknowledgement customer-value facts."""

    callable_ids = {
        item.symbol_id
        for item in source_index.symbols
        if item.kind
        in {
            SymbolKind.FUNCTION,
            SymbolKind.ASYNC_FUNCTION,
            SymbolKind.METHOD,
            SymbolKind.ASYNC_METHOD,
        }
    }
    parsed = parse_indexed_functions(repository_root, source_index, callable_ids)
    routes_by_registration = {
        item.registration.route_registration_id: item
        for item in compose_effective_routes(source_index).routes
    }
    state_nodes = {
        (item.details.route_registration_id, item.details.structural_anchor): item
        for item in nodes
        if isinstance(item.details, PaymentStateGateDetails)
    }
    ack_nodes = {
        (item.details.route_registration_id, item.details.structural_anchor): item
        for item in nodes
        if isinstance(item.details, AcknowledgementBoundaryDetails)
    }
    result = list(edges)
    diagnostic_result = list(diagnostics)
    ingress_nodes = [
        item
        for item in nodes
        if isinstance(item.details, PaymentIngressDetails)
        and any(
            edge.kind == GraphEdgeKind.CALLS
            and edge.source_node_id == item.node_id
            and edge.target_node_id == customer_node.node_id
            for edge in edges
        )
    ]
    for ingress in ingress_nodes:
        assert isinstance(ingress.details, PaymentIngressDetails)
        route_id = ingress.details.registration.route_registration_id
        route = routes_by_registration.get(route_id)
        if route is None:
            continue
        analysis = analyze_route_concepts(route, source_index, parsed)
        path = analysis.call_paths.get(selected)
        if not path:
            continue
        execution_gap = _path_execution_gap(source_index, parsed, path)
        if execution_gap is not None:
            diagnostic = GraphDiagnosticRecord(
                code=GraphDiagnosticCode.UNRESOLVED_STRUCTURAL_CANDIDATE,
                impact=GraphDiagnosticImpact.COVERAGE_REDUCED,
                candidate_kind=GraphCandidateKind.CUSTOMER_VALUE_EXECUTION,
                reason=GraphDiagnosticReason.EXECUTION_SEMANTICS_UNPROVEN,
                symbol_id=selected,
                route_registration_id=route_id,
                source_location=execution_gap.source_location,
            )
            if diagnostic not in diagnostic_result:
                diagnostic_result.append(diagnostic)
            continue
        for state_fact in analysis.state_gates:
            controlled = _controlled_path_context(state_fact, path, parsed)
            if controlled is None or controlled[1] != BranchDisposition.MATCHED:
                continue
            state_node = state_nodes.get((route_id, state_fact.context.anchor))
            if state_node is None:
                continue
            branch = GraphBranchDetails(
                disposition=BranchDisposition.MATCHED,
                states=state_fact.states,
            )
            edge = GraphEdge(
                edge_id=graph_edge_id(
                    GraphEdgeKind.BRANCHES_TO.value,
                    state_node.node_id,
                    customer_node.node_id,
                    discriminator=canonical_json(branch),
                ),
                source_node_id=state_node.node_id,
                target_node_id=customer_node.node_id,
                kind=GraphEdgeKind.BRANCHES_TO,
                branch=branch,
                provenance=_static_relationship_provenance(
                    source_index,
                    "ast-fact:PAYMENT_STATE_BRANCH_CONTROL:customer-value:"
                    f"{state_fact.context.anchor}",
                    controlled[0],
                    path,
                ),
            )
            if edge.edge_id not in {item.edge_id for item in result}:
                result.append(edge)

        route_work = _route_call_context(route.owner_symbol_id, path, parsed)
        if route_work is None:
            continue
        for ack_fact in analysis.acknowledgements:
            if not _work_precedes_ack(route_work, ack_fact, route.owner_symbol_id):
                continue
            ack_node = ack_nodes.get((route_id, ack_fact.anchor))
            if ack_node is None:
                continue
            edge = GraphEdge(
                edge_id=graph_edge_id(
                    GraphEdgeKind.ACKNOWLEDGES_AFTER.value,
                    ack_node.node_id,
                    customer_node.node_id,
                ),
                source_node_id=ack_node.node_id,
                target_node_id=customer_node.node_id,
                kind=GraphEdgeKind.ACKNOWLEDGES_AFTER,
                provenance=_static_relationship_provenance(
                    source_index,
                    f"ast-fact:EXIT_DOMINANCE:customer-value:{ack_fact.anchor}",
                    route_work,
                    path,
                ),
            )
            if edge.edge_id not in {item.edge_id for item in result}:
                result.append(edge)
    return (
        tuple(sorted(result, key=canonical_json)),
        tuple(sorted(diagnostic_result, key=canonical_json)),
    )


def fulfilment_verification_eligible(
    resolution: CustomerValueResolution | None,
    graph: PaymentSafetyGraphArtifact,
    *,
    runtime_capable: bool,
) -> bool:
    if (
        resolution is None
        or resolution.state != ResolutionState.UNIQUE
        or resolution.selected_symbol_id is None
        or not runtime_capable
    ):
        return False
    target_nodes = {
        item.node_id
        for item in graph.nodes
        if item.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
        and item.backing_symbol_id == resolution.selected_symbol_id
    }
    ingress_ids = {
        item.node_id for item in graph.nodes if item.kind == GraphNodeKind.PAYMENT_INGRESS
    }
    return any(
        item.kind == GraphEdgeKind.CALLS
        and item.source_node_id in ingress_ids
        and item.target_node_id in target_nodes
        for item in graph.edges
    )


def _resolved_path(
    source_index: SourceIndexArtifact,
    start: SymbolId,
    target: SymbolId,
) -> tuple[CallSiteRecord, ...] | None:
    outgoing: dict[SymbolId, list[CallSiteRecord]] = defaultdict(list)
    for item in source_index.call_sites:
        if item.callee_symbol_id is not None:
            outgoing[item.caller_symbol_id].append(item)
    for calls in outgoing.values():
        calls.sort(key=canonical_json)
    queue: deque[tuple[SymbolId, tuple[CallSiteRecord, ...]]] = deque([(start, ())])
    visited = {start}
    while queue:
        current, path = queue.popleft()
        if current == target:
            return path
        for call in outgoing.get(current, []):
            assert call.callee_symbol_id is not None
            if call.callee_symbol_id in visited:
                continue
            visited.add(call.callee_symbol_id)
            queue.append((call.callee_symbol_id, (*path, call)))
    return None


def _call_site_reference(source_index: SourceIndexArtifact, call_site: CallSiteRecord) -> str:
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
    ordinal = peers.index(call_site)
    return f"call-site:{call_site.caller_symbol_id}:{ordinal}"
