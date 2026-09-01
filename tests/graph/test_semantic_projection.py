from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from stateguard.contracts.config import StateGuardConfig
from stateguard.contracts.identity import (
    graph_edge_id,
    new_project_id,
    sha256_digest,
)
from stateguard.discovery.service import discover_and_index_project
from stateguard.graph.contracts import GraphEdgeKind, GraphNodeKind, graph_fingerprint
from stateguard.graph.semantic_projection import (
    _semantic_call_edge_discriminator,
    fulfilment_verification_eligible,
    project_customer_value,
)
from stateguard.graph.service import construct_payment_safety_graph
from stateguard.semantics.context import resolution_fingerprint, semantic_context_fingerprint
from stateguard.semantics.context_builder import build_semantic_context
from stateguard.semantics.contracts import (
    CustomerValueResolution,
    ResolutionBasis,
    ResolutionState,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"
NOW = datetime(2026, 8, 25, tzinfo=UTC)


def _facts_from_repository(repository: Path, *, project_id: str | None = None):
    config = StateGuardConfig.model_validate(
        {
            "schema_version": 2,
            "project": {
                "id": project_id or new_project_id(),
                "app_target": "main:app",
            },
            "analysis": {"include": ["**/*.py"], "exclude": []},
        }
    )
    index = discover_and_index_project(repository, config, generated_at=NOW).source_index
    graph = construct_payment_safety_graph(repository, index, generated_at=NOW)
    context = build_semantic_context(repository, index, graph).descriptor
    return index, graph, context


def _facts(tmp_path: Path, *, extend_to_three_hops: bool = False):
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "semantic_app", repository)
    if extend_to_three_hops:
        (repository / "storage.py").write_text(
            """from fulfilment import activate_ticket


def persist_ticket(payment_id):
    return activate_ticket(payment_id)
""",
            encoding="utf-8",
        )
        (repository / "fulfilment.py").write_text(
            """def activate_ticket(payment_id):
    return {"payment_id": payment_id, "status": "issued"}
""",
            encoding="utf-8",
        )
    return _facts_from_repository(repository)


def _customer_call_edge(projected):
    customer_ids = {
        item.node_id for item in projected.nodes if item.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
    }
    return next(
        item
        for item in projected.edges
        if item.kind == GraphEdgeKind.CALLS and item.target_node_id in customer_ids
    )


def _resolution(symbol_id: str, basis: ResolutionBasis) -> CustomerValueResolution:
    return CustomerValueResolution(
        state=ResolutionState.UNIQUE,
        basis=basis,
        selected_symbol_id=symbol_id,
    )


def test_connected_resolution_adds_customer_node_and_exact_static_call_edge(
    tmp_path: Path,
) -> None:
    index, graph, context = _facts(tmp_path)
    selected = next(
        item.symbol_id for item in index.symbols if item.qualified_name == "domain.grant_ticket"
    )
    resolution = _resolution(selected, ResolutionBasis.MODEL_UNIQUE)
    fingerprint = resolution_fingerprint(resolution, semantic_context_fingerprint(context))
    projected = project_customer_value(graph, index, resolution, fingerprint)
    customer = next(
        item for item in projected.nodes if item.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
    )
    ingress_ids = {
        item.node_id for item in projected.nodes if item.kind == GraphNodeKind.PAYMENT_INGRESS
    }
    edge = next(
        item
        for item in projected.edges
        if item.kind == GraphEdgeKind.CALLS and item.target_node_id == customer.node_id
    )
    assert edge.source_node_id in ingress_ids
    assert edge.provenance
    assert all(item.reference.startswith("call-site:") for item in edge.provenance)
    assert not fulfilment_verification_eligible(resolution, projected, runtime_capable=False)
    assert fulfilment_verification_eligible(resolution, projected, runtime_capable=True)


def test_semantic_call_edge_identity_is_structural_while_authority_stays_fresh(
    tmp_path: Path,
) -> None:
    index, graph, context = _facts(tmp_path)
    selected = next(
        item.symbol_id for item in index.symbols if item.qualified_name == "domain.grant_ticket"
    )
    model_resolution = _resolution(selected, ResolutionBasis.MODEL_UNIQUE)
    human_resolution = _resolution(selected, ResolutionBasis.MANUAL_SELECTION)
    model_fingerprint = resolution_fingerprint(
        model_resolution, semantic_context_fingerprint(context)
    )
    human_fingerprint = sha256_digest("same-structural-fact-new-human-authority")

    inferred = project_customer_value(graph, index, model_resolution, model_fingerprint)
    confirmed = project_customer_value(graph, index, human_resolution, human_fingerprint)

    inferred_edge = _customer_call_edge(inferred)
    confirmed_edge = _customer_call_edge(confirmed)
    inferred_customer = next(
        item for item in inferred.nodes if item.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
    )
    confirmed_customer = next(
        item for item in confirmed.nodes if item.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
    )

    assert inferred_edge.edge_id == confirmed_edge.edge_id
    assert inferred_customer.provenance != confirmed_customer.provenance
    assert confirmed_customer.provenance[0].supporting_fingerprint == human_fingerprint
    assert inferred.graph_fingerprint != confirmed.graph_fingerprint


def test_semantic_call_edge_identity_changes_with_exact_call_site_path(
    tmp_path: Path,
) -> None:
    index, graph, context = _facts(tmp_path)
    selected = next(
        item.symbol_id for item in index.symbols if item.qualified_name == "domain.grant_ticket"
    )
    resolution = _resolution(selected, ResolutionBasis.MANUAL_SELECTION)
    fingerprint = resolution_fingerprint(resolution, semantic_context_fingerprint(context))
    direct = project_customer_value(graph, index, resolution, fingerprint)
    direct_edge = _customer_call_edge(direct)
    changed_provenance = (
        direct_edge.provenance[0].model_copy(
            update={"reference": f"{direct_edge.provenance[0].reference}:changed-site"}
        ),
        *direct_edge.provenance[1:],
    )
    changed_edge_id = graph_edge_id(
        GraphEdgeKind.CALLS.value,
        direct_edge.source_node_id,
        direct_edge.target_node_id,
        discriminator=_semantic_call_edge_discriminator(changed_provenance),
    )

    assert changed_edge_id != direct_edge.edge_id


def test_legacy_resolution_keyed_call_edge_remains_readable_but_is_not_rewritten(
    tmp_path: Path,
) -> None:
    index, graph, context = _facts(tmp_path)
    selected = next(
        item.symbol_id for item in index.symbols if item.qualified_name == "domain.grant_ticket"
    )
    resolution = _resolution(selected, ResolutionBasis.MODEL_UNIQUE)
    fingerprint = resolution_fingerprint(resolution, semantic_context_fingerprint(context))
    current = project_customer_value(graph, index, resolution, fingerprint)
    call_edge = _customer_call_edge(current)
    legacy_edge = call_edge.model_copy(
        update={
            "edge_id": graph_edge_id(
                GraphEdgeKind.CALLS.value,
                call_edge.source_node_id,
                call_edge.target_node_id,
                discriminator=fingerprint,
            )
        }
    )
    legacy_edges = tuple(
        legacy_edge if item.edge_id == call_edge.edge_id else item for item in current.edges
    )

    legacy = current.model_copy(
        update={
            "edges": legacy_edges,
            "graph_fingerprint": graph_fingerprint(
                project_id=current.project_id,
                source_index_fingerprint=current.source_index_fingerprint,
                completeness=current.completeness,
                diagnostics=current.diagnostics,
                nodes=current.nodes,
                edges=legacy_edges,
            ),
        }
    )

    loaded = type(current).model_validate_json(legacy.model_dump_json())
    loaded_call = _customer_call_edge(loaded)
    assert loaded_call.edge_id == legacy_edge.edge_id
    assert loaded_call.edge_id != call_edge.edge_id


def test_multihop_resolution_compresses_reachability_with_ordered_call_site_provenance(
    tmp_path: Path,
) -> None:
    index, graph, context = _facts(tmp_path, extend_to_three_hops=True)
    symbols = {item.qualified_name: item.symbol_id for item in index.symbols}
    selected = symbols["fulfilment.activate_ticket"]
    resolution = _resolution(selected, ResolutionBasis.MODEL_UNIQUE)
    fingerprint = resolution_fingerprint(resolution, semantic_context_fingerprint(context))

    projected = project_customer_value(graph, index, resolution, fingerprint)
    customer = next(
        item for item in projected.nodes if item.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
    )
    edges = [
        item
        for item in projected.edges
        if item.kind == GraphEdgeKind.CALLS and item.target_node_id == customer.node_id
    ]
    assert len(edges) == 1
    edge = edges[0]
    ingress = next(item for item in projected.nodes if item.kind == GraphNodeKind.PAYMENT_INGRESS)
    assert edge.source_node_id == ingress.node_id
    expected_callers = [
        symbols["main.payment_webhook"],
        symbols["domain.grant_ticket"],
        symbols["storage.persist_ticket"],
    ]
    assert [item.reference for item in edge.provenance] == [
        f"call-site:{caller}:0" for caller in expected_callers
    ]
    assert [item.source_location.path for item in edge.provenance] == [
        "main.py",
        "domain.py",
        "storage.py",
    ]


def test_unconnected_manual_selection_is_semantically_resolved_but_isolated(
    tmp_path: Path,
) -> None:
    index, graph, context = _facts(tmp_path)
    selected = next(
        item.symbol_id
        for item in index.symbols
        if item.qualified_name == "domain.unused_imported_helper"
    )
    resolution = _resolution(selected, ResolutionBasis.MANUAL_SELECTION)
    fingerprint = resolution_fingerprint(resolution, semantic_context_fingerprint(context))
    projected = project_customer_value(graph, index, resolution, fingerprint)
    customer = next(
        item for item in projected.nodes if item.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
    )
    assert not any(item.target_node_id == customer.node_id for item in projected.edges)
    assert not fulfilment_verification_eligible(resolution, projected, runtime_capable=True)


def test_route_owner_cannot_masquerade_as_customer_value(tmp_path: Path) -> None:
    index, graph, context = _facts(tmp_path)
    route_symbol = index.routes[0].owner_symbol_id
    resolution = _resolution(route_symbol, ResolutionBasis.MANUAL_SELECTION)
    fingerprint = resolution_fingerprint(resolution, semantic_context_fingerprint(context))
    with pytest.raises(ValueError, match="non-route"):
        project_customer_value(graph, index, resolution, fingerprint)
