from __future__ import annotations

import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

from stateguard.contracts.config import StateGuardConfig
from stateguard.contracts.identity import new_project_id
from stateguard.discovery.service import discover_and_index_project
from stateguard.graph.contracts import (
    AcknowledgementBoundaryDetails,
    GraphDiagnosticReason,
    GraphEdgeKind,
    GraphNodeKind,
    MerchantStateMutationDetails,
    PaymentIngressDetails,
    TrustGateDetails,
    TrustGateKind,
)
from stateguard.graph.service import construct_payment_safety_graph

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"
NOW = datetime(2026, 8, 25, tzinfo=UTC)


def _construct(tmp_path: Path):
    repository = tmp_path / "graph_hardening"
    shutil.copytree(FIXTURES / "graph_hardening", repository)
    config = StateGuardConfig.model_validate(
        {
            "schema_version": 2,
            "project": {
                "id": new_project_id(),
                "source_root": ".",
                "framework": "fastapi",
                "app_target": "main:app",
            },
            "analysis": {"include": ["**/*.py"], "exclude": []},
        }
    )
    index = discover_and_index_project(repository, config, generated_at=NOW).source_index
    return construct_payment_safety_graph(repository, index, generated_at=NOW)


def _path_map(graph) -> dict[str, str]:
    return {
        node.details.registration.route_registration_id: node.details.registration.effective_path
        for node in graph.nodes
        if isinstance(node.details, PaymentIngressDetails)
    }


def _route_nodes(graph, path: str):
    paths = _path_map(graph)
    return [
        node
        for node in graph.nodes
        if (
            isinstance(node.details, PaymentIngressDetails)
            and node.details.registration.effective_path == path
        )
        or paths.get(getattr(node.details, "route_registration_id", None)) == path
    ]


def _has_edge(graph, kind: GraphEdgeKind, source_id: str, target_id: str) -> bool:
    return any(
        edge.kind == kind and edge.source_node_id == source_id and edge.target_node_id == target_id
        for edge in graph.edges
    )


def _only(nodes, kind: GraphNodeKind):
    matched = [node for node in nodes if node.kind == kind]
    assert len(matched) == 1
    return matched[0]


def test_exception_regions_control_guards_and_acknowledgements(tmp_path: Path) -> None:
    graph = _construct(tmp_path)

    swallowed = _route_nodes(graph, "/exceptions/swallowed")
    swallowed_mutation = _only(swallowed, GraphNodeKind.MERCHANT_STATE_MUTATION)
    assert not [node for node in swallowed if node.kind == GraphNodeKind.TRUST_GATE]
    assert swallowed_mutation
    assert any(
        diagnostic.reason == GraphDiagnosticReason.VALIDATION_NOT_CONTROL_EFFECTIVE
        and diagnostic.route_registration_id
        == next(
            node.details.registration.route_registration_id
            for node in swallowed
            if isinstance(node.details, PaymentIngressDetails)
        )
        for diagnostic in graph.diagnostics
    )

    terminating = _route_nodes(graph, "/exceptions/terminating")
    terminating_trust = _only(terminating, GraphNodeKind.TRUST_GATE)
    terminating_state = _only(terminating, GraphNodeKind.PAYMENT_STATE_GATE)
    terminating_mutation = _only(terminating, GraphNodeKind.MERCHANT_STATE_MUTATION)
    assert _has_edge(
        graph,
        GraphEdgeKind.GUARDS,
        terminating_trust.node_id,
        terminating_state.node_id,
    )
    assert _has_edge(
        graph,
        GraphEdgeKind.GUARDS,
        terminating_trust.node_id,
        terminating_mutation.node_id,
    )

    finally_return = _route_nodes(graph, "/exceptions/finally-return")
    finally_return_ack = _only(finally_return, GraphNodeKind.ACKNOWLEDGEMENT_BOUNDARY)
    finally_return_mutation = _only(finally_return, GraphNodeKind.MERCHANT_STATE_MUTATION)
    assert not _has_edge(
        graph,
        GraphEdgeKind.ACKNOWLEDGES_AFTER,
        finally_return_ack.node_id,
        finally_return_mutation.node_id,
    )

    finally_mutation = _route_nodes(graph, "/exceptions/finally-mutation")
    finally_mutation_trust = _only(finally_mutation, GraphNodeKind.TRUST_GATE)
    finally_mutation_write = _only(finally_mutation, GraphNodeKind.MERCHANT_STATE_MUTATION)
    assert not _has_edge(
        graph,
        GraphEdgeKind.GUARDS,
        finally_mutation_trust.node_id,
        finally_mutation_write.node_id,
    )

    multiple = _route_nodes(graph, "/exceptions/multiple-exits")
    multiple_trust = _only(multiple, GraphNodeKind.TRUST_GATE)
    acknowledgements = {
        node.details.status_code: node
        for node in multiple
        if isinstance(node.details, AcknowledgementBoundaryDetails)
    }
    assert set(acknowledgements) == {202, 400}
    assert _has_edge(
        graph,
        GraphEdgeKind.ACKNOWLEDGES_AFTER,
        acknowledgements[202].node_id,
        multiple_trust.node_id,
    )
    assert not _has_edge(
        graph,
        GraphEdgeKind.ACKNOWLEDGES_AFTER,
        acknowledgements[400].node_id,
        multiple_trust.node_id,
    )


def test_sdk_binding_and_helper_exception_effectiveness_are_proven(tmp_path: Path) -> None:
    graph = _construct(tmp_path)

    rebound = _route_nodes(graph, "/sdk/rebound")
    assert not [node for node in rebound if isinstance(node.details, TrustGateDetails)]
    rebound_registration = next(
        node.details.registration.route_registration_id
        for node in rebound
        if isinstance(node.details, PaymentIngressDetails)
    )
    assert any(
        item.route_registration_id == rebound_registration
        and item.reason == GraphDiagnosticReason.SDK_BINDING_UNRESOLVED
        for item in graph.diagnostics
    )

    propagated = _route_nodes(graph, "/helpers/propagated")
    propagated_trust = _only(propagated, GraphNodeKind.TRUST_GATE)
    assert isinstance(propagated_trust.details, TrustGateDetails)
    assert propagated_trust.details.trust_kind == TrustGateKind.WEBHOOK_SIGNATURE_VERIFICATION
    for target_kind in (
        GraphNodeKind.PAYMENT_STATE_GATE,
        GraphNodeKind.MERCHANT_STATE_MUTATION,
    ):
        target = _only(propagated, target_kind)
        assert _has_edge(
            graph,
            GraphEdgeKind.GUARDS,
            propagated_trust.node_id,
            target.node_id,
        )

    swallowed = _route_nodes(graph, "/helpers/swallowed")
    swallowed_trust = _only(swallowed, GraphNodeKind.TRUST_GATE)
    swallowed_mutation = _only(swallowed, GraphNodeKind.MERCHANT_STATE_MUTATION)
    assert not _has_edge(
        graph,
        GraphEdgeKind.GUARDS,
        swallowed_trust.node_id,
        swallowed_mutation.node_id,
    )
    assert any(
        item.reason == GraphDiagnosticReason.VALIDATION_NOT_CONTROL_EFFECTIVE
        and item.route_registration_id == swallowed_trust.details.route_registration_id
        for item in graph.diagnostics
    )


def test_mutation_carrier_is_bounded_persisted_and_provenanced(tmp_path: Path) -> None:
    graph = _construct(tmp_path)
    mutations = [
        node for node in graph.nodes if isinstance(node.details, MerchantStateMutationDetails)
    ]

    assert mutations
    assert all(
        re.fullmatch(r"sgcarrier_[0-9a-f]{32}", node.details.carrier_reference)
        for node in mutations
    )
    assert all(
        any(
            record.reference
            == (f"ast-fact:SG-AST-MERCHANT-CARRIER-001:carrier:{node.details.carrier_reference}")
            for record in node.provenance
        )
        for node in mutations
    )
    persisted = graph.model_dump_json()
    assert '"carrier_reference":"orders"' not in persisted
    assert '"carrier_reference":"metrics"' not in persisted
