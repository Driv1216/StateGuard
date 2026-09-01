from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from stateguard.contracts.common import ProvenanceKind, ProvenanceRecord
from stateguard.contracts.identity import (
    framework_instance_id,
    graph_edge_id,
    graph_node_id,
    merchant_state_carrier_id,
    new_project_id,
    route_registration_id,
    sha256_digest,
    source_file_id,
    structural_anchor,
    symbol_id,
)
from stateguard.graph.contracts import (
    AcknowledgementBoundaryDetails,
    AcknowledgementExitKind,
    AcknowledgementOutcome,
    EffectiveRouteRegistration,
    GraphCompleteness,
    GraphDiagnosticCode,
    GraphDiagnosticImpact,
    GraphDiagnosticRecord,
    GraphEdge,
    GraphEdgeKind,
    GraphNode,
    GraphNodeKind,
    MerchantMutationKind,
    MerchantStateMutationDetails,
    PaymentIngressDetails,
    PaymentIngressKind,
    PaymentSafetyGraphArtifact,
    TrustGateDetails,
    TrustGateKind,
    WebhookBodyOrigin,
    graph_completeness_for,
    graph_fingerprint,
)

NOW = datetime(2026, 8, 24, tzinfo=UTC)


def _facts():
    project = new_project_id()
    file_id = source_file_id(project, "app/main.py")
    symbol = symbol_id(file_id, "app.main.webhook", "ASYNC_FUNCTION")
    app = framework_instance_id(file_id, "app.main.app", "FASTAPI_APP")
    registration_id = route_registration_id(
        selected_app_instance_id=app,
        include_anchors=(),
        registrar_instance_id=app,
        owner_symbol_id=symbol,
        method="POST",
        route_path="/webhooks",
        same_shape_ordinal=0,
    )
    fingerprint = sha256_digest("index")
    evidence = (
        ProvenanceRecord(
            kind=ProvenanceKind.STATIC,
            reference=f"symbol:{symbol}",
            supporting_fingerprint=fingerprint,
        ),
    )
    registration = EffectiveRouteRegistration(
        route_registration_id=registration_id,
        app_instance_id=app,
        registrar_instance_id=app,
        method="post",
        component_path="/webhooks",
        effective_path="/webhooks",
    )
    ingress = GraphNode(
        node_id=graph_node_id(GraphNodeKind.PAYMENT_INGRESS.value, symbol, "ingress"),
        kind=GraphNodeKind.PAYMENT_INGRESS,
        label="Webhook ingress",
        backing_symbol_id=symbol,
        details=PaymentIngressDetails(
            ingress_kind=PaymentIngressKind.WEBHOOK,
            registration=registration,
            evidence_families=("WEBHOOK_SIGNATURE_PIPELINE", "PAYMENT_EVENT_BRANCH"),
        ),
        provenance=evidence,
    )
    trust = GraphNode(
        node_id=graph_node_id(GraphNodeKind.TRUST_GATE.value, symbol, "signature"),
        kind=GraphNodeKind.TRUST_GATE,
        label="Webhook signature verification",
        backing_symbol_id=symbol,
        details=TrustGateDetails(
            trust_kind=TrustGateKind.WEBHOOK_SIGNATURE_VERIFICATION,
            route_registration_id=registration_id,
            structural_anchor=structural_anchor(symbol, "signature"),
            webhook_body_origin=WebhookBodyOrigin.RAW_PRESERVED,
        ),
        provenance=evidence,
    )
    ack = GraphNode(
        node_id=graph_node_id(GraphNodeKind.ACKNOWLEDGEMENT_BOUNDARY.value, symbol, "return"),
        kind=GraphNodeKind.ACKNOWLEDGEMENT_BOUNDARY,
        label="HTTP 200 return",
        backing_symbol_id=symbol,
        details=AcknowledgementBoundaryDetails(
            route_registration_id=registration_id,
            structural_anchor=structural_anchor(symbol, "return"),
            exit_kind=AcknowledgementExitKind.RETURN,
            status_code=200,
            outcome=AcknowledgementOutcome.SUCCESS_2XX,
        ),
        provenance=evidence,
    )
    edge = GraphEdge(
        edge_id=graph_edge_id(GraphEdgeKind.ACKNOWLEDGES_AFTER.value, ack.node_id, trust.node_id),
        source_node_id=ack.node_id,
        target_node_id=trust.node_id,
        kind=GraphEdgeKind.ACKNOWLEDGES_AFTER,
        provenance=evidence,
    )
    return project, symbol, fingerprint, ingress, trust, ack, edge


def test_schema_v2_round_trip_and_fingerprint_validation() -> None:
    project, _, fingerprint, ingress, trust, ack, edge = _facts()
    nodes = (ingress, trust, ack)
    graph_hash = graph_fingerprint(
        project_id=project,
        source_index_fingerprint=fingerprint,
        completeness=GraphCompleteness.COMPLETE,
        diagnostics=(),
        nodes=nodes,
        edges=(edge,),
    )
    graph = PaymentSafetyGraphArtifact(
        producer_version="0.1.0",
        generated_at=NOW,
        project_id=project,
        source_index_fingerprint=fingerprint,
        graph_fingerprint=graph_hash,
        nodes=nodes,
        edges=(edge,),
    )

    assert graph.schema_version == 2
    assert PaymentSafetyGraphArtifact.model_validate_json(graph.model_dump_json()) == graph
    with pytest.raises(ValidationError, match="fingerprint"):
        PaymentSafetyGraphArtifact.model_validate(
            {**graph.model_dump(), "graph_fingerprint": sha256_digest("tampered")}
        )


def test_node_details_and_edge_orientation_are_kind_matched() -> None:
    _, symbol, _, ingress, trust, _, _ = _facts()
    with pytest.raises(ValidationError, match="details must match"):
        GraphNode(**{**ingress.model_dump(), "details": trust.details})
    invalid = GraphEdge(
        edge_id=graph_edge_id(GraphEdgeKind.GUARDS.value, trust.node_id, ingress.node_id),
        source_node_id=trust.node_id,
        target_node_id=ingress.node_id,
        kind=GraphEdgeKind.GUARDS,
        provenance=trust.provenance,
    )
    nodes = (ingress, trust)
    project = new_project_id()
    fingerprint = sha256_digest("source")
    graph_hash = graph_fingerprint(
        project_id=project,
        source_index_fingerprint=fingerprint,
        completeness=GraphCompleteness.COMPLETE,
        diagnostics=(),
        nodes=nodes,
        edges=(invalid,),
    )
    with pytest.raises(ValidationError, match="orientation"):
        PaymentSafetyGraphArtifact(
            producer_version="0.1.0",
            generated_at=NOW,
            project_id=project,
            source_index_fingerprint=fingerprint,
            graph_fingerprint=graph_hash,
            nodes=nodes,
            edges=(invalid,),
        )
    assert symbol == ingress.backing_symbol_id


def test_completeness_is_derived_only_from_coverage_reducing_diagnostics() -> None:
    notice = GraphDiagnosticRecord(
        code=GraphDiagnosticCode.ROUTE_COMPOSITION_UNRESOLVED,
        impact=GraphDiagnosticImpact.NOTICE,
    )
    reduced = GraphDiagnosticRecord(
        code=GraphDiagnosticCode.CONTROL_FLOW_UNSUPPORTED,
        impact=GraphDiagnosticImpact.COVERAGE_REDUCED,
    )
    assert graph_completeness_for((notice,)) == GraphCompleteness.COMPLETE
    assert graph_completeness_for((notice, reduced)) == GraphCompleteness.PARTIAL


def test_merchant_mutation_carrier_is_typed_and_confidentiality_safe() -> None:
    project, symbol, _, ingress, _, _, _ = _facts()
    assert isinstance(ingress.details, PaymentIngressDetails)
    file_id = source_file_id(project, "app/main.py")
    orders = merchant_state_carrier_id(file_id, "orders")
    subscriptions = merchant_state_carrier_id(file_id, "subscriptions")

    details = MerchantStateMutationDetails(
        route_registration_id=ingress.details.registration.route_registration_id,
        structural_anchor=structural_anchor(symbol, "mutation"),
        mutation_kind=MerchantMutationKind.SUBSCRIPT_WRITE,
        carrier_reference=orders,
    )
    assert details.carrier_reference == orders
    assert orders != subscriptions
    assert "orders" not in orders
    with pytest.raises(ValidationError, match="carrier_reference"):
        MerchantStateMutationDetails(
            route_registration_id=details.route_registration_id,
            structural_anchor=details.structural_anchor,
            mutation_kind=details.mutation_kind,
            carrier_reference="orders",
        )


def test_customer_value_action_keeps_semantic_authority_contract() -> None:
    _, symbol, _, _, _, _, _ = _facts()
    node_id = graph_node_id(GraphNodeKind.CUSTOMER_VALUE_ACTION.value, symbol)
    with pytest.raises(ValidationError, match="customer-value actions require"):
        GraphNode(
            node_id=node_id,
            kind=GraphNodeKind.CUSTOMER_VALUE_ACTION,
            label="Grant purchased access",
            backing_symbol_id=symbol,
            provenance=(
                ProvenanceRecord(
                    kind=ProvenanceKind.STATIC,
                    reference=f"symbol:{symbol}",
                    supporting_fingerprint=sha256_digest("static"),
                ),
            ),
        )

    semantic_fingerprint = sha256_digest("customer-value-resolution")
    inferred = GraphNode(
        node_id=node_id,
        kind=GraphNodeKind.CUSTOMER_VALUE_ACTION,
        label="Grant purchased access",
        backing_symbol_id=symbol,
        provenance=(
            ProvenanceRecord(
                kind=ProvenanceKind.AI_INFERRED,
                reference="customer-value-resolution:MODEL_UNIQUE",
                supporting_fingerprint=semantic_fingerprint,
            ),
        ),
    )
    assert inferred.details is None
