"""Exact graph/applicability bindings for Step 5 runtime assessment."""

from __future__ import annotations

from dataclasses import dataclass

from stateguard.applicability.contracts import (
    ApplicabilityReasonCode,
    EvidenceReferenceKind,
    ScenarioApplicabilityArtifact,
    ScenarioId,
)
from stateguard.discovery.contracts import AppTargetRecord, AppTargetSelection, SourceIndexArtifact
from stateguard.graph.contracts import (
    AcknowledgementBoundaryDetails,
    BranchDisposition,
    GraphEdgeKind,
    GraphNode,
    GraphNodeKind,
    MerchantStateMutationDetails,
    PaymentIngressDetails,
    PaymentSafetyGraphArtifact,
    PaymentStateGateDetails,
    TrustGateDetails,
    TrustGateKind,
)

from .contracts import (
    AcknowledgementRuntimeTarget,
    CustomerValueRuntimeTarget,
    IngressRuntimeBinding,
    MutationRuntimeTarget,
)


class RuntimePlanningError(ValueError):
    """Current static identities cannot produce an exact runtime plan."""


@dataclass(frozen=True)
class RuntimeTargetPlan:
    app_target: AppTargetRecord | None
    ingresses: tuple[IngressRuntimeBinding, ...]
    customer_values: tuple[CustomerValueRuntimeTarget, ...]
    mutations: tuple[MutationRuntimeTarget, ...]
    acknowledgements: tuple[AcknowledgementRuntimeTarget, ...]


def _selected_app_target(source_index: SourceIndexArtifact) -> AppTargetRecord | None:
    selected = tuple(
        item
        for item in source_index.app_targets
        if item.selection in {AppTargetSelection.CONFIGURED, AppTargetSelection.AUTO_SELECTED}
    )
    return selected[0] if len(selected) == 1 else None


def _binding(node: GraphNode) -> IngressRuntimeBinding:
    if (
        node.kind != GraphNodeKind.PAYMENT_INGRESS
        or node.backing_symbol_id is None
        or not isinstance(node.details, PaymentIngressDetails)
    ):
        raise RuntimePlanningError("runtime ingress binding requires an exact ingress graph node")
    registration = node.details.registration
    return IngressRuntimeBinding(
        ingress_node_id=node.node_id,
        route_registration_id=registration.route_registration_id,
        app_instance_id=registration.app_instance_id,
        ingress_symbol_id=node.backing_symbol_id,
        method=registration.method,
        effective_path=registration.effective_path,
        checkout_request_binding=node.details.checkout_request_binding,
    )


def _validate_mutation_assertion_evidence(
    applicability: ScenarioApplicabilityArtifact,
    graph: PaymentSafetyGraphArtifact,
    bindings: dict[str, IngressRuntimeBinding],
    mutations_by_route: dict[str, set[str]],
) -> None:
    nodes = {item.node_id: item for item in graph.nodes}
    controls = {item.control_id: item for item in applicability.normal_controls}
    for scenario in applicability.scenarios:
        if scenario.scenario_id not in {ScenarioId.SG_05, ScenarioId.SG_06}:
            continue
        for instance in scenario.instances:
            if instance.ingress_node_id is None:
                continue
            binding = bindings.get(instance.ingress_node_id)
            if binding is None:
                raise RuntimePlanningError("trust scenario refers to an unknown ingress binding")
            route_mutations = mutations_by_route.get(binding.route_registration_id, set())
            if scenario.scenario_id == ScenarioId.SG_05:
                control = (
                    controls.get(instance.normal_control_id)
                    if instance.normal_control_id is not None
                    else None
                )
                captured_gate_ids = {
                    edge.source_node_id
                    for edge in graph.edges
                    if edge.kind == GraphEdgeKind.BRANCHES_TO
                    and edge.branch is not None
                    and edge.branch.disposition == BranchDisposition.MATCHED
                    and any(
                        state.removeprefix("payment.") == "captured" for state in edge.branch.states
                    )
                    and (source := nodes.get(edge.source_node_id)) is not None
                    and isinstance(source.details, PaymentStateGateDetails)
                    and source.details.route_registration_id == binding.route_registration_id
                    and (
                        (
                            control is not None
                            and edge.target_node_id == control.customer_value_node_id
                        )
                        or control is None
                    )
                }
                expected = {
                    edge.target_node_id
                    for edge in graph.edges
                    if edge.kind == GraphEdgeKind.BRANCHES_TO
                    and edge.source_node_id in captured_gate_ids
                    and edge.branch is not None
                    and edge.branch.disposition == BranchDisposition.MATCHED
                    and any(
                        state.removeprefix("payment.") == "captured" for state in edge.branch.states
                    )
                    and edge.target_node_id in route_mutations
                }
            else:
                checkout_trust_ids = {
                    node.node_id
                    for node in graph.nodes
                    if isinstance(node.details, TrustGateDetails)
                    and node.details.route_registration_id == binding.route_registration_id
                    and node.details.trust_kind
                    in {
                        TrustGateKind.CHECKOUT_SIGNATURE_VERIFICATION,
                        TrustGateKind.SERVER_ORDER_IDENTITY_BINDING,
                    }
                }
                guarded = {
                    edge.target_node_id
                    for edge in graph.edges
                    if edge.kind == GraphEdgeKind.GUARDS
                    and edge.source_node_id in checkout_trust_ids
                }
                expected = {
                    node_id
                    for node_id in route_mutations
                    if node_id in guarded
                    or (
                        isinstance(
                            mutation_details := nodes[node_id].details,
                            MerchantStateMutationDetails,
                        )
                        and mutation_details.assigned_payment_state is not None
                    )
                }
            for assertion in instance.assertions:
                available = any(
                    reason.code == ApplicabilityReasonCode.MUTATION_TARGET_AVAILABLE
                    for reason in assertion.reasons
                )
                if not available:
                    continue
                observed = {
                    evidence.reference
                    for reason in assertion.reasons
                    for evidence in reason.evidence
                    if evidence.kind == EvidenceReferenceKind.GRAPH_NODE
                }
                if observed != expected:
                    raise RuntimePlanningError(
                        "mutation assertion evidence must match exact route mutation nodes"
                    )


def build_runtime_target_plan(
    source_index: SourceIndexArtifact,
    graph: PaymentSafetyGraphArtifact,
    applicability: ScenarioApplicabilityArtifact,
) -> RuntimeTargetPlan:
    if source_index.project_id != applicability.project_id:
        raise RuntimePlanningError("runtime inputs refer to different projects")
    if source_index.source_index_fingerprint != applicability.source_index_fingerprint:
        raise RuntimePlanningError("runtime source-index fingerprint is stale")
    if graph.graph_fingerprint != applicability.projected_graph_fingerprint:
        raise RuntimePlanningError("runtime graph fingerprint is stale")

    nodes = {item.node_id: item for item in graph.nodes}
    ingresses = tuple(
        sorted(
            (_binding(item) for item in graph.nodes if item.kind == GraphNodeKind.PAYMENT_INGRESS),
            key=lambda item: (item.route_registration_id, item.ingress_node_id),
        )
    )
    binding_by_node = {item.ingress_node_id: item for item in ingresses}
    binding_by_route: dict[str, IngressRuntimeBinding] = {}
    for item in ingresses:
        if item.route_registration_id in binding_by_route:
            raise RuntimePlanningError("one route registration produced multiple ingress nodes")
        binding_by_route[item.route_registration_id] = item

    customers: list[CustomerValueRuntimeTarget] = []
    for control in applicability.normal_controls:
        ingress = binding_by_node.get(control.ingress_node_id)
        node = nodes.get(control.customer_value_node_id)
        edge = next(
            (item for item in graph.edges if item.edge_id == control.connectivity_edge_id),
            None,
        )
        if (
            ingress is None
            or ingress.route_registration_id != control.route_registration_id
            or node is None
            or node.kind != GraphNodeKind.CUSTOMER_VALUE_ACTION
            or node.backing_symbol_id != control.customer_value_symbol_id
            or edge is None
            or edge.source_node_id != control.ingress_node_id
            or edge.target_node_id != control.customer_value_node_id
        ):
            raise RuntimePlanningError("normal control no longer matches exact runtime identities")
        customers.append(
            CustomerValueRuntimeTarget(
                ingress=ingress,
                normal_control_id=control.control_id,
                customer_value_node_id=control.customer_value_node_id,
                customer_value_symbol_id=control.customer_value_symbol_id,
                connectivity_edge_id=control.connectivity_edge_id,
                call_path_references=control.call_path_references,
                semantic_resolution_fingerprint=control.semantic_resolution_fingerprint,
            )
        )

    mutations: list[MutationRuntimeTarget] = []
    mutation_ids_by_route: dict[str, set[str]] = {}
    for node in graph.nodes:
        if not isinstance(node.details, MerchantStateMutationDetails):
            continue
        if node.backing_symbol_id is None:
            raise RuntimePlanningError("mutation node has no exact backing symbol")
        ingress = binding_by_route.get(node.details.route_registration_id)
        if ingress is None:
            raise RuntimePlanningError("mutation node has no exact ingress route")
        mutations.append(
            MutationRuntimeTarget(
                ingress=ingress,
                mutation_node_id=node.node_id,
                mutation_symbol_id=node.backing_symbol_id,
                structural_anchor=node.details.structural_anchor,
                mutation_kind=node.details.mutation_kind,
                carrier_reference=node.details.carrier_reference,
            )
        )
        mutation_ids_by_route.setdefault(ingress.route_registration_id, set()).add(node.node_id)

    acknowledgements: list[AcknowledgementRuntimeTarget] = []
    for node in graph.nodes:
        if not isinstance(node.details, AcknowledgementBoundaryDetails):
            continue
        if node.backing_symbol_id is None:
            raise RuntimePlanningError("acknowledgement node has no exact backing symbol")
        ingress = binding_by_route.get(node.details.route_registration_id)
        if ingress is None:
            raise RuntimePlanningError("acknowledgement node has no exact ingress route")
        acknowledgements.append(
            AcknowledgementRuntimeTarget(
                ingress=ingress,
                acknowledgement_node_id=node.node_id,
                acknowledgement_symbol_id=node.backing_symbol_id,
                structural_anchor=node.details.structural_anchor,
                exit_kind=node.details.exit_kind,
                status_code=node.details.status_code,
                outcome=node.details.outcome,
            )
        )

    _validate_mutation_assertion_evidence(
        applicability,
        graph,
        binding_by_node,
        mutation_ids_by_route,
    )
    return RuntimeTargetPlan(
        app_target=_selected_app_target(source_index),
        ingresses=ingresses,
        customer_values=tuple(sorted(customers, key=lambda item: item.normal_control_id)),
        mutations=tuple(sorted(mutations, key=lambda item: item.mutation_node_id)),
        acknowledgements=tuple(
            sorted(acknowledgements, key=lambda item: item.acknowledgement_node_id)
        ),
    )
