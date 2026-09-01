"""Pure deterministic Step 4 policy evidence and scenario applicability engine."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from stateguard import __version__
from stateguard.applicability.contracts import (
    SG01_ASSERTION_KEY,
    SG02_ASSERTION_KEY,
    SG03_ASSERTION_KEY,
    SG04_CUSTOMER_VALUE_ASSERTION_KEY,
    SG04_STATE_REGRESSION_ASSERTION_KEY,
    SG05_CUSTOMER_VALUE_ASSERTION_KEY,
    SG05_MUTATION_ASSERTION_KEY,
    SG06_CUSTOMER_VALUE_ASSERTION_KEY,
    SG06_MUTATION_ASSERTION_KEY,
    SG07_CUSTOMER_VALUE_ASSERTION_KEY,
    SG08_CAPTURE_ASSERTION_KEY,
    SG08_LATE_POLICY_ASSERTION_KEY,
    SG08_PRECAPTURE_ASSERTION_KEY,
    ApplicabilityReason,
    ApplicabilityReasonCode,
    ApplicabilityState,
    AssertionApplicability,
    AssertionRole,
    EvidenceReference,
    EvidenceReferenceKind,
    FulfilmentPolicyAssessment,
    LateAuthorisationPolicyAssessment,
    MerchantPolicyAssessment,
    NormalControlInstance,
    PolicyEvidenceStatus,
    ScenarioApplicability,
    ScenarioApplicabilityArtifact,
    ScenarioId,
    ScenarioInstance,
    applicability_fingerprint,
    roll_up_assertions,
)
from stateguard.contracts.config import (
    FulfilmentPolicy,
    LateAuthorisationPolicy,
    StateGuardConfig,
)
from stateguard.contracts.identity import (
    assertion_id,
    canonical_json,
    fingerprint_json,
    normal_control_id,
    scenario_instance_id,
)
from stateguard.discovery.contracts import SourceIndexArtifact
from stateguard.graph.contracts import (
    AcknowledgementBoundaryDetails,
    AcknowledgementOutcome,
    BranchDisposition,
    GraphCompleteness,
    GraphDiagnosticImpact,
    GraphDiagnosticRecord,
    GraphEdge,
    GraphEdgeKind,
    GraphNode,
    GraphNodeKind,
    MerchantStateMutationDetails,
    PaymentIngressDetails,
    PaymentIngressKind,
    PaymentSafetyGraphArtifact,
    PaymentStateGateDetails,
    TrustGateDetails,
    TrustGateKind,
)
from stateguard.rules.razorpay import RazorpayProtocolRuleId, razorpay_rule_fingerprint
from stateguard.semantics.contracts import CustomerValueResolution, ResolutionState


def customer_value_allowed(
    fulfilment: FulfilmentPolicy,
    late_authorisation: LateAuthorisationPolicy,
    *,
    payment_is_late_authorised: bool,
    payment_state: str,
) -> bool:
    """Compose late-payment eligibility with the ordinary fulfilment threshold."""

    if payment_is_late_authorised and late_authorisation == LateAuthorisationPolicy.DO_NOT_FULFIL:
        return False
    normalized = payment_state.strip().casefold().removeprefix("payment.")
    if fulfilment == FulfilmentPolicy.CAPTURE_REQUIRED:
        return normalized == "captured"
    return normalized in {"authorized", "captured"}


def _evidence(kind: EvidenceReferenceKind, reference: str) -> EvidenceReference:
    return EvidenceReference(kind=kind, reference=reference)


def _reason(
    code: ApplicabilityReasonCode,
    *evidence: EvidenceReference,
) -> tuple[ApplicabilityReason, ...]:
    return (ApplicabilityReason(code=code, evidence=tuple(evidence)),)


def _normal_controls(
    graph: PaymentSafetyGraphArtifact,
    resolution: CustomerValueResolution | None,
    resolution_fingerprint: str | None,
) -> tuple[NormalControlInstance, ...]:
    if (
        resolution is None
        or resolution.state != ResolutionState.UNIQUE
        or resolution.selected_symbol_id is None
        or resolution_fingerprint is None
    ):
        return ()
    nodes = {item.node_id: item for item in graph.nodes}
    controls: list[NormalControlInstance] = []
    for edge in graph.edges:
        source = nodes.get(edge.source_node_id)
        target = nodes.get(edge.target_node_id)
        if (
            edge.kind != GraphEdgeKind.CALLS
            or source is None
            or target is None
            or not isinstance(source.details, PaymentIngressDetails)
            or target.kind != GraphNodeKind.CUSTOMER_VALUE_ACTION
            or target.backing_symbol_id != resolution.selected_symbol_id
        ):
            continue
        call_path = tuple(
            record.reference
            for record in edge.provenance
            if record.reference.startswith("call-site:")
        )
        if not call_path:
            continue
        control_id = normal_control_id(
            source.node_id,
            source.details.registration.route_registration_id,
            target.node_id,
            resolution.selected_symbol_id,
            edge.edge_id,
            *call_path,
            resolution_fingerprint,
        )
        controls.append(
            NormalControlInstance(
                control_id=control_id,
                ingress_node_id=source.node_id,
                route_registration_id=source.details.registration.route_registration_id,
                ingress_kind=source.details.ingress_kind,
                customer_value_node_id=target.node_id,
                customer_value_symbol_id=resolution.selected_symbol_id,
                connectivity_edge_id=edge.edge_id,
                call_path_references=call_path,
                semantic_resolution_fingerprint=resolution_fingerprint,
            )
        )
    return tuple(sorted(controls, key=canonical_json))


def _relevant_diagnostics(
    graph: PaymentSafetyGraphArtifact,
    controls: tuple[NormalControlInstance, ...],
) -> tuple[GraphDiagnosticRecord, ...]:
    route_ids = {item.route_registration_id for item in controls}
    return tuple(
        item
        for item in graph.diagnostics
        if item.impact == GraphDiagnosticImpact.COVERAGE_REDUCED
        and item.route_registration_id in route_ids
    )


def _policy_control_evidence(control: NormalControlInstance) -> dict[str, object]:
    return {
        "ingress_node_id": control.ingress_node_id,
        "route_registration_id": control.route_registration_id,
        "ingress_kind": control.ingress_kind.value,
        "customer_value_node_id": control.customer_value_node_id,
        "customer_value_symbol_id": control.customer_value_symbol_id,
        "call_path_references": control.call_path_references,
    }


def _policy_state_edge_evidence(
    edge: GraphEdge,
    nodes: dict[str, GraphNode],
) -> dict[str, object]:
    source = nodes[edge.source_node_id]
    assert edge.branch is not None
    return {
        "source_node_id": edge.source_node_id,
        "route_registration_id": _route_id_for_node(source),
        "target_node_id": edge.target_node_id,
        "disposition": edge.branch.disposition.value,
        "states": tuple(sorted(edge.branch.states)),
        "provenance": tuple(
            {
                "kind": record.kind.value,
                "reference": record.reference,
            }
            for record in edge.provenance
        ),
    }


def _policy_diagnostic_evidence(diagnostic: GraphDiagnosticRecord) -> dict[str, object]:
    return {
        "code": diagnostic.code.value,
        "impact": diagnostic.impact.value,
        "candidate_kind": (
            diagnostic.candidate_kind.value if diagnostic.candidate_kind is not None else None
        ),
        "reason": diagnostic.reason.value if diagnostic.reason is not None else None,
        "symbol_id": diagnostic.symbol_id,
        "route_registration_id": diagnostic.route_registration_id,
    }


def _policy_webhook_evidence(node: GraphNode) -> dict[str, object]:
    assert isinstance(node.details, PaymentIngressDetails)
    registration = node.details.registration
    return {
        "node_id": node.node_id,
        "route_registration_id": registration.route_registration_id,
        "method": registration.method,
        "effective_path": registration.effective_path,
        "ingress_kind": node.details.ingress_kind.value,
    }


def _route_id_for_node(node: GraphNode) -> str | None:
    details = node.details
    if isinstance(details, PaymentIngressDetails):
        return details.registration.route_registration_id
    return getattr(details, "route_registration_id", None)


def _policy_assessment(
    config: StateGuardConfig,
    graph: PaymentSafetyGraphArtifact,
    controls: tuple[NormalControlInstance, ...],
) -> MerchantPolicyAssessment:
    nodes = {item.node_id: item for item in graph.nodes}
    routes = {item.route_registration_id for item in controls}
    state_edges = tuple(
        edge
        for edge in graph.edges
        if edge.kind == GraphEdgeKind.BRANCHES_TO
        and edge.branch is not None
        and edge.branch.disposition == BranchDisposition.MATCHED
        and edge.target_node_id in {item.customer_value_node_id for item in controls}
        and (source := nodes.get(edge.source_node_id)) is not None
        and _route_id_for_node(source) in routes
    )
    observed_states = tuple(
        sorted(
            {
                state.removeprefix("payment.")
                for edge in state_edges
                for state in (edge.branch.states if edge.branch is not None else ())
                if state.removeprefix("payment.") in {"authorized", "captured"}
            }
        )
    )
    states_by_route: dict[str, set[str]] = {item.route_registration_id: set() for item in controls}
    for edge in state_edges:
        source = nodes[edge.source_node_id]
        route_id = _route_id_for_node(source)
        if route_id is None or edge.branch is None:
            continue
        states_by_route.setdefault(route_id, set()).update(
            state.removeprefix("payment.")
            for state in edge.branch.states
            if state.removeprefix("payment.") in {"authorized", "captured"}
        )
    relevant_diagnostics = _relevant_diagnostics(graph, controls)
    if (
        relevant_diagnostics
        or not controls
        or not observed_states
        or any(not states for states in states_by_route.values())
    ):
        evidence_status = PolicyEvidenceStatus.INSUFFICIENT_EVIDENCE
        suggestion = None
    elif observed_states == ("captured",):
        evidence_status = PolicyEvidenceStatus.CONSISTENT_SUGGESTION
        suggestion = FulfilmentPolicy.CAPTURE_REQUIRED
    elif observed_states == ("authorized",):
        evidence_status = PolicyEvidenceStatus.CONSISTENT_SUGGESTION
        suggestion = FulfilmentPolicy.AUTHORIZED_ALLOWED
    else:
        evidence_status = PolicyEvidenceStatus.CONFLICTING_EVIDENCE
        suggestion = None

    fulfilment_fp = fingerprint_json(
        {
            "rules": {
                RazorpayProtocolRuleId.CAPTURE_BEFORE_FULFILMENT.value: (
                    razorpay_rule_fingerprint(RazorpayProtocolRuleId.CAPTURE_BEFORE_FULFILMENT)
                )
            },
            "controls": tuple(_policy_control_evidence(item) for item in controls),
            "state_edges": tuple(_policy_state_edge_evidence(item, nodes) for item in state_edges),
            "diagnostics": tuple(
                _policy_diagnostic_evidence(item) for item in relevant_diagnostics
            ),
        }
    )
    webhook_controls = tuple(
        item for item in controls if item.ingress_kind == PaymentIngressKind.WEBHOOK
    )
    webhook_nodes = tuple(
        item
        for item in graph.nodes
        if isinstance(item.details, PaymentIngressDetails)
        and item.details.ingress_kind == PaymentIngressKind.WEBHOOK
        and item.node_id in {control.ingress_node_id for control in webhook_controls}
    )
    late_fp = fingerprint_json(
        {
            "rules": {
                RazorpayProtocolRuleId.LATE_AUTHORISATION_BUSINESS_POLICY.value: (
                    razorpay_rule_fingerprint(
                        RazorpayProtocolRuleId.LATE_AUTHORISATION_BUSINESS_POLICY
                    )
                )
            },
            "webhook_controls": tuple(_policy_control_evidence(item) for item in webhook_controls),
            "webhook_nodes": tuple(_policy_webhook_evidence(item) for item in webhook_nodes),
            "state_edges": tuple(
                _policy_state_edge_evidence(edge, nodes)
                for edge in state_edges
                if _route_id_for_node(nodes[edge.source_node_id])
                in {item.route_registration_id for item in webhook_controls}
            ),
            "diagnostics": tuple(
                _policy_diagnostic_evidence(item)
                for item in _relevant_diagnostics(graph, webhook_controls)
            ),
        }
    )
    configured = config.policy
    fulfilment_config = configured.fulfilment if configured is not None else None
    late_config = configured.late_authorisation if configured is not None else None
    confirmed_fulfilment = fulfilment_config.value if fulfilment_config is not None else None
    return MerchantPolicyAssessment(
        fulfilment=FulfilmentPolicyAssessment(
            evidence_status=evidence_status,
            evidence_fingerprint=fulfilment_fp,
            observed_states=observed_states,
            suggested_policy=suggestion,
            confirmed_policy=confirmed_fulfilment,
            evidence_current=(
                fulfilment_config.evidence_fingerprint == fulfilment_fp
                if fulfilment_config is not None
                else None
            ),
            implementation_mismatch=(
                confirmed_fulfilment is not None
                and suggestion is not None
                and confirmed_fulfilment != suggestion
            ),
        ),
        late_authorisation=LateAuthorisationPolicyAssessment(
            evidence_fingerprint=late_fp,
            confirmed_policy=late_config.value if late_config is not None else None,
            evidence_current=(
                late_config.evidence_fingerprint == late_fp if late_config is not None else None
            ),
        ),
    )


def _assertion(
    instance_id: str,
    key: str,
    role: AssertionRole,
    state: ApplicabilityState,
    reasons: tuple[ApplicabilityReason, ...],
    control: NormalControlInstance | None = None,
) -> AssertionApplicability:
    return AssertionApplicability(
        assertion_id=assertion_id(instance_id, key),
        key=key,
        role=role,
        state=state,
        reasons=reasons,
        normal_control_id=control.control_id if control is not None else None,
    )


def _instance(
    scenario: ScenarioId,
    discriminator: str,
    assertions: Iterable[AssertionApplicability],
    *,
    ingress: GraphNode | None = None,
    control: NormalControlInstance | None = None,
) -> ScenarioInstance:
    instance_id = scenario_instance_id(scenario.value, discriminator)
    values = tuple(assertions)
    return ScenarioInstance(
        instance_id=instance_id,
        state=roll_up_assertions(values),
        ingress_node_id=ingress.node_id if ingress is not None else None,
        normal_control_id=control.control_id if control is not None else None,
        route_registration_id=(control.route_registration_id if control is not None else None),
        customer_value_node_id=(control.customer_value_node_id if control is not None else None),
        customer_value_symbol_id=(
            control.customer_value_symbol_id if control is not None else None
        ),
        assertions=values,
    )


def _scenario(scenario: ScenarioId, instances: Iterable[ScenarioInstance]) -> ScenarioApplicability:
    values = tuple(instances)
    return ScenarioApplicability(
        scenario_id=scenario,
        state=roll_up_assertions(
            assertion for instance in values for assertion in instance.assertions
        ),
        instances=values,
    )


def _fallback_state(
    graph: PaymentSafetyGraphArtifact,
    resolution: CustomerValueResolution | None,
    ingresses: tuple[GraphNode, ...],
) -> tuple[ApplicabilityState, tuple[ApplicabilityReason, ...]]:
    if not ingresses:
        if graph.completeness == GraphCompleteness.PARTIAL:
            return (
                ApplicabilityState.INDETERMINATE,
                _reason(ApplicabilityReasonCode.GRAPH_COVERAGE_INSUFFICIENT),
            )
        return ApplicabilityState.NOT_APPLICABLE, _reason(ApplicabilityReasonCode.INGRESS_ABSENT)
    if resolution is None or resolution.state != ResolutionState.UNIQUE:
        return (
            ApplicabilityState.NEEDS_INPUT,
            _reason(ApplicabilityReasonCode.CUSTOMER_VALUE_UNRESOLVED),
        )
    if graph.completeness == GraphCompleteness.PARTIAL:
        return (
            ApplicabilityState.INDETERMINATE,
            _reason(ApplicabilityReasonCode.GRAPH_COVERAGE_INSUFFICIENT),
        )
    return (
        ApplicabilityState.NOT_APPLICABLE,
        _reason(ApplicabilityReasonCode.CUSTOMER_VALUE_PATH_ABSENT),
    )


def _policy_state(
    policy: MerchantPolicyAssessment,
    control: NormalControlInstance,
) -> tuple[ApplicabilityState, tuple[ApplicabilityReason, ...]]:
    if policy.fulfilment.confirmed_policy is None:
        return (
            ApplicabilityState.NEEDS_INPUT,
            _reason(ApplicabilityReasonCode.FULFILMENT_POLICY_REQUIRED),
        )
    if policy.fulfilment.evidence_current is not True:
        return (
            ApplicabilityState.NEEDS_INPUT,
            _reason(ApplicabilityReasonCode.FULFILMENT_POLICY_STALE),
        )
    return (
        ApplicabilityState.APPLICABLE,
        _reason(
            ApplicabilityReasonCode.EXACT_CONTROL_AVAILABLE,
            _evidence(EvidenceReferenceKind.NORMAL_CONTROL, control.control_id),
        ),
    )


def _control_state_edges(
    graph: PaymentSafetyGraphArtifact,
    nodes: dict[str, GraphNode],
    control: NormalControlInstance,
) -> tuple[GraphEdge, ...]:
    return tuple(
        edge
        for edge in graph.edges
        if edge.kind == GraphEdgeKind.BRANCHES_TO
        and edge.branch is not None
        and edge.branch.disposition == BranchDisposition.MATCHED
        and edge.target_node_id == control.customer_value_node_id
        and (source := nodes.get(edge.source_node_id)) is not None
        and _route_id_for_node(source) == control.route_registration_id
    )


def _regression_mutations_for_control(
    graph: PaymentSafetyGraphArtifact,
    nodes: dict[str, GraphNode],
    control: NormalControlInstance,
) -> tuple[GraphNode, ...]:
    mutations_by_carrier: dict[str, dict[str, GraphNode]] = {}
    for mutation_edge in graph.edges:
        mutation = nodes.get(mutation_edge.target_node_id)
        state_gate = nodes.get(mutation_edge.source_node_id)
        if (
            mutation_edge.kind != GraphEdgeKind.BRANCHES_TO
            or mutation_edge.branch is None
            or mutation_edge.branch.disposition != BranchDisposition.MATCHED
            or state_gate is None
            or not isinstance(state_gate.details, PaymentStateGateDetails)
        ):
            continue
        if mutation is None or not isinstance(mutation.details, MerchantStateMutationDetails):
            continue
        mutation_details = mutation.details
        state_details = state_gate.details
        if (
            mutation_details.route_registration_id != control.route_registration_id
            or state_details.route_registration_id != control.route_registration_id
        ):
            continue
        assigned = mutation_details.assigned_payment_state
        if assigned not in {"authorized", "captured"}:
            continue
        mutation_states = {state.removeprefix("payment.") for state in mutation_edge.branch.states}
        if assigned not in mutation_states:
            continue
        mutations_by_carrier.setdefault(mutation_details.carrier_reference, {})[assigned] = mutation
    selected = {
        node.node_id: node
        for values in mutations_by_carrier.values()
        if {"authorized", "captured"} <= set(values)
        for node in values.values()
    }
    return tuple(sorted(selected.values(), key=canonical_json))


def _checkout_protected_mutations(
    graph: PaymentSafetyGraphArtifact,
    nodes: dict[str, GraphNode],
    ingress: GraphNode,
) -> tuple[GraphNode, ...]:
    if not isinstance(ingress.details, PaymentIngressDetails):
        return ()
    route_id = ingress.details.registration.route_registration_id
    trust_ids = {
        node.node_id
        for node in graph.nodes
        if isinstance(node.details, TrustGateDetails)
        and node.details.route_registration_id == route_id
        and node.details.trust_kind
        in {
            TrustGateKind.CHECKOUT_SIGNATURE_VERIFICATION,
            TrustGateKind.SERVER_ORDER_IDENTITY_BINDING,
        }
    }
    guarded = {
        edge.target_node_id
        for edge in graph.edges
        if edge.kind == GraphEdgeKind.GUARDS and edge.source_node_id in trust_ids
    }
    return tuple(
        sorted(
            (
                node
                for node in graph.nodes
                if isinstance(node.details, MerchantStateMutationDetails)
                and node.details.route_registration_id == route_id
                and (node.node_id in guarded or node.details.assigned_payment_state is not None)
            ),
            key=canonical_json,
        )
    )


def _route_payment_states(
    graph: PaymentSafetyGraphArtifact,
    control: NormalControlInstance,
) -> frozenset[str]:
    return frozenset(
        state.removeprefix("payment.")
        for node in graph.nodes
        if isinstance(node.details, PaymentStateGateDetails)
        and node.details.route_registration_id == control.route_registration_id
        for state in node.details.states
    )


def _captured_webhook_control_evidence(
    graph: PaymentSafetyGraphArtifact,
    nodes: dict[str, GraphNode],
    control: NormalControlInstance,
) -> tuple[EvidenceReference, ...] | None:
    """Bind captured-state evidence to one exact webhook normal control."""

    ingress = nodes.get(control.ingress_node_id)
    if (
        ingress is None
        or not isinstance(ingress.details, PaymentIngressDetails)
        or ingress.details.ingress_kind != PaymentIngressKind.WEBHOOK
        or ingress.details.registration.method != "POST"
        or _relevant_diagnostics(graph, (control,))
    ):
        return None
    captured_control_edges = tuple(
        edge
        for edge in _control_state_edges(graph, nodes, control)
        if edge.branch is not None
        and any(state.removeprefix("payment.") == "captured" for state in edge.branch.states)
    )
    if not captured_control_edges:
        return None
    return (
        _evidence(EvidenceReferenceKind.NORMAL_CONTROL, control.control_id),
        *(
            evidence
            for edge in captured_control_edges
            for evidence in (
                _evidence(EvidenceReferenceKind.GRAPH_NODE, edge.source_node_id),
                _evidence(EvidenceReferenceKind.GRAPH_EDGE, edge.edge_id),
            )
        ),
    )


def _captured_path_mutations(
    graph: PaymentSafetyGraphArtifact,
    nodes: dict[str, GraphNode],
    ingress: GraphNode,
    control: NormalControlInstance | None,
) -> tuple[GraphNode, ...]:
    """Return only mutations proven below the captured path used by the valid control."""

    if (
        not isinstance(ingress.details, PaymentIngressDetails)
        or ingress.details.ingress_kind != PaymentIngressKind.WEBHOOK
        or ingress.details.registration.method != "POST"
    ):
        return ()
    route_id = ingress.details.registration.route_registration_id
    if control is not None:
        captured_gate_ids = {
            edge.source_node_id
            for edge in _control_state_edges(graph, nodes, control)
            if edge.branch is not None
            and any(state.removeprefix("payment.") == "captured" for state in edge.branch.states)
        }
    else:
        captured_gate_ids = {
            node.node_id
            for node in graph.nodes
            if isinstance(node.details, PaymentStateGateDetails)
            and node.details.route_registration_id == route_id
            and any(state.removeprefix("payment.") == "captured" for state in node.details.states)
        }
    mutation_ids = {
        edge.target_node_id
        for edge in graph.edges
        if edge.kind == GraphEdgeKind.BRANCHES_TO
        and edge.source_node_id in captured_gate_ids
        and edge.branch is not None
        and edge.branch.disposition == BranchDisposition.MATCHED
        and any(state.removeprefix("payment.") == "captured" for state in edge.branch.states)
        and (mutation := nodes.get(edge.target_node_id)) is not None
        and isinstance(mutation.details, MerchantStateMutationDetails)
        and mutation.details.route_registration_id == route_id
    }
    return tuple(
        sorted(
            (nodes[node_id] for node_id in mutation_ids),
            key=canonical_json,
        )
    )


def _normal_capture_state(
    graph: PaymentSafetyGraphArtifact,
    nodes: dict[str, GraphNode],
    policy: MerchantPolicyAssessment,
    control: NormalControlInstance,
) -> tuple[ApplicabilityState, tuple[ApplicabilityReason, ...]]:
    policy_state, policy_reasons = _policy_state(policy, control)
    if policy_state != ApplicabilityState.APPLICABLE:
        return policy_state, policy_reasons
    if policy.fulfilment.confirmed_policy != FulfilmentPolicy.CAPTURE_REQUIRED:
        return (
            ApplicabilityState.INDETERMINATE,
            _reason(ApplicabilityReasonCode.NORMAL_CAPTURE_THRESHOLD_UNPROVEN),
        )
    captured_control_evidence = _captured_webhook_control_evidence(graph, nodes, control)
    if captured_control_evidence is None:
        return (
            ApplicabilityState.INDETERMINATE,
            _reason(ApplicabilityReasonCode.NORMAL_CAPTURE_THRESHOLD_UNPROVEN),
        )
    return (
        ApplicabilityState.APPLICABLE,
        _reason(
            ApplicabilityReasonCode.NORMAL_CAPTURE_THRESHOLD_AVAILABLE,
            *captured_control_evidence,
        ),
    )


def _duplicate_capture_state(
    graph: PaymentSafetyGraphArtifact,
    nodes: dict[str, GraphNode],
    policy: MerchantPolicyAssessment,
    control: NormalControlInstance,
) -> tuple[ApplicabilityState, tuple[ApplicabilityReason, ...]]:
    policy_state, policy_reasons = _policy_state(policy, control)
    if policy_state != ApplicabilityState.APPLICABLE:
        return policy_state, policy_reasons
    captured_control_evidence = _captured_webhook_control_evidence(graph, nodes, control)
    if captured_control_evidence is None:
        return (
            ApplicabilityState.INDETERMINATE,
            _reason(ApplicabilityReasonCode.CAPTURED_EVENT_TARGET_UNPROVEN),
        )
    return (
        ApplicabilityState.APPLICABLE,
        _reason(
            ApplicabilityReasonCode.CAPTURED_EVENT_TARGET_AVAILABLE,
            *captured_control_evidence,
        ),
    )


def _catalog_scenarios(
    graph: PaymentSafetyGraphArtifact,
    resolution: CustomerValueResolution | None,
    controls: tuple[NormalControlInstance, ...],
    policy: MerchantPolicyAssessment,
) -> tuple[ScenarioApplicability, ...]:
    nodes = {item.node_id: item for item in graph.nodes}
    ingresses = tuple(
        item for item in graph.nodes if isinstance(item.details, PaymentIngressDetails)
    )
    webhook_ingresses = tuple(
        item
        for item in ingresses
        if isinstance(item.details, PaymentIngressDetails)
        and item.details.ingress_kind == PaymentIngressKind.WEBHOOK
    )
    checkout_ingresses = tuple(
        item
        for item in ingresses
        if isinstance(item.details, PaymentIngressDetails)
        and item.details.ingress_kind == PaymentIngressKind.CHECKOUT_CALLBACK
    )
    webhook_controls = tuple(
        item for item in controls if item.ingress_kind == PaymentIngressKind.WEBHOOK
    )
    controls_by_ingress: dict[str, tuple[NormalControlInstance, ...]] = {
        ingress.node_id: tuple(item for item in controls if item.ingress_node_id == ingress.node_id)
        for ingress in ingresses
    }

    scenarios: list[ScenarioApplicability] = []

    sg01_instances: list[ScenarioInstance] = []
    # SG-01 proves the normal captured-webhook path. Other normal-control
    # domains (notably Checkout callbacks) remain available to scenarios that
    # own those inputs, but must not create SG-01 instances that SG-01 can
    # never authoritatively execute.
    for control in webhook_controls:
        instance_id = scenario_instance_id(ScenarioId.SG_01.value, control.control_id)
        state, reasons = _normal_capture_state(graph, nodes, policy, control)
        sg01_instances.append(
            _instance(
                ScenarioId.SG_01,
                control.control_id,
                (
                    _assertion(
                        instance_id,
                        SG01_ASSERTION_KEY,
                        AssertionRole.CORE,
                        state,
                        reasons,
                        control,
                    ),
                ),
                ingress=nodes[control.ingress_node_id],
                control=control,
            )
        )
    if not sg01_instances:
        state, reasons = _fallback_state(graph, resolution, ingresses)
        iid = scenario_instance_id(ScenarioId.SG_01.value, "catalog")
        sg01_instances.append(
            _instance(
                ScenarioId.SG_01,
                "catalog",
                (
                    _assertion(
                        iid,
                        SG01_ASSERTION_KEY,
                        AssertionRole.CORE,
                        state,
                        reasons,
                    ),
                ),
            )
        )
    scenarios.append(_scenario(ScenarioId.SG_01, sg01_instances))

    def controls_or_fallback(
        scenario: ScenarioId,
        key: str,
        available: tuple[NormalControlInstance, ...],
        relevant_ingresses: tuple[GraphNode, ...],
    ) -> ScenarioApplicability:
        instances: list[ScenarioInstance] = []
        for control in available:
            iid = scenario_instance_id(scenario.value, control.control_id)
            state, reasons = _policy_state(policy, control)
            instances.append(
                _instance(
                    scenario,
                    control.control_id,
                    (_assertion(iid, key, AssertionRole.CORE, state, reasons, control),),
                    ingress=nodes[control.ingress_node_id],
                    control=control,
                )
            )
        if not instances:
            state, reasons = _fallback_state(graph, resolution, relevant_ingresses)
            iid = scenario_instance_id(scenario.value, "catalog")
            instances.append(
                _instance(
                    scenario,
                    "catalog",
                    (_assertion(iid, key, AssertionRole.CORE, state, reasons),),
                )
            )
        return _scenario(scenario, instances)

    sg02_instances: list[ScenarioInstance] = []
    for control in webhook_controls:
        iid = scenario_instance_id(ScenarioId.SG_02.value, control.control_id)
        state, reasons = _duplicate_capture_state(graph, nodes, policy, control)
        sg02_instances.append(
            _instance(
                ScenarioId.SG_02,
                control.control_id,
                (
                    _assertion(
                        iid,
                        SG02_ASSERTION_KEY,
                        AssertionRole.CORE,
                        state,
                        reasons,
                        control,
                    ),
                ),
                ingress=nodes[control.ingress_node_id],
                control=control,
            )
        )
    if not sg02_instances:
        state, reasons = _fallback_state(graph, resolution, webhook_ingresses)
        iid = scenario_instance_id(ScenarioId.SG_02.value, "catalog")
        sg02_instances.append(
            _instance(
                ScenarioId.SG_02,
                "catalog",
                (
                    _assertion(
                        iid,
                        SG02_ASSERTION_KEY,
                        AssertionRole.CORE,
                        state,
                        reasons,
                    ),
                ),
            )
        )
    scenarios.append(_scenario(ScenarioId.SG_02, sg02_instances))

    sg03_instances: list[ScenarioInstance] = []
    for control in webhook_controls:
        iid = scenario_instance_id(ScenarioId.SG_03.value, control.control_id)
        base_state, base_reasons = _duplicate_capture_state(graph, nodes, policy, control)
        before_ack = tuple(
            edge
            for edge in graph.edges
            if edge.kind == GraphEdgeKind.ACKNOWLEDGES_AFTER
            and edge.target_node_id == control.customer_value_node_id
            and (ack := nodes.get(edge.source_node_id)) is not None
            and _route_id_for_node(ack) == control.route_registration_id
            and isinstance(ack.details, AcknowledgementBoundaryDetails)
            and ack.details.outcome == AcknowledgementOutcome.SUCCESS_2XX
            and ack.details.status_code is not None
        )
        if base_state != ApplicabilityState.APPLICABLE:
            state, reasons = base_state, base_reasons
        elif len(before_ack) == 1:
            state = ApplicabilityState.APPLICABLE
            reasons = _reason(
                ApplicabilityReasonCode.VALUE_BEFORE_ACK_PROVEN,
                *(evidence for reason in base_reasons for evidence in reason.evidence),
                _evidence(EvidenceReferenceKind.GRAPH_NODE, before_ack[0].source_node_id),
                *(_evidence(EvidenceReferenceKind.GRAPH_EDGE, edge.edge_id) for edge in before_ack),
            )
        else:
            state = ApplicabilityState.INDETERMINATE
            reasons = _reason(ApplicabilityReasonCode.ACK_ORDER_UNRESOLVED)
        sg03_instances.append(
            _instance(
                ScenarioId.SG_03,
                control.control_id,
                (_assertion(iid, SG03_ASSERTION_KEY, AssertionRole.CORE, state, reasons, control),),
                ingress=nodes[control.ingress_node_id],
                control=control,
            )
        )
    if not sg03_instances:
        state, reasons = _fallback_state(graph, resolution, webhook_ingresses)
        iid = scenario_instance_id(ScenarioId.SG_03.value, "catalog")
        sg03_instances.append(
            _instance(
                ScenarioId.SG_03,
                "catalog",
                (_assertion(iid, SG03_ASSERTION_KEY, AssertionRole.CORE, state, reasons),),
            )
        )
    scenarios.append(_scenario(ScenarioId.SG_03, sg03_instances))

    sg04_instances: list[ScenarioInstance] = []
    for control in webhook_controls:
        iid = scenario_instance_id(ScenarioId.SG_04.value, control.control_id)
        state, reasons = _duplicate_capture_state(graph, nodes, policy, control)
        regression_mutations = _regression_mutations_for_control(graph, nodes, control)
        optional_state = (
            ApplicabilityState.APPLICABLE
            if regression_mutations and not _relevant_diagnostics(graph, (control,))
            else (
                ApplicabilityState.INDETERMINATE
                if _relevant_diagnostics(graph, (control,))
                else ApplicabilityState.NOT_APPLICABLE
            )
        )
        if regression_mutations:
            optional_reason = ApplicabilityReasonCode.STATE_REGRESSION_TARGET_AVAILABLE
        elif optional_state == ApplicabilityState.INDETERMINATE:
            optional_reason = ApplicabilityReasonCode.STATE_REGRESSION_TARGET_UNRESOLVED
        else:
            optional_reason = ApplicabilityReasonCode.STATE_REGRESSION_TARGET_ABSENT
        sg04_instances.append(
            _instance(
                ScenarioId.SG_04,
                control.control_id,
                (
                    _assertion(
                        iid,
                        SG04_CUSTOMER_VALUE_ASSERTION_KEY,
                        AssertionRole.CORE,
                        state,
                        reasons,
                        control,
                    ),
                    _assertion(
                        iid,
                        SG04_STATE_REGRESSION_ASSERTION_KEY,
                        AssertionRole.OPTIONAL,
                        optional_state,
                        _reason(
                            optional_reason,
                            *(
                                _evidence(EvidenceReferenceKind.GRAPH_NODE, node.node_id)
                                for node in regression_mutations
                            ),
                        ),
                        control,
                    ),
                ),
                ingress=nodes[control.ingress_node_id],
                control=control,
            )
        )
    if not sg04_instances:
        state, reasons = _fallback_state(graph, resolution, webhook_ingresses)
        iid = scenario_instance_id(ScenarioId.SG_04.value, "catalog")
        sg04_instances.append(
            _instance(
                ScenarioId.SG_04,
                "catalog",
                (
                    _assertion(
                        iid,
                        SG04_CUSTOMER_VALUE_ASSERTION_KEY,
                        AssertionRole.CORE,
                        state,
                        reasons,
                    ),
                ),
            )
        )
    scenarios.append(_scenario(ScenarioId.SG_04, sg04_instances))

    def trust_scenario(
        scenario: ScenarioId,
        relevant_ingresses: tuple[GraphNode, ...],
        value_key: str,
        mutation_key: str,
    ) -> ScenarioApplicability:
        instances: list[ScenarioInstance] = []
        for ingress in relevant_ingresses:
            route_id = _route_id_for_node(ingress)
            route_mutations = tuple(
                item
                for item in graph.nodes
                if isinstance(item.details, MerchantStateMutationDetails)
                and item.details.route_registration_id == route_id
            )
            checkout_binding = (
                ingress.details.checkout_request_binding
                if isinstance(ingress.details, PaymentIngressDetails)
                else None
            )
            matched_controls = controls_by_ingress.get(ingress.node_id, ())
            targets: tuple[NormalControlInstance | None, ...] = matched_controls or (None,)
            for control in targets:
                discriminator = control.control_id if control is not None else ingress.node_id
                iid = scenario_instance_id(scenario.value, discriminator)
                mutations = (
                    _captured_path_mutations(graph, nodes, ingress, control)
                    if scenario == ScenarioId.SG_05
                    else _checkout_protected_mutations(graph, nodes, ingress)
                )
                if control is not None:
                    if scenario == ScenarioId.SG_05:
                        captured_control_evidence = _captured_webhook_control_evidence(
                            graph,
                            nodes,
                            control,
                        )
                        if captured_control_evidence is None:
                            value_state = ApplicabilityState.INDETERMINATE
                            value_reasons = _reason(
                                ApplicabilityReasonCode.CAPTURED_EVENT_TARGET_UNPROVEN
                            )
                        else:
                            value_state = ApplicabilityState.APPLICABLE
                            value_reasons = _reason(
                                ApplicabilityReasonCode.CAPTURED_EVENT_TARGET_AVAILABLE,
                                *captured_control_evidence,
                            )
                    elif checkout_binding is None:
                        value_state = ApplicabilityState.INDETERMINATE
                        value_reasons = _reason(
                            ApplicabilityReasonCode.CHECKOUT_REQUEST_BINDING_UNRESOLVED
                        )
                    else:
                        value_state = ApplicabilityState.APPLICABLE
                        value_reasons = _reason(
                            ApplicabilityReasonCode.CHECKOUT_REQUEST_BINDING_AVAILABLE,
                            _evidence(EvidenceReferenceKind.NORMAL_CONTROL, control.control_id),
                        )
                else:
                    value_state, value_reasons = _fallback_state(graph, resolution, (ingress,))
                mutation_state = (
                    ApplicabilityState.INDETERMINATE
                    if scenario == ScenarioId.SG_06 and checkout_binding is None
                    else ApplicabilityState.APPLICABLE
                    if mutations
                    else (
                        ApplicabilityState.INDETERMINATE
                        if graph.completeness == GraphCompleteness.PARTIAL or route_mutations
                        else ApplicabilityState.NOT_APPLICABLE
                    )
                )
                mutation_reason = (
                    ApplicabilityReasonCode.CHECKOUT_REQUEST_BINDING_UNRESOLVED
                    if scenario == ScenarioId.SG_06 and checkout_binding is None
                    else ApplicabilityReasonCode.MUTATION_TARGET_AVAILABLE
                    if mutations
                    else ApplicabilityReasonCode.MUTATION_TARGET_ABSENT
                )
                mutation_evidence = tuple(
                    _evidence(EvidenceReferenceKind.GRAPH_NODE, mutation.node_id)
                    for mutation in sorted(mutations, key=canonical_json)
                )
                instances.append(
                    _instance(
                        scenario,
                        discriminator,
                        (
                            _assertion(
                                iid,
                                mutation_key,
                                AssertionRole.CORE,
                                mutation_state,
                                _reason(mutation_reason, *mutation_evidence),
                            ),
                            _assertion(
                                iid,
                                value_key,
                                AssertionRole.CORE,
                                value_state,
                                value_reasons,
                                control,
                            ),
                        ),
                        ingress=ingress,
                        control=control,
                    )
                )
        if not instances:
            state, reasons = _fallback_state(graph, resolution, relevant_ingresses)
            iid = scenario_instance_id(scenario.value, "catalog")
            instances.append(
                _instance(
                    scenario,
                    "catalog",
                    (_assertion(iid, value_key, AssertionRole.CORE, state, reasons),),
                )
            )
        return _scenario(scenario, instances)

    scenarios.append(
        trust_scenario(
            ScenarioId.SG_05,
            webhook_ingresses,
            SG05_CUSTOMER_VALUE_ASSERTION_KEY,
            SG05_MUTATION_ASSERTION_KEY,
        )
    )
    scenarios.append(
        trust_scenario(
            ScenarioId.SG_06,
            checkout_ingresses,
            SG06_CUSTOMER_VALUE_ASSERTION_KEY,
            SG06_MUTATION_ASSERTION_KEY,
        )
    )

    sg07_instances: list[ScenarioInstance] = []
    if checkout_ingresses:
        for control in webhook_controls:
            iid = scenario_instance_id(ScenarioId.SG_07.value, control.control_id)
            state, reasons = _duplicate_capture_state(graph, nodes, policy, control)
            linked_checkout_controls = tuple(
                item
                for item in controls
                if item.ingress_kind == PaymentIngressKind.CHECKOUT_CALLBACK
                and item.customer_value_node_id == control.customer_value_node_id
                and item.customer_value_symbol_id == control.customer_value_symbol_id
            )
            if state == ApplicabilityState.APPLICABLE and not linked_checkout_controls:
                state = ApplicabilityState.INDETERMINATE
                reasons = _reason(ApplicabilityReasonCode.CHECKOUT_TARGET_LINK_UNRESOLVED)
            elif state == ApplicabilityState.APPLICABLE:
                reasons = _reason(
                    ApplicabilityReasonCode.CHECKOUT_TARGET_LINK_AVAILABLE,
                    *(
                        _evidence(EvidenceReferenceKind.NORMAL_CONTROL, item.control_id)
                        for item in linked_checkout_controls
                    ),
                    *reasons[0].evidence,
                )
            sg07_instances.append(
                _instance(
                    ScenarioId.SG_07,
                    control.control_id,
                    (
                        _assertion(
                            iid,
                            SG07_CUSTOMER_VALUE_ASSERTION_KEY,
                            AssertionRole.CORE,
                            state,
                            reasons,
                            control,
                        ),
                    ),
                    ingress=nodes[control.ingress_node_id],
                    control=control,
                )
            )
    if not sg07_instances:
        iid = scenario_instance_id(ScenarioId.SG_07.value, "catalog")
        if checkout_ingresses and not webhook_controls:
            state, reasons = _fallback_state(graph, resolution, webhook_ingresses)
        else:
            state = ApplicabilityState.NOT_APPLICABLE
            reasons = _reason(ApplicabilityReasonCode.CHECKOUT_SURFACE_REQUIRED)
        sg07_instances.append(
            _instance(
                ScenarioId.SG_07,
                "catalog",
                (
                    _assertion(
                        iid,
                        SG07_CUSTOMER_VALUE_ASSERTION_KEY,
                        AssertionRole.CORE,
                        state,
                        reasons,
                    ),
                ),
            )
        )
    scenarios.append(_scenario(ScenarioId.SG_07, sg07_instances))

    sg08_instances: list[ScenarioInstance] = []
    late_sequence_not_supported = False
    for control in webhook_controls:
        iid = scenario_instance_id(ScenarioId.SG_08.value, control.control_id)
        fulfilment = policy.fulfilment.confirmed_policy
        late = policy.late_authorisation.confirmed_policy
        assertions: tuple[AssertionApplicability, ...]
        route_states = _route_payment_states(graph, control)
        captured_evidence = _captured_webhook_control_evidence(graph, nodes, control)
        relevant_diagnostics = _relevant_diagnostics(graph, (control,))
        if "authorized" not in route_states and route_states:
            late_sequence_not_supported = True
            continue
        if fulfilment is None:
            assertions = (
                _assertion(
                    iid,
                    SG08_LATE_POLICY_ASSERTION_KEY,
                    AssertionRole.CORE,
                    ApplicabilityState.NEEDS_INPUT,
                    _reason(ApplicabilityReasonCode.FULFILMENT_POLICY_REQUIRED),
                    control,
                ),
            )
        elif policy.fulfilment.evidence_current is not True:
            assertions = (
                _assertion(
                    iid,
                    SG08_LATE_POLICY_ASSERTION_KEY,
                    AssertionRole.CORE,
                    ApplicabilityState.NEEDS_INPUT,
                    _reason(ApplicabilityReasonCode.FULFILMENT_POLICY_STALE),
                    control,
                ),
            )
        elif late is None:
            assertions = (
                _assertion(
                    iid,
                    SG08_LATE_POLICY_ASSERTION_KEY,
                    AssertionRole.CORE,
                    ApplicabilityState.NEEDS_INPUT,
                    _reason(ApplicabilityReasonCode.LATE_AUTHORISATION_POLICY_REQUIRED),
                    control,
                ),
            )
        elif policy.late_authorisation.evidence_current is not True:
            assertions = (
                _assertion(
                    iid,
                    SG08_LATE_POLICY_ASSERTION_KEY,
                    AssertionRole.CORE,
                    ApplicabilityState.NEEDS_INPUT,
                    _reason(ApplicabilityReasonCode.LATE_AUTHORISATION_POLICY_STALE),
                    control,
                ),
            )
        elif not route_states or relevant_diagnostics:
            assertions = (
                _assertion(
                    iid,
                    SG08_LATE_POLICY_ASSERTION_KEY,
                    AssertionRole.CORE,
                    ApplicabilityState.INDETERMINATE,
                    _reason(
                        ApplicabilityReasonCode.LATE_SEQUENCE_UNRESOLVED,
                        _evidence(EvidenceReferenceKind.NORMAL_CONTROL, control.control_id),
                    ),
                    control,
                ),
            )
        elif fulfilment == FulfilmentPolicy.CAPTURE_REQUIRED:
            values: list[AssertionApplicability] = [
                _assertion(
                    iid,
                    SG08_PRECAPTURE_ASSERTION_KEY,
                    AssertionRole.CORE,
                    ApplicabilityState.APPLICABLE,
                    _reason(ApplicabilityReasonCode.POLICY_MATRIX_SELECTED),
                    control,
                )
            ]
            if late == LateAuthorisationPolicy.FULFIL_LATER:
                values.append(
                    _assertion(
                        iid,
                        SG08_CAPTURE_ASSERTION_KEY,
                        AssertionRole.CORE,
                        (
                            ApplicabilityState.APPLICABLE
                            if captured_evidence is not None
                            else ApplicabilityState.INDETERMINATE
                        ),
                        (
                            _reason(
                                ApplicabilityReasonCode.POLICY_MATRIX_SELECTED,
                                *(captured_evidence or ()),
                            )
                            if captured_evidence is not None
                            else _reason(ApplicabilityReasonCode.CAPTURED_EVENT_TARGET_UNPROVEN)
                        ),
                        control,
                    )
                )
            assertions = tuple(values)
        else:
            assertions = (
                _assertion(
                    iid,
                    SG08_LATE_POLICY_ASSERTION_KEY,
                    AssertionRole.CORE,
                    ApplicabilityState.INDETERMINATE,
                    _reason(ApplicabilityReasonCode.MERCHANT_LATE_CONTEXT_UNPROVEN),
                    control,
                ),
            )
        sg08_instances.append(
            _instance(
                ScenarioId.SG_08,
                control.control_id,
                assertions,
                ingress=nodes[control.ingress_node_id],
                control=control,
            )
        )
    if not sg08_instances:
        state, reasons = _fallback_state(graph, resolution, webhook_ingresses)
        if late_sequence_not_supported and webhook_controls:
            state = ApplicabilityState.NOT_APPLICABLE
            reasons = _reason(ApplicabilityReasonCode.LATE_SEQUENCE_NOT_SUPPORTED)
        iid = scenario_instance_id(ScenarioId.SG_08.value, "catalog")
        sg08_instances.append(
            _instance(
                ScenarioId.SG_08,
                "catalog",
                (
                    _assertion(
                        iid, SG08_LATE_POLICY_ASSERTION_KEY, AssertionRole.CORE, state, reasons
                    ),
                ),
            )
        )
    scenarios.append(_scenario(ScenarioId.SG_08, sg08_instances))
    return tuple(scenarios)


def evaluate_applicability(
    *,
    generated_at: datetime,
    config: StateGuardConfig,
    source_index: SourceIndexArtifact,
    structural_graph: PaymentSafetyGraphArtifact,
    projected_graph: PaymentSafetyGraphArtifact,
    resolution: CustomerValueResolution | None,
    resolution_fingerprint: str | None,
) -> ScenarioApplicabilityArtifact:
    controls = _normal_controls(projected_graph, resolution, resolution_fingerprint)
    policy = _policy_assessment(config, projected_graph, controls)
    scenarios = _catalog_scenarios(projected_graph, resolution, controls, policy)
    fingerprint = applicability_fingerprint(
        project_id=source_index.project_id,
        project_source_fingerprint=source_index.project_source_fingerprint,
        source_index_fingerprint=source_index.source_index_fingerprint,
        structural_graph_fingerprint=structural_graph.graph_fingerprint,
        projected_graph_fingerprint=projected_graph.graph_fingerprint,
        semantic_resolution_fingerprint=resolution_fingerprint,
        policy=policy,
        normal_controls=controls,
        scenarios=scenarios,
    )
    return ScenarioApplicabilityArtifact(
        producer_version=__version__,
        generated_at=generated_at,
        project_id=source_index.project_id,
        project_source_fingerprint=source_index.project_source_fingerprint,
        source_index_fingerprint=source_index.source_index_fingerprint,
        structural_graph_fingerprint=structural_graph.graph_fingerprint,
        projected_graph_fingerprint=projected_graph.graph_fingerprint,
        semantic_resolution_fingerprint=resolution_fingerprint,
        policy=policy,
        normal_controls=controls,
        scenarios=scenarios,
        applicability_fingerprint=fingerprint,
    )
