"""Persisted Payment Safety Graph contracts."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Literal, TypeAlias

from pydantic import Field, field_validator, model_validator

from stateguard.contracts.common import (
    ArtifactFields,
    FrameworkInstanceId,
    GraphEdgeId,
    GraphNodeId,
    MerchantStateCarrierId,
    PersistedArtifactModel,
    ProjectId,
    ProvenanceKind,
    ProvenanceRecord,
    RouteRegistrationId,
    Sha256Digest,
    SourceLocation,
    SymbolId,
)
from stateguard.contracts.identity import canonical_json, fingerprint_json

_MODEL_UNIQUE_REFERENCE = "customer-value-resolution:MODEL_UNIQUE"
_HUMAN_RESOLUTION_REFERENCES = frozenset(
    {
        "customer-value-resolution:HUMAN_CONFIRMED",
        "customer-value-resolution:MANUAL_SELECTION",
    }
)
_STRUCTURAL_ANCHOR_PATTERN = r"^sganchor_[0-9a-f]{32}$"


class GraphNodeKind(StrEnum):
    PAYMENT_INGRESS = "PAYMENT_INGRESS"
    TRUST_GATE = "TRUST_GATE"
    EVENT_IDENTITY_GUARD = "EVENT_IDENTITY_GUARD"
    PAYMENT_STATE_GATE = "PAYMENT_STATE_GATE"
    MERCHANT_STATE_MUTATION = "MERCHANT_STATE_MUTATION"
    CUSTOMER_VALUE_ACTION = "CUSTOMER_VALUE_ACTION"
    ACKNOWLEDGEMENT_BOUNDARY = "ACKNOWLEDGEMENT_BOUNDARY"


class GraphEdgeKind(StrEnum):
    CALLS = "CALLS"
    GUARDS = "GUARDS"
    BRANCHES_TO = "BRANCHES_TO"
    MUTATES = "MUTATES"
    TRIGGERS = "TRIGGERS"
    ACKNOWLEDGES_AFTER = "ACKNOWLEDGES_AFTER"


class GraphCompleteness(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


class GraphDiagnosticImpact(StrEnum):
    COVERAGE_REDUCED = "COVERAGE_REDUCED"
    NOTICE = "NOTICE"


class GraphDiagnosticCode(StrEnum):
    UPSTREAM_SOURCE_INDEX_PARTIAL = "UPSTREAM_SOURCE_INDEX_PARTIAL"
    APP_TARGET_UNSELECTED = "APP_TARGET_UNSELECTED"
    ROUTE_COMPOSITION_UNRESOLVED = "ROUTE_COMPOSITION_UNRESOLVED"
    ROUTE_COMPOSITION_CYCLE = "ROUTE_COMPOSITION_CYCLE"
    UNRESOLVED_STRUCTURAL_CANDIDATE = "UNRESOLVED_STRUCTURAL_CANDIDATE"
    CONTROL_FLOW_UNSUPPORTED = "CONTROL_FLOW_UNSUPPORTED"
    CALL_PATH_UNRESOLVED = "CALL_PATH_UNRESOLVED"


class GraphCandidateKind(StrEnum):
    WEBHOOK_INGRESS = "WEBHOOK_INGRESS"
    CHECKOUT_CALLBACK_INGRESS = "CHECKOUT_CALLBACK_INGRESS"
    WEBHOOK_SIGNATURE = "WEBHOOK_SIGNATURE"
    CHECKOUT_SIGNATURE = "CHECKOUT_SIGNATURE"
    SERVER_ORDER_IDENTITY = "SERVER_ORDER_IDENTITY"
    EVENT_IDENTITY = "EVENT_IDENTITY"
    PAYMENT_STATE = "PAYMENT_STATE"
    MERCHANT_MUTATION = "MERCHANT_MUTATION"
    ACKNOWLEDGEMENT = "ACKNOWLEDGEMENT"
    CUSTOMER_VALUE_EXECUTION = "CUSTOMER_VALUE_EXECUTION"


class GraphDiagnosticReason(StrEnum):
    INSUFFICIENT_CONVERGING_EVIDENCE = "INSUFFICIENT_CONVERGING_EVIDENCE"
    RAW_BODY_UNRESOLVED = "RAW_BODY_UNRESOLVED"
    PARSED_BODY_USED = "PARSED_BODY_USED"
    VALIDATION_NOT_CONTROL_EFFECTIVE = "VALIDATION_NOT_CONTROL_EFFECTIVE"
    VALIDATION_AFTER_MUTATION = "VALIDATION_AFTER_MUTATION"
    CLIENT_ORDER_ID_USED = "CLIENT_ORDER_ID_USED"
    ORDER_IDENTITY_UNKNOWN = "ORDER_IDENTITY_UNKNOWN"
    EVENT_ID_OBSERVED_ONLY = "EVENT_ID_OBSERVED_ONLY"
    PERSISTENCE_UNRESOLVED = "PERSISTENCE_UNRESOLVED"
    DYNAMIC_RESPONSE = "DYNAMIC_RESPONSE"
    RECURSIVE_CALL_PATH = "RECURSIVE_CALL_PATH"
    UNSUPPORTED_AST = "UNSUPPORTED_AST"
    SDK_BINDING_UNRESOLVED = "SDK_BINDING_UNRESOLVED"
    EXECUTION_SEMANTICS_UNPROVEN = "EXECUTION_SEMANTICS_UNPROVEN"


class GraphDiagnosticRecord(PersistedArtifactModel):
    code: GraphDiagnosticCode
    impact: GraphDiagnosticImpact
    candidate_kind: GraphCandidateKind | None = None
    reason: GraphDiagnosticReason | None = None
    symbol_id: SymbolId | None = None
    route_registration_id: RouteRegistrationId | None = None
    source_location: SourceLocation | None = None

    @model_validator(mode="after")
    def validate_candidate_fields(self) -> GraphDiagnosticRecord:
        if self.code == GraphDiagnosticCode.UNRESOLVED_STRUCTURAL_CANDIDATE:
            if self.candidate_kind is None or self.reason is None:
                raise ValueError("unresolved structural candidates require kind and reason")
        elif self.candidate_kind is not None or self.reason is not None:
            raise ValueError("candidate kind/reason are valid only for unresolved candidates")
        return self


def graph_completeness_for(
    diagnostics: Iterable[GraphDiagnosticRecord],
) -> GraphCompleteness:
    if any(item.impact == GraphDiagnosticImpact.COVERAGE_REDUCED for item in diagnostics):
        return GraphCompleteness.PARTIAL
    return GraphCompleteness.COMPLETE


class PaymentIngressKind(StrEnum):
    WEBHOOK = "WEBHOOK"
    CHECKOUT_CALLBACK = "CHECKOUT_CALLBACK"


class CheckoutRequestTransport(StrEnum):
    JSON = "JSON"
    FORM_URLENCODED = "FORM_URLENCODED"
    QUERY = "QUERY"


class CheckoutFieldBinding(PersistedArtifactModel):
    canonical_name: Literal[
        "razorpay_payment_id",
        "razorpay_order_id",
        "razorpay_signature",
    ]
    request_name: str = Field(min_length=1, max_length=128)


class CheckoutRequestBinding(PersistedArtifactModel):
    transport: CheckoutRequestTransport
    fields: tuple[CheckoutFieldBinding, ...] = Field(min_length=3, max_length=3)

    @model_validator(mode="after")
    def validate_fields(self) -> CheckoutRequestBinding:
        expected = {
            "razorpay_payment_id",
            "razorpay_order_id",
            "razorpay_signature",
        }
        canonical = {item.canonical_name for item in self.fields}
        request_names = {item.request_name for item in self.fields}
        if canonical != expected or len(request_names) != 3:
            raise ValueError("Checkout request binding requires three unique exact fields")
        return self


class TrustGateKind(StrEnum):
    WEBHOOK_SIGNATURE_VERIFICATION = "WEBHOOK_SIGNATURE_VERIFICATION"
    CHECKOUT_SIGNATURE_VERIFICATION = "CHECKOUT_SIGNATURE_VERIFICATION"
    SERVER_ORDER_IDENTITY_BINDING = "SERVER_ORDER_IDENTITY_BINDING"


class OrderIdentityOrigin(StrEnum):
    CLIENT_RETURNED = "CLIENT_RETURNED"
    SERVER_STATE_CONFIRMED = "SERVER_STATE_CONFIRMED"
    UNKNOWN = "UNKNOWN"


class WebhookBodyOrigin(StrEnum):
    RAW_PRESERVED = "RAW_PRESERVED"
    PARSED = "PARSED"
    UNKNOWN = "UNKNOWN"


class EventIdentityStrategy(StrEnum):
    LOOKUP_AND_RECORD = "LOOKUP_AND_RECORD"
    ATOMIC_CLAIM = "ATOMIC_CLAIM"


class PaymentStateOperator(StrEnum):
    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    IN = "IN"
    NOT_IN = "NOT_IN"
    MATCH_CASE = "MATCH_CASE"
    COMPOUND = "COMPOUND"


class MerchantMutationKind(StrEnum):
    ATTRIBUTE_WRITE = "ATTRIBUTE_WRITE"
    SUBSCRIPT_WRITE = "SUBSCRIPT_WRITE"
    MERCHANT_HELPER = "MERCHANT_HELPER"


class AcknowledgementExitKind(StrEnum):
    RETURN = "RETURN"
    IMPLICIT_RETURN = "IMPLICIT_RETURN"
    RESPONSE = "RESPONSE"
    HTTP_EXCEPTION = "HTTP_EXCEPTION"


class AcknowledgementOutcome(StrEnum):
    SUCCESS_2XX = "SUCCESS_2XX"
    NON_SUCCESS = "NON_SUCCESS"
    UNKNOWN = "UNKNOWN"


class EffectiveRouteRegistration(PersistedArtifactModel):
    route_registration_id: RouteRegistrationId
    app_instance_id: FrameworkInstanceId
    registrar_instance_id: FrameworkInstanceId
    method: str = Field(min_length=1, max_length=16)
    component_path: str = Field(min_length=1, max_length=2048)
    effective_path: str = Field(min_length=1, max_length=4096)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator("component_path", "effective_path")
    @classmethod
    def validate_route_path(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped.startswith("/"):
            raise ValueError("graph route paths must begin with '/'")
        return stripped


class PaymentIngressDetails(PersistedArtifactModel):
    detail_kind: Literal["PAYMENT_INGRESS"] = "PAYMENT_INGRESS"
    ingress_kind: PaymentIngressKind
    registration: EffectiveRouteRegistration
    evidence_families: tuple[str, ...] = Field(min_length=1)
    checkout_request_binding: CheckoutRequestBinding | None = None

    @model_validator(mode="after")
    def validate_checkout_binding(self) -> PaymentIngressDetails:
        if self.ingress_kind == PaymentIngressKind.WEBHOOK and self.checkout_request_binding:
            raise ValueError("webhook ingress cannot carry a Checkout request binding")
        return self


class TrustGateDetails(PersistedArtifactModel):
    detail_kind: Literal["TRUST_GATE"] = "TRUST_GATE"
    trust_kind: TrustGateKind
    route_registration_id: RouteRegistrationId
    structural_anchor: str = Field(pattern=_STRUCTURAL_ANCHOR_PATTERN)
    webhook_body_origin: WebhookBodyOrigin | None = None
    order_identity_origin: OrderIdentityOrigin | None = None

    @model_validator(mode="after")
    def validate_subtype_details(self) -> TrustGateDetails:
        if self.trust_kind == TrustGateKind.WEBHOOK_SIGNATURE_VERIFICATION:
            if self.webhook_body_origin is None or self.order_identity_origin is not None:
                raise ValueError("webhook trust details require only webhook body origin")
        elif self.webhook_body_origin is not None:
            raise ValueError("webhook body origin is valid only for webhook signature trust")
        elif self.order_identity_origin is None:
            raise ValueError("Checkout trust details require order identity origin")
        if (
            self.trust_kind == TrustGateKind.SERVER_ORDER_IDENTITY_BINDING
            and self.order_identity_origin != OrderIdentityOrigin.SERVER_STATE_CONFIRMED
        ):
            raise ValueError("server order binding requires confirmed server-state origin")
        return self


class EventIdentityGuardDetails(PersistedArtifactModel):
    detail_kind: Literal["EVENT_IDENTITY_GUARD"] = "EVENT_IDENTITY_GUARD"
    route_registration_id: RouteRegistrationId
    structural_anchor: str = Field(pattern=_STRUCTURAL_ANCHOR_PATTERN)
    strategy: EventIdentityStrategy


class PaymentStateGateDetails(PersistedArtifactModel):
    detail_kind: Literal["PAYMENT_STATE_GATE"] = "PAYMENT_STATE_GATE"
    route_registration_id: RouteRegistrationId
    structural_anchor: str = Field(pattern=_STRUCTURAL_ANCHOR_PATTERN)
    operator: PaymentStateOperator
    states: tuple[str, ...] = Field(min_length=1)


class MerchantStateMutationDetails(PersistedArtifactModel):
    detail_kind: Literal["MERCHANT_STATE_MUTATION"] = "MERCHANT_STATE_MUTATION"
    route_registration_id: RouteRegistrationId
    structural_anchor: str = Field(pattern=_STRUCTURAL_ANCHOR_PATTERN)
    mutation_kind: MerchantMutationKind
    carrier_reference: MerchantStateCarrierId
    assigned_payment_state: Literal["authorized", "captured"] | None = None


class AcknowledgementBoundaryDetails(PersistedArtifactModel):
    detail_kind: Literal["ACKNOWLEDGEMENT_BOUNDARY"] = "ACKNOWLEDGEMENT_BOUNDARY"
    route_registration_id: RouteRegistrationId
    structural_anchor: str = Field(pattern=_STRUCTURAL_ANCHOR_PATTERN)
    exit_kind: AcknowledgementExitKind
    status_code: int | None = Field(default=None, ge=100, le=599)
    outcome: AcknowledgementOutcome

    @model_validator(mode="after")
    def validate_outcome(self) -> AcknowledgementBoundaryDetails:
        if self.status_code is None and self.outcome != AcknowledgementOutcome.UNKNOWN:
            raise ValueError("unknown acknowledgement status requires UNKNOWN outcome")
        if self.status_code is not None:
            expected = (
                AcknowledgementOutcome.SUCCESS_2XX
                if 200 <= self.status_code < 300
                else AcknowledgementOutcome.NON_SUCCESS
            )
            if self.outcome != expected:
                raise ValueError("acknowledgement outcome must match status code")
        return self


GraphNodeDetails: TypeAlias = (
    PaymentIngressDetails
    | TrustGateDetails
    | EventIdentityGuardDetails
    | PaymentStateGateDetails
    | MerchantStateMutationDetails
    | AcknowledgementBoundaryDetails
)


class GraphNode(PersistedArtifactModel):
    node_id: GraphNodeId
    kind: GraphNodeKind
    label: str = Field(min_length=1, max_length=4096)
    backing_symbol_id: SymbolId | None = None
    details: GraphNodeDetails | None = None
    provenance: tuple[ProvenanceRecord, ...] = Field(min_length=1)

    @field_validator("label")
    @classmethod
    def strip_label(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def validate_node(self) -> GraphNode:
        expected_details: dict[GraphNodeKind, type[PersistedArtifactModel]] = {
            GraphNodeKind.PAYMENT_INGRESS: PaymentIngressDetails,
            GraphNodeKind.TRUST_GATE: TrustGateDetails,
            GraphNodeKind.EVENT_IDENTITY_GUARD: EventIdentityGuardDetails,
            GraphNodeKind.PAYMENT_STATE_GATE: PaymentStateGateDetails,
            GraphNodeKind.MERCHANT_STATE_MUTATION: MerchantStateMutationDetails,
            GraphNodeKind.ACKNOWLEDGEMENT_BOUNDARY: AcknowledgementBoundaryDetails,
        }
        expected = expected_details.get(self.kind)
        if expected is not None and not isinstance(self.details, expected):
            raise ValueError("graph node details must match node kind")
        if self.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION and self.details is not None:
            raise ValueError("customer-value details are owned by semantic resolution")
        if self.backing_symbol_id is None:
            raise ValueError("graph nodes require a backing symbol")
        for record in self.provenance:
            if record.kind == ProvenanceKind.STATIC and record.supporting_fingerprint is None:
                raise ValueError("static graph provenance requires a supporting fingerprint")
        if self.kind != GraphNodeKind.CUSTOMER_VALUE_ACTION:
            return self
        semantic_evidence = [
            record
            for record in self.provenance
            if record.supporting_fingerprint is not None
            and (
                (
                    record.kind == ProvenanceKind.AI_INFERRED
                    and record.reference == _MODEL_UNIQUE_REFERENCE
                )
                or (
                    record.kind == ProvenanceKind.HUMAN_CONFIRMED
                    and record.reference in _HUMAN_RESOLUTION_REFERENCES
                )
            )
        ]
        if not semantic_evidence:
            raise ValueError(
                "customer-value actions require fingerprinted semantic-resolution provenance "
                "from AI inference or human confirmation"
            )
        return self


class BranchDisposition(StrEnum):
    MATCHED = "MATCHED"
    NOT_MATCHED = "NOT_MATCHED"
    DEFAULT = "DEFAULT"


class GraphBranchDetails(PersistedArtifactModel):
    disposition: BranchDisposition
    states: tuple[str, ...] = ()


class GraphEdge(PersistedArtifactModel):
    edge_id: GraphEdgeId
    source_node_id: GraphNodeId
    target_node_id: GraphNodeId
    kind: GraphEdgeKind
    branch: GraphBranchDetails | None = None
    provenance: tuple[ProvenanceRecord, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_edge_details(self) -> GraphEdge:
        if self.kind == GraphEdgeKind.BRANCHES_TO and self.branch is None:
            raise ValueError("BRANCHES_TO edges require branch details")
        if self.kind != GraphEdgeKind.BRANCHES_TO and self.branch is not None:
            raise ValueError("branch details are valid only for BRANCHES_TO edges")
        for record in self.provenance:
            if record.kind == ProvenanceKind.STATIC and record.supporting_fingerprint is None:
                raise ValueError("static graph provenance requires a supporting fingerprint")
        return self


def _ordered_records(records: Iterable[PersistedArtifactModel]) -> list[dict[str, object]]:
    return [
        item.model_dump(mode="json")
        for item in sorted(records, key=lambda record: canonical_json(record))
    ]


def graph_fingerprint(
    *,
    project_id: ProjectId,
    source_index_fingerprint: Sha256Digest,
    completeness: GraphCompleteness,
    diagnostics: Iterable[GraphDiagnosticRecord],
    nodes: Iterable[GraphNode],
    edges: Iterable[GraphEdge] = (),
) -> Sha256Digest:
    return fingerprint_json(
        {
            "schema_version": 2,
            "project_id": project_id,
            "source_index_fingerprint": source_index_fingerprint,
            "completeness": completeness,
            "diagnostics": _ordered_records(diagnostics),
            "nodes": _ordered_records(nodes),
            "edges": _ordered_records(edges),
        }
    )


class PaymentSafetyGraphArtifact(ArtifactFields):
    artifact_type: Literal["PAYMENT_SAFETY_GRAPH"] = "PAYMENT_SAFETY_GRAPH"
    schema_version: Literal[2] = 2
    project_id: ProjectId
    source_index_fingerprint: Sha256Digest
    graph_fingerprint: Sha256Digest
    completeness: GraphCompleteness = GraphCompleteness.COMPLETE
    diagnostics: tuple[GraphDiagnosticRecord, ...] = ()
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...] = ()

    @model_validator(mode="after")
    def validate_graph(self) -> PaymentSafetyGraphArtifact:
        node_ids = [item.node_id for item in self.nodes]
        edge_ids = [item.edge_id for item in self.edges]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("graph node IDs must be unique")
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("graph edge IDs must be unique")
        nodes_by_id = {item.node_id: item for item in self.nodes}
        for edge in self.edges:
            source = nodes_by_id.get(edge.source_node_id)
            target = nodes_by_id.get(edge.target_node_id)
            if source is None or target is None:
                raise ValueError("graph edge endpoints must refer to existing nodes")
            self._validate_edge_kinds(edge.kind, source.kind, target.kind)
        if self.completeness != graph_completeness_for(self.diagnostics):
            raise ValueError("graph completeness must match diagnostic impact")
        expected = graph_fingerprint(
            project_id=self.project_id,
            source_index_fingerprint=self.source_index_fingerprint,
            completeness=self.completeness,
            diagnostics=self.diagnostics,
            nodes=self.nodes,
            edges=self.edges,
        )
        if self.graph_fingerprint != expected:
            raise ValueError("graph fingerprint must match graph contents")
        return self

    @staticmethod
    def _validate_edge_kinds(
        edge_kind: GraphEdgeKind,
        source_kind: GraphNodeKind,
        target_kind: GraphNodeKind,
    ) -> None:
        callers = {
            GraphNodeKind.PAYMENT_INGRESS,
            GraphNodeKind.TRUST_GATE,
            GraphNodeKind.EVENT_IDENTITY_GUARD,
            GraphNodeKind.PAYMENT_STATE_GATE,
            GraphNodeKind.MERCHANT_STATE_MUTATION,
        }
        called = {
            GraphNodeKind.TRUST_GATE,
            GraphNodeKind.EVENT_IDENTITY_GUARD,
            GraphNodeKind.PAYMENT_STATE_GATE,
            GraphNodeKind.MERCHANT_STATE_MUTATION,
            GraphNodeKind.CUSTOMER_VALUE_ACTION,
        }
        guarded = called | {GraphNodeKind.CUSTOMER_VALUE_ACTION}
        if edge_kind == GraphEdgeKind.CALLS and not (
            source_kind in callers and target_kind in called
        ):
            raise ValueError("CALLS edge has invalid node-kind orientation")
        if edge_kind == GraphEdgeKind.GUARDS and not (
            source_kind in {GraphNodeKind.TRUST_GATE, GraphNodeKind.EVENT_IDENTITY_GUARD}
            and target_kind in guarded
        ):
            raise ValueError("GUARDS edge has invalid node-kind orientation")
        if edge_kind == GraphEdgeKind.BRANCHES_TO and not (
            source_kind == GraphNodeKind.PAYMENT_STATE_GATE
            and target_kind in guarded | {GraphNodeKind.ACKNOWLEDGEMENT_BOUNDARY}
        ):
            raise ValueError("BRANCHES_TO edge has invalid node-kind orientation")
        if edge_kind == GraphEdgeKind.ACKNOWLEDGES_AFTER and not (
            source_kind == GraphNodeKind.ACKNOWLEDGEMENT_BOUNDARY and target_kind in guarded
        ):
            raise ValueError("ACKNOWLEDGES_AFTER edge has invalid node-kind orientation")
        if edge_kind == GraphEdgeKind.MUTATES and not (
            source_kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
            and target_kind == GraphNodeKind.MERCHANT_STATE_MUTATION
        ):
            raise ValueError("MUTATES edge has invalid node-kind orientation")
        if edge_kind == GraphEdgeKind.TRIGGERS and not (
            source_kind in {GraphNodeKind.PAYMENT_STATE_GATE, GraphNodeKind.MERCHANT_STATE_MUTATION}
            and target_kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
        ):
            raise ValueError("TRIGGERS edge has invalid node-kind orientation")
