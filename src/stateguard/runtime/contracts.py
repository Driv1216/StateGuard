"""Typed Step 5 capability and session-scoped observation contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from stateguard.contracts.common import (
    ArtifactFields,
    FrameworkInstanceId,
    GraphEdgeId,
    GraphNodeId,
    MerchantStateCarrierId,
    NormalControlId,
    PersistedArtifactModel,
    ProjectId,
    RouteRegistrationId,
    RuntimeRequestId,
    RuntimeSessionId,
    Sha256Digest,
    SymbolId,
)
from stateguard.contracts.identity import canonical_json, fingerprint_json
from stateguard.graph.contracts import (
    AcknowledgementExitKind,
    AcknowledgementOutcome,
    CheckoutRequestBinding,
    MerchantMutationKind,
)


class RuntimeCapabilityState(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"


class RuntimeProcessOwnership(StrEnum):
    STATEGUARD = "STATEGUARD"
    EXTERNAL = "EXTERNAL"
    NONE = "NONE"


class RuntimeLifecycleState(StrEnum):
    READY = "READY"
    HISTORICAL = "HISTORICAL"
    UNAVAILABLE = "UNAVAILABLE"


class RuntimeCapabilityReasonCode(StrEnum):
    AVAILABLE = "AVAILABLE"
    STATIC_ONLY_CONFIGURED = "STATIC_ONLY_CONFIGURED"
    APP_TARGET_UNRESOLVED = "APP_TARGET_UNRESOLVED"
    RUNTIME_DEPENDENCY_MISSING = "RUNTIME_DEPENDENCY_MISSING"
    RUNTIME_VERSION_UNTESTED = "RUNTIME_VERSION_UNTESTED"
    UNSUPPORTED_PYTHON_RUNTIME = "UNSUPPORTED_PYTHON_RUNTIME"
    RUNTIME_ROUTE_NOT_FOUND = "RUNTIME_ROUTE_NOT_FOUND"
    RUNTIME_ROUTE_AMBIGUOUS = "RUNTIME_ROUTE_AMBIGUOUS"
    RUNTIME_ROUTE_SHADOWED = "RUNTIME_ROUTE_SHADOWED"
    TARGET_CODE_MISMATCH = "TARGET_CODE_MISMATCH"
    MUTATION_INSTRUCTION_UNRESOLVED = "MUTATION_INSTRUCTION_UNRESOLVED"
    CHECKOUT_REQUEST_BINDING_UNRESOLVED = "CHECKOUT_REQUEST_BINDING_UNRESOLVED"
    ENTRY_ONLY = "ENTRY_ONLY"
    CLIENT_RESPONSE_ONLY = "CLIENT_RESPONSE_ONLY"
    IN_PROCESS_INSTRUMENTATION_UNAVAILABLE = "IN_PROCESS_INSTRUMENTATION_UNAVAILABLE"
    EXTERNAL_STATE_RESET_UNAVAILABLE = "EXTERNAL_STATE_RESET_UNAVAILABLE"
    EXTERNAL_RUNTIME_UNAVAILABLE = "EXTERNAL_RUNTIME_UNAVAILABLE"
    TARGET_POLICY_REJECTED = "TARGET_POLICY_REJECTED"
    STARTUP_FAILED = "STARTUP_FAILED"
    STARTUP_TIMEOUT = "STARTUP_TIMEOUT"
    PROCESS_CRASHED = "PROCESS_CRASHED"
    OBSERVATION_CHANNEL_FAILED = "OBSERVATION_CHANNEL_FAILED"
    UNCORRELATED_TARGET_EXECUTION = "UNCORRELATED_TARGET_EXECUTION"
    SOURCE_STALE = "SOURCE_STALE"
    CONFIG_STALE = "CONFIG_STALE"
    CLEANUP_FAILED = "CLEANUP_FAILED"


class RuntimeDiagnosticStage(StrEnum):
    PREFLIGHT = "PREFLIGHT"
    STARTUP = "STARTUP"
    ATTACHMENT = "ATTACHMENT"
    READINESS = "READINESS"
    REQUEST = "REQUEST"
    OBSERVATION = "OBSERVATION"
    CLEANUP = "CLEANUP"


class CustomerValueLifecycleStrength(StrEnum):
    ENTRY_ONLY = "ENTRY_ONLY"
    ENTRY_AND_TERMINAL = "ENTRY_AND_TERMINAL"


class MutationObservationStrength(StrEnum):
    PYTHON_ASSIGNMENT_INSTRUCTION_COMPLETION = "PYTHON_ASSIGNMENT_INSTRUCTION_COMPLETION"


class RuntimeObservationKind(StrEnum):
    REQUEST_DISPATCHED = "REQUEST_DISPATCHED"
    REQUEST_RECEIVED = "REQUEST_RECEIVED"
    CUSTOMER_VALUE_ENTERED = "CUSTOMER_VALUE_ENTERED"
    CUSTOMER_VALUE_RETURNED_NORMALLY = "CUSTOMER_VALUE_RETURNED_NORMALLY"
    CUSTOMER_VALUE_EXCEPTION_ESCAPED = "CUSTOMER_VALUE_EXCEPTION_ESCAPED"
    MERCHANT_ASSIGNMENT_INSTRUCTION_REACHED = "MERCHANT_ASSIGNMENT_INSTRUCTION_REACHED"
    MERCHANT_ASSIGNMENT_INSTRUCTION_COMPLETED_NORMALLY = (
        "MERCHANT_ASSIGNMENT_INSTRUCTION_COMPLETED_NORMALLY"
    )
    MERCHANT_ASSIGNMENT_INSTRUCTION_RAISED = "MERCHANT_ASSIGNMENT_INSTRUCTION_RAISED"
    RESPONSE_STARTED = "RESPONSE_STARTED"
    ACKNOWLEDGEMENT_FAILURE_INJECTED = "ACKNOWLEDGEMENT_FAILURE_INJECTED"
    RESPONSE_COMPLETED = "RESPONSE_COMPLETED"
    RESPONSE_RECEIVED = "RESPONSE_RECEIVED"
    REQUEST_ABORTED = "REQUEST_ABORTED"


class ManagedAcknowledgementFailureMode(StrEnum):
    FORCE_NON_2XX_AFTER_SUCCESS = "FORCE_NON_2XX_AFTER_SUCCESS"


class RuntimeCapabilityAssessment(PersistedArtifactModel):
    state: RuntimeCapabilityState
    reasons: tuple[RuntimeCapabilityReasonCode, ...] = Field(min_length=1)


class IngressRuntimeBinding(PersistedArtifactModel):
    ingress_node_id: GraphNodeId
    route_registration_id: RouteRegistrationId
    app_instance_id: FrameworkInstanceId
    ingress_symbol_id: SymbolId
    method: str = Field(min_length=1, max_length=16)
    effective_path: str = Field(min_length=1, max_length=4096)
    checkout_request_binding: CheckoutRequestBinding | None = None

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator("effective_path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped.startswith("/"):
            raise ValueError("runtime ingress path must begin with '/'")
        return stripped


class CustomerValueRuntimeTarget(PersistedArtifactModel):
    ingress: IngressRuntimeBinding
    normal_control_id: NormalControlId
    customer_value_node_id: GraphNodeId
    customer_value_symbol_id: SymbolId
    connectivity_edge_id: GraphEdgeId
    call_path_references: tuple[str, ...] = Field(min_length=1)
    semantic_resolution_fingerprint: Sha256Digest


class MutationRuntimeTarget(PersistedArtifactModel):
    ingress: IngressRuntimeBinding
    mutation_node_id: GraphNodeId
    mutation_symbol_id: SymbolId
    structural_anchor: str = Field(min_length=1, max_length=128)
    mutation_kind: MerchantMutationKind
    carrier_reference: MerchantStateCarrierId


class AcknowledgementRuntimeTarget(PersistedArtifactModel):
    ingress: IngressRuntimeBinding
    acknowledgement_node_id: GraphNodeId
    acknowledgement_symbol_id: SymbolId
    structural_anchor: str = Field(min_length=1, max_length=128)
    exit_kind: AcknowledgementExitKind
    status_code: int | None = Field(default=None, ge=100, le=599)
    outcome: AcknowledgementOutcome


class IngressRuntimeCapability(PersistedArtifactModel):
    binding: IngressRuntimeBinding
    addressability: RuntimeCapabilityAssessment
    request_correlation: RuntimeCapabilityAssessment


class CustomerValueRuntimeCapability(PersistedArtifactModel):
    target: CustomerValueRuntimeTarget
    lifecycle: RuntimeCapabilityAssessment
    strength: CustomerValueLifecycleStrength | None = None

    @model_validator(mode="after")
    def validate_strength(self) -> CustomerValueRuntimeCapability:
        if (self.lifecycle.state == RuntimeCapabilityState.UNAVAILABLE) != (self.strength is None):
            raise ValueError("customer lifecycle strength must match availability")
        return self


class MutationRuntimeCapability(PersistedArtifactModel):
    target: MutationRuntimeTarget
    assignment: RuntimeCapabilityAssessment
    strength: MutationObservationStrength | None = None

    @model_validator(mode="after")
    def validate_strength(self) -> MutationRuntimeCapability:
        if (self.assignment.state == RuntimeCapabilityState.UNAVAILABLE) != (self.strength is None):
            raise ValueError("mutation observation strength must match availability")
        return self


class AcknowledgementRuntimeCapability(PersistedArtifactModel):
    target: AcknowledgementRuntimeTarget
    timeline: RuntimeCapabilityAssessment


class RuntimeIsolationCapability(PersistedArtifactModel):
    fresh_process: RuntimeCapabilityAssessment
    observation_reset: RuntimeCapabilityAssessment
    external_state_reset: RuntimeCapabilityAssessment


class RuntimeCompatibility(PersistedArtifactModel):
    python_implementation: str = Field(min_length=1, max_length=64)
    python_version: str = Field(min_length=1, max_length=64)
    fastapi_version: str | None = Field(default=None, max_length=64)
    starlette_version: str | None = Field(default=None, max_length=64)
    uvicorn_version: str | None = Field(default=None, max_length=64)


class RuntimeDiagnostic(PersistedArtifactModel):
    code: RuntimeCapabilityReasonCode
    stage: RuntimeDiagnosticStage
    reference: str | None = Field(default=None, min_length=1, max_length=2048)


def runtime_capability_fingerprint(
    *,
    project_id: ProjectId,
    project_source_fingerprint: Sha256Digest,
    source_index_fingerprint: Sha256Digest,
    structural_graph_fingerprint: Sha256Digest,
    projected_graph_fingerprint: Sha256Digest,
    applicability_fingerprint: Sha256Digest,
    runtime_config_fingerprint: Sha256Digest,
    mode: str,
    ownership: RuntimeProcessOwnership,
    lifecycle: RuntimeLifecycleState,
    compatibility: RuntimeCompatibility,
    ingresses: tuple[IngressRuntimeCapability, ...],
    customer_values: tuple[CustomerValueRuntimeCapability, ...],
    mutations: tuple[MutationRuntimeCapability, ...],
    acknowledgements: tuple[AcknowledgementRuntimeCapability, ...],
    isolation: RuntimeIsolationCapability,
    diagnostics: tuple[RuntimeDiagnostic, ...],
) -> Sha256Digest:
    return fingerprint_json(
        {
            "schema_version": 1,
            "project_id": project_id,
            "project_source_fingerprint": project_source_fingerprint,
            "source_index_fingerprint": source_index_fingerprint,
            "structural_graph_fingerprint": structural_graph_fingerprint,
            "projected_graph_fingerprint": projected_graph_fingerprint,
            "applicability_fingerprint": applicability_fingerprint,
            "runtime_config_fingerprint": runtime_config_fingerprint,
            "mode": mode,
            "ownership": ownership,
            "lifecycle": lifecycle,
            "compatibility": compatibility,
            "ingresses": sorted(ingresses, key=canonical_json),
            "customer_values": sorted(customer_values, key=canonical_json),
            "mutations": sorted(mutations, key=canonical_json),
            "acknowledgements": sorted(acknowledgements, key=canonical_json),
            "isolation": isolation,
            "diagnostics": sorted(diagnostics, key=canonical_json),
        }
    )


class RuntimeCapabilityArtifact(ArtifactFields):
    artifact_type: Literal["RUNTIME_CAPABILITY"] = "RUNTIME_CAPABILITY"
    schema_version: Literal[1] = 1
    project_id: ProjectId
    project_source_fingerprint: Sha256Digest
    source_index_fingerprint: Sha256Digest
    structural_graph_fingerprint: Sha256Digest
    projected_graph_fingerprint: Sha256Digest
    applicability_fingerprint: Sha256Digest
    runtime_config_fingerprint: Sha256Digest
    assessment_session_id: RuntimeSessionId
    mode: Literal["managed", "byo", "static"]
    ownership: RuntimeProcessOwnership
    lifecycle: RuntimeLifecycleState
    compatibility: RuntimeCompatibility
    ingresses: tuple[IngressRuntimeCapability, ...] = ()
    customer_values: tuple[CustomerValueRuntimeCapability, ...] = ()
    mutations: tuple[MutationRuntimeCapability, ...] = ()
    acknowledgements: tuple[AcknowledgementRuntimeCapability, ...] = ()
    isolation: RuntimeIsolationCapability
    diagnostics: tuple[RuntimeDiagnostic, ...] = ()
    capability_fingerprint: Sha256Digest

    @model_validator(mode="after")
    def validate_artifact(self) -> RuntimeCapabilityArtifact:
        bindings = {
            (item.binding.ingress_node_id, item.binding.route_registration_id): item.binding
            for item in self.ingresses
        }
        if len(bindings) != len(self.ingresses):
            raise ValueError("runtime ingress bindings must be unique")
        for collection in (self.customer_values, self.mutations, self.acknowledgements):
            for item in collection:
                target_binding = item.target.ingress
                key = (target_binding.ingress_node_id, target_binding.route_registration_id)
                if bindings.get(key) != target_binding:
                    raise ValueError("runtime target must use an exact assessed ingress binding")
        if len({item.target.normal_control_id for item in self.customer_values}) != len(
            self.customer_values
        ):
            raise ValueError("customer-value runtime controls must be unique")
        if len({item.target.mutation_node_id for item in self.mutations}) != len(self.mutations):
            raise ValueError("mutation runtime targets must be unique")
        if len({item.target.acknowledgement_node_id for item in self.acknowledgements}) != len(
            self.acknowledgements
        ):
            raise ValueError("acknowledgement runtime targets must be unique")
        expected = runtime_capability_fingerprint(
            project_id=self.project_id,
            project_source_fingerprint=self.project_source_fingerprint,
            source_index_fingerprint=self.source_index_fingerprint,
            structural_graph_fingerprint=self.structural_graph_fingerprint,
            projected_graph_fingerprint=self.projected_graph_fingerprint,
            applicability_fingerprint=self.applicability_fingerprint,
            runtime_config_fingerprint=self.runtime_config_fingerprint,
            mode=self.mode,
            ownership=self.ownership,
            lifecycle=self.lifecycle,
            compatibility=self.compatibility,
            ingresses=self.ingresses,
            customer_values=self.customer_values,
            mutations=self.mutations,
            acknowledgements=self.acknowledgements,
            isolation=self.isolation,
            diagnostics=self.diagnostics,
        )
        if self.capability_fingerprint != expected:
            raise ValueError("runtime capability fingerprint must match artifact contents")
        return self


class RuntimeObservationEvent(PersistedArtifactModel):
    session_id: RuntimeSessionId
    request_id: RuntimeRequestId
    sequence: int = Field(ge=1)
    kind: RuntimeObservationKind
    ingress_node_id: GraphNodeId
    route_registration_id: RouteRegistrationId
    normal_control_id: NormalControlId | None = None
    customer_value_node_id: GraphNodeId | None = None
    customer_value_symbol_id: SymbolId | None = None
    mutation_node_id: GraphNodeId | None = None
    acknowledgement_node_id: GraphNodeId | None = None
    status_code: int | None = Field(default=None, ge=100, le=599)
    original_status_code: int | None = Field(default=None, ge=100, le=599)

    @model_validator(mode="after")
    def validate_target(self) -> RuntimeObservationEvent:
        customer = self.kind in {
            RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
            RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
            RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED,
        }
        mutation = self.kind in {
            RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_REACHED,
            RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_COMPLETED_NORMALLY,
            RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_RAISED,
        }
        customer_identity = (
            self.normal_control_id,
            self.customer_value_node_id,
            self.customer_value_symbol_id,
        )
        if customer and not all(item is not None for item in customer_identity):
            raise ValueError("customer lifecycle events require only exact fulfilment identity")
        if not customer and any(item is not None for item in customer_identity):
            raise ValueError("non-customer events cannot carry fulfilment identity")
        if mutation != (self.mutation_node_id is not None):
            raise ValueError("mutation events require only an exact mutation node")
        response = self.kind in {
            RuntimeObservationKind.RESPONSE_STARTED,
            RuntimeObservationKind.RESPONSE_COMPLETED,
            RuntimeObservationKind.RESPONSE_RECEIVED,
            RuntimeObservationKind.ACKNOWLEDGEMENT_FAILURE_INJECTED,
        }
        if response != (self.status_code is not None):
            raise ValueError("response events require a status code")
        managed_response = self.kind in {
            RuntimeObservationKind.RESPONSE_STARTED,
            RuntimeObservationKind.RESPONSE_COMPLETED,
            RuntimeObservationKind.ACKNOWLEDGEMENT_FAILURE_INJECTED,
        }
        if self.acknowledgement_node_id is not None and not managed_response:
            raise ValueError("acknowledgement identity is valid only at the app response boundary")
        injected = self.kind == RuntimeObservationKind.ACKNOWLEDGEMENT_FAILURE_INJECTED
        if injected:
            if (
                self.acknowledgement_node_id is None
                or self.original_status_code is None
                or not 200 <= self.original_status_code < 300
                or self.status_code != 503
            ):
                raise ValueError("acknowledgement injection requires exact 2xx to 503 evidence")
        elif self.original_status_code is not None:
            raise ValueError("original status is valid only for acknowledgement injection")
        return self


class RuntimeObservationTranscript(PersistedArtifactModel):
    session_id: RuntimeSessionId
    capability_fingerprint: Sha256Digest
    complete: bool
    events: tuple[RuntimeObservationEvent, ...]
    diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = ()
    transcript_fingerprint: Sha256Digest

    @model_validator(mode="after")
    def validate_transcript(self) -> RuntimeObservationTranscript:
        if any(item.session_id != self.session_id for item in self.events):
            raise ValueError("transcript events must belong to one runtime session")
        sequences = [item.sequence for item in self.events]
        if sequences != list(range(1, len(sequences) + 1)):
            raise ValueError("transcript event sequence must be contiguous and ordered")
        expected = fingerprint_json(
            {
                "session_id": self.session_id,
                "capability_fingerprint": self.capability_fingerprint,
                "complete": self.complete,
                "events": self.events,
                "diagnostics": self.diagnostics,
            }
        )
        if self.transcript_fingerprint != expected:
            raise ValueError("runtime transcript fingerprint must match contents")
        return self


class RuntimeTranscriptMismatchError(ValueError):
    """A sealed observation transcript does not match its assessed runtime authority."""


def validate_observation_transcript(
    artifact: RuntimeCapabilityArtifact,
    transcript: RuntimeObservationTranscript,
) -> None:
    """Reject incomplete, stale, or cross-target observations before Step 6 consumes them."""

    if not transcript.complete or transcript.diagnostics:
        raise RuntimeTranscriptMismatchError("runtime observation transcript is incomplete")
    if transcript.session_id != artifact.assessment_session_id:
        raise RuntimeTranscriptMismatchError("runtime observation session identity is mismatched")
    if transcript.capability_fingerprint != artifact.capability_fingerprint:
        raise RuntimeTranscriptMismatchError("runtime capability fingerprint is mismatched")

    bindings = {
        (item.binding.ingress_node_id, item.binding.route_registration_id): item.binding
        for item in artifact.ingresses
    }
    customers = {item.target.normal_control_id: item.target for item in artifact.customer_values}
    mutations = {item.target.mutation_node_id: item.target for item in artifact.mutations}
    acknowledgements = {
        item.target.acknowledgement_node_id: item.target for item in artifact.acknowledgements
    }
    request_bindings: dict[RuntimeRequestId, tuple[GraphNodeId, RouteRegistrationId]] = {}
    for event in transcript.events:
        binding_key = (event.ingress_node_id, event.route_registration_id)
        if binding_key not in bindings:
            raise RuntimeTranscriptMismatchError("observation ingress binding is not assessed")
        previous = request_bindings.setdefault(event.request_id, binding_key)
        if previous != binding_key:
            raise RuntimeTranscriptMismatchError("one request crossed exact ingress bindings")
        if event.normal_control_id is not None:
            customer_target = customers.get(event.normal_control_id)
            if (
                customer_target is None
                or customer_target.ingress != bindings[binding_key]
                or customer_target.customer_value_node_id != event.customer_value_node_id
                or customer_target.customer_value_symbol_id != event.customer_value_symbol_id
            ):
                raise RuntimeTranscriptMismatchError(
                    "customer observation target is not the assessed normal control"
                )
        if event.mutation_node_id is not None:
            mutation_target = mutations.get(event.mutation_node_id)
            if mutation_target is None or mutation_target.ingress != bindings[binding_key]:
                raise RuntimeTranscriptMismatchError(
                    "mutation observation target is not the assessed graph node"
                )
        if event.acknowledgement_node_id is not None:
            acknowledgement_target = acknowledgements.get(event.acknowledgement_node_id)
            if (
                acknowledgement_target is None
                or acknowledgement_target.ingress != bindings[binding_key]
            ):
                raise RuntimeTranscriptMismatchError(
                    "acknowledgement observation target is not the assessed graph node"
                )
