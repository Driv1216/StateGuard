"""Build exact capability artifacts from current static and runtime attachment facts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from stateguard import __version__
from stateguard.applicability.contracts import ScenarioApplicabilityArtifact
from stateguard.contracts.common import RuntimeSessionId
from stateguard.contracts.config import RuntimeConfig, RuntimeMode
from stateguard.contracts.identity import fingerprint_json
from stateguard.discovery.contracts import SourceIndexArtifact
from stateguard.graph.contracts import PaymentSafetyGraphArtifact

from .compatibility import detect_runtime_compatibility
from .contracts import (
    AcknowledgementRuntimeCapability,
    CustomerValueLifecycleStrength,
    CustomerValueRuntimeCapability,
    IngressRuntimeCapability,
    MutationObservationStrength,
    MutationRuntimeCapability,
    RuntimeCapabilityArtifact,
    RuntimeCapabilityAssessment,
    RuntimeCapabilityReasonCode,
    RuntimeCapabilityState,
    RuntimeDiagnostic,
    RuntimeIsolationCapability,
    RuntimeLifecycleState,
    RuntimeProcessOwnership,
    runtime_capability_fingerprint,
)
from .instrumentation import (
    CustomerTraceTarget,
    InstrumentationError,
    MutationTraceTarget,
    PythonCallableShape,
    compile_mutation_trace_target,
    compile_symbol_descriptor,
    live_symbol_matches_descriptor,
)
from .planning import RuntimeTargetPlan
from .routes import RouteAttachment


def assessment(
    state: RuntimeCapabilityState,
    reason: RuntimeCapabilityReasonCode,
) -> RuntimeCapabilityAssessment:
    return RuntimeCapabilityAssessment(state=state, reasons=(reason,))


@dataclass(frozen=True)
class PreparedInstrumentation:
    customers: tuple[CustomerTraceTarget, ...]
    customer_failures: dict[str, RuntimeCapabilityReasonCode]
    mutations: tuple[MutationTraceTarget, ...]
    mutation_failures: dict[str, RuntimeCapabilityReasonCode]


def reconcile_live_instrumentation(
    repository_root: Path,
    source_index: SourceIndexArtifact,
    plan: RuntimeTargetPlan,
    prepared: PreparedInstrumentation,
) -> PreparedInstrumentation:
    """Retain only targets whose exact code object exists in the imported runtime."""

    customer_symbols = {
        item.normal_control_id: item.customer_value_symbol_id for item in plan.customer_values
    }
    mutation_symbols = {item.mutation_node_id: item.mutation_symbol_id for item in plan.mutations}
    customers = tuple(
        item
        for item in prepared.customers
        if live_symbol_matches_descriptor(
            source_index,
            customer_symbols[item.normal_control_id],
            item.descriptor,
            repository_root,
        )
    )
    mutations = tuple(
        item
        for item in prepared.mutations
        if live_symbol_matches_descriptor(
            source_index,
            mutation_symbols[item.mutation_node_id],
            item.descriptor,
            repository_root,
        )
    )
    return restrict_prepared_instrumentation(
        prepared,
        live_customer_ids={item.normal_control_id for item in customers},
        live_mutation_ids={item.mutation_node_id for item in mutations},
    )


def restrict_prepared_instrumentation(
    prepared: PreparedInstrumentation,
    *,
    live_customer_ids: set[str],
    live_mutation_ids: set[str],
) -> PreparedInstrumentation:
    """Apply worker-proven live attachments to the parent capability assessment."""

    customers = tuple(
        item for item in prepared.customers if item.normal_control_id in live_customer_ids
    )
    mutations = tuple(
        item for item in prepared.mutations if item.mutation_node_id in live_mutation_ids
    )
    customer_failures = dict(prepared.customer_failures)
    mutation_failures = dict(prepared.mutation_failures)
    for customer in prepared.customers:
        if customer.normal_control_id not in live_customer_ids:
            customer_failures[customer.normal_control_id] = (
                RuntimeCapabilityReasonCode.TARGET_CODE_MISMATCH
            )
    for mutation in prepared.mutations:
        if mutation.mutation_node_id not in live_mutation_ids:
            mutation_failures[mutation.mutation_node_id] = (
                RuntimeCapabilityReasonCode.TARGET_CODE_MISMATCH
            )
    return PreparedInstrumentation(
        customers=customers,
        customer_failures=customer_failures,
        mutations=mutations,
        mutation_failures=mutation_failures,
    )


class StaleRuntimeCapabilityError(ValueError):
    """A historical runtime assessment no longer matches its static/runtime inputs."""


def validate_historical_capability_inputs(
    artifact: RuntimeCapabilityArtifact,
    *,
    runtime_config: RuntimeConfig | None,
    source_index: SourceIndexArtifact,
    structural_graph: PaymentSafetyGraphArtifact,
    graph: PaymentSafetyGraphArtifact,
    applicability: ScenarioApplicabilityArtifact,
) -> None:
    """Validate assessment freshness without treating it as current session evidence."""

    current_runtime_fingerprint = fingerprint_json(
        runtime_config if runtime_config is not None else {"mode": RuntimeMode.STATIC}
    )
    observed = (
        artifact.project_id,
        artifact.project_source_fingerprint,
        artifact.source_index_fingerprint,
        artifact.structural_graph_fingerprint,
        artifact.projected_graph_fingerprint,
        artifact.applicability_fingerprint,
        artifact.runtime_config_fingerprint,
        artifact.compatibility,
    )
    expected = (
        source_index.project_id,
        source_index.project_source_fingerprint,
        source_index.source_index_fingerprint,
        structural_graph.graph_fingerprint,
        graph.graph_fingerprint,
        applicability.applicability_fingerprint,
        current_runtime_fingerprint,
        detect_runtime_compatibility(),
    )
    if observed != expected:
        raise StaleRuntimeCapabilityError(
            "historical runtime capability inputs are stale; reassessment is required"
        )


def prepare_instrumentation(
    repository_root: Path,
    source_index: SourceIndexArtifact,
    graph: PaymentSafetyGraphArtifact,
    plan: RuntimeTargetPlan,
) -> PreparedInstrumentation:
    customer_traces: list[CustomerTraceTarget] = []
    customer_failures: dict[str, RuntimeCapabilityReasonCode] = {}
    for customer_target in plan.customer_values:
        try:
            descriptor = compile_symbol_descriptor(
                repository_root,
                source_index,
                customer_target.customer_value_symbol_id,
            )
            customer_traces.append(
                CustomerTraceTarget(
                    descriptor=descriptor,
                    normal_control_id=customer_target.normal_control_id,
                    customer_value_node_id=customer_target.customer_value_node_id,
                    customer_value_symbol_id=customer_target.customer_value_symbol_id,
                )
            )
        except InstrumentationError:
            customer_failures[customer_target.normal_control_id] = (
                RuntimeCapabilityReasonCode.TARGET_CODE_MISMATCH
            )

    nodes = {item.node_id: item for item in graph.nodes}
    mutation_traces: list[MutationTraceTarget] = []
    mutation_failures: dict[str, RuntimeCapabilityReasonCode] = {}
    for mutation_target in plan.mutations:
        node = nodes[mutation_target.mutation_node_id]
        try:
            mutation_traces.append(
                compile_mutation_trace_target(
                    repository_root,
                    source_index,
                    node,
                    mutation_target.mutation_kind,
                    mutation_target.ingress,
                )
            )
        except (InstrumentationError, StopIteration):
            mutation_failures[mutation_target.mutation_node_id] = (
                RuntimeCapabilityReasonCode.MUTATION_INSTRUCTION_UNRESOLVED
            )
    return PreparedInstrumentation(
        customers=tuple(customer_traces),
        customer_failures=customer_failures,
        mutations=tuple(mutation_traces),
        mutation_failures=mutation_failures,
    )


def _route_assessments(
    plan: RuntimeTargetPlan,
    mode: RuntimeMode,
    attachments: tuple[RouteAttachment, ...],
) -> dict[str, RuntimeCapabilityAssessment]:
    if mode == RuntimeMode.STATIC:
        return {
            item.ingress_node_id: assessment(
                RuntimeCapabilityState.UNAVAILABLE,
                RuntimeCapabilityReasonCode.STATIC_ONLY_CONFIGURED,
            )
            for item in plan.ingresses
        }
    if mode == RuntimeMode.BYO:
        counts: dict[tuple[str, str], int] = {}
        for item in plan.ingresses:
            key = (item.method, item.effective_path)
            counts[key] = counts.get(key, 0) + 1
        return {
            item.ingress_node_id: assessment(
                (
                    RuntimeCapabilityState.PARTIAL
                    if counts[(item.method, item.effective_path)] == 1
                    else RuntimeCapabilityState.UNAVAILABLE
                ),
                (
                    RuntimeCapabilityReasonCode.CLIENT_RESPONSE_ONLY
                    if counts[(item.method, item.effective_path)] == 1
                    else RuntimeCapabilityReasonCode.RUNTIME_ROUTE_AMBIGUOUS
                ),
            )
            for item in plan.ingresses
        }
    by_ingress = {item.binding.ingress_node_id: item for item in attachments}
    return {
        item.ingress_node_id: assessment(
            (
                RuntimeCapabilityState.COMPLETE
                if by_ingress.get(item.ingress_node_id) is not None
                and by_ingress[item.ingress_node_id].attached
                else RuntimeCapabilityState.UNAVAILABLE
            ),
            (
                RuntimeCapabilityReasonCode.AVAILABLE
                if by_ingress.get(item.ingress_node_id) is not None
                and by_ingress[item.ingress_node_id].attached
                else (
                    by_ingress[item.ingress_node_id].reason
                    if by_ingress.get(item.ingress_node_id) is not None
                    else RuntimeCapabilityReasonCode.RUNTIME_ROUTE_NOT_FOUND
                )
            ),
        )
        for item in plan.ingresses
    }


def build_capability_artifact(
    *,
    generated_at: datetime,
    session_id: RuntimeSessionId,
    runtime_config: RuntimeConfig | None,
    source_index: SourceIndexArtifact,
    structural_graph: PaymentSafetyGraphArtifact,
    graph: PaymentSafetyGraphArtifact,
    applicability: ScenarioApplicabilityArtifact,
    plan: RuntimeTargetPlan,
    prepared: PreparedInstrumentation,
    attachments: tuple[RouteAttachment, ...] = (),
    lifecycle: RuntimeLifecycleState,
    ownership: RuntimeProcessOwnership,
    diagnostics: tuple[RuntimeDiagnostic, ...] = (),
) -> RuntimeCapabilityArtifact:
    mode = runtime_config.mode if runtime_config is not None else RuntimeMode.STATIC
    compatibility = detect_runtime_compatibility()
    route = _route_assessments(plan, mode, attachments)
    ingresses = tuple(
        IngressRuntimeCapability(
            binding=item,
            addressability=route[item.ingress_node_id],
            request_correlation=(
                route[item.ingress_node_id]
                if mode == RuntimeMode.MANAGED
                else assessment(
                    (
                        RuntimeCapabilityState.PARTIAL
                        if route[item.ingress_node_id].state != RuntimeCapabilityState.UNAVAILABLE
                        else RuntimeCapabilityState.UNAVAILABLE
                    ),
                    (
                        RuntimeCapabilityReasonCode.CLIENT_RESPONSE_ONLY
                        if mode == RuntimeMode.BYO
                        else route[item.ingress_node_id].reasons[0]
                    ),
                )
            ),
        )
        for item in plan.ingresses
    )
    customer_trace = {item.normal_control_id: item for item in prepared.customers}
    customer_values: list[CustomerValueRuntimeCapability] = []
    for customer_target in plan.customer_values:
        trace = customer_trace.get(customer_target.normal_control_id)
        route_state = route[customer_target.ingress.ingress_node_id]
        if mode != RuntimeMode.MANAGED:
            state = RuntimeCapabilityState.UNAVAILABLE
            reason = (
                RuntimeCapabilityReasonCode.STATIC_ONLY_CONFIGURED
                if mode == RuntimeMode.STATIC
                else RuntimeCapabilityReasonCode.IN_PROCESS_INSTRUMENTATION_UNAVAILABLE
            )
            strength = None
        elif route_state.state == RuntimeCapabilityState.UNAVAILABLE or trace is None:
            state = RuntimeCapabilityState.UNAVAILABLE
            reason = prepared.customer_failures.get(
                customer_target.normal_control_id, route_state.reasons[0]
            )
            strength = None
        elif trace.descriptor.shape in {
            PythonCallableShape.GENERATOR,
            PythonCallableShape.ASYNC_GENERATOR,
        }:
            state = RuntimeCapabilityState.PARTIAL
            reason = RuntimeCapabilityReasonCode.ENTRY_ONLY
            strength = CustomerValueLifecycleStrength.ENTRY_ONLY
        else:
            state = RuntimeCapabilityState.COMPLETE
            reason = RuntimeCapabilityReasonCode.AVAILABLE
            strength = CustomerValueLifecycleStrength.ENTRY_AND_TERMINAL
        customer_values.append(
            CustomerValueRuntimeCapability(
                target=customer_target,
                lifecycle=assessment(state, reason),
                strength=strength,
            )
        )

    mutation_trace = {item.mutation_node_id: item for item in prepared.mutations}
    mutations: list[MutationRuntimeCapability] = []
    for mutation_target in plan.mutations:
        route_state = route[mutation_target.ingress.ingress_node_id]
        available = (
            mode == RuntimeMode.MANAGED
            and route_state.state != RuntimeCapabilityState.UNAVAILABLE
            and mutation_target.mutation_node_id in mutation_trace
        )
        reason = (
            RuntimeCapabilityReasonCode.AVAILABLE
            if available
            else (
                RuntimeCapabilityReasonCode.STATIC_ONLY_CONFIGURED
                if mode == RuntimeMode.STATIC
                else (
                    RuntimeCapabilityReasonCode.IN_PROCESS_INSTRUMENTATION_UNAVAILABLE
                    if mode == RuntimeMode.BYO
                    else prepared.mutation_failures.get(
                        mutation_target.mutation_node_id, route_state.reasons[0]
                    )
                )
            )
        )
        mutations.append(
            MutationRuntimeCapability(
                target=mutation_target,
                assignment=assessment(
                    RuntimeCapabilityState.COMPLETE
                    if available
                    else RuntimeCapabilityState.UNAVAILABLE,
                    reason,
                ),
                strength=(
                    MutationObservationStrength.PYTHON_ASSIGNMENT_INSTRUCTION_COMPLETION
                    if available
                    else None
                ),
            )
        )

    acknowledgements = tuple(
        AcknowledgementRuntimeCapability(
            target=target,
            timeline=(
                route[target.ingress.ingress_node_id]
                if mode == RuntimeMode.MANAGED
                else assessment(
                    (
                        RuntimeCapabilityState.PARTIAL
                        if mode == RuntimeMode.BYO
                        and route[target.ingress.ingress_node_id].state
                        != RuntimeCapabilityState.UNAVAILABLE
                        else RuntimeCapabilityState.UNAVAILABLE
                    ),
                    (
                        RuntimeCapabilityReasonCode.CLIENT_RESPONSE_ONLY
                        if mode == RuntimeMode.BYO
                        else RuntimeCapabilityReasonCode.STATIC_ONLY_CONFIGURED
                    ),
                )
            ),
        )
        for target in plan.acknowledgements
    )
    unavailable_reset = assessment(
        RuntimeCapabilityState.UNAVAILABLE,
        RuntimeCapabilityReasonCode.EXTERNAL_STATE_RESET_UNAVAILABLE,
    )
    owned = ownership == RuntimeProcessOwnership.STATEGUARD
    isolation = RuntimeIsolationCapability(
        fresh_process=assessment(
            RuntimeCapabilityState.COMPLETE if owned else RuntimeCapabilityState.UNAVAILABLE,
            (
                RuntimeCapabilityReasonCode.AVAILABLE
                if owned
                else RuntimeCapabilityReasonCode.EXTERNAL_STATE_RESET_UNAVAILABLE
            ),
        ),
        observation_reset=assessment(
            RuntimeCapabilityState.COMPLETE
            if mode == RuntimeMode.MANAGED and owned
            else RuntimeCapabilityState.UNAVAILABLE,
            (
                RuntimeCapabilityReasonCode.AVAILABLE
                if mode == RuntimeMode.MANAGED and owned
                else RuntimeCapabilityReasonCode.IN_PROCESS_INSTRUMENTATION_UNAVAILABLE
            ),
        ),
        external_state_reset=unavailable_reset,
    )
    runtime_config_fp = fingerprint_json(
        runtime_config if runtime_config is not None else {"mode": RuntimeMode.STATIC}
    )
    fingerprint = runtime_capability_fingerprint(
        project_id=source_index.project_id,
        project_source_fingerprint=source_index.project_source_fingerprint,
        source_index_fingerprint=source_index.source_index_fingerprint,
        structural_graph_fingerprint=structural_graph.graph_fingerprint,
        projected_graph_fingerprint=graph.graph_fingerprint,
        applicability_fingerprint=applicability.applicability_fingerprint,
        runtime_config_fingerprint=runtime_config_fp,
        mode=mode.value,
        ownership=ownership,
        lifecycle=lifecycle,
        compatibility=compatibility,
        ingresses=ingresses,
        customer_values=tuple(customer_values),
        mutations=tuple(mutations),
        acknowledgements=acknowledgements,
        isolation=isolation,
        diagnostics=diagnostics,
    )
    return RuntimeCapabilityArtifact(
        producer_version=__version__,
        generated_at=generated_at,
        project_id=source_index.project_id,
        project_source_fingerprint=source_index.project_source_fingerprint,
        source_index_fingerprint=source_index.source_index_fingerprint,
        structural_graph_fingerprint=structural_graph.graph_fingerprint,
        projected_graph_fingerprint=graph.graph_fingerprint,
        applicability_fingerprint=applicability.applicability_fingerprint,
        runtime_config_fingerprint=runtime_config_fp,
        assessment_session_id=session_id,
        mode=mode.value,
        ownership=ownership,
        lifecycle=lifecycle,
        compatibility=compatibility,
        ingresses=ingresses,
        customer_values=tuple(customer_values),
        mutations=tuple(mutations),
        acknowledgements=acknowledgements,
        isolation=isolation,
        diagnostics=diagnostics,
        capability_fingerprint=fingerprint,
    )
