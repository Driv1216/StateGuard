"""Exact CPython 3.11 tracing without merchant value capture or source rewriting."""

from __future__ import annotations

import contextlib
import dis
import inspect
import sys
import threading
from collections.abc import Callable, Iterator
from contextvars import ContextVar, Token
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import CodeType, FrameType, TracebackType
from typing import Any, cast

from pydantic import Field

from stateguard.contracts.common import (
    GraphNodeId,
    NormalControlId,
    PersistedArtifactModel,
    RouteRegistrationId,
    RuntimeRequestId,
    RuntimeSessionId,
    Sha256Digest,
    SourceLocation,
    SymbolId,
)
from stateguard.contracts.identity import fingerprint_json, sha256_digest
from stateguard.discovery.contracts import SourceIndexArtifact, SymbolKind, SymbolRecord
from stateguard.graph.contracts import GraphNode, MerchantMutationKind

from .contracts import (
    IngressRuntimeBinding,
    RuntimeCapabilityReasonCode,
    RuntimeObservationEvent,
    RuntimeObservationKind,
)


class InstrumentationError(ValueError):
    """An exact trace target could not be reconciled."""


class PythonCallableShape(StrEnum):
    SYNC = "SYNC"
    COROUTINE = "COROUTINE"
    GENERATOR = "GENERATOR"
    ASYNC_GENERATOR = "ASYNC_GENERATOR"


class TraceCodeDescriptor(PersistedArtifactModel):
    source_path: str
    qualified_name: str = Field(min_length=1, max_length=512)
    definition_line: int = Field(ge=1)
    definition_ordinal: int = Field(ge=0)
    first_line: int = Field(ge=1)
    code_fingerprint: Sha256Digest
    initial_resume_offset: int = Field(ge=0)
    shape: PythonCallableShape


class CustomerTraceTarget(PersistedArtifactModel):
    descriptor: TraceCodeDescriptor
    normal_control_id: NormalControlId
    customer_value_node_id: GraphNodeId
    customer_value_symbol_id: SymbolId


class MutationTraceTarget(PersistedArtifactModel):
    descriptor: TraceCodeDescriptor
    mutation_node_id: GraphNodeId
    mutation_symbol_id: SymbolId
    ingress_node_id: GraphNodeId
    route_registration_id: RouteRegistrationId
    instruction_offset: int = Field(ge=0)
    instruction_name: str = Field(pattern=r"^STORE_(?:SUBSCR|ATTR)$")


@dataclass(frozen=True)
class RuntimeRequestContext:
    session_id: RuntimeSessionId
    request_id: RuntimeRequestId
    ingress: IngressRuntimeBinding
    normal_control_id: NormalControlId | None = None


_REQUEST_CONTEXT: ContextVar[RuntimeRequestContext | None] = ContextVar(
    "stateguard_runtime_request_context", default=None
)


def bind_runtime_request(context: RuntimeRequestContext) -> Token[RuntimeRequestContext | None]:
    return _REQUEST_CONTEXT.set(context)


def reset_runtime_request(token: Token[RuntimeRequestContext | None]) -> None:
    _REQUEST_CONTEXT.reset(token)


def current_runtime_request() -> RuntimeRequestContext | None:
    return _REQUEST_CONTEXT.get()


def _walk_code(code: CodeType) -> Iterator[CodeType]:
    for value in code.co_consts:
        if isinstance(value, CodeType):
            yield value
            yield from _walk_code(value)


def _module_name(source_index: SourceIndexArtifact, symbol: SymbolRecord) -> str:
    modules = [
        item.qualified_name
        for item in source_index.symbols
        if item.source_file_id == symbol.source_file_id and item.kind == SymbolKind.MODULE
    ]
    if len(modules) != 1:
        raise InstrumentationError("symbol module identity is not unique")
    return modules[0]


def _callable_shape(code: CodeType) -> PythonCallableShape:
    if code.co_flags & inspect.CO_ASYNC_GENERATOR:
        return PythonCallableShape.ASYNC_GENERATOR
    if code.co_flags & inspect.CO_GENERATOR:
        return PythonCallableShape.GENERATOR
    if code.co_flags & inspect.CO_COROUTINE:
        return PythonCallableShape.COROUTINE
    return PythonCallableShape.SYNC


def _descriptor(
    relative_path: str,
    code: CodeType,
    *,
    definition_line: int,
    definition_ordinal: int,
) -> TraceCodeDescriptor:
    resume = next(
        (
            instruction.offset
            for instruction in dis.get_instructions(code)
            if instruction.opname == "RESUME" and instruction.arg == 0
        ),
        None,
    )
    if resume is None:
        raise InstrumentationError("target code has no initial CPython RESUME instruction")
    return TraceCodeDescriptor(
        source_path=relative_path,
        qualified_name=code.co_qualname,
        definition_line=definition_line,
        definition_ordinal=definition_ordinal,
        first_line=code.co_firstlineno,
        code_fingerprint=sha256_digest(code.co_code),
        initial_resume_offset=resume,
        shape=_callable_shape(code),
    )


def compile_symbol_descriptor(
    repository_root: Path,
    source_index: SourceIndexArtifact,
    symbol_id: SymbolId,
) -> TraceCodeDescriptor:
    symbols = {item.symbol_id: item for item in source_index.symbols}
    files = {item.file_id: item for item in source_index.indexed_files}
    symbol = symbols.get(symbol_id)
    if symbol is None or symbol.kind not in {
        SymbolKind.FUNCTION,
        SymbolKind.ASYNC_FUNCTION,
        SymbolKind.METHOD,
        SymbolKind.ASYNC_METHOD,
    }:
        raise InstrumentationError("trace target is not an exact indexed callable")
    source_file = files[symbol.source_file_id]
    path = (repository_root / source_file.path).resolve(strict=True)
    raw = path.read_bytes()
    if sha256_digest(raw) != source_file.content_fingerprint:
        raise InstrumentationError("trace target source bytes are stale")
    compiled = compile(raw, str(path), "exec", dont_inherit=True)
    module_name = _module_name(source_index, symbol)
    relative_qualname = symbol.qualified_name.removeprefix(f"{module_name}.")
    candidates = [code for code in _walk_code(compiled) if code.co_qualname == relative_qualname]
    if len(candidates) <= symbol.definition_ordinal:
        raise InstrumentationError("indexed callable ordinal did not resolve exactly")
    candidate = candidates[symbol.definition_ordinal]
    if candidate.co_firstlineno > symbol.source_location.line_start:
        raise InstrumentationError("indexed callable definition line is inconsistent")
    return _descriptor(
        source_file.path,
        candidate,
        definition_line=symbol.source_location.line_start,
        definition_ordinal=symbol.definition_ordinal,
    )


def _mutation_location(node: GraphNode) -> SourceLocation:
    locations = {
        record.source_location
        for record in node.provenance
        if record.reference.startswith("ast-fact:SG-AST-MERCHANT-MUTATION-001:node:")
        and record.source_location is not None
    }
    if len(locations) != 1:
        raise InstrumentationError("mutation graph node has no unique AST location")
    return next(iter(locations))


def compile_mutation_trace_target(
    repository_root: Path,
    source_index: SourceIndexArtifact,
    node: GraphNode,
    mutation_kind: MerchantMutationKind,
    ingress: IngressRuntimeBinding,
) -> MutationTraceTarget:
    if node.backing_symbol_id is None:
        raise InstrumentationError("mutation graph node has no backing symbol")
    descriptor = compile_symbol_descriptor(repository_root, source_index, node.backing_symbol_id)
    source_path = (repository_root / descriptor.source_path).resolve(strict=True)
    compiled = compile(source_path.read_bytes(), str(source_path), "exec", dont_inherit=True)
    code = next(
        item
        for item in _walk_code(compiled)
        if item.co_qualname == descriptor.qualified_name
        and item.co_firstlineno == descriptor.first_line
        and sha256_digest(item.co_code) == descriptor.code_fingerprint
    )
    location = _mutation_location(node)
    expected_name = (
        "STORE_ATTR" if mutation_kind == MerchantMutationKind.ATTRIBUTE_WRITE else "STORE_SUBSCR"
    )
    candidates = []
    for instruction in dis.get_instructions(code):
        position = instruction.positions
        if (
            instruction.opname == expected_name
            and position is not None
            and position.lineno == location.line_start
            and position.end_lineno == location.line_end
            and position.col_offset == location.column_start
            and position.end_col_offset == location.column_end
        ):
            candidates.append(instruction)
    if len(candidates) != 1:
        raise InstrumentationError(
            "mutation AST location did not resolve to one exact assignment instruction"
        )
    instruction = candidates[0]
    return MutationTraceTarget(
        descriptor=descriptor,
        mutation_node_id=node.node_id,
        mutation_symbol_id=node.backing_symbol_id,
        ingress_node_id=ingress.ingress_node_id,
        route_registration_id=ingress.route_registration_id,
        instruction_offset=instruction.offset,
        instruction_name=instruction.opname,
    )


def descriptor_matches_code(
    descriptor: TraceCodeDescriptor,
    code: CodeType,
    repository_root: Path,
) -> bool:
    if (
        code.co_qualname != descriptor.qualified_name
        or code.co_firstlineno != descriptor.first_line
        or sha256_digest(code.co_code) != descriptor.code_fingerprint
    ):
        return False
    try:
        runtime_path = Path(code.co_filename).resolve(strict=True)
    except OSError:
        return False
    try:
        expected_path = (repository_root.resolve(strict=True) / descriptor.source_path).resolve(
            strict=True
        )
    except OSError:
        return False
    return bool(runtime_path == expected_path)


def live_symbol_matches_descriptor(
    source_index: SourceIndexArtifact,
    symbol_id: SymbolId,
    descriptor: TraceCodeDescriptor,
    repository_root: Path,
) -> bool:
    """Resolve one imported symbol exactly and prove its live code descriptor."""

    symbols = {item.symbol_id: item for item in source_index.symbols}
    symbol = symbols.get(symbol_id)
    if symbol is None:
        return False
    module_name = _module_name(source_index, symbol)
    module = sys.modules.get(module_name)
    if module is None:
        return False
    relative_qualname = symbol.qualified_name.removeprefix(f"{module_name}.")
    components = relative_qualname.split(".")
    if not components or "<locals>" in components:
        return False
    value: object = module
    try:
        for component in components:
            value = inspect.getattr_static(value, component)
            if isinstance(value, (staticmethod, classmethod)):
                value = value.__func__
    except (AttributeError, TypeError):
        return False

    matching_codes: set[int] = set()
    seen_values: set[int] = set()
    while id(value) not in seen_values:
        seen_values.add(id(value))
        code = getattr(value, "__code__", None)
        if isinstance(code, CodeType) and descriptor_matches_code(
            descriptor, code, repository_root
        ):
            matching_codes.add(id(code))
        wrapped = getattr(value, "__wrapped__", None)
        if wrapped is None:
            break
        value = wrapped
    return len(matching_codes) == 1


class ObservationCollector:
    """Bounded, thread-safe and value-free observation collector."""

    def __init__(
        self,
        *,
        max_events: int = 10_000,
        event_sink: Callable[[RuntimeObservationEvent], None] | None = None,
    ) -> None:
        if max_events < 1:
            raise ValueError("max_events must be positive")
        self._max_events = max_events
        self._event_sink = event_sink
        self._events: list[RuntimeObservationEvent] = []
        self._diagnostics: set[RuntimeCapabilityReasonCode] = set()
        self._complete = True
        self._lock = threading.Lock()

    def emit(
        self,
        kind: RuntimeObservationKind,
        context: RuntimeRequestContext,
        *,
        normal_control_id: NormalControlId | None = None,
        customer_value_node_id: GraphNodeId | None = None,
        customer_value_symbol_id: SymbolId | None = None,
        mutation_node_id: GraphNodeId | None = None,
        acknowledgement_node_id: GraphNodeId | None = None,
        status_code: int | None = None,
        original_status_code: int | None = None,
    ) -> None:
        with self._lock:
            if len(self._events) >= self._max_events:
                self._complete = False
                self._diagnostics.add(RuntimeCapabilityReasonCode.OBSERVATION_CHANNEL_FAILED)
                return
            observation = RuntimeObservationEvent(
                session_id=context.session_id,
                request_id=context.request_id,
                sequence=len(self._events) + 1,
                kind=kind,
                ingress_node_id=context.ingress.ingress_node_id,
                route_registration_id=context.ingress.route_registration_id,
                normal_control_id=normal_control_id,
                customer_value_node_id=customer_value_node_id,
                customer_value_symbol_id=customer_value_symbol_id,
                mutation_node_id=mutation_node_id,
                acknowledgement_node_id=acknowledgement_node_id,
                status_code=status_code,
                original_status_code=original_status_code,
            )
            self._events.append(observation)
            if self._event_sink is not None:
                try:
                    self._event_sink(observation)
                except BaseException:
                    self._complete = False
                    self._diagnostics.add(RuntimeCapabilityReasonCode.OBSERVATION_CHANNEL_FAILED)

    def fail(self, reason: RuntimeCapabilityReasonCode) -> None:
        with self._lock:
            self._complete = False
            self._diagnostics.add(reason)

    def snapshot(
        self,
    ) -> tuple[
        tuple[RuntimeObservationEvent, ...],
        bool,
        tuple[RuntimeCapabilityReasonCode, ...],
    ]:
        with self._lock:
            return (
                tuple(self._events),
                self._complete,
                tuple(sorted(self._diagnostics)),
            )


@dataclass
class _FrameState:
    context: RuntimeRequestContext
    customer: CustomerTraceTarget | None
    mutations: dict[int, MutationTraceTarget]
    pending_exception: bool = False
    pending_mutation: MutationTraceTarget | None = None


class ExactTraceEngine:
    """A fail-closed trace function for exact code and assignment targets."""

    def __init__(
        self,
        collector: ObservationCollector,
        *,
        repository_root: Path,
        customers: tuple[CustomerTraceTarget, ...] = (),
        mutations: tuple[MutationTraceTarget, ...] = (),
        failure_probe: Callable[[], None] | None = None,
    ) -> None:
        self.collector = collector
        self.repository_root = repository_root.resolve(strict=True)
        self.customers = customers
        self.mutations = mutations
        self.failure_probe = failure_probe
        self._states: dict[int, _FrameState] = {}
        self._disabled = False
        self._previous_sys: Callable[..., object] | None = None
        self._previous_thread: Callable[..., object] | None = None
        self._lock = threading.Lock()
        self._target_code_matches: dict[CodeType, bool] = {}

    def __enter__(self) -> ExactTraceEngine:
        self.install()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.uninstall()

    def install(self) -> None:
        self._previous_sys = sys.gettrace()
        self._previous_thread = threading.gettrace()
        threading.settrace(cast(Any, self._global_trace))
        sys.settrace(cast(Any, self._global_trace))

    def uninstall(self) -> None:
        sys.settrace(cast(Any, self._previous_sys))
        threading.settrace(cast(Any, self._previous_thread))
        with self._lock:
            self._states.clear()
            self._target_code_matches.clear()

    def _fail_closed(self) -> None:
        self._disabled = True
        self.collector.fail(RuntimeCapabilityReasonCode.OBSERVATION_CHANNEL_FAILED)

    def _matching_customer(
        self,
        code: CodeType,
        context: RuntimeRequestContext,
    ) -> CustomerTraceTarget | None:
        matches = [
            item
            for item in self.customers
            if item.normal_control_id == context.normal_control_id
            and descriptor_matches_code(item.descriptor, code, self.repository_root)
        ]
        if len(matches) > 1:
            raise InstrumentationError("runtime code matched multiple customer-value controls")
        return matches[0] if matches else None

    def _matching_mutations(
        self,
        code: CodeType,
        context: RuntimeRequestContext,
    ) -> dict[int, MutationTraceTarget]:
        matches = [
            item
            for item in self.mutations
            if item.ingress_node_id == context.ingress.ingress_node_id
            and item.route_registration_id == context.ingress.route_registration_id
            and descriptor_matches_code(item.descriptor, code, self.repository_root)
        ]
        result = {item.instruction_offset: item for item in matches}
        if len(result) != len(matches):
            raise InstrumentationError("runtime code matched duplicate mutation instructions")
        return result

    def _matches_any_target_code(self, code: CodeType) -> bool:
        cached = self._target_code_matches.get(code)
        if cached is not None:
            return cached
        matches = any(
            descriptor_matches_code(item.descriptor, code, self.repository_root)
            for item in self.customers
        ) or any(
            descriptor_matches_code(item.descriptor, code, self.repository_root)
            for item in self.mutations
        )
        self._target_code_matches[code] = matches
        return matches

    def _global_trace(
        self,
        frame: FrameType,
        event: str,
        arg: object,
    ) -> Callable[[FrameType, str, object], object] | None:
        del arg
        if self._disabled or event != "call":
            return None
        try:
            if self.failure_probe is not None:
                self.failure_probe()
            context = current_runtime_request()
            if context is None:
                if self._matches_any_target_code(frame.f_code):
                    self.collector.fail(RuntimeCapabilityReasonCode.UNCORRELATED_TARGET_EXECUTION)
                return None
            customer = self._matching_customer(frame.f_code, context)
            mutations = self._matching_mutations(frame.f_code, context)
            if customer is None and not mutations:
                if self._matches_any_target_code(frame.f_code):
                    self.collector.fail(RuntimeCapabilityReasonCode.UNCORRELATED_TARGET_EXECUTION)
                return None
            initial_resume = (
                customer.descriptor.initial_resume_offset
                if customer is not None
                else next(iter(mutations.values())).descriptor.initial_resume_offset
            )
            frame_id = id(frame)
            with self._lock:
                state = self._states.get(frame_id)
                if state is None and frame.f_lasti == initial_resume:
                    state = _FrameState(context=context, customer=customer, mutations=mutations)
                    self._states[frame_id] = state
                    if customer is not None:
                        self.collector.emit(
                            RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
                            context,
                            normal_control_id=customer.normal_control_id,
                            customer_value_node_id=customer.customer_value_node_id,
                            customer_value_symbol_id=customer.customer_value_symbol_id,
                        )
                if state is None:
                    return None
            if mutations:
                frame.f_trace_opcodes = True
            return self._local_trace
        except BaseException:
            self._fail_closed()
            return None

    def _local_trace(self, frame: FrameType, event: str, arg: object) -> object:
        del arg
        if self._disabled:
            return None
        try:
            frame_id = id(frame)
            with self._lock:
                state = self._states.get(frame_id)
                if state is None:
                    return None
                if state.pending_mutation is not None:
                    pending = state.pending_mutation
                    if event == "exception":
                        self.collector.emit(
                            RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_RAISED,
                            state.context,
                            mutation_node_id=pending.mutation_node_id,
                        )
                        state.pending_mutation = None
                    elif event in {"opcode", "line", "return"}:
                        self.collector.emit(
                            RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_COMPLETED_NORMALLY,
                            state.context,
                            mutation_node_id=pending.mutation_node_id,
                        )
                        state.pending_mutation = None

                if event == "opcode":
                    state.pending_exception = False
                    mutation = state.mutations.get(frame.f_lasti)
                    if mutation is not None:
                        self.collector.emit(
                            RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_REACHED,
                            state.context,
                            mutation_node_id=mutation.mutation_node_id,
                        )
                        state.pending_mutation = mutation
                    return self._local_trace

                if event == "exception":
                    state.pending_exception = True
                    return self._local_trace

                if event == "line":
                    state.pending_exception = False
                    return self._local_trace

                if event != "return":
                    return self._local_trace

                instruction = next(
                    (
                        item
                        for item in dis.get_instructions(frame.f_code)
                        if item.offset == frame.f_lasti
                    ),
                    None,
                )
                if instruction is not None and instruction.opname == "YIELD_VALUE":
                    return self._local_trace
                customer = state.customer
                if customer is not None and customer.descriptor.shape not in {
                    PythonCallableShape.GENERATOR,
                    PythonCallableShape.ASYNC_GENERATOR,
                }:
                    kind = (
                        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY
                        if instruction is not None and instruction.opname == "RETURN_VALUE"
                        else RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED
                    )
                    self.collector.emit(
                        kind,
                        state.context,
                        normal_control_id=customer.normal_control_id,
                        customer_value_node_id=customer.customer_value_node_id,
                        customer_value_symbol_id=customer.customer_value_symbol_id,
                    )
                self._states.pop(frame_id, None)
                return None
        except BaseException:
            self._fail_closed()
            return None


@contextlib.contextmanager
def traced_request(context: RuntimeRequestContext) -> Iterator[None]:
    token = bind_runtime_request(context)
    try:
        yield
    finally:
        reset_runtime_request(token)


def transcript_fingerprint_payload(
    events: tuple[RuntimeObservationEvent, ...],
    *,
    complete: bool,
    diagnostics: tuple[RuntimeCapabilityReasonCode, ...],
) -> Sha256Digest:
    return fingerprint_json({"complete": complete, "events": events, "diagnostics": diagnostics})
