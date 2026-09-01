from __future__ import annotations

import asyncio
import dis
import functools
import threading
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request

from stateguard.contracts.identity import (
    framework_instance_id,
    graph_node_id,
    new_project_id,
    new_runtime_session_id,
    normal_control_id,
    route_registration_id,
    runtime_request_id,
    sha256_digest,
    source_file_id,
    symbol_id,
)
from stateguard.discovery.contracts import FrameworkKind
from stateguard.runtime.contracts import (
    IngressRuntimeBinding,
    RuntimeCapabilityReasonCode,
    RuntimeObservationKind,
)
from stateguard.runtime.instrumentation import (
    CustomerTraceTarget,
    ExactTraceEngine,
    MutationTraceTarget,
    ObservationCollector,
    PythonCallableShape,
    RuntimeRequestContext,
    TraceCodeDescriptor,
    descriptor_matches_code,
    traced_request,
)

ROOT = Path(__file__).resolve().parents[2]
RELATIVE_PATH = Path(__file__).resolve().relative_to(ROOT).as_posix()


def sync_target(value: int) -> int:
    return value + 1


async def async_target(value: int) -> int:
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    return value + 1


def throwing_target() -> None:
    raise RuntimeError("merchant exception must survive")


def caught_target() -> str:
    try:
        raise ValueError("caught")
    except ValueError:
        return "recovered"


def decorate(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        return function(*args, **kwargs)

    return wrapper


@decorate
def decorated_target(value: int) -> int:
    return value * 2


class TargetOwner:
    def method(self, value: int) -> int:
        return value * 3


def assignment_target(state: dict[str, str], value: str) -> str:
    state["status"] = value
    return state["status"]


def _descriptor(function, *, shape: PythonCallableShape) -> TraceCodeDescriptor:
    code = function.__code__
    resume = next(
        item.offset
        for item in dis.get_instructions(code)
        if item.opname == "RESUME" and item.arg == 0
    )
    return TraceCodeDescriptor(
        source_path=RELATIVE_PATH,
        qualified_name=code.co_qualname,
        definition_line=code.co_firstlineno,
        definition_ordinal=0,
        first_line=code.co_firstlineno,
        code_fingerprint=sha256_digest(code.co_code),
        initial_resume_offset=resume,
        shape=shape,
    )


def _identities(ordinal: int = 0):
    project = new_project_id()
    file_id = source_file_id(project, RELATIVE_PATH)
    ingress_symbol = symbol_id(file_id, f"tests.runtime.ingress_{ordinal}", "ASYNC_FUNCTION")
    app = framework_instance_id(file_id, "app", FrameworkKind.FASTAPI_APP.value)
    route = route_registration_id(
        selected_app_instance_id=app,
        include_anchors=(),
        registrar_instance_id=app,
        owner_symbol_id=ingress_symbol,
        method="POST",
        route_path=f"/webhook-{ordinal}",
        same_shape_ordinal=0,
    )
    ingress_node = graph_node_id("PAYMENT_INGRESS", ingress_symbol, str(ordinal))
    ingress = IngressRuntimeBinding(
        ingress_node_id=ingress_node,
        route_registration_id=route,
        app_instance_id=app,
        ingress_symbol_id=ingress_symbol,
        method="POST",
        effective_path=f"/webhook-{ordinal}",
    )
    control = normal_control_id(ingress_node, route, ordinal)
    customer_node = graph_node_id("CUSTOMER_VALUE_ACTION", ingress_symbol, str(ordinal))
    customer_symbol = symbol_id(file_id, f"tests.runtime.customer_{ordinal}", "FUNCTION")
    session = new_runtime_session_id()
    context = RuntimeRequestContext(
        session_id=session,
        request_id=runtime_request_id(session, 0),
        ingress=ingress,
        normal_control_id=control,
    )
    return context, control, customer_node, customer_symbol


def _customer_target(function, shape: PythonCallableShape, ordinal: int = 0):
    context, control, customer_node, customer_symbol = _identities(ordinal)
    return (
        context,
        CustomerTraceTarget(
            descriptor=_descriptor(function, shape=shape),
            normal_control_id=control,
            customer_value_node_id=customer_node,
            customer_value_symbol_id=customer_symbol,
        ),
    )


def _kinds(collector: ObservationCollector) -> list[RuntimeObservationKind]:
    return [item.kind for item in collector.snapshot()[0]]


def test_descriptor_match_rejects_non_target_metadata_before_filesystem_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor(sync_target, shape=PythonCallableShape.SYNC)

    def forbidden_resolve(*args, **kwargs):
        raise AssertionError("non-target code must not enter filesystem matching")

    monkeypatch.setattr(Path, "resolve", forbidden_resolve)
    assert not descriptor_matches_code(descriptor, throwing_target.__code__, ROOT)


def test_sync_normal_exception_and_caught_exception_preserve_behavior() -> None:
    context, normal = _customer_target(sync_target, PythonCallableShape.SYNC)
    throwing_context, throwing = _customer_target(throwing_target, PythonCallableShape.SYNC, 1)
    caught_context, caught = _customer_target(caught_target, PythonCallableShape.SYNC, 2)
    collector = ObservationCollector()
    with ExactTraceEngine(
        collector,
        repository_root=ROOT,
        customers=(normal, throwing, caught),
    ):
        with traced_request(context):
            assert sync_target(4) == 5
        with traced_request(throwing_context):
            with pytest.raises(RuntimeError, match="merchant exception must survive"):
                throwing_target()
        with traced_request(caught_context):
            assert caught_target() == "recovered"
    assert _kinds(collector) == [
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED,
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
    ]


def test_awaited_async_suspension_is_one_entry_and_one_completion() -> None:
    context, target = _customer_target(async_target, PythonCallableShape.COROUTINE)
    collector = ObservationCollector()

    async def execute() -> None:
        with ExactTraceEngine(collector, repository_root=ROOT, customers=(target,)):
            with traced_request(context):
                assert await async_target(7) == 8

    asyncio.run(execute())
    assert _kinds(collector) == [
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
    ]


def test_unawaited_coroutine_has_no_body_entry() -> None:
    context, target = _customer_target(async_target, PythonCallableShape.COROUTINE)
    collector = ObservationCollector()
    with ExactTraceEngine(collector, repository_root=ROOT, customers=(target,)):
        with traced_request(context):
            coroutine = async_target(1)
            coroutine.close()
    assert collector.snapshot()[0] == ()


def test_alias_decorator_and_method_execute_exact_original_bodies() -> None:
    alias = sync_target
    decorated_original = decorated_target.__wrapped__
    first_context, first = _customer_target(sync_target, PythonCallableShape.SYNC)
    second_context, second = _customer_target(decorated_original, PythonCallableShape.SYNC, 1)
    third_context, third = _customer_target(TargetOwner.method, PythonCallableShape.SYNC, 2)
    collector = ObservationCollector()
    with ExactTraceEngine(
        collector,
        repository_root=ROOT,
        customers=(first, second, third),
    ):
        with traced_request(first_context):
            assert alias(1) == 2
        with traced_request(second_context):
            assert decorated_target(3) == 6
        with traced_request(third_context):
            assert TargetOwner().method(4) == 12
    assert _kinds(collector).count(RuntimeObservationKind.CUSTOMER_VALUE_ENTERED) == 3
    assert _kinds(collector).count(RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY) == 3


def test_concurrent_async_requests_keep_exact_request_identity() -> None:
    first_context, first = _customer_target(async_target, PythonCallableShape.COROUTINE)
    second_context, second = _customer_target(async_target, PythonCallableShape.COROUTINE, 1)
    collector = ObservationCollector()

    async def one(context: RuntimeRequestContext, value: int) -> None:
        with traced_request(context):
            assert await async_target(value) == value + 1

    async def execute() -> None:
        with ExactTraceEngine(
            collector,
            repository_root=ROOT,
            customers=(first, second),
        ):
            await asyncio.gather(one(first_context, 1), one(second_context, 2))

    asyncio.run(execute())
    events = collector.snapshot()[0]
    by_request = {first_context.request_id: [], second_context.request_id: []}
    for event in events:
        by_request[event.request_id].append(event.kind)
    assert all(
        kinds
        == [
            RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
            RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        ]
        for kinds in by_request.values()
    )


def test_fastapi_async_and_sync_threadpool_endpoints_preserve_correlation() -> None:
    sync_context, sync_trace = _customer_target(sync_target, PythonCallableShape.SYNC)
    async_context, async_trace = _customer_target(async_target, PythonCallableShape.COROUTINE, 1)
    contexts = {"sync": sync_context, "async": async_context}
    app = FastAPI()

    @app.middleware("http")
    async def bind_context(request: Request, call_next):
        with traced_request(contexts[request.headers["x-test-context"]]):
            return await call_next(request)

    @app.get("/sync")
    def sync_endpoint() -> dict[str, int]:
        return {"value": sync_target(3)}

    @app.get("/async")
    async def async_endpoint() -> dict[str, int]:
        return {"value": await async_target(5)}

    collector = ObservationCollector()

    async def execute() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            with ExactTraceEngine(
                collector,
                repository_root=ROOT,
                customers=(sync_trace, async_trace),
            ):
                sync_response, async_response = await asyncio.gather(
                    client.get("/sync", headers={"x-test-context": "sync"}),
                    client.get("/async", headers={"x-test-context": "async"}),
                )
        assert sync_response.json() == {"value": 4}
        assert async_response.json() == {"value": 6}

    asyncio.run(execute())
    events = collector.snapshot()[0]
    by_request = {sync_context.request_id: [], async_context.request_id: []}
    for event in events:
        by_request[event.request_id].append(event.kind)
    assert all(
        kinds
        == [
            RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
            RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        ]
        for kinds in by_request.values()
    )


def test_assignment_instruction_success_and_exception_are_distinct() -> None:
    context, _, _, _ = _identities()
    descriptor = _descriptor(assignment_target, shape=PythonCallableShape.SYNC)
    instruction = next(
        item for item in dis.get_instructions(assignment_target) if item.opname == "STORE_SUBSCR"
    )
    mutation = MutationTraceTarget(
        descriptor=descriptor,
        mutation_node_id=graph_node_id(
            "MERCHANT_STATE_MUTATION", context.ingress.ingress_symbol_id
        ),
        mutation_symbol_id=context.ingress.ingress_symbol_id,
        ingress_node_id=context.ingress.ingress_node_id,
        route_registration_id=context.ingress.route_registration_id,
        instruction_offset=instruction.offset,
        instruction_name=instruction.opname,
    )
    collector = ObservationCollector()

    class RejectingDict(dict[str, str]):
        def __setitem__(self, key: str, value: str) -> None:
            raise RuntimeError("assignment rejected")

    with ExactTraceEngine(
        collector,
        repository_root=ROOT,
        mutations=(mutation,),
    ):
        with traced_request(context):
            state: dict[str, str] = {}
            assert assignment_target(state, "captured") == "captured"
            assert state == {"status": "captured"}
        with traced_request(context):
            with pytest.raises(RuntimeError, match="assignment rejected"):
                assignment_target(RejectingDict(), "captured")
    assert _kinds(collector) == [
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_REACHED,
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_COMPLETED_NORMALLY,
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_REACHED,
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_RAISED,
    ]


def test_tracer_failure_is_contained_and_exact_mismatch_is_not_observed() -> None:
    context, target = _customer_target(sync_target, PythonCallableShape.SYNC)
    collector = ObservationCollector()

    def fail() -> None:
        raise RuntimeError("tracer failure")

    with ExactTraceEngine(
        collector,
        repository_root=ROOT,
        customers=(target,),
        failure_probe=fail,
    ):
        with traced_request(context):
            assert sync_target(2) == 3
    events, complete, diagnostics = collector.snapshot()
    assert events == ()
    assert not complete
    assert diagnostics == (RuntimeCapabilityReasonCode.OBSERVATION_CHANNEL_FAILED,)

    mismatch = target.model_copy(
        update={"descriptor": target.descriptor.model_copy(update={"first_line": 1})}
    )
    collector = ObservationCollector()
    with ExactTraceEngine(
        collector,
        repository_root=ROOT,
        customers=(mismatch,),
    ):
        with traced_request(context):
            assert sync_target(2) == 3
    assert collector.snapshot() == ((), True, ())


def test_observations_contain_no_merchant_values() -> None:
    context, target = _customer_target(sync_target, PythonCallableShape.SYNC)
    collector = ObservationCollector()
    secret = "never-persist-this-value"
    with ExactTraceEngine(collector, repository_root=ROOT, customers=(target,)):
        with traced_request(context):
            assert sync_target(len(secret)) == len(secret) + 1
    payload = "\n".join(item.model_dump_json() for item in collector.snapshot()[0])
    assert secret not in payload
    for forbidden in ("arguments", "return_value", "exception", "locals", "payload"):
        assert forbidden not in payload.casefold()


def test_customer_and_assignment_facts_keep_distinct_target_authority() -> None:
    context, customer = _customer_target(assignment_target, PythonCallableShape.SYNC)
    instruction = next(
        item for item in dis.get_instructions(assignment_target) if item.opname == "STORE_SUBSCR"
    )
    mutation_node = graph_node_id("MERCHANT_STATE_MUTATION", context.ingress.ingress_symbol_id)
    mutation = MutationTraceTarget(
        descriptor=customer.descriptor,
        mutation_node_id=mutation_node,
        mutation_symbol_id=context.ingress.ingress_symbol_id,
        ingress_node_id=context.ingress.ingress_node_id,
        route_registration_id=context.ingress.route_registration_id,
        instruction_offset=instruction.offset,
        instruction_name=instruction.opname,
    )
    collector = ObservationCollector()
    with ExactTraceEngine(
        collector,
        repository_root=ROOT,
        customers=(customer,),
        mutations=(mutation,),
    ):
        with traced_request(context):
            assert assignment_target({}, "captured") == "captured"

    events = collector.snapshot()[0]
    assert [item.kind for item in events] == [
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_REACHED,
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_COMPLETED_NORMALLY,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
    ]
    customer_events = [item for item in events if item.normal_control_id is not None]
    mutation_events = [item for item in events if item.mutation_node_id is not None]
    assert {item.normal_control_id for item in customer_events} == {customer.normal_control_id}
    assert all(item.mutation_node_id is None for item in customer_events)
    assert {item.mutation_node_id for item in mutation_events} == {mutation_node}
    assert all(item.normal_control_id is None for item in mutation_events)


def test_observation_overflow_marks_stream_incomplete() -> None:
    context, _, _, _ = _identities()
    collector = ObservationCollector(max_events=1)
    collector.emit(RuntimeObservationKind.REQUEST_RECEIVED, context)
    collector.emit(RuntimeObservationKind.REQUEST_RECEIVED, context)
    events, complete, diagnostics = collector.snapshot()
    assert len(events) == 1
    assert not complete
    assert diagnostics == (RuntimeCapabilityReasonCode.OBSERVATION_CHANNEL_FAILED,)


def test_raw_thread_target_execution_without_correlation_is_incomplete() -> None:
    _, target = _customer_target(sync_target, PythonCallableShape.SYNC)
    collector = ObservationCollector()
    results: list[int] = []

    with ExactTraceEngine(collector, repository_root=ROOT, customers=(target,)):
        thread = threading.Thread(target=lambda: results.append(sync_target(4)))
        thread.start()
        thread.join()

    events, complete, diagnostics = collector.snapshot()
    assert results == [5]
    assert events == ()
    assert not complete
    assert diagnostics == (RuntimeCapabilityReasonCode.UNCORRELATED_TARGET_EXECUTION,)
