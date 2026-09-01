from __future__ import annotations

import asyncio
import json
import shutil
import signal
import socket
import sys
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from stateguard.applicability.contracts import (
    ApplicabilityReasonCode,
    EvidenceReference,
    EvidenceReferenceKind,
    ScenarioId,
)
from stateguard.application.applicability import analyze_applicability
from stateguard.application.runtime import assess_runtime_capability, open_runtime_session
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.contracts.config import ManagedRuntimeConfig, StateGuardConfig
from stateguard.contracts.identity import (
    fingerprint_json,
    new_project_id,
    new_runtime_session_id,
)
from stateguard.runtime import session as runtime_session_module
from stateguard.runtime.capability import (
    StaleRuntimeCapabilityError,
    build_capability_artifact,
    validate_historical_capability_inputs,
)
from stateguard.runtime.compatibility import managed_compatibility_reason
from stateguard.runtime.contracts import (
    MutationObservationStrength,
    RuntimeCapabilityReasonCode,
    RuntimeCapabilityState,
    RuntimeCompatibility,
    RuntimeLifecycleState,
    RuntimeObservationKind,
    RuntimeObservationTranscript,
    RuntimeProcessOwnership,
    RuntimeTranscriptMismatchError,
    validate_observation_transcript,
)
from stateguard.runtime.planning import RuntimePlanningError, build_runtime_target_plan
from stateguard.runtime.session import (
    ManagedRuntimeSession,
    RuntimeSessionError,
    _sanitized_environment,
)
from stateguard.workspace.config import load_config
from stateguard.workspace.runtime_artifacts import (
    load_runtime_artifact,
    write_runtime_artifact,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"
NOW = datetime(2026, 8, 26, tzinfo=UTC)


def _repository(tmp_path: Path, *, runtime_yaml: str) -> tuple[Path, Path]:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "runtime_app", repository)
    config = repository / "stateguard.yaml"
    config.write_text(
        f"""schema_version: 2
project:
  id: {new_project_id()}
  app_target: main:app
analysis:
  include: ["**/*.py"]
  exclude: [".stateguard/**"]
runtime:
{runtime_yaml}
""",
        encoding="utf-8",
    )
    return repository, config


def _semantic_runtime_repository(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "semantic-merchant"
    shutil.copytree(FIXTURES / "semantic_app", repository)
    shutil.copy(FIXTURES / "runtime_app" / "razorpay.py", repository / "razorpay.py")
    config = repository / "stateguard.yaml"
    config.write_text(
        f"""schema_version: 2
project:
  id: {new_project_id()}
  app_target: main:app
analysis:
  include: ["**/*.py"]
  exclude: [".stateguard/**"]
runtime:
  mode: managed
""",
        encoding="utf-8",
    )
    return repository, config


def _shared_customer_runtime_repository(
    tmp_path: Path,
    *,
    second_path: str,
) -> tuple[Path, Path]:
    repository = tmp_path / "shared-customer-merchant"
    repository.mkdir()
    shutil.copy(FIXTURES / "runtime_app" / "razorpay.py", repository / "razorpay.py")
    shutil.copy(FIXTURES / "semantic_app" / "domain.py", repository / "domain.py")
    shutil.copy(FIXTURES / "semantic_app" / "storage.py", repository / "storage.py")
    (repository / "main.py").write_text(
        f'''import razorpay
from domain import grant_ticket
from fastapi import FastAPI, Request

app = FastAPI()
client = razorpay.Client(auth=("key", "secret"))

@app.post("/webhook-a")
async def webhook_a(request: Request):
    raw_body = await request.body()
    client.utility.verify_webhook_signature(
        raw_body, request.headers["x-razorpay-signature"], "webhook-secret"
    )
    payload = await request.json()
    if payload["event"] == "payment.captured":
        grant_ticket(payload["payment_id"])
    return {{"route": "a"}}

@app.post("{second_path}")
async def webhook_b(request: Request):
    raw_body = await request.body()
    client.utility.verify_webhook_signature(
        raw_body, request.headers["x-razorpay-signature"], "webhook-secret"
    )
    payload = await request.json()
    if payload["event"] == "payment.captured":
        grant_ticket(payload["payment_id"])
    return {{"route": "b"}}
''',
        encoding="utf-8",
    )
    config = repository / "stateguard.yaml"
    config.write_text(
        f"""schema_version: 2
project:
  id: {new_project_id()}
  app_target: main:app
analysis:
  include: ["**/*.py"]
  exclude: [".stateguard/**"]
runtime:
  mode: managed
""",
        encoding="utf-8",
    )
    return repository, config


def _confirm_shared_customer(repository: Path, config: Path) -> None:
    unresolved = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    customer_symbol = next(
        item.symbol_id
        for item in unresolved.source_index.symbols
        if item.qualified_name == "domain.grant_ticket"
    )
    asyncio.run(confirm_customer_value(repository, config, customer_symbol, generated_at=NOW))


def test_step4_mutation_evidence_and_runtime_binding_need_no_normal_control(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path, runtime_yaml="  mode: static")
    result = analyze_applicability(repository, config, generated_at=NOW)
    assert result.artifact.normal_controls == ()
    plan = build_runtime_target_plan(
        result.snapshot.source_index,
        result.snapshot.graph,
        result.artifact,
    )
    assert len(plan.ingresses) == 1
    # The audit marker is not a bounded merchant payment-state field; only the exact
    # payment-state mutation is eligible for runtime mutation authority.
    assert len(plan.mutations) == 1
    assert plan.customer_values == ()
    assert {item.ingress.ingress_node_id for item in plan.mutations} == {
        plan.ingresses[0].ingress_node_id
    }


def test_cross_route_mutation_evidence_substitution_is_rejected(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path, runtime_yaml="  mode: static")
    result = analyze_applicability(repository, config, generated_at=NOW)
    scenarios = list(result.artifact.scenarios)
    scenario_index = next(
        index for index, item in enumerate(scenarios) if item.scenario_id == ScenarioId.SG_05
    )
    scenario = scenarios[scenario_index]
    instances = list(scenario.instances)
    instance = instances[0]
    assertions = list(instance.assertions)
    assertion_index = next(
        index
        for index, item in enumerate(assertions)
        if any(
            reason.code == ApplicabilityReasonCode.MUTATION_TARGET_AVAILABLE
            for reason in item.reasons
        )
    )
    assertion = assertions[assertion_index]
    assert instance.ingress_node_id is not None
    reasons = list(assertion.reasons)
    reason_index = next(
        index
        for index, item in enumerate(reasons)
        if item.code == ApplicabilityReasonCode.MUTATION_TARGET_AVAILABLE
    )
    reasons[reason_index] = reasons[reason_index].model_copy(
        update={
            "evidence": (
                EvidenceReference(
                    kind=EvidenceReferenceKind.GRAPH_NODE,
                    reference=instance.ingress_node_id,
                ),
            )
        }
    )
    assertions[assertion_index] = assertion.model_copy(update={"reasons": tuple(reasons)})
    instances[0] = instance.model_copy(update={"assertions": tuple(assertions)})
    scenarios[scenario_index] = scenario.model_copy(update={"instances": tuple(instances)})
    substituted = result.artifact.model_copy(update={"scenarios": tuple(scenarios)})

    with pytest.raises(RuntimePlanningError, match="exact route mutation nodes"):
        build_runtime_target_plan(
            result.snapshot.source_index,
            result.snapshot.graph,
            substituted,
        )


def test_runtime_target_policy_rejects_public_default_and_requires_declaration() -> None:
    base = {"schema_version": 2, "project": {"id": new_project_id()}}
    with pytest.raises(ValueError, match="loopback"):
        StateGuardConfig.model_validate(
            {
                **base,
                "runtime": {
                    "mode": "byo",
                    "target": {"kind": "local", "base_url": "https://example.com"},
                    "readiness": {"path": "/health"},
                },
            }
        )
    declared = StateGuardConfig.model_validate(
        {
            **base,
            "runtime": {
                "mode": "byo",
                "target": {
                    "kind": "declared_test",
                    "base_url": "https://test.example.com",
                    "declaration": "NON_PRODUCTION_TEST_ENVIRONMENT",
                },
                "readiness": {"path": "/health"},
            },
        }
    )
    assert declared.runtime is not None and declared.runtime.mode.value == "byo"


@pytest.mark.parametrize(
    ("compatibility", "reason"),
    [
        (
            RuntimeCompatibility(
                python_implementation="CPython",
                python_version="3.11.15",
                fastapi_version=None,
                starlette_version=None,
                uvicorn_version=None,
            ),
            RuntimeCapabilityReasonCode.RUNTIME_DEPENDENCY_MISSING,
        ),
        (
            RuntimeCompatibility(
                python_implementation="CPython",
                python_version="3.11.15",
                fastapi_version="0.142.0",
                starlette_version="1.6.0",
                uvicorn_version="0.52.4",
            ),
            RuntimeCapabilityReasonCode.RUNTIME_VERSION_UNTESTED,
        ),
        (
            RuntimeCompatibility(
                python_implementation="PyPy",
                python_version="3.11.15",
                fastapi_version="0.141.1",
                starlette_version="1.6.0",
                uvicorn_version="0.52.4",
            ),
            RuntimeCapabilityReasonCode.UNSUPPORTED_PYTHON_RUNTIME,
        ),
    ],
)
def test_managed_compatibility_degrades_without_dependency_mutation(
    compatibility: RuntimeCompatibility,
    reason: RuntimeCapabilityReasonCode,
) -> None:
    assert managed_compatibility_reason(compatibility) == reason


def test_child_environment_does_not_inherit_unselected_host_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MERCHANT_TEST_SECRET", "must-not-leak-by-default")
    environment = _sanitized_environment({})
    assert "MERCHANT_TEST_SECRET" not in environment
    selected = _sanitized_environment({"MERCHANT_CHILD_NAME": "MERCHANT_TEST_SECRET"})
    assert selected["MERCHANT_CHILD_NAME"] == "must-not-leak-by-default"


def test_static_assessment_persists_capability_without_observations(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path, runtime_yaml="  mode: static")
    result = assess_runtime_capability(repository, config, generated_at=NOW)
    assert result.artifact.mode == "static"
    assert result.artifact.lifecycle == RuntimeLifecycleState.UNAVAILABLE
    assert result.artifact.ingresses[0].addressability.state == RuntimeCapabilityState.UNAVAILABLE
    path = repository / ".stateguard" / "runtime.json"
    assert load_runtime_artifact(repository) == result.artifact
    assert path.stat().st_mode & 0o777 == 0o600
    payload = json.loads(path.read_text(encoding="utf-8"))

    def all_keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | set().union(*(all_keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(all_keys(item) for item in value))
        return set()

    assert {"events", "request_id", "transcript_fingerprint"}.isdisjoint(all_keys(payload))

    snapshot = result.applicability.snapshot
    runtime_config = load_config(config).runtime
    validate_historical_capability_inputs(
        result.artifact,
        runtime_config=runtime_config,
        source_index=snapshot.source_index,
        structural_graph=snapshot.structural_graph,
        graph=snapshot.graph,
        applicability=result.applicability.artifact,
    )
    with pytest.raises(StaleRuntimeCapabilityError, match="reassessment"):
        validate_historical_capability_inputs(
            result.artifact,
            runtime_config=ManagedRuntimeConfig(),
            source_index=snapshot.source_index,
            structural_graph=snapshot.structural_graph,
            graph=snapshot.graph,
            applicability=result.applicability.artifact,
        )


def test_runtime_artifact_refuses_symlink_replacement(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path, runtime_yaml="  mode: static")
    artifact = assess_runtime_capability(repository, config, generated_at=NOW).artifact
    runtime_path = repository / ".stateguard" / "runtime.json"
    runtime_path.unlink()
    runtime_path.symlink_to(repository / "outside.json")
    with pytest.raises(ValueError, match="symlinked runtime"):
        write_runtime_artifact(repository, artifact)


def test_managed_assessment_attaches_exact_route_and_mutation(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path, runtime_yaml="  mode: managed")
    result = assess_runtime_capability(repository, config, generated_at=NOW)
    assert result.artifact.mode == "managed"
    assert result.artifact.lifecycle == RuntimeLifecycleState.HISTORICAL
    assert result.artifact.ownership == RuntimeProcessOwnership.STATEGUARD
    assert result.artifact.ingresses[0].addressability.state == RuntimeCapabilityState.COMPLETE, (
        result.artifact.ingresses[0].addressability
    )
    assert all(
        item.assignment.state == RuntimeCapabilityState.COMPLETE
        for item in result.artifact.mutations
    )
    assert all(
        item.strength == MutationObservationStrength.PYTHON_ASSIGNMENT_INSTRUCTION_COMPLETION
        for item in result.artifact.mutations
    )
    assert result.artifact.customer_values == ()
    assert result.artifact.acknowledgements
    assert all(
        item.timeline.state == RuntimeCapabilityState.COMPLETE
        for item in result.artifact.acknowledgements
    )


def test_open_runtime_session_exposes_fresh_authority_without_persisting(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path, runtime_yaml="  mode: managed")
    opened = open_runtime_session(repository, config, generated_at=NOW)
    assert opened.artifact.lifecycle == RuntimeLifecycleState.READY
    assert opened.session is not None
    assert not (repository / ".stateguard" / "runtime.json").exists()
    transcript = opened.session.close(opened.artifact.capability_fingerprint)
    validate_observation_transcript(opened.artifact, transcript)


def test_live_customer_value_descriptor_mismatch_is_unavailable(tmp_path: Path) -> None:
    repository, config = _semantic_runtime_repository(tmp_path)
    domain = repository / "domain.py"
    domain.write_text(
        domain.read_text(encoding="utf-8")
        + "\ndef replacement_grant_ticket(payment_id):\n"
        + "    return {'replacement': payment_id}\n"
        + "grant_ticket = replacement_grant_ticket\n",
        encoding="utf-8",
    )
    unresolved = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    customer_symbol = next(
        item.symbol_id
        for item in unresolved.source_index.symbols
        if item.qualified_name == "domain.grant_ticket"
    )
    asyncio.run(confirm_customer_value(repository, config, customer_symbol, generated_at=NOW))

    opened = open_runtime_session(repository, config, generated_at=NOW)
    assert opened.session is not None
    assert len(opened.artifact.customer_values) == 1
    capability = opened.artifact.customer_values[0]
    assert capability.lifecycle.state == RuntimeCapabilityState.UNAVAILABLE
    assert capability.lifecycle.reasons == (RuntimeCapabilityReasonCode.TARGET_CODE_MISMATCH,)
    opened.session.close(opened.artifact.capability_fingerprint)


def test_live_mutation_descriptor_mismatch_is_unavailable(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path, runtime_yaml="  mode: managed")
    source = repository / "main.py"
    source.write_text(
        source.read_text(encoding="utf-8")
        + "\nasync def replacement_payment_webhook(request):\n"
        + "    return {'replacement': True}\n"
        + "payment_webhook = replacement_payment_webhook\n",
        encoding="utf-8",
    )

    opened = open_runtime_session(repository, config, generated_at=NOW)
    assert opened.session is not None
    assert opened.artifact.mutations
    assert all(
        item.assignment.state == RuntimeCapabilityState.UNAVAILABLE
        and item.assignment.reasons == (RuntimeCapabilityReasonCode.TARGET_CODE_MISMATCH,)
        for item in opened.artifact.mutations
    )
    opened.session.close(opened.artifact.capability_fingerprint)


def test_managed_raw_thread_customer_execution_makes_transcript_incomplete(
    tmp_path: Path,
) -> None:
    repository, config = _semantic_runtime_repository(tmp_path)
    source = repository / "main.py"
    raw = source.read_text(encoding="utf-8")
    raw = raw.replace("import razorpay\n", "import razorpay\nimport threading\n")
    raw = raw.replace(
        '        grant_ticket(payload["payload"]["payment"]["entity"]["id"])',
        '        payment_id = payload["payload"]["payment"]["entity"]["id"]\n'
        '        if payload.get("background"):\n'
        "            thread = threading.Thread(target=grant_ticket, args=(payment_id,))\n"
        "            thread.start()\n"
        "            thread.join()\n"
        "        else:\n"
        "            grant_ticket(payment_id)",
    )
    source.write_text(raw, encoding="utf-8")
    _confirm_shared_customer(repository, config)
    opened = open_runtime_session(repository, config, generated_at=NOW)
    assert isinstance(opened.session, ManagedRuntimeSession)
    opened.session.request(
        opened.plan.ingresses[0],
        headers={"x-razorpay-signature": "test-signature"},
        content=json.dumps(
            {
                "event": "payment.captured",
                "background": True,
                "payload": {"payment": {"entity": {"id": "pay_background"}}},
            }
        ).encode(),
    )
    transcript = opened.session.close(opened.artifact.capability_fingerprint)
    assert not transcript.complete
    assert RuntimeCapabilityReasonCode.UNCORRELATED_TARGET_EXECUTION in transcript.diagnostics


def test_same_session_concurrent_routes_keep_shared_customer_identity(
    tmp_path: Path,
) -> None:
    repository, config = _shared_customer_runtime_repository(
        tmp_path,
        second_path="/webhook-b",
    )
    _confirm_shared_customer(repository, config)
    opened = open_runtime_session(repository, config, generated_at=NOW)
    assert isinstance(opened.session, ManagedRuntimeSession)
    bindings = {item.effective_path: item for item in opened.plan.ingresses}
    targets = {item.ingress.effective_path: item for item in opened.plan.customer_values}
    results = []
    failures: list[BaseException] = []

    def drive(path: str, payment_id: str) -> None:
        try:
            results.append(
                opened.session.request(
                    bindings[path],
                    headers={"x-razorpay-signature": "test-signature"},
                    content=json.dumps(
                        {"event": "payment.captured", "payment_id": payment_id}
                    ).encode(),
                )
            )
        except BaseException as exc:  # pragma: no cover - assertion reports the exact failure
            failures.append(exc)

    threads = [
        threading.Thread(target=drive, args=("/webhook-a", "pay_a")),
        threading.Thread(target=drive, args=("/webhook-b", "pay_b")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []
    assert len(results) == 2

    transcript = opened.session.close(opened.artifact.capability_fingerprint)
    validate_observation_transcript(opened.artifact, transcript)
    customer_events = [
        item
        for item in transcript.events
        if item.kind
        in {
            RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
            RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        }
    ]
    for result in results:
        correlated = [item for item in customer_events if item.request_id == result.request_id]
        expected = targets[result.binding.effective_path]
        assert [item.kind for item in correlated] == [
            RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
            RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
        ]
        assert {item.ingress_node_id for item in correlated} == {result.binding.ingress_node_id}
        assert {item.route_registration_id for item in correlated} == {
            result.binding.route_registration_id
        }
        assert {item.normal_control_id for item in correlated} == {expected.normal_control_id}

    first_result = next(item for item in results if item.binding.effective_path == "/webhook-a")
    other_target = targets["/webhook-b"]
    substituted_events = list(transcript.events)
    event_index = next(
        index
        for index, item in enumerate(substituted_events)
        if item.request_id == first_result.request_id
        and item.kind == RuntimeObservationKind.CUSTOMER_VALUE_ENTERED
    )
    substituted_events[event_index] = substituted_events[event_index].model_copy(
        update={
            "normal_control_id": other_target.normal_control_id,
            "customer_value_node_id": other_target.customer_value_node_id,
            "customer_value_symbol_id": other_target.customer_value_symbol_id,
        }
    )
    substituted_payload = {
        "session_id": transcript.session_id,
        "capability_fingerprint": transcript.capability_fingerprint,
        "complete": True,
        "events": tuple(substituted_events),
        "diagnostics": (),
    }
    substituted = RuntimeObservationTranscript(
        **substituted_payload,
        transcript_fingerprint=fingerprint_json(substituted_payload),
    )
    with pytest.raises(RuntimeTranscriptMismatchError, match="normal control"):
        validate_observation_transcript(opened.artifact, substituted)


def test_shadowed_runtime_route_is_not_independently_addressable(tmp_path: Path) -> None:
    repository, config = _shared_customer_runtime_repository(
        tmp_path,
        second_path="/webhook-a",
    )
    _confirm_shared_customer(repository, config)
    opened = open_runtime_session(repository, config, generated_at=NOW)
    assert isinstance(opened.session, ManagedRuntimeSession)
    symbol_names = {
        item.symbol_id: item.qualified_name
        for item in opened.applicability.snapshot.source_index.symbols
    }
    bindings = {symbol_names[item.ingress_symbol_id]: item for item in opened.plan.ingresses}
    capabilities = {
        symbol_names[item.binding.ingress_symbol_id]: item for item in opened.artifact.ingresses
    }
    assert capabilities["main.webhook_a"].addressability.state == RuntimeCapabilityState.COMPLETE
    assert capabilities["main.webhook_b"].addressability.state == RuntimeCapabilityState.UNAVAILABLE
    assert capabilities["main.webhook_b"].addressability.reasons == (
        RuntimeCapabilityReasonCode.RUNTIME_ROUTE_SHADOWED,
    )

    request_result = opened.session.request(
        bindings["main.webhook_b"],
        headers={"x-razorpay-signature": "test-signature"},
        content=json.dumps({"event": "payment.captured", "payment_id": "pay_shadowed"}).encode(),
    )
    transcript = opened.session.close(opened.artifact.capability_fingerprint)
    correlated = [
        item for item in transcript.events if item.request_id == request_result.request_id
    ]
    assert correlated
    assert {item.ingress_node_id for item in correlated} == {
        bindings["main.webhook_a"].ingress_node_id
    }
    assert all(
        item.normal_control_id
        != next(
            target.normal_control_id
            for target in opened.plan.customer_values
            if target.ingress == bindings["main.webhook_b"]
        )
        for item in correlated
    )


def test_repeated_same_endpoint_registration_is_not_guessed(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path, runtime_yaml="  mode: managed")
    source = repository / "main.py"
    raw = source.read_text(encoding="utf-8")
    source.write_text(
        raw.replace(
            '@app.post("/webhooks/payment")',
            '@app.post("/webhooks/payment")\n@app.post("/webhooks/payment")',
        ),
        encoding="utf-8",
    )
    opened = open_runtime_session(repository, config, generated_at=NOW)
    assert opened.session is not None
    assert len(opened.artifact.ingresses) == 2
    assert all(
        item.addressability.state == RuntimeCapabilityState.UNAVAILABLE
        and item.addressability.reasons == (RuntimeCapabilityReasonCode.RUNTIME_ROUTE_AMBIGUOUS,)
        for item in opened.artifact.ingresses
    )
    opened.session.close(opened.artifact.capability_fingerprint)


def test_managed_session_start_cleans_owned_resources_when_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, config_path = _repository(tmp_path, runtime_yaml="  mode: managed")
    config = load_config(config_path)
    applicability_result = analyze_applicability(repository, config_path, generated_at=NOW)
    snapshot = applicability_result.snapshot
    plan = build_runtime_target_plan(
        snapshot.source_index,
        snapshot.graph,
        applicability_result.artifact,
    )
    temporary_directory = tmp_path / "managed-start"
    terminated: list[object] = []

    class _PendingProcess:
        def poll(self) -> None:
            return None

    process = _PendingProcess()

    def _make_temp(*, prefix: str) -> str:
        assert prefix == "stateguard-runtime-"
        temporary_directory.mkdir()
        return str(temporary_directory)

    monkeypatch.setattr(runtime_session_module.tempfile, "mkdtemp", _make_temp)
    monkeypatch.setattr(runtime_session_module.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        runtime_session_module,
        "_terminate_process",
        lambda owned, timeout: terminated.append(owned),
    )
    monkeypatch.setattr(
        runtime_session_module.time,
        "sleep",
        lambda seconds: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    assert config.runtime is not None and config.runtime.mode.value == "managed"
    with pytest.raises(KeyboardInterrupt):
        ManagedRuntimeSession.start(
            repository_root=repository,
            config_path=config_path,
            config=config.runtime,
            source_root=config.project.source_root,
            session_id=new_runtime_session_id(),
            source_index=snapshot.source_index,
            structural_graph=snapshot.structural_graph,
            graph=snapshot.graph,
            applicability=applicability_result.artifact,
            plan=plan,
        )

    assert terminated == [process]
    assert not temporary_directory.exists()


def test_managed_session_stream_is_not_runtime_artifact_evidence(tmp_path: Path) -> None:
    repository, config_path = _repository(tmp_path, runtime_yaml="  mode: managed")
    config = load_config(config_path)
    applicability_result = analyze_applicability(repository, config_path, generated_at=NOW)
    snapshot = applicability_result.snapshot
    plan = build_runtime_target_plan(
        snapshot.source_index,
        snapshot.graph,
        applicability_result.artifact,
    )
    assert config.runtime is not None and config.runtime.mode.value == "managed"
    started = ManagedRuntimeSession.start(
        repository_root=repository,
        config_path=config_path,
        config=config.runtime,
        source_root=config.project.source_root,
        session_id=new_runtime_session_id(),
        source_index=snapshot.source_index,
        structural_graph=snapshot.structural_graph,
        graph=snapshot.graph,
        applicability=applicability_result.artifact,
        plan=plan,
    )
    assert started.attachments[0].attached, started.attachments
    ready = build_capability_artifact(
        generated_at=NOW,
        session_id=started.session.session_id,
        runtime_config=config.runtime,
        source_index=snapshot.source_index,
        structural_graph=snapshot.structural_graph,
        graph=snapshot.graph,
        applicability=applicability_result.artifact,
        plan=plan,
        prepared=started.prepared,
        attachments=started.attachments,
        lifecycle=RuntimeLifecycleState.READY,
        ownership=RuntimeProcessOwnership.STATEGUARD,
    )
    request_result = started.session.request(
        plan.ingresses[0],
        headers={"x-razorpay-signature": "invalid-test-value"},
        content=json.dumps({"event": "payment.captured"}).encode(),
    )
    assert request_result.response.status_code == 200
    assert request_result.response.json() == {
        "processed": True,
        "correlation_visible": False,
    }
    transcript = started.session.close(ready.capability_fingerprint)
    assert transcript.complete, (transcript.diagnostics, started.session.process.returncode)
    assert [item.kind for item in transcript.events] == [
        RuntimeObservationKind.REQUEST_RECEIVED,
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_REACHED,
        RuntimeObservationKind.MERCHANT_ASSIGNMENT_INSTRUCTION_COMPLETED_NORMALLY,
        RuntimeObservationKind.RESPONSE_STARTED,
        RuntimeObservationKind.RESPONSE_COMPLETED,
    ]
    assert {item.request_id for item in transcript.events} == {request_result.request_id}
    validate_observation_transcript(ready, transcript)
    with pytest.raises(RuntimeTranscriptMismatchError, match="session identity"):
        validate_observation_transcript(
            ready,
            transcript.model_copy(update={"session_id": new_runtime_session_id()}),
        )
    truncated_payload = {
        "session_id": transcript.session_id,
        "capability_fingerprint": transcript.capability_fingerprint,
        "complete": True,
        "events": transcript.events[:1] + transcript.events[2:],
        "diagnostics": (),
    }
    with pytest.raises(ValueError, match="contiguous"):
        RuntimeObservationTranscript(
            **truncated_payload,
            transcript_fingerprint=fingerprint_json(truncated_payload),
        )
    assert not (repository / ".stateguard" / "runtime.json").exists()


def test_managed_process_death_before_request_makes_transcript_incomplete(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path, runtime_yaml="  mode: managed")
    opened = open_runtime_session(repository, config, generated_at=NOW)
    assert isinstance(opened.session, ManagedRuntimeSession)
    opened.session.process.kill()
    opened.session.process.wait(timeout=5)
    with pytest.raises(RuntimeSessionError) as captured:
        opened.session.request(opened.plan.ingresses[0])
    assert captured.value.reason == RuntimeCapabilityReasonCode.PROCESS_CRASHED
    transcript = opened.session.close(opened.artifact.capability_fingerprint)
    assert not transcript.complete
    assert RuntimeCapabilityReasonCode.PROCESS_CRASHED in transcript.diagnostics


def test_unexpected_managed_server_termination_is_incomplete(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path, runtime_yaml="  mode: managed")
    opened = open_runtime_session(repository, config, generated_at=NOW)
    assert isinstance(opened.session, ManagedRuntimeSession)
    opened.session.process.send_signal(signal.SIGTERM)
    opened.session.process.wait(timeout=5)
    transcript = opened.session.close(opened.artifact.capability_fingerprint)
    assert not transcript.complete
    assert RuntimeCapabilityReasonCode.PROCESS_CRASHED in transcript.diagnostics


def test_actual_managed_observation_transport_loss_is_incomplete(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path, runtime_yaml="  mode: managed")
    opened = open_runtime_session(repository, config, generated_at=NOW)
    assert isinstance(opened.session, ManagedRuntimeSession)
    opened.session.observation_path.unlink()
    transcript = opened.session.close(opened.artifact.capability_fingerprint)
    assert not transcript.complete
    assert RuntimeCapabilityReasonCode.OBSERVATION_CHANNEL_FAILED in transcript.diagnostics


def test_managed_customer_lifecycle_uses_exact_normal_control(tmp_path: Path) -> None:
    repository, config_path = _semantic_runtime_repository(tmp_path)
    unresolved = asyncio.run(resolve_customer_value(repository, config_path, generated_at=NOW))
    customer_symbol = next(
        item.symbol_id
        for item in unresolved.source_index.symbols
        if item.qualified_name == "domain.grant_ticket"
    )
    asyncio.run(
        confirm_customer_value(
            repository,
            config_path,
            customer_symbol,
            generated_at=NOW,
        )
    )
    config = load_config(config_path)
    applicability_result = analyze_applicability(repository, config_path, generated_at=NOW)
    snapshot = applicability_result.snapshot
    plan = build_runtime_target_plan(
        snapshot.source_index,
        snapshot.graph,
        applicability_result.artifact,
    )
    assert len(plan.customer_values) == 1
    assert config.runtime is not None and config.runtime.mode.value == "managed"
    started = ManagedRuntimeSession.start(
        repository_root=repository,
        config_path=config_path,
        config=config.runtime,
        source_root=config.project.source_root,
        session_id=new_runtime_session_id(),
        source_index=snapshot.source_index,
        structural_graph=snapshot.structural_graph,
        graph=snapshot.graph,
        applicability=applicability_result.artifact,
        plan=plan,
    )
    ready = build_capability_artifact(
        generated_at=NOW,
        session_id=started.session.session_id,
        runtime_config=config.runtime,
        source_index=snapshot.source_index,
        structural_graph=snapshot.structural_graph,
        graph=snapshot.graph,
        applicability=applicability_result.artifact,
        plan=plan,
        prepared=started.prepared,
        attachments=started.attachments,
        lifecycle=RuntimeLifecycleState.READY,
        ownership=RuntimeProcessOwnership.STATEGUARD,
    )
    request_result = started.session.request(
        plan.ingresses[0],
        headers={"x-razorpay-signature": "test-signature"},
        content=json.dumps(
            {
                "event": "payment.captured",
                "payload": {"payment": {"entity": {"id": "pay_test"}}},
            }
        ).encode(),
    )
    assert request_result.response.status_code == 200
    transcript = started.session.close(ready.capability_fingerprint)
    validate_observation_transcript(ready, transcript)
    customer_events = [
        item
        for item in transcript.events
        if item.kind
        in {
            RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
            RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
            RuntimeObservationKind.CUSTOMER_VALUE_EXCEPTION_ESCAPED,
        }
    ]
    assert [item.kind for item in customer_events] == [
        RuntimeObservationKind.CUSTOMER_VALUE_ENTERED,
        RuntimeObservationKind.CUSTOMER_VALUE_RETURNED_NORMALLY,
    ]
    assert {item.normal_control_id for item in customer_events} == {
        plan.customer_values[0].normal_control_id
    }
    assert all(item.customer_value_symbol_id == customer_symbol for item in customer_events)


def test_managed_session_close_detects_source_drift(tmp_path: Path) -> None:
    repository, config_path = _repository(tmp_path, runtime_yaml="  mode: managed")
    config = load_config(config_path)
    applicability_result = analyze_applicability(repository, config_path, generated_at=NOW)
    snapshot = applicability_result.snapshot
    plan = build_runtime_target_plan(
        snapshot.source_index,
        snapshot.graph,
        applicability_result.artifact,
    )
    assert config.runtime is not None and config.runtime.mode.value == "managed"
    started = ManagedRuntimeSession.start(
        repository_root=repository,
        config_path=config_path,
        config=config.runtime,
        source_root=config.project.source_root,
        session_id=new_runtime_session_id(),
        source_index=snapshot.source_index,
        structural_graph=snapshot.structural_graph,
        graph=snapshot.graph,
        applicability=applicability_result.artifact,
        plan=plan,
    )
    source = repository / "main.py"
    source.write_text(source.read_text(encoding="utf-8") + "\n# session drift\n", encoding="utf-8")
    transcript = started.session.close(fingerprint_json("test capability"))
    assert not transcript.complete
    assert RuntimeCapabilityReasonCode.SOURCE_STALE in transcript.diagnostics


def test_managed_session_rejects_source_drift_before_import(tmp_path: Path) -> None:
    repository, config_path = _repository(tmp_path, runtime_yaml="  mode: managed")
    config = load_config(config_path)
    applicability_result = analyze_applicability(repository, config_path, generated_at=NOW)
    snapshot = applicability_result.snapshot
    plan = build_runtime_target_plan(
        snapshot.source_index,
        snapshot.graph,
        applicability_result.artifact,
    )
    source = repository / "main.py"
    source.write_text(
        source.read_text(encoding="utf-8") + "\n# pre-import drift\n",
        encoding="utf-8",
    )
    assert config.runtime is not None and config.runtime.mode.value == "managed"
    with pytest.raises(RuntimeSessionError) as captured:
        ManagedRuntimeSession.start(
            repository_root=repository,
            config_path=config_path,
            config=config.runtime,
            source_root=config.project.source_root,
            session_id=new_runtime_session_id(),
            source_index=snapshot.source_index,
            structural_graph=snapshot.structural_graph,
            graph=snapshot.graph,
            applicability=applicability_result.artifact,
            plan=plan,
        )
    assert captured.value.reason == RuntimeCapabilityReasonCode.SOURCE_STALE


def test_managed_session_close_detects_runtime_config_drift(tmp_path: Path) -> None:
    repository, config_path = _repository(tmp_path, runtime_yaml="  mode: managed")
    config = load_config(config_path)
    applicability_result = analyze_applicability(repository, config_path, generated_at=NOW)
    snapshot = applicability_result.snapshot
    plan = build_runtime_target_plan(
        snapshot.source_index,
        snapshot.graph,
        applicability_result.artifact,
    )
    assert config.runtime is not None and config.runtime.mode.value == "managed"
    started = ManagedRuntimeSession.start(
        repository_root=repository,
        config_path=config_path,
        config=config.runtime,
        source_root=config.project.source_root,
        session_id=new_runtime_session_id(),
        source_index=snapshot.source_index,
        structural_graph=snapshot.structural_graph,
        graph=snapshot.graph,
        applicability=applicability_result.artifact,
        plan=plan,
    )
    config_path.write_text(
        config_path.read_text(encoding="utf-8") + "  request_timeout_seconds: 11\n",
        encoding="utf-8",
    )
    transcript = started.session.close(fingerprint_json("test capability"))
    assert not transcript.complete
    assert RuntimeCapabilityReasonCode.CONFIG_STALE in transcript.diagnostics


class _ReadyHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args) -> None:
        return None


class _RedirectHandler(_ReadyHandler):
    def do_GET(self) -> None:
        self.send_response(302)
        self.send_header("Location", "https://production.example.invalid")
        self.end_headers()


def test_byo_readiness_redirect_is_refused(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        repository, config = _repository(
            tmp_path,
            runtime_yaml=f"""  mode: byo
  target:
    kind: local
    base_url: http://127.0.0.1:{server.server_port}
  readiness:
    path: /health
    accepted_statuses: [302]
""",
        )
        result = assess_runtime_capability(repository, config, generated_at=NOW)
        assert result.artifact.lifecycle == RuntimeLifecycleState.UNAVAILABLE
        assert [item.code for item in result.artifact.diagnostics] == [
            RuntimeCapabilityReasonCode.TARGET_POLICY_REJECTED
        ]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_byo_external_is_partial_and_never_claims_in_process_observation(
    tmp_path: Path,
) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ReadyHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        repository, config = _repository(
            tmp_path,
            runtime_yaml=f"""  mode: byo
  target:
    kind: local
    base_url: http://127.0.0.1:{server.server_port}
  readiness:
    path: /health
    accepted_statuses: [204]
""",
        )
        result = assess_runtime_capability(repository, config, generated_at=NOW)
        assert result.artifact.lifecycle == RuntimeLifecycleState.HISTORICAL
        assert result.artifact.ownership == RuntimeProcessOwnership.EXTERNAL
        assert result.artifact.ingresses[0].addressability.state == RuntimeCapabilityState.PARTIAL
        assert result.artifact.mutations[0].assignment.state == RuntimeCapabilityState.UNAVAILABLE
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_byo_launched_process_is_owned_but_in_process_tracing_is_unavailable(
    tmp_path: Path,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    repository, config = _repository(
        tmp_path,
        runtime_yaml=f"""  mode: byo
  target:
    kind: local
    base_url: http://127.0.0.1:{port}
  readiness:
    path: /health
    accepted_statuses: [404]
  launch_argv:
    - {json.dumps(sys.executable)}
    - -m
    - http.server
    - "{port}"
    - --bind
    - 127.0.0.1
""",
    )
    result = assess_runtime_capability(repository, config, generated_at=NOW)
    assert result.artifact.lifecycle == RuntimeLifecycleState.HISTORICAL
    assert result.artifact.ownership == RuntimeProcessOwnership.STATEGUARD
    assert result.artifact.ingresses[0].addressability.state == RuntimeCapabilityState.PARTIAL
    assert all(
        item.assignment.state == RuntimeCapabilityState.UNAVAILABLE
        for item in result.artifact.mutations
    )
