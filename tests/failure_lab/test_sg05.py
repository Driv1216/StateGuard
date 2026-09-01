from __future__ import annotations

import asyncio
import hashlib
import hmac
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from stateguard.applicability.contracts import (
    SG05_CUSTOMER_VALUE_ASSERTION_KEY,
    SG05_MUTATION_ASSERTION_KEY,
    ApplicabilityState,
    ScenarioId,
)
from stateguard.application.applicability import analyze_applicability
from stateguard.application.failure_lab import execute_sg05
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.contracts.identity import fingerprint_json, new_project_id
from stateguard.failure_lab.contracts import (
    CustomerTargetObservationSummary,
    EvidenceTier,
    MutationScenarioRequestObservation,
    MutationTargetObservationSummary,
    ScenarioResultReasonCode,
    VerificationResultState,
)
from stateguard.failure_lab.sg05 import (
    evaluate_customer_sequence,
    evaluate_mutation_sequence,
    prepare_sg05_requests,
)
from stateguard.graph.contracts import (
    BranchDisposition,
    GraphEdgeKind,
    MerchantStateMutationDetails,
    PaymentStateGateDetails,
)
from stateguard.runtime.contracts import (
    IngressRuntimeBinding,
    RuntimeCapabilityReasonCode,
    RuntimeObservationTranscript,
)
from stateguard.runtime.session import ManagedRuntimeSession, RuntimeSessionError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"
NOW = datetime(2026, 8, 27, tzinfo=UTC)
SECRET = "failure-lab-sg05-secret-sentinel"
MUTATION_NODE_ID = f"sgnode_{'0' * 32}"


def _repository(
    tmp_path: Path,
    *,
    fixture: str = "failure_lab_sg05",
    runtime_mode: str = "managed",
) -> tuple[Path, Path]:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / fixture, repository)
    runtime = (
        "runtime:\n"
        "  mode: managed\n"
        "  env_from_host:\n"
        "    STATEGUARD_TEST_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET\n"
        "    MERCHANT_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET\n"
        "    SG05_BEHAVIOR: SG05_BEHAVIOR_HOST\n"
        if runtime_mode == "managed"
        else f"runtime:\n  mode: {runtime_mode}\n"
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
{runtime}""",
        encoding="utf-8",
    )
    return repository, config


def _prepare_authority(repository: Path, config: Path) -> tuple[str, str]:
    unresolved = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    symbol = next(
        item.symbol_id
        for item in unresolved.source_index.symbols
        if item.qualified_name == "domain.grant_ticket"
    )
    asyncio.run(confirm_customer_value(repository, config, symbol, generated_at=NOW))
    analyzed = analyze_applicability(repository, config, generated_at=NOW)
    scenario = next(
        item for item in analyzed.artifact.scenarios if item.scenario_id == ScenarioId.SG_05
    )
    instances = tuple(
        item
        for item in scenario.instances
        if {assertion.key for assertion in item.assertions}
        == {SG05_MUTATION_ASSERTION_KEY, SG05_CUSTOMER_VALUE_ASSERTION_KEY}
    )
    assert len(instances) == 1
    return instances[0].instance_id, analyzed.artifact.applicability_fingerprint


def _customer_summary(
    *,
    entered: int,
    returned: int,
    received: bool = True,
    completed: bool = True,
    aborted: bool = False,
    status: int = 200,
    offset: int = 0,
) -> CustomerTargetObservationSummary:
    return CustomerTargetObservationSummary(
        entered_count=entered,
        returned_normally_count=returned,
        exception_escaped_count=0,
        entered_sequences=tuple(range(offset + 2, offset + 2 + entered)),
        returned_normally_sequences=tuple(range(offset + 5, offset + 5 + returned)),
        request_received_sequences=((offset + 1,) if received else ()),
        response_completed_sequences=((offset + 10,) if completed else ()),
        request_aborted_sequences=((offset + 11,) if aborted else ()),
        http_status_code=status,
    )


def _mutation_observation(
    *,
    reached: int,
    completed_mutations: int,
    raised: int = 0,
    completed_request: bool = True,
    status: int = 200,
    offset: int = 0,
) -> MutationScenarioRequestObservation:
    return MutationScenarioRequestObservation(
        request_id=f"sgreq_{offset:032x}",
        mutation_targets=(
            MutationTargetObservationSummary(
                mutation_node_id=MUTATION_NODE_ID,
                reached_count=reached,
                completed_normally_count=completed_mutations,
                raised_count=raised,
                reached_sequences=tuple(range(offset + 2, offset + 2 + reached)),
                completed_normally_sequences=tuple(
                    range(offset + 5, offset + 5 + completed_mutations)
                ),
                raised_sequences=tuple(range(offset + 8, offset + 8 + raised)),
            ),
        ),
        request_received_sequences=(offset + 1,),
        response_completed_sequences=((offset + 10,) if completed_request else ()),
        request_aborted_sequences=(() if completed_request else (offset + 11,)),
        http_status_code=status,
    )


def test_rejected_signature_is_the_only_request_variation() -> None:
    prepared = prepare_sg05_requests(
        execution_id="sgexec_0123456789abcdef0123456789abcdef",
        path="/webhooks/payment",
        secret=SECRET,
    )
    valid = prepared.valid_headers["X-Razorpay-Signature"]
    rejected = prepared.rejected_headers["X-Razorpay-Signature"]
    expected = hmac.new(SECRET.encode(), prepared.raw_body, hashlib.sha256).hexdigest()

    assert valid == expected
    assert rejected != expected
    assert len(rejected) == 64
    assert set(rejected) <= set("0123456789abcdef")
    assert {
        key: value
        for key, value in prepared.rejected_headers.items()
        if key != "X-Razorpay-Signature"
    } == {
        key: value for key, value in prepared.valid_headers.items() if key != "X-Razorpay-Signature"
    }
    assert SECRET not in repr(prepared)
    assert valid not in repr(prepared)
    assert rejected not in repr(prepared)


def test_sg05_reducers_require_a_positive_control_for_pass() -> None:
    rejected_customer = _customer_summary(entered=0, returned=0, status=500)
    valid_customer = _customer_summary(entered=1, returned=1, offset=20)
    assert evaluate_customer_sequence(rejected_customer, valid_customer) == (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.REJECTED_SIGNATURE_ADDED_NO_CUSTOMER_TARGET_ENTRY,
    )
    assert evaluate_customer_sequence(
        rejected_customer,
        _customer_summary(entered=0, returned=0, offset=20),
    ) == (
        VerificationResultState.UNVERIFIED,
        None,
        ScenarioResultReasonCode.VALID_SIGNATURE_CONTROL_UNPROVEN,
    )
    assert evaluate_customer_sequence(
        _customer_summary(entered=1, returned=0, status=500),
        _customer_summary(entered=0, returned=0, offset=20),
    ) == (
        VerificationResultState.VERIFIED_FAIL,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.REJECTED_SIGNATURE_ADDED_CUSTOMER_TARGET_ENTRY,
    )

    rejected_mutation = _mutation_observation(
        reached=0,
        completed_mutations=0,
        status=500,
    )
    valid_mutation = _mutation_observation(
        reached=1,
        completed_mutations=1,
        offset=20,
    )
    assert evaluate_mutation_sequence(rejected_mutation, valid_mutation) == (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.REJECTED_SIGNATURE_ADDED_NO_MUTATION,
    )
    assert evaluate_mutation_sequence(
        _mutation_observation(reached=1, completed_mutations=0, raised=1, status=500),
        valid_mutation,
    ) == (
        VerificationResultState.UNVERIFIED,
        None,
        ScenarioResultReasonCode.MUTATION_OUTCOME_UNPROVEN,
    )
    assert evaluate_mutation_sequence(
        _mutation_observation(reached=1, completed_mutations=1, status=500),
        _mutation_observation(reached=0, completed_mutations=0, offset=20),
    ) == (
        VerificationResultState.VERIFIED_FAIL,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.REJECTED_SIGNATURE_COMPLETED_MUTATION,
    )


def test_sg05_applicability_is_per_assertion_and_policy_independent(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path, runtime_mode="static")
    instance_id, _ = _prepare_authority(repository, config)
    analyzed = analyze_applicability(repository, config, generated_at=NOW)
    scenario = next(
        item for item in analyzed.artifact.scenarios if item.scenario_id == ScenarioId.SG_05
    )
    instance = next(item for item in scenario.instances if item.instance_id == instance_id)
    assert analyzed.artifact.policy.fulfilment.confirmed_policy is None
    assert instance.state == ApplicabilityState.APPLICABLE
    assert {item.key: item.state for item in instance.assertions} == {
        SG05_MUTATION_ASSERTION_KEY: ApplicabilityState.APPLICABLE,
        SG05_CUSTOMER_VALUE_ASSERTION_KEY: ApplicabilityState.APPLICABLE,
    }


def test_sg05_mutation_binding_excludes_same_route_unrelated_state_branch(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path, runtime_mode="static")
    instance_id, _ = _prepare_authority(repository, config)
    analyzed = analyze_applicability(repository, config, generated_at=NOW)
    graph = analyzed.snapshot.graph
    nodes = {item.node_id: item for item in graph.nodes}
    route_mutations = tuple(
        item for item in graph.nodes if isinstance(item.details, MerchantStateMutationDetails)
    )
    assert len(route_mutations) == 2

    scenario = next(
        item for item in analyzed.artifact.scenarios if item.scenario_id == ScenarioId.SG_05
    )
    instance = next(item for item in scenario.instances if item.instance_id == instance_id)
    mutation_assertion = next(
        item for item in instance.assertions if item.key == SG05_MUTATION_ASSERTION_KEY
    )
    covered_ids = {
        evidence.reference
        for reason in mutation_assertion.reasons
        for evidence in reason.evidence
        if evidence.kind.value == "GRAPH_NODE"
    }
    assert len(covered_ids) == 1
    covered_id = next(iter(covered_ids))
    controlling_states = {
        state
        for edge in graph.edges
        if edge.kind == GraphEdgeKind.BRANCHES_TO
        and edge.target_node_id == covered_id
        and edge.branch is not None
        and edge.branch.disposition == BranchDisposition.MATCHED
        and isinstance(nodes[edge.source_node_id].details, PaymentStateGateDetails)
        for state in edge.branch.states
    }
    assert "payment.captured" in controlling_states
    assert "payment.authorized" not in controlling_states


@pytest.mark.parametrize(
    ("behavior", "mutation_result", "customer_result"),
    [
        (
            "safe",
            VerificationResultState.VERIFIED_PASS,
            VerificationResultState.VERIFIED_PASS,
        ),
        (
            "mutation_fail",
            VerificationResultState.VERIFIED_FAIL,
            VerificationResultState.VERIFIED_PASS,
        ),
        (
            "customer_fail",
            VerificationResultState.VERIFIED_PASS,
            VerificationResultState.VERIFIED_FAIL,
        ),
    ],
)
def test_managed_sg05_per_assertion_truth_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
    mutation_result: VerificationResultState,
    customer_result: VerificationResultState,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG05_BEHAVIOR_HOST", behavior)
    repository, config = _repository(tmp_path)
    instance_id, applicability_fingerprint = _prepare_authority(repository, config)
    calls: list[tuple[dict[str, str], bytes | None]] = []
    original_request = ManagedRuntimeSession.request

    def recorded_request(
        self: ManagedRuntimeSession,
        binding: IngressRuntimeBinding,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ):
        calls.append((dict(headers or {}), content))
        return original_request(self, binding, headers=headers, content=content)

    monkeypatch.setattr(ManagedRuntimeSession, "request", recorded_request)
    results = execute_sg05(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )

    assert tuple(item.result for item in results) == (mutation_result, customer_result), tuple(
        (item.result, item.reason, item.runtime_diagnostics, item.request_observations)
        for item in results
    )
    assert all(item.scenario_id == ScenarioId.SG_05 for item in results)
    assert all(item.evidence_tier == EvidenceTier.E3_DYNAMIC_VERIFIED for item in results)
    assert results[0].authority.normal_control_id is None
    assert results[1].authority.normal_control_id is not None
    assert results[0].execution_id == results[1].execution_id
    assert results[0].authority.runtime_request_ids == results[1].authority.runtime_request_ids
    assert len(calls) == 2
    assert all(len(item.mutation_targets) == 1 for item in results[0].request_observations)
    assert calls[0][1] == calls[1][1]
    assert calls[0][0]["X-Razorpay-Signature"] != calls[1][0]["X-Razorpay-Signature"]
    persisted = "".join(item.model_dump_json() for item in results)
    assert SECRET not in persisted
    assert calls[0][0]["X-Razorpay-Signature"] not in persisted
    assert calls[1][0]["X-Razorpay-Signature"] not in persisted
    assert not (repository / ".stateguard" / "runs").exists()


def test_mutation_only_sg05_can_fail_without_normal_control(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG05_BEHAVIOR_HOST", "safe")
    repository, config = _repository(tmp_path, fixture="runtime_app")
    analyzed = analyze_applicability(repository, config, generated_at=NOW)
    scenario = next(
        item for item in analyzed.artifact.scenarios if item.scenario_id == ScenarioId.SG_05
    )
    instance = next(
        item
        for item in scenario.instances
        if any(
            assertion.key == SG05_MUTATION_ASSERTION_KEY
            and assertion.state == ApplicabilityState.APPLICABLE
            for assertion in item.assertions
        )
    )
    results = execute_sg05(
        repository,
        config,
        scenario_instance_id=instance.instance_id,
        expected_applicability_fingerprint=analyzed.artifact.applicability_fingerprint,
        generated_at=NOW,
    )
    assert results[0].result == VerificationResultState.VERIFIED_FAIL
    assert results[0].reason == ScenarioResultReasonCode.REJECTED_SIGNATURE_COMPLETED_MUTATION
    assert results[0].authority.normal_control_id is None
    assert results[1].result == VerificationResultState.NEEDS_INPUT


def test_sg05_stale_static_and_missing_secret_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG05_BEHAVIOR_HOST", "safe")
    repository, config = _repository(tmp_path)
    instance_id, fingerprint = _prepare_authority(repository, config)

    stale = execute_sg05(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=f"sha256:{'0' * 64}",
        generated_at=NOW,
    )
    assert {item.reason for item in stale} == {
        ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY
    }

    monkeypatch.delenv("SG_TEST_WEBHOOK_SECRET")
    missing = execute_sg05(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=fingerprint,
        generated_at=NOW,
    )
    assert {item.reason for item in missing} == {
        ScenarioResultReasonCode.WEBHOOK_SECRET_UNAVAILABLE
    }

    static_repository, static_config = _repository(
        tmp_path / "static",
        runtime_mode="static",
    )
    static_instance, static_fingerprint = _prepare_authority(static_repository, static_config)
    static_results = execute_sg05(
        static_repository,
        static_config,
        scenario_instance_id=static_instance,
        expected_applicability_fingerprint=static_fingerprint,
        generated_at=NOW,
    )
    assert {item.reason for item in static_results} == {
        ScenarioResultReasonCode.RUNTIME_MODE_UNSUPPORTED
    }


def test_sg05_request_failure_is_unverified_and_session_closes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG05_BEHAVIOR_HOST", "safe")
    repository, config = _repository(tmp_path)
    instance_id, fingerprint = _prepare_authority(repository, config)
    original_request = ManagedRuntimeSession.request
    original_close = ManagedRuntimeSession.close
    request_calls = 0
    close_calls = 0

    def fail_second(self: ManagedRuntimeSession, *args: object, **kwargs: object):
        nonlocal request_calls
        request_calls += 1
        if request_calls == 2:
            raise RuntimeSessionError(RuntimeCapabilityReasonCode.EXTERNAL_RUNTIME_UNAVAILABLE)
        return original_request(self, *args, **kwargs)

    def counted_close(self: ManagedRuntimeSession, capability_fingerprint: str):
        nonlocal close_calls
        close_calls += 1
        return original_close(self, capability_fingerprint)

    monkeypatch.setattr(ManagedRuntimeSession, "request", fail_second)
    monkeypatch.setattr(ManagedRuntimeSession, "close", counted_close)
    results = execute_sg05(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=fingerprint,
        generated_at=NOW,
    )

    assert request_calls == 2
    assert close_calls == 1
    assert {item.result for item in results} == {VerificationResultState.UNVERIFIED}
    assert {item.reason for item in results} == {ScenarioResultReasonCode.REQUEST_EXECUTION_FAILED}


def test_sg05_untrusted_transcript_cannot_create_a_verdict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG05_BEHAVIOR_HOST", "safe")
    repository, config = _repository(tmp_path)
    instance_id, fingerprint = _prepare_authority(repository, config)
    original_close = ManagedRuntimeSession.close

    def inject_diagnostic(
        self: ManagedRuntimeSession,
        capability_fingerprint: str,
    ) -> RuntimeObservationTranscript:
        transcript = original_close(self, capability_fingerprint)
        payload = {
            "session_id": transcript.session_id,
            "capability_fingerprint": transcript.capability_fingerprint,
            "complete": False,
            "events": transcript.events,
            "diagnostics": (RuntimeCapabilityReasonCode.UNCORRELATED_TARGET_EXECUTION,),
        }
        return RuntimeObservationTranscript(
            **payload,
            transcript_fingerprint=fingerprint_json(payload),
        )

    monkeypatch.setattr(ManagedRuntimeSession, "close", inject_diagnostic)
    results = execute_sg05(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=fingerprint,
        generated_at=NOW,
    )

    assert {item.result for item in results} == {VerificationResultState.UNVERIFIED}
    assert {item.reason for item in results} == {ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY}
    assert all(
        RuntimeCapabilityReasonCode.UNCORRELATED_TARGET_EXECUTION in item.runtime_diagnostics
        for item in results
    )
