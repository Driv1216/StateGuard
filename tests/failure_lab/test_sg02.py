from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from stateguard.applicability.contracts import ApplicabilityState, ScenarioId
from stateguard.application.applicability import confirm_merchant_policy
from stateguard.application.failure_lab import execute_sg02
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.contracts.config import FulfilmentPolicy
from stateguard.contracts.identity import fingerprint_json, new_project_id, runtime_request_id
from stateguard.failure_lab.contracts import (
    CustomerTargetObservationSummary,
    EvidenceTier,
    ScenarioExecutionResult,
    ScenarioResultReasonCode,
    VerificationResultState,
)
from stateguard.failure_lab.sg02 import evaluate_sequence
from stateguard.runtime.contracts import (
    IngressRuntimeBinding,
    RuntimeCapabilityReasonCode,
    RuntimeObservationTranscript,
)
from stateguard.runtime.session import ManagedRuntimeSession, RuntimeSessionError

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos" / "failure_lab_sg01"
NOW = datetime(2026, 8, 27, tzinfo=UTC)
SECRET = "failure-lab-secret-sentinel"


def _repository(tmp_path: Path, *, runtime_mode: str = "managed") -> tuple[Path, Path]:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURE, repository)
    config = repository / "stateguard.yaml"
    runtime = (
        "runtime:\n"
        "  mode: managed\n"
        "  env_from_host:\n"
        "    STATEGUARD_TEST_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET\n"
        "    MERCHANT_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET\n"
        "    SG02_BEHAVIOR: SG02_BEHAVIOR_HOST\n"
        if runtime_mode == "managed"
        else "runtime:\n  mode: static\n"
    )
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
    confirmed = confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        generated_at=NOW,
    )
    scenario = next(
        item for item in confirmed.artifact.scenarios if item.scenario_id == ScenarioId.SG_02
    )
    applicable = tuple(
        item for item in scenario.instances if item.state == ApplicabilityState.APPLICABLE
    )
    assert len(applicable) == 1
    return applicable[0].instance_id, confirmed.artifact.applicability_fingerprint


def _summary(
    *,
    entered: int,
    returned: int,
    escaped: int = 0,
    received: bool = True,
    completed: bool = True,
    aborted: bool = False,
    status: int = 200,
    offset: int = 0,
) -> CustomerTargetObservationSummary:
    return CustomerTargetObservationSummary(
        entered_count=entered,
        returned_normally_count=returned,
        exception_escaped_count=escaped,
        entered_sequences=tuple(range(offset + 2, offset + 2 + entered)),
        returned_normally_sequences=tuple(range(offset + 5, offset + 5 + returned)),
        exception_escaped_sequences=tuple(range(offset + 8, offset + 8 + escaped)),
        request_received_sequences=((offset + 1,) if received else ()),
        response_completed_sequences=((offset + 10,) if completed else ()),
        request_aborted_sequences=((offset + 11,) if aborted else ()),
        http_status_code=status,
    )


@pytest.mark.parametrize(
    ("first", "second", "expected_result", "expected_reason", "expected_tier"),
    [
        (
            _summary(entered=1, returned=1),
            _summary(entered=0, returned=0, offset=20),
            VerificationResultState.VERIFIED_PASS,
            ScenarioResultReasonCode.DUPLICATE_DELIVERY_ADDED_NO_TARGET_ENTRY,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
        ),
        (
            _summary(entered=1, returned=1),
            _summary(entered=1, returned=1, offset=20),
            VerificationResultState.VERIFIED_FAIL,
            ScenarioResultReasonCode.DUPLICATE_DELIVERY_ADDED_TARGET_ENTRY,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
        ),
        (
            _summary(entered=2, returned=2),
            _summary(entered=0, returned=0, offset=20),
            VerificationResultState.VERIFIED_FAIL,
            ScenarioResultReasonCode.NORMAL_CONTROL_MULTIPLE_TARGET_ENTRIES,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
        ),
        (
            _summary(entered=0, returned=0),
            _summary(entered=0, returned=0, offset=20),
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
            None,
        ),
        (
            _summary(entered=1, returned=0, escaped=1),
            _summary(entered=0, returned=0, offset=20),
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.TARGET_TERMINAL_UNPROVEN,
            None,
        ),
        (
            _summary(entered=1, returned=1),
            _summary(entered=0, returned=0, completed=False, offset=20),
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
            None,
        ),
        (
            _summary(entered=1, returned=1),
            _summary(entered=0, returned=0, status=500, offset=20),
            VerificationResultState.VERIFIED_PASS,
            ScenarioResultReasonCode.DUPLICATE_DELIVERY_ADDED_NO_TARGET_ENTRY,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
        ),
    ],
)
def test_sg02_sequence_reducer(
    first: CustomerTargetObservationSummary,
    second: CustomerTargetObservationSummary,
    expected_result: VerificationResultState,
    expected_reason: ScenarioResultReasonCode,
    expected_tier: EvidenceTier | None,
) -> None:
    assert evaluate_sequence(first, second) == (
        expected_result,
        expected_tier,
        expected_reason,
    )


@pytest.mark.parametrize(
    ("behavior", "expected_result", "expected_reason", "entries", "second_status"),
    [
        (
            "pass",
            VerificationResultState.VERIFIED_PASS,
            ScenarioResultReasonCode.DUPLICATE_DELIVERY_ADDED_NO_TARGET_ENTRY,
            (1, 0),
            200,
        ),
        (
            "fail",
            VerificationResultState.VERIFIED_FAIL,
            ScenarioResultReasonCode.DUPLICATE_DELIVERY_ADDED_TARGET_ENTRY,
            (1, 1),
            200,
        ),
        (
            "first_multiple",
            VerificationResultState.VERIFIED_FAIL,
            ScenarioResultReasonCode.NORMAL_CONTROL_MULTIPLE_TARGET_ENTRIES,
            (2, 0),
            200,
        ),
        (
            "zero",
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
            (0, 0),
            200,
        ),
        (
            "second_500",
            VerificationResultState.VERIFIED_PASS,
            ScenarioResultReasonCode.DUPLICATE_DELIVERY_ADDED_NO_TARGET_ENTRY,
            (1, 0),
            500,
        ),
    ],
)
def test_managed_sg02_truth_mapping_and_exact_event_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
    expected_result: VerificationResultState,
    expected_reason: ScenarioResultReasonCode,
    entries: tuple[int, int],
    second_status: int,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG02_BEHAVIOR_HOST", behavior)
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
    result = execute_sg02(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )

    assert result.result == expected_result
    assert result.reason == expected_reason
    assert result.scenario_id == ScenarioId.SG_02
    assert result.schema_version == 3
    assert len(result.request_observations) == 2
    assert tuple(item.observations.entered_count for item in result.request_observations) == entries
    assert result.request_observations[1].observations.http_status_code == second_status
    assert result.authority.runtime_request_ids == tuple(
        item.request_id for item in result.request_observations
    )
    assert len(set(result.authority.runtime_request_ids)) == 2
    assert len(calls) == 2
    assert calls[0] == calls[1]
    headers, raw_body = calls[0]
    assert raw_body is not None
    body = json.loads(raw_body)
    payment = body["payload"]["payment"]["entity"]
    assert body["event"] == "payment.captured"
    assert payment["id"].startswith("pay_")
    assert payment["order_id"].startswith("order_")
    assert headers["x-razorpay-event-id"] == result.input_reference.synthetic_event_id
    assert (
        headers["X-Razorpay-Signature"]
        == hmac.new(SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    )
    persisted = result.model_dump_json()
    assert SECRET not in persisted
    assert headers["X-Razorpay-Signature"] not in persisted
    assert not (repository / ".stateguard" / "runs").exists()
    if behavior in {"fail", "first_multiple"}:
        payload = result.model_dump(mode="python")
        payload["reason"] = (
            ScenarioResultReasonCode.NORMAL_CONTROL_MULTIPLE_TARGET_ENTRIES
            if behavior == "fail"
            else ScenarioResultReasonCode.DUPLICATE_DELIVERY_ADDED_TARGET_ENTRY
        )
        with pytest.raises(ValueError, match="identify the delivery"):
            ScenarioExecutionResult.model_validate(payload)


def test_sg02_request_failure_is_unverified_and_session_closes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG02_BEHAVIOR_HOST", "pass")
    repository, config = _repository(tmp_path)
    instance_id, applicability_fingerprint = _prepare_authority(repository, config)
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
    result = execute_sg02(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )
    assert request_calls == 2
    assert close_calls == 1
    assert result.result == VerificationResultState.UNVERIFIED
    assert result.reason == ScenarioResultReasonCode.REQUEST_EXECUTION_FAILED


def test_sg02_static_mode_and_stale_selection_do_not_open_runtime(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path, runtime_mode="static")
    instance_id, applicability_fingerprint = _prepare_authority(repository, config)
    static_result = execute_sg02(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )
    assert static_result.result == VerificationResultState.UNVERIFIED
    assert static_result.reason == ScenarioResultReasonCode.RUNTIME_MODE_UNSUPPORTED
    assert static_result.authority.runtime_session_id is None

    stale_result = execute_sg02(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=f"sha256:{'0' * 64}",
        generated_at=NOW,
    )
    assert stale_result.result == VerificationResultState.UNVERIFIED
    assert stale_result.reason == ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY
    assert stale_result.authority.runtime_session_id is None


def test_sg02_uncorrelated_target_diagnostic_cannot_create_a_verdict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG02_BEHAVIOR_HOST", "pass")
    repository, config = _repository(tmp_path)
    instance_id, applicability_fingerprint = _prepare_authority(repository, config)
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
    result = execute_sg02(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )
    assert result.result == VerificationResultState.UNVERIFIED
    assert result.reason == ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY
    assert RuntimeCapabilityReasonCode.UNCORRELATED_TARGET_EXECUTION in result.runtime_diagnostics


def test_sg02_rejects_unrelated_request_observations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG02_BEHAVIOR_HOST", "pass")
    repository, config = _repository(tmp_path)
    instance_id, applicability_fingerprint = _prepare_authority(repository, config)
    original_close = ManagedRuntimeSession.close

    def substitute_request(
        self: ManagedRuntimeSession,
        capability_fingerprint: str,
    ) -> RuntimeObservationTranscript:
        transcript = original_close(self, capability_fingerprint)
        events = list(transcript.events)
        events[0] = events[0].model_copy(
            update={"request_id": runtime_request_id(transcript.session_id, 2)}
        )
        payload = {
            "session_id": transcript.session_id,
            "capability_fingerprint": transcript.capability_fingerprint,
            "complete": transcript.complete,
            "events": tuple(events),
            "diagnostics": transcript.diagnostics,
        }
        return RuntimeObservationTranscript(
            **payload,
            transcript_fingerprint=fingerprint_json(payload),
        )

    monkeypatch.setattr(ManagedRuntimeSession, "close", substitute_request)
    result = execute_sg02(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )
    assert result.result == VerificationResultState.UNVERIFIED
    assert result.reason == ScenarioResultReasonCode.AUTHORITY_MISMATCH


def test_sg02_result_contract_rejects_duplicate_request_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG02_BEHAVIOR_HOST", "pass")
    repository, config = _repository(tmp_path)
    instance_id, applicability_fingerprint = _prepare_authority(repository, config)
    result = execute_sg02(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )
    payload = result.model_dump(mode="python")
    first_request = result.authority.runtime_request_ids[0]
    authority = result.authority.model_dump(mode="python")
    authority["runtime_request_ids"] = (first_request, first_request)
    payload["authority"] = authority
    with pytest.raises(ValueError, match="unique and ordered"):
        ScenarioExecutionResult.model_validate(payload)
