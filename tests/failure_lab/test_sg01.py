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
from stateguard.application.failure_lab import execute_sg01
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.contracts.config import FulfilmentPolicy
from stateguard.contracts.identity import new_project_id
from stateguard.failure_lab.contracts import (
    EvidenceTier,
    ScenarioResultReasonCode,
    VerificationResultState,
)
from stateguard.failure_lab.sg01 import prepare_sg01_request
from stateguard.runtime.contracts import RuntimeTranscriptMismatchError
from stateguard.runtime.session import ManagedRuntimeSession

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
        "    SG01_BEHAVIOR: SG01_BEHAVIOR_HOST\n"
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
        item for item in confirmed.artifact.scenarios if item.scenario_id == ScenarioId.SG_01
    )
    applicable = tuple(
        item for item in scenario.instances if item.state == ApplicabilityState.APPLICABLE
    )
    assert len(applicable) == 1
    return applicable[0].instance_id, confirmed.artifact.applicability_fingerprint


def test_pinned_fixture_signs_exact_raw_bytes_without_exposing_signature() -> None:
    prepared = prepare_sg01_request(
        execution_id="sgexec_0123456789abcdef0123456789abcdef",
        path="/webhooks/payment",
        secret=SECRET,
    )
    expected = hmac.new(SECRET.encode(), prepared.raw_body, hashlib.sha256).hexdigest()
    assert prepared.headers["X-Razorpay-Signature"] == expected
    body = json.loads(prepared.raw_body)
    payment = body["payload"]["payment"]["entity"]
    assert body["event"] == "payment.captured"
    assert payment["status"] == "captured"
    assert payment["captured"] is True
    assert SECRET not in repr(prepared)
    assert expected not in repr(prepared)


@pytest.mark.parametrize(
    ("behavior", "expected_result", "expected_reason", "expected_tier", "entries"),
    [
        (
            "pass",
            VerificationResultState.VERIFIED_PASS,
            ScenarioResultReasonCode.EXACT_TARGET_ENTERED_ONCE,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            1,
        ),
        (
            "multiple",
            VerificationResultState.VERIFIED_FAIL,
            ScenarioResultReasonCode.EXACT_TARGET_ENTERED_MULTIPLE_TIMES,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            2,
        ),
        (
            "zero",
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
            None,
            0,
        ),
        (
            "exception",
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.TARGET_TERMINAL_UNPROVEN,
            None,
            1,
        ),
    ],
)
def test_managed_sg01_truth_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
    expected_result: VerificationResultState,
    expected_reason: ScenarioResultReasonCode,
    expected_tier: EvidenceTier | None,
    entries: int,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG01_BEHAVIOR_HOST", behavior)
    repository, config = _repository(tmp_path)
    instance_id, applicability_fingerprint = _prepare_authority(repository, config)

    result = execute_sg01(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )

    assert result.result == expected_result
    assert result.reason == expected_reason
    assert result.evidence_tier == expected_tier
    assert len(result.request_observations) == 1
    assert result.request_observations[0].observations.entered_count == entries
    assert result.authority.runtime_request_ids == (result.request_observations[0].request_id,)
    persisted = result.model_dump_json()
    assert SECRET not in persisted
    prepared = prepare_sg01_request(
        execution_id=result.execution_id,
        path="/webhooks/payment",
        secret=SECRET,
    )
    assert prepared.headers["X-Razorpay-Signature"] not in persisted
    assert "X-Razorpay-Signature" in persisted
    assert not (repository / ".stateguard" / "runs").exists()


def test_static_mode_and_stale_selection_do_not_open_runtime(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path, runtime_mode="static")
    instance_id, applicability_fingerprint = _prepare_authority(repository, config)
    static_result = execute_sg01(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )
    assert static_result.result == VerificationResultState.UNVERIFIED
    assert static_result.reason == ScenarioResultReasonCode.RUNTIME_MODE_UNSUPPORTED
    assert static_result.authority.runtime_session_id is None

    stale_result = execute_sg01(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=f"sha256:{'0' * 64}",
        generated_at=NOW,
    )
    assert stale_result.result == VerificationResultState.UNVERIFIED
    assert stale_result.reason == ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY
    assert stale_result.authority.runtime_session_id is None


def test_missing_reserved_secret_mapping_is_unverified(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path)
    raw = config.read_text(encoding="utf-8")
    config.write_text(
        raw.replace(
            "    STATEGUARD_TEST_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET\n",
            "",
        ),
        encoding="utf-8",
    )
    instance_id, applicability_fingerprint = _prepare_authority(repository, config)
    result = execute_sg01(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )
    assert result.result == VerificationResultState.UNVERIFIED
    assert result.reason == ScenarioResultReasonCode.WEBHOOK_SECRET_UNAVAILABLE


def test_executor_closes_once_and_rejects_untrusted_transcript(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG01_BEHAVIOR_HOST", "pass")
    repository, config = _repository(tmp_path)
    instance_id, applicability_fingerprint = _prepare_authority(repository, config)
    close_calls = 0
    original_close = ManagedRuntimeSession.close

    def counted_close(self: ManagedRuntimeSession, capability_fingerprint: str):
        nonlocal close_calls
        close_calls += 1
        return original_close(self, capability_fingerprint)

    def reject_transcript(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeTranscriptMismatchError("synthetic mismatch")

    monkeypatch.setattr(ManagedRuntimeSession, "close", counted_close)
    monkeypatch.setattr(
        "stateguard.application.failure_lab.validate_observation_transcript",
        reject_transcript,
    )
    result = execute_sg01(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )
    assert close_calls == 1
    assert result.result == VerificationResultState.UNVERIFIED
    assert result.reason == ScenarioResultReasonCode.TRANSCRIPT_UNTRUSTWORTHY
