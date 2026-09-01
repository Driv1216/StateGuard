from __future__ import annotations

import asyncio
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from stateguard.applicability.contracts import ApplicabilityState, ScenarioId
from stateguard.application.applicability import confirm_merchant_policy
from stateguard.application.failure_lab import execute_sg07
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.contracts.config import FulfilmentPolicy
from stateguard.contracts.identity import new_project_id
from stateguard.failure_lab.contracts import (
    CustomerTargetObservationSummary,
    EvidenceTier,
    ScenarioExecutionResult,
    ScenarioResultReasonCode,
    VerificationResultState,
)
from stateguard.failure_lab.sg07 import evaluate_webhook_only

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos" / "failure_lab_batch_a"
)
NOW = datetime(2026, 8, 28, tzinfo=UTC)
SECRET = "batch-a-webhook-secret-sentinel"


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURE, repository)
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
  env_from_host:
    STATEGUARD_TEST_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET
    MERCHANT_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET
    STATEGUARD_TEST_RAZORPAY_KEY_SECRET: SG_TEST_CHECKOUT_SECRET
    MERCHANT_CHECKOUT_SECRET: SG_TEST_CHECKOUT_SECRET
    STATEGUARD_TEST_SERVER_ORDER_ID: SG_TEST_SERVER_ORDER
    MERCHANT_SERVER_ORDER_ID: SG_TEST_SERVER_ORDER
    WEBHOOK_CAPTURE_BEHAVIOR: WEBHOOK_CAPTURE_BEHAVIOR_HOST
""",
        encoding="utf-8",
    )
    return repository, config


def _authority(repository: Path, config: Path) -> tuple[str, str]:
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
        item for item in confirmed.artifact.scenarios if item.scenario_id == ScenarioId.SG_07
    )
    instance = next(
        item for item in scenario.instances if item.state == ApplicabilityState.APPLICABLE
    )
    return instance.instance_id, confirmed.artifact.applicability_fingerprint


def _summary(entered: int) -> CustomerTargetObservationSummary:
    return CustomerTargetObservationSummary(
        entered_count=entered,
        returned_normally_count=entered,
        exception_escaped_count=0,
        entered_sequences=tuple(range(2, 2 + entered)),
        returned_normally_sequences=tuple(range(5, 5 + entered)),
        request_received_sequences=(1,),
        response_completed_sequences=(10,),
        request_aborted_sequences=(),
        http_status_code=200,
    )


def test_sg07_reducer_preserves_webhook_only_truth_mapping() -> None:
    assert evaluate_webhook_only(_summary(1)) == (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.WEBHOOK_ONLY_TARGET_ENTERED_ONCE,
    )
    assert evaluate_webhook_only(_summary(2)) == (
        VerificationResultState.VERIFIED_FAIL,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.WEBHOOK_ONLY_TARGET_ENTERED_MULTIPLE_TIMES,
    )
    assert evaluate_webhook_only(_summary(0)) == (
        VerificationResultState.UNVERIFIED,
        None,
        ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
    )


@pytest.mark.parametrize(
    ("behavior", "expected", "reason"),
    [
        (
            "once",
            VerificationResultState.VERIFIED_PASS,
            ScenarioResultReasonCode.WEBHOOK_ONLY_TARGET_ENTERED_ONCE,
        ),
        (
            "multiple",
            VerificationResultState.VERIFIED_FAIL,
            ScenarioResultReasonCode.WEBHOOK_ONLY_TARGET_ENTERED_MULTIPLE_TIMES,
        ),
        (
            "zero",
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
        ),
    ],
)
def test_managed_sg07_dispatches_only_the_webhook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
    expected: VerificationResultState,
    reason: ScenarioResultReasonCode,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG_TEST_CHECKOUT_SECRET", "checkout-secret")
    monkeypatch.setenv("SG_TEST_SERVER_ORDER", "order_server_control")
    monkeypatch.setenv("WEBHOOK_CAPTURE_BEHAVIOR_HOST", behavior)
    repository, config = _repository(tmp_path)
    instance_id, fingerprint = _authority(repository, config)

    result = execute_sg07(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=fingerprint,
        generated_at=NOW,
    )
    assert result.result == expected
    assert result.reason == reason
    assert len(result.authority.runtime_request_ids) == 1
    assert len(result.request_observations) == 1
    if expected != VerificationResultState.UNVERIFIED:
        assert result.evidence_tier == EvidenceTier.E3_DYNAMIC_VERIFIED
    persisted = result.model_dump_json()
    assert SECRET not in persisted
    assert "checkout" not in persisted.lower()
    if behavior == "once":
        payload = result.model_dump(mode="python")
        payload["authority"]["runtime_request_ids"] = (f"sgreq_{'d' * 32}",)
        with pytest.raises(ValidationError, match="ordered request observations"):
            ScenarioExecutionResult.model_validate(payload)
