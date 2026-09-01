from __future__ import annotations

import asyncio
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from stateguard.applicability.contracts import ApplicabilityState, ScenarioId
from stateguard.application.applicability import confirm_merchant_policy
from stateguard.application.failure_lab import execute_sg03
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.contracts.common import GraphNodeId
from stateguard.contracts.config import FulfilmentPolicy
from stateguard.contracts.identity import new_project_id
from stateguard.failure_lab.contracts import (
    CustomerTargetObservationSummary,
    EvidenceTier,
    ScenarioRequestObservation,
    ScenarioResultReasonCode,
    VerificationResultState,
)
from stateguard.failure_lab.sg03 import evaluate_sequence
from stateguard.runtime.contracts import (
    IngressRuntimeBinding,
    ManagedAcknowledgementFailureMode,
)
from stateguard.runtime.session import ManagedRuntimeSession

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos" / "failure_lab_batch_a"
)
NOW = datetime(2026, 8, 29, tzinfo=UTC)
SECRET = "sg03-webhook-secret-sentinel"


def _summary(
    *, entered: int, returned: int, status: int, offset: int = 0
) -> CustomerTargetObservationSummary:
    return CustomerTargetObservationSummary(
        entered_count=entered,
        returned_normally_count=returned,
        exception_escaped_count=0,
        entered_sequences=tuple(range(offset + 2, offset + 2 + entered)),
        returned_normally_sequences=tuple(range(offset + 4, offset + 4 + returned)),
        request_received_sequences=(offset + 1,),
        response_completed_sequences=(offset + 8,),
        http_status_code=status,
    )


def test_two_ordinary_deliveries_are_not_sg03_evidence() -> None:
    first = ScenarioRequestObservation(
        request_id=f"sgreq_{'1' * 32}",
        observations=_summary(entered=1, returned=1, status=200),
    )
    retry = ScenarioRequestObservation(
        request_id=f"sgreq_{'2' * 32}",
        observations=_summary(entered=0, returned=0, status=200, offset=20),
    )
    assert evaluate_sequence(first, retry) == (
        VerificationResultState.UNVERIFIED,
        None,
        ScenarioResultReasonCode.MODELED_ACK_FAILURE_UNPROVEN,
    )


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
    MERCHANT_CHECKOUT_SECRET: SG_TEST_CHECKOUT_SECRET
    MERCHANT_SERVER_ORDER_ID: SG_TEST_SERVER_ORDER
    SG03_BEHAVIOR: SG03_BEHAVIOR_HOST
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
        item for item in confirmed.artifact.scenarios if item.scenario_id == ScenarioId.SG_03
    )
    instance = next(
        item for item in scenario.instances if item.state == ApplicabilityState.APPLICABLE
    )
    return instance.instance_id, confirmed.artifact.applicability_fingerprint


@pytest.mark.parametrize(
    ("behavior", "expected_result", "expected_reason", "entries"),
    [
        (
            "pass",
            VerificationResultState.VERIFIED_PASS,
            ScenarioResultReasonCode.MODELED_RETRY_ADDED_NO_TARGET_ENTRY,
            (1, 0),
        ),
        (
            "retry_entry",
            VerificationResultState.VERIFIED_FAIL,
            ScenarioResultReasonCode.MODELED_RETRY_ADDED_TARGET_ENTRY,
            (1, 1),
        ),
        (
            "initial_multiple",
            VerificationResultState.VERIFIED_FAIL,
            ScenarioResultReasonCode.INITIAL_DELIVERY_MULTIPLE_TARGET_ENTRIES,
            (2, 0),
        ),
        (
            "zero",
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
            (0, 0),
        ),
    ],
)
def test_managed_sg03_truth_mapping_and_exact_modeled_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
    expected_result: VerificationResultState,
    expected_reason: ScenarioResultReasonCode,
    entries: tuple[int, int],
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG_TEST_CHECKOUT_SECRET", "checkout-secret")
    monkeypatch.setenv("SG_TEST_SERVER_ORDER", "order_server_control")
    monkeypatch.setenv("SG03_BEHAVIOR_HOST", behavior)
    repository, config = _repository(tmp_path)
    instance_id, applicability_fingerprint = _authority(repository, config)
    calls: list[
        tuple[
            dict[str, str],
            bytes | None,
            ManagedAcknowledgementFailureMode | None,
        ]
    ] = []
    original_request = ManagedRuntimeSession.request

    def recorded_request(
        self: ManagedRuntimeSession,
        binding: IngressRuntimeBinding,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        params: dict[str, str] | None = None,
        acknowledgement_failure: ManagedAcknowledgementFailureMode | None = None,
        acknowledgement_node_id: GraphNodeId | None = None,
    ):
        calls.append((dict(headers or {}), content, acknowledgement_failure))
        return original_request(
            self,
            binding,
            headers=headers,
            content=content,
            params=params,
            acknowledgement_failure=acknowledgement_failure,
            acknowledgement_node_id=acknowledgement_node_id,
        )

    monkeypatch.setattr(ManagedRuntimeSession, "request", recorded_request)
    result = execute_sg03(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )

    assert result.result == expected_result
    assert result.reason == expected_reason
    assert result.scenario_id == ScenarioId.SG_03
    assert tuple(item.observations.entered_count for item in result.request_observations) == entries
    assert len(result.request_observations) == 2
    first, retry = result.request_observations
    assert first.acknowledgement_failure is not None
    assert first.acknowledgement_failure.original_status_code == 200
    assert first.acknowledgement_failure.effective_status_code == 503
    assert first.observations.http_status_code == 503
    assert retry.acknowledgement_failure is None
    assert len(set(result.authority.runtime_request_ids)) == 2
    assert len(calls) == 2
    assert calls[0][0] == calls[1][0]
    assert calls[0][1] == calls[1][1]
    assert calls[0][2] == ManagedAcknowledgementFailureMode.FORCE_NON_2XX_AFTER_SUCCESS
    assert calls[1][2] is None
    if expected_result != VerificationResultState.UNVERIFIED:
        assert result.evidence_tier == EvidenceTier.E3_DYNAMIC_VERIFIED


def test_sg03_stale_authority_does_not_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    repository, config = _repository(tmp_path)
    instance_id, _ = _authority(repository, config)
    result = execute_sg03(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=f"sha256:{'0' * 64}",
        generated_at=NOW,
    )
    assert result.result == VerificationResultState.UNVERIFIED
    assert result.reason == ScenarioResultReasonCode.STALE_APPLICABILITY_AUTHORITY
    assert result.authority.runtime_request_ids == ()
