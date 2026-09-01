from __future__ import annotations

import asyncio
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from stateguard.applicability.contracts import (
    SG04_CUSTOMER_VALUE_ASSERTION_KEY,
    SG04_STATE_REGRESSION_ASSERTION_KEY,
    ApplicabilityState,
    ScenarioId,
)
from stateguard.application.applicability import confirm_merchant_policy
from stateguard.application.failure_lab import execute_sg04
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.contracts.config import FulfilmentPolicy
from stateguard.contracts.identity import new_project_id
from stateguard.failure_lab.contracts import (
    CustomerTargetObservationSummary,
    EvidenceTier,
    MutationScenarioRequestObservation,
    MutationTargetObservationSummary,
    ScenarioExecutionResult,
    ScenarioResultReasonCode,
    VerificationResultState,
)
from stateguard.failure_lab.sg04 import (
    evaluate_customer_sequence,
    evaluate_state_sequence,
    prepare_sg04_requests,
)

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos" / "failure_lab_batch_a"
)
NOW = datetime(2026, 8, 28, tzinfo=UTC)
SECRET = "batch-a-webhook-secret-sentinel"
CAPTURED_NODE = f"sgnode_{'1' * 32}"
AUTHORIZED_NODE = f"sgnode_{'2' * 32}"


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
    SG04_CUSTOMER_BEHAVIOR: SG04_CUSTOMER_BEHAVIOR_HOST
    SG04_STATE_BEHAVIOR: SG04_STATE_BEHAVIOR_HOST
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
        item for item in confirmed.artifact.scenarios if item.scenario_id == ScenarioId.SG_04
    )
    instance = next(
        item
        for item in scenario.instances
        if item.state == ApplicabilityState.APPLICABLE
        and {assertion.key for assertion in item.assertions}
        == {SG04_CUSTOMER_VALUE_ASSERTION_KEY, SG04_STATE_REGRESSION_ASSERTION_KEY}
    )
    return instance.instance_id, confirmed.artifact.applicability_fingerprint


def _customer(entered: int, *, offset: int = 0) -> CustomerTargetObservationSummary:
    return CustomerTargetObservationSummary(
        entered_count=entered,
        returned_normally_count=entered,
        exception_escaped_count=0,
        entered_sequences=tuple(range(offset + 2, offset + 2 + entered)),
        returned_normally_sequences=tuple(range(offset + 4, offset + 4 + entered)),
        request_received_sequences=(offset + 1,),
        response_completed_sequences=(offset + 9,),
        request_aborted_sequences=(),
        http_status_code=200,
    )


def _mutation(
    captured: tuple[int, int], authorized: tuple[int, int], *, offset: int = 0
) -> MutationScenarioRequestObservation:
    return MutationScenarioRequestObservation(
        request_id=f"sgreq_{offset:032x}",
        mutation_targets=tuple(
            MutationTargetObservationSummary(
                mutation_node_id=node_id,
                reached_count=counts[0],
                completed_normally_count=counts[1],
                raised_count=0,
                reached_sequences=((offset + 2,) if counts[0] else ()),
                completed_normally_sequences=((offset + 3,) if counts[1] else ()),
                raised_sequences=(),
            )
            for node_id, counts in ((CAPTURED_NODE, captured), (AUTHORIZED_NODE, authorized))
        ),
        request_received_sequences=(offset + 1,),
        response_completed_sequences=(offset + 9,),
        request_aborted_sequences=(),
        http_status_code=200,
    )


def test_sg04_fixture_identity_event_ids_and_confidentiality() -> None:
    prepared = prepare_sg04_requests(
        execution_id="sgexec_0123456789abcdef0123456789abcdef",
        path="/webhooks/payment",
        secret=SECRET,
    )
    captured = json.loads(prepared.captured.raw_body)
    authorized = json.loads(prepared.authorized.raw_body)
    captured_payment = captured["payload"]["payment"]["entity"]
    authorized_payment = authorized["payload"]["payment"]["entity"]

    assert captured["event"] == "payment.captured"
    assert authorized["event"] == "payment.authorized"
    assert captured_payment["id"] == authorized_payment["id"]
    assert captured_payment["order_id"] == authorized_payment["order_id"]
    assert captured_payment["status"] == "captured"
    assert authorized_payment["status"] == "authorized"
    assert prepared.captured.synthetic_event_id != prepared.authorized.synthetic_event_id
    assert SECRET not in repr(prepared)
    assert SECRET not in prepared.input_reference.model_dump_json()


def test_sg04_reducers_cover_pass_fail_and_unverified() -> None:
    assert evaluate_customer_sequence(_customer(1), _customer(0, offset=20))[0] == (
        VerificationResultState.VERIFIED_PASS
    )
    assert evaluate_customer_sequence(_customer(1), _customer(1, offset=20))[0] == (
        VerificationResultState.VERIFIED_FAIL
    )
    broken = evaluate_customer_sequence(_customer(2), _customer(0, offset=20))
    assert broken == (
        VerificationResultState.VERIFIED_FAIL,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.OUT_OF_ORDER_CONTROL_MULTIPLE_TARGET_ENTRIES,
    )
    assert evaluate_customer_sequence(_customer(0), _customer(0, offset=20))[0] == (
        VerificationResultState.UNVERIFIED
    )

    first = _mutation((1, 1), (0, 0))
    safe = _mutation((0, 0), (0, 0), offset=20)
    regressed = _mutation((0, 0), (1, 1), offset=20)
    assert (
        evaluate_state_sequence(
            first,
            safe,
            captured_node_id=CAPTURED_NODE,
            authorized_node_id=AUTHORIZED_NODE,
        )[0]
        == VerificationResultState.VERIFIED_PASS
    )
    assert (
        evaluate_state_sequence(
            first,
            regressed,
            captured_node_id=CAPTURED_NODE,
            authorized_node_id=AUTHORIZED_NODE,
        )[0]
        == VerificationResultState.VERIFIED_FAIL
    )


@pytest.mark.parametrize(
    ("customer_behavior", "state_behavior", "customer_result", "state_result"),
    [
        (
            "safe",
            "safe",
            VerificationResultState.VERIFIED_PASS,
            VerificationResultState.VERIFIED_PASS,
        ),
        (
            "duplicate",
            "regress",
            VerificationResultState.VERIFIED_FAIL,
            VerificationResultState.VERIFIED_FAIL,
        ),
    ],
)
def test_managed_sg04_assertion_truth_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    customer_behavior: str,
    state_behavior: str,
    customer_result: VerificationResultState,
    state_result: VerificationResultState,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG_TEST_CHECKOUT_SECRET", "checkout-secret")
    monkeypatch.setenv("SG_TEST_SERVER_ORDER", "order_server_control")
    monkeypatch.setenv("WEBHOOK_CAPTURE_BEHAVIOR_HOST", "once")
    monkeypatch.setenv("SG04_CUSTOMER_BEHAVIOR_HOST", customer_behavior)
    monkeypatch.setenv("SG04_STATE_BEHAVIOR_HOST", state_behavior)
    repository, config = _repository(tmp_path)
    instance_id, applicability_fingerprint = _authority(repository, config)

    results = execute_sg04(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=applicability_fingerprint,
        generated_at=NOW,
    )
    assert tuple(item.result for item in results) == (customer_result, state_result)
    assert len({item.execution_id for item in results}) == 1
    assert len({item.authority.runtime_session_id for item in results}) == 1
    assert all(len(item.authority.runtime_request_ids) == 2 for item in results)
    assert all(item.evidence_tier == EvidenceTier.E3_DYNAMIC_VERIFIED for item in results)
    persisted = "".join(item.model_dump_json() for item in results)
    assert SECRET not in persisted
    assert "payment.captured" not in persisted
    assert "payment.authorized" not in persisted
    if customer_behavior == "safe":
        payload = results[0].model_dump(mode="python")
        payload["authority"]["runtime_request_ids"] = (
            f"sgreq_{'f' * 32}",
            results[0].authority.runtime_request_ids[1],
        )
        with pytest.raises(ValidationError, match="ordered request observations"):
            ScenarioExecutionResult.model_validate(payload)
