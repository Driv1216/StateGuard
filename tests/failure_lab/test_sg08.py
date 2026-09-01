from __future__ import annotations

import asyncio
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from stateguard.applicability.contracts import (
    SG08_CAPTURE_ASSERTION_KEY,
    SG08_LATE_POLICY_ASSERTION_KEY,
    SG08_PRECAPTURE_ASSERTION_KEY,
    ApplicabilityReasonCode,
    ApplicabilityState,
    ScenarioId,
)
from stateguard.application.applicability import confirm_merchant_policy
from stateguard.application.failure_lab import execute_sg08
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.contracts.config import FulfilmentPolicy, LateAuthorisationPolicy
from stateguard.contracts.identity import new_project_id
from stateguard.failure_lab.contracts import (
    EvidenceTier,
    LateAuthorisationInputReference,
    ScenarioResultReasonCode,
    VerificationResultState,
)
from stateguard.runtime.session import ManagedRuntimeSession

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos" / "failure_lab_batch_a"
)
NOW = datetime(2026, 8, 29, tzinfo=UTC)
SECRET = "sg08-webhook-secret-sentinel"


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
    WEBHOOK_CAPTURE_BEHAVIOR: WEBHOOK_CAPTURE_BEHAVIOR_HOST
    SG08_AUTHORIZED_BEHAVIOR: SG08_AUTHORIZED_BEHAVIOR_HOST
""",
        encoding="utf-8",
    )
    return repository, config


def _authority(
    repository: Path,
    config: Path,
    *,
    fulfilment: FulfilmentPolicy,
    late: LateAuthorisationPolicy,
) -> tuple[str, str, ApplicabilityState]:
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
        fulfilment=fulfilment,
        late_authorisation=late,
        generated_at=NOW,
    )
    scenario = next(
        item for item in confirmed.artifact.scenarios if item.scenario_id == ScenarioId.SG_08
    )
    instance = next(item for item in scenario.instances if item.normal_control_id is not None)
    return (
        instance.instance_id,
        confirmed.artifact.applicability_fingerprint,
        instance.state,
    )


@pytest.mark.parametrize(
    (
        "authorized_behavior",
        "captured_behavior",
        "expected_states",
        "expected_reasons",
    ),
    [
        (
            "zero",
            "once",
            (
                VerificationResultState.VERIFIED_PASS,
                VerificationResultState.VERIFIED_PASS,
            ),
            (
                ScenarioResultReasonCode.AUTHORIZED_ADDED_NO_TARGET_ENTRY,
                ScenarioResultReasonCode.CAPTURED_THRESHOLD_TARGET_ENTERED_ONCE,
            ),
        ),
        (
            "once",
            "once",
            (
                VerificationResultState.VERIFIED_FAIL,
                VerificationResultState.VERIFIED_FAIL,
            ),
            (
                ScenarioResultReasonCode.AUTHORIZED_EXECUTED_BEFORE_CAPTURE,
                ScenarioResultReasonCode.AUTHORIZED_EXECUTED_BEFORE_CAPTURE,
            ),
        ),
        (
            "zero",
            "multiple",
            (
                VerificationResultState.UNVERIFIED,
                VerificationResultState.VERIFIED_FAIL,
            ),
            (
                ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
                ScenarioResultReasonCode.CAPTURED_THRESHOLD_MULTIPLE_TARGET_ENTRIES,
            ),
        ),
        (
            "zero",
            "zero",
            (
                VerificationResultState.UNVERIFIED,
                VerificationResultState.UNVERIFIED,
            ),
            (
                ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
                ScenarioResultReasonCode.NORMAL_INPUT_PRECONDITION_UNPROVEN,
            ),
        ),
    ],
)
def test_capture_required_fulfil_later_uses_only_context_independent_invariants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authorized_behavior: str,
    captured_behavior: str,
    expected_states: tuple[VerificationResultState, VerificationResultState],
    expected_reasons: tuple[ScenarioResultReasonCode, ScenarioResultReasonCode],
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG_TEST_CHECKOUT_SECRET", "checkout-secret")
    monkeypatch.setenv("SG_TEST_SERVER_ORDER", "order_server_control")
    monkeypatch.setenv("SG08_AUTHORIZED_BEHAVIOR_HOST", authorized_behavior)
    monkeypatch.setenv("WEBHOOK_CAPTURE_BEHAVIOR_HOST", captured_behavior)
    repository, config = _repository(tmp_path)
    instance_id, fingerprint, state = _authority(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        late=LateAuthorisationPolicy.FULFIL_LATER,
    )
    assert state == ApplicabilityState.APPLICABLE

    results = execute_sg08(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=fingerprint,
        generated_at=NOW,
    )

    assert tuple(item.result for item in results) == expected_states
    assert tuple(item.reason for item in results) == expected_reasons
    assert tuple(item.assertion_id for item in results) == tuple(
        item.assertion_id
        for item in sorted(
            next(
                instance
                for scenario in confirm_merchant_policy(
                    repository,
                    config,
                    fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
                    late_authorisation=LateAuthorisationPolicy.FULFIL_LATER,
                    generated_at=NOW,
                ).artifact.scenarios
                if scenario.scenario_id == ScenarioId.SG_08
                for instance in scenario.instances
                if instance.instance_id == instance_id
            ).assertions,
            key=lambda assertion: (
                assertion.key != SG08_PRECAPTURE_ASSERTION_KEY,
                assertion.key,
            ),
        )
    )
    assert len({item.execution_id for item in results}) == 1
    assert all(len(item.authority.runtime_request_ids) == 2 for item in results)
    assert all(
        isinstance(item.input_reference, LateAuthorisationInputReference) for item in results
    )
    reference = results[0].input_reference
    assert isinstance(reference, LateAuthorisationInputReference)
    assert reference.context_authority == "STATEGUARD_MODELED_NOT_MERCHANT_OBSERVED"
    assert tuple(event.role for event in reference.events) == (
        "MODELED_LATE_AUTHORIZED",
        "CAPTURED_THRESHOLD_CONTROL",
    )
    assert len({event.synthetic_event_id for event in reference.events}) == 2
    persisted = "".join(item.model_dump_json() for item in results)
    assert SECRET not in persisted
    assert "x-razorpay-signature" not in persisted.casefold()
    for result in results:
        if result.result in {
            VerificationResultState.VERIFIED_PASS,
            VerificationResultState.VERIFIED_FAIL,
        }:
            assert result.evidence_tier == EvidenceTier.E3_DYNAMIC_VERIFIED


@pytest.mark.parametrize(
    ("authorized_behavior", "expected_state", "expected_reason"),
    [
        (
            "once",
            VerificationResultState.VERIFIED_FAIL,
            ScenarioResultReasonCode.AUTHORIZED_EXECUTED_BEFORE_CAPTURE,
        ),
        (
            "zero",
            VerificationResultState.UNVERIFIED,
            ScenarioResultReasonCode.MERCHANT_LATE_CONTEXT_UNPROVEN,
        ),
    ],
)
def test_capture_required_do_not_fulfil_is_conservative_on_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authorized_behavior: str,
    expected_state: VerificationResultState,
    expected_reason: ScenarioResultReasonCode,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("SG_TEST_CHECKOUT_SECRET", "checkout-secret")
    monkeypatch.setenv("SG_TEST_SERVER_ORDER", "order_server_control")
    monkeypatch.setenv("SG08_AUTHORIZED_BEHAVIOR_HOST", authorized_behavior)
    monkeypatch.setenv("WEBHOOK_CAPTURE_BEHAVIOR_HOST", "once")
    repository, config = _repository(tmp_path)
    instance_id, fingerprint, _ = _authority(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        late=LateAuthorisationPolicy.DO_NOT_FULFIL,
    )
    results = execute_sg08(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=fingerprint,
        generated_at=NOW,
    )
    assert len(results) == 1
    assert results[0].result == expected_state
    assert results[0].reason == expected_reason
    assert len(results[0].authority.runtime_request_ids) == 1


@pytest.mark.parametrize(
    "late",
    [LateAuthorisationPolicy.FULFIL_LATER, LateAuthorisationPolicy.DO_NOT_FULFIL],
)
def test_authorized_allowed_rows_are_unverified_without_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    late: LateAuthorisationPolicy,
) -> None:
    repository, config = _repository(tmp_path)
    instance_id, fingerprint, state = _authority(
        repository,
        config,
        fulfilment=FulfilmentPolicy.AUTHORIZED_ALLOWED,
        late=late,
    )
    assert state == ApplicabilityState.INDETERMINATE

    def forbidden_request(*args, **kwargs):
        raise AssertionError("late-context-unproven rows must not dispatch")

    monkeypatch.setattr(ManagedRuntimeSession, "request", forbidden_request)
    results = execute_sg08(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=fingerprint,
        generated_at=NOW,
    )
    assert len(results) == 1
    assert results[0].result == VerificationResultState.UNVERIFIED
    assert results[0].reason == ScenarioResultReasonCode.MERCHANT_LATE_CONTEXT_UNPROVEN
    assert results[0].authority.runtime_request_ids == ()
    assert results[0].input_reference is None


def test_missing_late_sequence_remains_not_applicable_without_runtime_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, config = _repository(tmp_path)
    source = repository / "main.py"
    raw = source.read_text(encoding="utf-8")
    late_branch_start = raw.index('    if payload["event"] == "payment.authorized":')
    fallback_start = raw.index(
        '    return JSONResponse({"accepted": False}, status_code=400)',
        late_branch_start,
    )
    source.write_text(raw[:late_branch_start] + raw[fallback_start:], encoding="utf-8")
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
        item for item in confirmed.artifact.scenarios if item.scenario_id == ScenarioId.SG_08
    )
    instance = scenario.instances[0]
    assert instance.state == ApplicabilityState.NOT_APPLICABLE
    assert instance.normal_control_id is None

    def forbidden_request(*args, **kwargs):
        raise AssertionError("not-applicable SG08 rows must not dispatch")

    monkeypatch.setattr(ManagedRuntimeSession, "request", forbidden_request)
    result = execute_sg08(
        repository,
        config,
        scenario_instance_id=instance.instance_id,
        expected_applicability_fingerprint=confirmed.artifact.applicability_fingerprint,
        generated_at=NOW,
    )[0]
    assert result.result == VerificationResultState.NOT_APPLICABLE
    assert result.reason == ScenarioResultReasonCode.APPLICABILITY_NOT_APPLICABLE
    assert result.authority.runtime_request_ids == ()


def test_sg08_applicability_and_safe_reference_retain_truth_authority(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path)
    instance_id, fingerprint, _ = _authority(
        repository,
        config,
        fulfilment=FulfilmentPolicy.AUTHORIZED_ALLOWED,
        late=LateAuthorisationPolicy.DO_NOT_FULFIL,
    )
    confirmed = confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.AUTHORIZED_ALLOWED,
        late_authorisation=LateAuthorisationPolicy.DO_NOT_FULFIL,
        generated_at=NOW,
    )
    instance = next(
        instance
        for scenario in confirmed.artifact.scenarios
        if scenario.scenario_id == ScenarioId.SG_08
        for instance in scenario.instances
        if instance.instance_id == instance_id
    )
    assertion = instance.assertions[0]
    assert assertion.key == SG08_LATE_POLICY_ASSERTION_KEY
    assert assertion.state == ApplicabilityState.INDETERMINATE
    assert assertion.reasons[0].code == ApplicabilityReasonCode.MERCHANT_LATE_CONTEXT_UNPROVEN
    result = execute_sg08(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=fingerprint,
        generated_at=NOW,
    )[0]
    payload = result.model_dump(mode="python")
    payload["result"] = VerificationResultState.VERIFIED_FAIL
    payload["evidence_tier"] = EvidenceTier.E3_DYNAMIC_VERIFIED
    with pytest.raises(ValidationError):
        type(result).model_validate(payload)


def test_sg08_capture_required_assertion_keys_are_authority_split(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path)
    instance_id, _, _ = _authority(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        late=LateAuthorisationPolicy.FULFIL_LATER,
    )
    confirmed = confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        late_authorisation=LateAuthorisationPolicy.FULFIL_LATER,
        generated_at=NOW,
    )
    instance = next(
        instance
        for scenario in confirmed.artifact.scenarios
        if scenario.scenario_id == ScenarioId.SG_08
        for instance in scenario.instances
        if instance.instance_id == instance_id
    )
    assert tuple(item.key for item in instance.assertions) == (
        SG08_PRECAPTURE_ASSERTION_KEY,
        SG08_CAPTURE_ASSERTION_KEY,
    )
