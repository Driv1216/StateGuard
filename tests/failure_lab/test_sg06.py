from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs

import pytest
from pydantic import ValidationError

from stateguard.applicability.contracts import (
    SG06_CUSTOMER_VALUE_ASSERTION_KEY,
    SG06_MUTATION_ASSERTION_KEY,
    ApplicabilityState,
    ScenarioId,
)
from stateguard.application.applicability import analyze_applicability
from stateguard.application.failure_lab import execute_sg06
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
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
from stateguard.failure_lab.sg06 import (
    evaluate_customer_sequence,
    evaluate_mutation_sequence,
    prepare_sg06_requests,
)
from stateguard.graph.contracts import (
    CheckoutFieldBinding,
    CheckoutRequestBinding,
    CheckoutRequestTransport,
)

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos" / "failure_lab_batch_a"
)
NOW = datetime(2026, 8, 28, tzinfo=UTC)
SECRET = "batch-a-checkout-secret-sentinel"
SERVER_ORDER = "order_server_control"
MUTATION_NODE = f"sgnode_{'3' * 32}"


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
    SG06_BEHAVIOR: SG06_BEHAVIOR_HOST
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
    analyzed = analyze_applicability(repository, config, generated_at=NOW)
    scenario = next(
        item for item in analyzed.artifact.scenarios if item.scenario_id == ScenarioId.SG_06
    )
    instance = next(
        item
        for item in scenario.instances
        if item.state == ApplicabilityState.APPLICABLE
        and {assertion.key for assertion in item.assertions}
        == {SG06_MUTATION_ASSERTION_KEY, SG06_CUSTOMER_VALUE_ASSERTION_KEY}
    )
    return instance.instance_id, analyzed.artifact.applicability_fingerprint


def _binding(transport: CheckoutRequestTransport) -> CheckoutRequestBinding:
    return CheckoutRequestBinding(
        transport=transport,
        fields=tuple(
            CheckoutFieldBinding(canonical_name=name, request_name=name)
            for name in (
                "razorpay_payment_id",
                "razorpay_order_id",
                "razorpay_signature",
            )
        ),
    )


def _payload(request_content: bytes | None, params: dict[str, str] | None) -> dict[str, str]:
    if params is not None:
        return params
    assert request_content is not None
    if request_content.startswith(b"{"):
        return json.loads(request_content)
    return {key: values[0] for key, values in parse_qs(request_content.decode()).items()}


def _customer(
    entered: int, *, offset: int = 0, status: int = 200
) -> CustomerTargetObservationSummary:
    return CustomerTargetObservationSummary(
        entered_count=entered,
        returned_normally_count=entered,
        exception_escaped_count=0,
        entered_sequences=tuple(range(offset + 2, offset + 2 + entered)),
        returned_normally_sequences=tuple(range(offset + 4, offset + 4 + entered)),
        request_received_sequences=(offset + 1,),
        response_completed_sequences=(offset + 9,),
        request_aborted_sequences=(),
        http_status_code=status,
    )


def _mutation(
    completed: int, *, offset: int = 0, status: int = 200
) -> MutationScenarioRequestObservation:
    return MutationScenarioRequestObservation(
        request_id=f"sgreq_{offset:032x}",
        mutation_targets=(
            MutationTargetObservationSummary(
                mutation_node_id=MUTATION_NODE,
                reached_count=completed,
                completed_normally_count=completed,
                raised_count=0,
                reached_sequences=((offset + 2,) if completed else ()),
                completed_normally_sequences=((offset + 3,) if completed else ()),
                raised_sequences=(),
            ),
        ),
        request_received_sequences=(offset + 1,),
        response_completed_sequences=(offset + 9,),
        request_aborted_sequences=(),
        http_status_code=status,
    )


@pytest.mark.parametrize("transport", list(CheckoutRequestTransport))
def test_sg06_supported_transports_bind_exact_values_without_persisting_them(
    transport: CheckoutRequestTransport,
) -> None:
    prepared = prepare_sg06_requests(
        execution_id="sgexec_0123456789abcdef0123456789abcdef",
        path="/checkout/callback",
        binding=_binding(transport),
        secret=SECRET,
        server_order_id=SERVER_ORDER,
    )
    tampered = _payload(prepared.tampered.content, prepared.tampered.params)
    valid = _payload(prepared.valid.content, prepared.valid.params)
    payment_id = valid["razorpay_payment_id"]

    assert tampered["razorpay_order_id"].startswith("order_")
    assert tampered["razorpay_order_id"] != SERVER_ORDER
    assert valid["razorpay_order_id"] == SERVER_ORDER
    for payload in (tampered, valid):
        expected = hmac.new(
            SECRET.encode(),
            f"{payload['razorpay_order_id']}|{payment_id}".encode(),
            hashlib.sha256,
        ).hexdigest()
        assert payload["razorpay_signature"] == expected
    persisted = prepared.input_reference.model_dump_json()
    assert SECRET not in persisted
    assert SERVER_ORDER not in persisted
    assert payment_id not in persisted
    assert valid["razorpay_signature"] not in persisted


def test_sg06_reducers_require_a_valid_differential_control() -> None:
    assert evaluate_customer_sequence(_customer(0, status=400), _customer(1, offset=20))[0] == (
        VerificationResultState.VERIFIED_PASS
    )
    assert evaluate_customer_sequence(_customer(1), _customer(0, offset=20))[0] == (
        VerificationResultState.VERIFIED_FAIL
    )
    assert evaluate_customer_sequence(_customer(0, status=400), _customer(0, offset=20)) == (
        VerificationResultState.UNVERIFIED,
        None,
        ScenarioResultReasonCode.VALID_CHECKOUT_CONTROL_UNPROVEN,
    )
    assert evaluate_mutation_sequence(_mutation(0, status=400), _mutation(1, offset=20))[0] == (
        VerificationResultState.VERIFIED_PASS
    )
    assert evaluate_mutation_sequence(_mutation(1), _mutation(0, offset=20))[0] == (
        VerificationResultState.VERIFIED_FAIL
    )


@pytest.mark.parametrize(
    ("behavior", "expected"),
    [
        ("safe", VerificationResultState.VERIFIED_PASS),
        ("vulnerable", VerificationResultState.VERIFIED_FAIL),
    ],
)
def test_managed_sg06_truth_mapping_and_confidentiality(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
    expected: VerificationResultState,
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", "webhook-secret")
    monkeypatch.setenv("SG_TEST_CHECKOUT_SECRET", SECRET)
    monkeypatch.setenv("SG_TEST_SERVER_ORDER", SERVER_ORDER)
    monkeypatch.setenv("SG06_BEHAVIOR_HOST", behavior)
    repository, config = _repository(tmp_path)
    instance_id, fingerprint = _authority(repository, config)

    results = execute_sg06(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=fingerprint,
        generated_at=NOW,
    )
    assert {item.result for item in results} == {expected}
    assert all(item.evidence_tier == EvidenceTier.E3_DYNAMIC_VERIFIED for item in results)
    assert all(len(item.authority.runtime_request_ids) == 2 for item in results)
    persisted = "".join(item.model_dump_json() for item in results)
    assert SECRET not in persisted
    assert SERVER_ORDER not in persisted
    assert "razorpay_signature" not in persisted
    if behavior == "safe":
        payload = results[0].model_dump(mode="python")
        payload["authority"]["runtime_request_ids"] = (
            f"sgreq_{'e' * 32}",
            results[0].authority.runtime_request_ids[1],
        )
        with pytest.raises(ValidationError, match="ordered request observations"):
            ScenarioExecutionResult.model_validate(payload)


def test_sg06_missing_host_authority_is_unverified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", "webhook-secret")
    monkeypatch.setenv("SG_TEST_CHECKOUT_SECRET", SECRET)
    monkeypatch.setenv("SG_TEST_SERVER_ORDER", SERVER_ORDER)
    monkeypatch.setenv("SG06_BEHAVIOR_HOST", "safe")
    repository, config = _repository(tmp_path)
    instance_id, fingerprint = _authority(repository, config)

    monkeypatch.delenv("SG_TEST_CHECKOUT_SECRET")
    missing_secret = execute_sg06(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=fingerprint,
        generated_at=NOW,
    )
    assert {item.reason for item in missing_secret} == {
        ScenarioResultReasonCode.CHECKOUT_SECRET_UNAVAILABLE
    }

    monkeypatch.setenv("SG_TEST_CHECKOUT_SECRET", SECRET)
    monkeypatch.delenv("SG_TEST_SERVER_ORDER")
    missing_order = execute_sg06(
        repository,
        config,
        scenario_instance_id=instance_id,
        expected_applicability_fingerprint=fingerprint,
        generated_at=NOW,
    )
    assert {item.reason for item in missing_order} == {
        ScenarioResultReasonCode.SERVER_ORDER_CONTROL_UNAVAILABLE
    }


def test_sg06_manual_extra_required_payload_is_unverified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SG_TEST_WEBHOOK_SECRET", "webhook-secret")
    monkeypatch.setenv("SG_TEST_CHECKOUT_SECRET", SECRET)
    monkeypatch.setenv("SG_TEST_SERVER_ORDER", SERVER_ORDER)
    monkeypatch.setenv("SG06_BEHAVIOR_HOST", "safe")
    repository, config = _repository(tmp_path)
    source = repository / "main.py"
    source.write_text(
        source.read_text(encoding="utf-8").replace(
            '    payment_id = payload["razorpay_payment_id"]\n',
            '    merchant_required = payload["merchant_required"]\n'
            '    payment_id = payload["razorpay_payment_id"]\n',
        ),
        encoding="utf-8",
    )
    unresolved = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    symbol = next(
        item.symbol_id
        for item in unresolved.source_index.symbols
        if item.qualified_name == "domain.grant_ticket"
    )
    asyncio.run(confirm_customer_value(repository, config, symbol, generated_at=NOW))
    analyzed = analyze_applicability(repository, config, generated_at=NOW)
    scenario = next(
        item for item in analyzed.artifact.scenarios if item.scenario_id == ScenarioId.SG_06
    )
    instance = next(item for item in scenario.instances if item.route_registration_id is not None)

    results = execute_sg06(
        repository,
        config,
        scenario_instance_id=instance.instance_id,
        expected_applicability_fingerprint=analyzed.artifact.applicability_fingerprint,
        generated_at=NOW,
    )

    assert {item.result for item in results} == {VerificationResultState.UNVERIFIED}
    assert {item.reason for item in results} == {
        ScenarioResultReasonCode.APPLICABILITY_INDETERMINATE
    }
