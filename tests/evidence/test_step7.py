from __future__ import annotations

import asyncio
import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from stateguard.applicability.contracts import (
    SG04_CUSTOMER_VALUE_ASSERTION_KEY,
    SG04_STATE_REGRESSION_ASSERTION_KEY,
    SG05_CUSTOMER_VALUE_ASSERTION_KEY,
    SG05_MUTATION_ASSERTION_KEY,
    SG06_CUSTOMER_VALUE_ASSERTION_KEY,
    SG06_MUTATION_ASSERTION_KEY,
    ScenarioId,
)
from stateguard.application.applicability import (
    analyze_applicability,
    confirm_merchant_policy,
)
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.application.verification import create_verification_run
from stateguard.ci import evaluate_ci_gate
from stateguard.contracts.config import FulfilmentPolicy, LateAuthorisationPolicy
from stateguard.contracts.identity import (
    fingerprint_json,
    new_project_id,
    new_verification_run_id,
)
from stateguard.evidence.catalog import assertion_definition
from stateguard.evidence.contracts import (
    EvidenceTier,
    FindingKind,
    VerificationCheck,
    VerificationResultState,
    VerificationRun,
    VerificationRunStatus,
    build_verification_check_key,
    derive_findings,
    verification_run_fingerprint_payload,
)
from stateguard.failure_lab.contracts import GroundedScenarioInputReference
from stateguard.grounding.contracts import (
    RazorpayGroundingReason,
    RazorpayGroundingStatus,
    RazorpayTestGroundingRequest,
)
from stateguard.grounding.razorpay import acquire_razorpay_test_grounding
from stateguard.workspace.run_artifacts import (
    list_verification_runs,
    load_latest_verification_run,
    load_verification_run,
    write_verification_run,
)

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos" / "failure_lab_batch_a"
)
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
WEBHOOK_SECRET = "step7-webhook-secret-sentinel"
CHECKOUT_SECRET = "step7-checkout-secret-sentinel"
SERVER_ORDER = "step7-server-order-sentinel"


def _repository(tmp_path: Path, *, managed: bool = True) -> tuple[Path, Path]:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURE, repository)
    config = repository / "stateguard.yaml"
    runtime = (
        """runtime:
  mode: managed
  env_from_host:
    STATEGUARD_TEST_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET
    MERCHANT_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET
    STATEGUARD_TEST_RAZORPAY_KEY_SECRET: SG_TEST_CHECKOUT_SECRET
    MERCHANT_CHECKOUT_SECRET: SG_TEST_CHECKOUT_SECRET
    STATEGUARD_TEST_SERVER_ORDER_ID: SG_TEST_SERVER_ORDER
    MERCHANT_SERVER_ORDER_ID: SG_TEST_SERVER_ORDER
    WEBHOOK_CAPTURE_BEHAVIOR: WEBHOOK_CAPTURE_BEHAVIOR_HOST
    SG03_BEHAVIOR: SG03_BEHAVIOR_HOST
    SG04_CUSTOMER_BEHAVIOR: SG04_CUSTOMER_BEHAVIOR_HOST
    SG04_STATE_BEHAVIOR: SG04_STATE_BEHAVIOR_HOST
    SG06_BEHAVIOR: SG06_BEHAVIOR_HOST
    SG08_AUTHORIZED_BEHAVIOR: SG08_AUTHORIZED_BEHAVIOR_HOST
"""
        if managed
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


def _confirm_authority(
    repository: Path,
    config: Path,
    *,
    fulfilment: FulfilmentPolicy = FulfilmentPolicy.CAPTURE_REQUIRED,
    late: LateAuthorisationPolicy = LateAuthorisationPolicy.FULFIL_LATER,
) -> None:
    unresolved = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    symbol = next(
        item.symbol_id
        for item in unresolved.source_index.symbols
        if item.qualified_name == "domain.grant_ticket"
    )
    asyncio.run(confirm_customer_value(repository, config, symbol, generated_at=NOW))
    confirm_merchant_policy(
        repository,
        config,
        fulfilment=fulfilment,
        late_authorisation=late,
        generated_at=NOW,
    )


def _managed_environment(monkeypatch: pytest.MonkeyPatch, behavior: str) -> None:
    values = {
        "SG_TEST_WEBHOOK_SECRET": WEBHOOK_SECRET,
        "SG_TEST_CHECKOUT_SECRET": CHECKOUT_SECRET,
        "SG_TEST_SERVER_ORDER": SERVER_ORDER,
        "WEBHOOK_CAPTURE_BEHAVIOR_HOST": "once",
        "SG03_BEHAVIOR_HOST": behavior,
        "SG04_CUSTOMER_BEHAVIOR_HOST": "safe",
        "SG04_STATE_BEHAVIOR_HOST": "safe",
        "SG06_BEHAVIOR_HOST": "safe",
        "SG08_AUTHORIZED_BEHAVIOR_HOST": "zero",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def _check(run: VerificationRun, scenario: ScenarioId, assertion_key: str):
    return next(
        item
        for item in run.checks
        if item.scenario_id == scenario and item.assertion_key == assertion_key
    )


def test_complete_runs_preserve_assertions_keys_findings_and_confidentiality(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, config = _repository(tmp_path)
    _confirm_authority(repository, config)
    _managed_environment(monkeypatch, "initial_multiple")
    failed = create_verification_run(repository, config, created_at=NOW).artifact
    _managed_environment(monkeypatch, "pass")
    passed = create_verification_run(repository, config, created_at=NOW).artifact

    current = analyze_applicability(repository, config, generated_at=NOW).artifact
    assertion_count = sum(
        len(instance.assertions)
        for scenario in current.scenarios
        for instance in scenario.instances
    )
    assert len(failed.checks) == len(passed.checks) == assertion_count
    assert {item.scenario_id for item in passed.checks} == set(ScenarioId)
    assert {
        item.assertion_key for item in passed.checks if item.scenario_id == ScenarioId.SG_04
    } == {SG04_CUSTOMER_VALUE_ASSERTION_KEY, SG04_STATE_REGRESSION_ASSERTION_KEY}
    assert {
        item.assertion_key for item in passed.checks if item.scenario_id == ScenarioId.SG_05
    } == {SG05_CUSTOMER_VALUE_ASSERTION_KEY, SG05_MUTATION_ASSERTION_KEY}
    assert {
        item.assertion_key for item in passed.checks if item.scenario_id == ScenarioId.SG_06
    } == {SG06_CUSTOMER_VALUE_ASSERTION_KEY, SG06_MUTATION_ASSERTION_KEY}

    failed_check = next(
        item for item in failed.checks if item.result == VerificationResultState.VERIFIED_FAIL
    )
    passed_check = next(item for item in passed.checks if item.check_key == failed_check.check_key)
    assert failed_check.check_key == passed_check.check_key
    assert failed_check.result == VerificationResultState.VERIFIED_FAIL
    assert passed_check.result == VerificationResultState.VERIFIED_PASS
    failed_finding = next(
        item for item in failed.findings if item.check_id == failed_check.check_id
    )
    assert failed_finding.kind == FindingKind.VERIFIED_FAILURE
    assert failed_finding.critical is True
    assert all(item.check_id != passed_check.check_id for item in passed.findings)
    assert not hasattr(passed_check, "finding_key")
    expected_finding_kinds = {
        VerificationResultState.VERIFIED_FAIL: FindingKind.VERIFIED_FAILURE,
        VerificationResultState.STATIC_WARNING: FindingKind.STATIC_WARNING,
        VerificationResultState.NEEDS_INPUT: FindingKind.RESOLUTION_REQUIRED,
        VerificationResultState.UNVERIFIED: FindingKind.VERIFICATION_COVERAGE,
    }
    for state, kind in expected_finding_kinds.items():
        payload = passed_check.model_dump(mode="python")
        payload["result"] = state
        payload["evidence_tier"] = (
            EvidenceTier.E3_DYNAMIC_VERIFIED
            if state == VerificationResultState.VERIFIED_FAIL
            else None
        )
        projected = VerificationCheck.model_validate(payload)
        finding = derive_findings(passed.run_id, (projected,))
        assert len(finding) == 1
        assert finding[0].kind == kind
        assert finding[0].critical == (state == VerificationResultState.VERIFIED_FAIL)

    serialized = (repository / ".stateguard" / "runs" / passed.run_id / "run.json").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        WEBHOOK_SECRET,
        CHECKOUT_SECRET,
        SERVER_ORDER,
        "razorpay_signature",
        '"raw_body":',
        "response_body",
        "Traceback",
    ):
        assert forbidden not in serialized

    assert '"scenario_id":"SG-01"' in serialized
    assert passed.summary.dynamic_coverage_numerator == sum(
        item.evidence_tier in {EvidenceTier.E3_DYNAMIC_VERIFIED, EvidenceTier.E4_RAZORPAY_GROUNDED}
        for item in passed.checks
    )
    assert passed.summary.dynamic_coverage_denominator == sum(
        item.result != VerificationResultState.NOT_APPLICABLE for item in passed.checks
    )

    assert load_verification_run(repository, failed.run_id) == failed
    assert list_verification_runs(repository) == tuple(
        sorted((failed, passed), key=lambda item: (item.completed_at, item.run_id), reverse=True)
    )
    assert load_latest_verification_run(repository) == list_verification_runs(repository)[0]
    with pytest.raises(FileExistsError):
        write_verification_run(repository, passed)
    if os.name == "posix":
        assert (repository / ".stateguard" / "runs").stat().st_mode & 0o777 == 0o700
        assert (
            repository / ".stateguard" / "runs" / passed.run_id / "run.json"
        ).stat().st_mode & 0o777 == 0o600


def test_sg01_resource_profile_grounding_promotes_only_proven_e3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, config = _repository(tmp_path)
    _confirm_authority(repository, config)
    _managed_environment(monkeypatch, "pass")
    request = RazorpayTestGroundingRequest(payment_id_env="GROUNDING_PAYMENT_ID")

    degraded = create_verification_run(
        repository,
        config,
        created_at=NOW,
        razorpay_grounding_request=request,
    ).artifact
    degraded_sg01 = next(
        check for check in degraded.checks if check.scenario_id == ScenarioId.SG_01
    )
    assert degraded.authority.razorpay_grounding is not None
    assert degraded.authority.razorpay_grounding.status == RazorpayGroundingStatus.UNAVAILABLE
    assert (
        degraded.authority.razorpay_grounding.unavailable_reason
        == RazorpayGroundingReason.MISSING_ENVIRONMENT
    )
    assert degraded_sg01.evidence_tier == EvidenceTier.E3_DYNAMIC_VERIFIED
    assert degraded_sg01.grounding is None

    payment_id = "pay_Step7Grounding"
    order_id = "order_Step7Grounding"

    def handler(provider_request: httpx.Request) -> httpx.Response:
        if provider_request.url.path == f"/v1/payments/{payment_id}":
            return httpx.Response(
                200,
                json={
                    "id": payment_id,
                    "entity": "payment",
                    "amount": 9900,
                    "currency": "INR",
                    "status": "captured",
                    "captured": True,
                    "order_id": order_id,
                    "amount_refunded": 0,
                    "refund_status": None,
                    "email": "must-not-persist@example.invalid",
                },
            )
        return httpx.Response(
            200,
            json={
                "id": order_id,
                "entity": "order",
                "amount": 9900,
                "amount_paid": 9900,
                "amount_due": 0,
                "currency": "INR",
                "status": "paid",
                "receipt": "must-not-persist",
            },
        )

    def successful_acquisition(
        selected: RazorpayTestGroundingRequest,
        run_id: str,
        *,
        acquired_at: datetime,
    ):
        assert selected == request
        return acquire_razorpay_test_grounding(
            selected,
            run_id,
            environment={
                "RAZORPAY_KEY_ID": "rzp_test_step7Key",
                "RAZORPAY_KEY_SECRET": "provider-key-secret-sentinel",
                "GROUNDING_PAYMENT_ID": payment_id,
            },
            acquired_at=acquired_at,
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(
        "stateguard.application.verification.acquire_razorpay_test_grounding",
        successful_acquisition,
    )
    grounded = create_verification_run(
        repository,
        config,
        created_at=NOW,
        razorpay_grounding_request=request,
    ).artifact
    e4_checks = tuple(
        check
        for check in grounded.checks
        if check.evidence_tier == EvidenceTier.E4_RAZORPAY_GROUNDED
    )
    assert len(e4_checks) == 1
    grounded_sg01 = e4_checks[0]
    assert grounded_sg01.scenario_id == ScenarioId.SG_01
    assert grounded_sg01.check_key == degraded_sg01.check_key
    assert grounded_sg01.result == degraded_sg01.result
    assert grounded_sg01.reason == degraded_sg01.reason
    assert isinstance(grounded_sg01.input_reference, GroundedScenarioInputReference)
    assert grounded_sg01.grounding is not None
    assert grounded_sg01.grounding.label == "TEST MODE RESOURCE PROFILE GROUNDED"
    e4_payload = grounded_sg01.model_dump(mode="python")
    with pytest.raises(ValidationError, match="E4 requires exact SG-01"):
        VerificationCheck.model_validate({**e4_payload, "grounding": None})
    with pytest.raises(ValidationError, match="non-verified checks cannot claim E4"):
        VerificationCheck.model_validate(
            {
                **e4_payload,
                "result": VerificationResultState.UNVERIFIED,
                "reason": "RUNTIME_CAPABILITY_INSUFFICIENT",
            }
        )
    with pytest.raises(ValidationError, match="E4 requires exact SG-01"):
        VerificationCheck.model_validate({**e4_payload, "scenario_id": ScenarioId.SG_02})
    assert all(
        check.evidence_tier != EvidenceTier.E4_RAZORPAY_GROUNDED
        for check in grounded.checks
        if check.scenario_id != ScenarioId.SG_01
    )
    assert evaluate_ci_gate(grounded).exit_code == evaluate_ci_gate(degraded).exit_code
    assert grounded.summary.verified_pass == degraded.summary.verified_pass
    assert grounded.summary.verified_fail == degraded.summary.verified_fail
    serialized = grounded.model_dump_json()
    for forbidden in (
        payment_id,
        order_id,
        "rzp_test_step7Key",
        "provider-key-secret-sentinel",
        "must-not-persist@example.invalid",
        "receipt",
    ):
        assert forbidden not in serialized

    monkeypatch.setenv("SG03_BEHAVIOR_HOST", "initial_multiple")
    vulnerable = create_verification_run(
        repository,
        config,
        created_at=NOW,
        razorpay_grounding_request=request,
    ).artifact
    vulnerable_sg01 = next(
        check for check in vulnerable.checks if check.scenario_id == ScenarioId.SG_01
    )
    assert vulnerable_sg01.evidence_tier == EvidenceTier.E4_RAZORPAY_GROUNDED
    assert vulnerable_sg01.result == VerificationResultState.VERIFIED_FAIL


def test_authorized_allowed_sg08_remains_visible_and_old_run_is_self_contained(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path, managed=False)
    _confirm_authority(
        repository,
        config,
        fulfilment=FulfilmentPolicy.AUTHORIZED_ALLOWED,
    )
    run = create_verification_run(repository, config, created_at=NOW).artifact
    assert run.schema_version == 3
    assert all(check.relevant_authority is not None for check in run.checks)
    sg08 = tuple(item for item in run.checks if item.scenario_id == ScenarioId.SG_08)
    assert sg08
    assert all(item.result == VerificationResultState.UNVERIFIED for item in sg08)
    assert all(
        any(
            finding.check_id == check.check_id
            and finding.kind == FindingKind.VERIFICATION_COVERAGE
            and not finding.critical
            for finding in run.findings
        )
        for check in sg08
    )

    for name in ("semantics.json", "applicability.json", "runtime.json"):
        (repository / ".stateguard" / name).write_text("{}\n", encoding="utf-8")
    assert load_verification_run(repository, run.run_id) == run

    v2_authority = run.authority.model_copy(
        update={
            "schema_versions": run.authority.schema_versions.model_copy(
                update={"scenario_execution_result": 2, "razorpay_grounding": None}
            ),
            "razorpay_grounding": None,
        }
    )
    v2_checks = tuple(check.model_copy(update={"grounding": None}) for check in run.checks)
    v2_payload = verification_run_fingerprint_payload(
        schema_version=2,
        producer_version=run.producer_version,
        generated_at=run.generated_at,
        run_id=run.run_id,
        status=VerificationRunStatus(run.status),
        created_at=run.created_at,
        completed_at=run.completed_at,
        authority=v2_authority,
        checks=v2_checks,
        findings=run.findings,
        summary=run.summary,
    )
    v2 = VerificationRun(
        **v2_payload,
        run_fingerprint=fingerprint_json(v2_payload),
    )
    assert VerificationRun.model_validate_json(v2.model_dump_json()) == v2


def test_key_dimensions_and_invariant_version_are_explicit(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path, managed=False)
    _confirm_authority(repository, config)
    run = create_verification_run(repository, config, created_at=NOW).artifact
    check = next(item for item in run.checks if item.targets.ingress_node_id is not None)
    policy = run.authority.policy
    definition = assertion_definition(check.scenario_id, check.assertion_key)

    def key_for(
        *,
        invariant_version: int = check.invariant_version,
        assertion_key: str = check.assertion_key,
        targets=check.targets,
        selected_policy=policy,
    ):
        return build_verification_check_key(
            project_id=run.authority.project_id,
            scenario_id=check.scenario_id,
            assertion_key=assertion_key,
            invariant_id=check.invariant_id,
            invariant_version=invariant_version,
            targets=targets,
            key_policy_dimensions=definition.key_policy_dimensions,
            policy=selected_policy,
        )

    same = key_for()
    changed_version = key_for(invariant_version=check.invariant_version + 1)
    changed_assertion = key_for(assertion_key=f"{check.assertion_key}_DIFFERENT")
    changed_target = key_for(
        targets=check.targets.model_copy(update={"ingress_node_id": f"sgnode_{'f' * 32}"})
    )
    assert same == check.check_key
    assert len({same, changed_version, changed_assertion, changed_target}) == 4

    if definition.key_policy_dimensions:
        alternative = (
            FulfilmentPolicy.AUTHORIZED_ALLOWED
            if policy.fulfilment == FulfilmentPolicy.CAPTURE_REQUIRED
            else FulfilmentPolicy.CAPTURE_REQUIRED
        )
        changed_policy = key_for(
            selected_policy=policy.model_copy(update={"fulfilment": alternative})
        )
        assert changed_policy != same


def test_storage_rejects_tampering_corrupt_final_runs_and_symlinks(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path, managed=False)
    _confirm_authority(repository, config)
    run = create_verification_run(repository, config, created_at=NOW).artifact
    path = repository / ".stateguard" / "runs" / run.run_id / "run.json"
    original = path.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="invalid verification run ID"):
        load_verification_run(repository, "../../outside")

    legacy_payload = json.loads(original)
    legacy_payload["schema_version"] = 1
    for check in legacy_payload["checks"]:
        check.pop("relevant_authority")
    legacy_checks = tuple(
        check.model_copy(update={"relevant_authority": None}) for check in run.checks
    )
    legacy_fingerprint_payload = verification_run_fingerprint_payload(
        schema_version=1,
        producer_version=run.producer_version,
        generated_at=run.generated_at,
        run_id=run.run_id,
        status=VerificationRunStatus(run.status),
        created_at=run.created_at,
        completed_at=run.completed_at,
        authority=run.authority,
        checks=legacy_checks,
        findings=run.findings,
        summary=run.summary,
    )
    legacy_payload["run_fingerprint"] = fingerprint_json(legacy_fingerprint_payload)
    path.write_text(json.dumps(legacy_payload), encoding="utf-8")
    legacy = load_verification_run(repository, run.run_id)
    assert legacy.schema_version == 1
    assert all(check.relevant_authority is None for check in legacy.checks)
    path.write_text(original, encoding="utf-8")

    payload = json.loads(original)
    payload["summary"]["unverified"] += 1
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid StateGuard verification-run"):
        load_verification_run(repository, run.run_id)
    path.write_text(original, encoding="utf-8")

    payload = json.loads(original)
    payload["schema_version"] = 1
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid StateGuard verification-run"):
        load_verification_run(repository, run.run_id)
    path.write_text(original, encoding="utf-8")

    payload = json.loads(original)
    payload["run_fingerprint"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid StateGuard verification-run"):
        load_verification_run(repository, run.run_id)
    path.write_text(original, encoding="utf-8")

    other_run_id = new_verification_run_id()
    mismatched = repository / ".stateguard" / "runs" / other_run_id
    shutil.copytree(path.parent, mismatched)
    with pytest.raises(ValueError, match="directory and artifact identities differ"):
        load_verification_run(repository, other_run_id)
    shutil.rmtree(mismatched)

    staging = repository / ".stateguard" / "runs" / ".abandoned.tmp"
    staging.mkdir()
    assert list_verification_runs(repository) == (run,)
    corrupt = repository / ".stateguard" / "runs" / f"sgvrun_{'f' * 32}"
    corrupt.mkdir()
    with pytest.raises(ValueError, match="directory must contain only run.json"):
        list_verification_runs(repository)
    corrupt.rmdir()

    if not hasattr(os, "symlink"):
        return
    outside = tmp_path / "outside.json"
    outside.write_text(original, encoding="utf-8")
    path.unlink()
    try:
        path.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ValueError, match="symlinked verification-run artifact"):
        load_verification_run(repository, run.run_id)

    linked_state_repository = tmp_path / "linked-state-repository"
    linked_state_repository.mkdir()
    (linked_state_repository / ".stateguard").symlink_to(
        repository / ".stateguard", target_is_directory=True
    )
    with pytest.raises(ValueError, match="symlinked .stateguard directory"):
        list_verification_runs(linked_state_repository)

    linked_runs_repository = tmp_path / "linked-runs-repository"
    (linked_runs_repository / ".stateguard").mkdir(parents=True)
    (linked_runs_repository / ".stateguard" / "runs").symlink_to(
        repository / ".stateguard" / "runs", target_is_directory=True
    )
    with pytest.raises(ValueError, match="symlinked verification-runs directory"):
        list_verification_runs(linked_runs_repository)

    linked_final_repository = tmp_path / "linked-final-repository"
    linked_final_runs = linked_final_repository / ".stateguard" / "runs"
    linked_final_runs.mkdir(parents=True)
    (linked_final_runs / run.run_id).symlink_to(path.parent, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinked verification-run directory"):
        load_verification_run(linked_final_repository, run.run_id)


def test_failed_staged_validation_leaves_no_completed_or_partial_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, config = _repository(tmp_path, managed=False)
    _confirm_authority(repository, config)
    run = create_verification_run(repository, config, created_at=NOW).artifact
    destination = tmp_path / "destination"
    destination.mkdir()

    def reject_staged_artifact(path: Path) -> VerificationRun:
        raise ValueError(f"rejected staged artifact {path.name}")

    monkeypatch.setattr(
        "stateguard.workspace.run_artifacts._load_artifact_file",
        reject_staged_artifact,
    )
    with pytest.raises(ValueError, match="rejected staged artifact"):
        write_verification_run(destination, run)
    runs = destination / ".stateguard" / "runs"
    assert tuple(runs.iterdir()) == ()


def test_schema_and_derived_summary_are_validated() -> None:
    with pytest.raises(ValidationError):
        VerificationRun.model_validate(
            {
                "artifact_type": "VERIFICATION_RUN",
                "schema_version": 2,
            }
        )


def test_authority_drift_aborts_without_completed_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, config = _repository(tmp_path, managed=False)
    _confirm_authority(repository, config)

    def reject_drift(*args: object, **kwargs: object) -> None:
        raise ValueError("verification authority changed before run completion")

    monkeypatch.setattr(
        "stateguard.application.verification._validate_unchanged_authority",
        reject_drift,
    )
    with pytest.raises(ValueError, match="authority changed"):
        create_verification_run(repository, config, created_at=NOW)
    assert not (repository / ".stateguard" / "runs").exists()


@pytest.mark.parametrize(
    ("corruption", "message"),
    [
        ("duplicate", "duplicate scenario execution assertion authority"),
        ("missing", "map one-to-one"),
    ],
)
def test_exact_assertion_correlation_aborts_without_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    corruption: str,
    message: str,
) -> None:
    repository, config = _repository(tmp_path, managed=False)
    _confirm_authority(repository, config)

    from stateguard.application import verification as verification_module

    original = verification_module.execute_sg04

    def corrupt_results(*args: object, **kwargs: object):
        results = original(*args, **kwargs)
        assert len(results) == 2
        return (*results, results[0]) if corruption == "duplicate" else results[:-1]

    monkeypatch.setattr(verification_module, "execute_sg04", corrupt_results)
    with pytest.raises(ValueError, match=message):
        create_verification_run(repository, config, created_at=NOW)
    assert not (repository / ".stateguard" / "runs").exists()
