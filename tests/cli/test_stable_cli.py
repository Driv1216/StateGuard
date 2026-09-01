from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from stateguard.applicability.contracts import AssertionRole, ScenarioId
from stateguard.application.applicability import confirm_merchant_policy
from stateguard.application.control import ControlOperationError
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.application.verification import create_verification_run
from stateguard.cli.main import main
from stateguard.contracts.config import FulfilmentPolicy, LateAuthorisationPolicy
from stateguard.contracts.identity import new_project_id, new_verification_run_id
from stateguard.control.contracts import ControlErrorCode
from stateguard.evidence.contracts import (
    ApplicabilityEvidenceSnapshot,
    EvidenceTierDistribution,
    VerificationCheck,
    VerificationRun,
    VerificationRunSummary,
)
from stateguard.failure_lab.contracts import (
    ScenarioResultReasonCode,
    VerificationResultState,
)
from stateguard.workspace.config import load_config

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "failure_lab_batch_a", repository)
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
  mode: static
""",
        encoding="utf-8",
    )
    return repository, config


def _completed_run(repository: Path, config: Path):
    unresolved = asyncio.run(resolve_customer_value(repository, config))
    symbol = next(
        item.symbol_id
        for item in unresolved.source_index.symbols
        if item.qualified_name == "domain.grant_ticket"
    )
    asyncio.run(confirm_customer_value(repository, config, symbol))
    confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        late_authorisation=LateAuthorisationPolicy.FULFIL_LATER,
    )
    return create_verification_run(repository, config).artifact


def test_analyze_json_uses_project_relative_config_and_does_not_persist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, _ = _repository(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert main(["analyze", str(repository), "--json"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["schema_version"] == 1
    assert "source_index" not in payload
    assert str(repository.resolve()) not in captured.out
    assert not (repository / ".stateguard" / "applicability.json").exists()
    assert "\x1b" not in captured.out


def test_legacy_repository_alias_is_preserved_but_not_ambiguous(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, config = _repository(tmp_path)
    assert (
        main(
            [
                "analyze",
                "--repository",
                str(repository),
                "--config",
                str(config),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "analyze",
                str(repository),
                "--repository",
                str(repository),
                "--json",
            ]
        )
        == 2
    )
    error = json.loads(capsys.readouterr().err)
    assert error["code"] == "INVALID_REQUEST"


def test_configure_ai_json_is_project_relative_and_never_resolves_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, config = _repository(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MODEL_PROVIDER_KEY", "provider-secret-sentinel")
    assert (
        main(
            [
                "configure",
                "ai",
                str(repository),
                "--provider",
                "openai-compatible",
                "--model",
                "bounded-model",
                "--api-key-env",
                "MODEL_PROVIDER_KEY",
                "--base-url",
                "https://models.example/v1",
                "--json",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["ai_provider"] == "openai-compatible"
    assert payload["ai_model"] == "bounded-model"
    assert payload["ai_api_key_env"] == "MODEL_PROVIDER_KEY"
    assert payload["ai_base_url"] == "https://models.example/v1"
    assert "provider-secret-sentinel" not in captured.out
    loaded = load_config(config)
    assert loaded.ai is not None and loaded.ai.api_key_env == "MODEL_PROVIDER_KEY"


def test_configure_runtime_human_output_does_not_claim_capability(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, config = _repository(tmp_path)
    assert (
        main(
            [
                "configure",
                "runtime",
                "managed",
                str(repository),
                "--env-from-host",
                "MERCHANT_SECRET=HOST_SECRET_NAME",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "StateGuard project setup configured" in output
    assert "runtime_mode: managed" in output
    assert "runtime_env: MERCHANT_SECRET<-HOST_SECRET_NAME" in output
    assert "AVAILABLE" not in output
    assert not (repository / ".stateguard" / "runtime.json").exists()
    loaded = load_config(config)
    assert loaded.runtime is not None and loaded.runtime.mode.value == "managed"


def test_configure_runtime_byo_uses_existing_safe_contract(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, config = _repository(tmp_path)
    assert (
        main(
            [
                "configure",
                "runtime",
                "byo",
                str(repository),
                "--target-kind",
                "local",
                "--base-url",
                "http://127.0.0.1:9123",
                "--readiness-path",
                "/ready",
                "--readiness-status",
                "204",
                "--launch-arg",
                "python",
                "--json",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["runtime"]["mode"] == "byo"
    assert payload["runtime"]["target"]["base_url"] == "http://127.0.0.1:9123"
    assert payload["runtime"]["readiness"]["accepted_statuses"] == [204]
    assert payload["runtime"]["launch_configured"] is True
    assert "python" not in json.dumps(payload)
    loaded = load_config(config)
    assert loaded.runtime is not None and loaded.runtime.mode.value == "byo"


def test_configure_ai_rejects_secret_flag_and_unsafe_url_atomically(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, config = _repository(tmp_path)
    original = config.read_bytes()
    assert (
        main(
            [
                "configure",
                "ai",
                str(repository),
                "--provider",
                "gemini",
                "--model",
                "bounded-model",
                "--api-key-env",
                "MODEL_PROVIDER_KEY",
                "--api-key",
                "literal-secret",
                "--json",
            ]
        )
        == 2
    )
    secret_error = capsys.readouterr().err
    assert json.loads(secret_error)["code"] == "INVALID_REQUEST"
    assert "literal-secret" not in secret_error
    assert config.read_bytes() == original

    assert (
        main(
            [
                "configure",
                "ai",
                str(repository),
                "--provider",
                "openai-compatible",
                "--model",
                "bounded-model",
                "--api-key-env",
                "MODEL_PROVIDER_KEY",
                "--base-url",
                "https://user:password@models.example/v1",
                "--json",
            ]
        )
        == 2
    )
    unsafe_error = capsys.readouterr().err
    assert json.loads(unsafe_error)["code"] == "CONFIG_INVALID"
    assert "password" not in unsafe_error
    assert config.read_bytes() == original


def test_run_history_list_latest_show_and_full_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, config = _repository(tmp_path)
    run = _completed_run(repository, config)

    assert main(["runs", "list", str(repository), "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["runs"][0]["run_id"] == run.run_id
    assert listed["runs"][0]["status"] == "COMPLETED"
    assert "verified_pass" in listed["runs"][0]["summary"]
    assert "overall_result" not in listed["runs"][0]

    assert main(["runs", "latest", str(repository), "--json"]) == 0
    latest = json.loads(capsys.readouterr().out)
    assert latest["run_id"] == run.run_id
    assert "runtime_evidence" not in json.dumps(latest)

    assert main(["runs", "show", run.run_id, str(repository), "--json"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown == latest

    assert (
        main(
            [
                "runs",
                "show",
                run.run_id,
                str(repository),
                "--full",
                "--json",
            ]
        )
        == 0
    )
    full = json.loads(capsys.readouterr().out)
    assert full["artifact_type"] == "VERIFICATION_RUN"
    assert full["run_id"] == run.run_id


def test_empty_history_and_invalid_run_id_use_safe_json_errors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, _ = _repository(tmp_path)
    assert main(["runs", "list", str(repository), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["runs"] == []

    assert main(["runs", "latest", str(repository), "--json"]) == 2
    latest_error = json.loads(capsys.readouterr().err)
    assert latest_error["code"] == "RUN_NOT_FOUND"

    invalid = "../../secret-sentinel"
    assert main(["runs", "show", invalid, str(repository), "--json"]) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.err)["code"] == "INVALID_RUN_ID"
    assert invalid not in captured.err
    assert str(repository.resolve()) not in captured.err


def test_verify_exit_zero_when_completed_summary_contains_verified_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, _ = _repository(tmp_path)
    summary = VerificationRunSummary(
        verified_pass=0,
        verified_fail=1,
        static_warning=0,
        needs_input=0,
        unverified=0,
        not_applicable=0,
        dynamic_coverage_numerator=1,
        dynamic_coverage_denominator=1,
        evidence_tiers=EvidenceTierDistribution(
            no_tier=0,
            e0_discovered=0,
            e1_resolved=0,
            e2_static_verified=0,
            e3_dynamic_verified=1,
            e4_razorpay_grounded=0,
        ),
    )
    completed = SimpleNamespace(
        run_id=new_verification_run_id(),
        summary=summary,
        findings=(object(),),
    )
    monkeypatch.setattr(
        "stateguard.cli.main.StateGuardControl.verify",
        lambda self: completed,
    )
    assert main(["verify", str(repository)]) == 0
    output = capsys.readouterr().out
    assert "verified_fail: 1" in output


def test_verify_grounding_options_pass_only_environment_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, config = _repository(tmp_path)
    completed = _completed_run(repository, config)
    observed = []

    def verify(self: object, *, razorpay_grounding_request=None):
        del self
        observed.append(razorpay_grounding_request)
        return completed

    monkeypatch.setattr("stateguard.cli.main.StateGuardControl.verify", verify)
    assert (
        main(
            [
                "verify",
                str(repository),
                "--razorpay-test-payment-id-env",
                "SG_RZP_PAYMENT",
                "--razorpay-test-key-id-env",
                "SG_RZP_KEY",
                "--razorpay-test-key-secret-env",
                "SG_RZP_SECRET",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert len(observed) == 1
    assert observed[0].payment_id_env == "SG_RZP_PAYMENT"
    assert observed[0].key_id_env == "SG_RZP_KEY"
    assert observed[0].key_secret_env == "SG_RZP_SECRET"
    assert main(["verify", str(repository), "--razorpay-test-payment-id-env", "BAD-NAME"]) == 2


def _ci_check(
    ordinal: int,
    role: AssertionRole,
    result: VerificationResultState,
) -> VerificationCheck:
    reason = {
        VerificationResultState.VERIFIED_PASS: (ScenarioResultReasonCode.EXACT_TARGET_ENTERED_ONCE),
        VerificationResultState.VERIFIED_FAIL: (
            ScenarioResultReasonCode.MERCHANT_STATE_REGRESSED_TO_AUTHORIZED
        ),
        VerificationResultState.UNVERIFIED: (
            ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT
        ),
        VerificationResultState.NOT_APPLICABLE: (
            ScenarioResultReasonCode.APPLICABILITY_NOT_APPLICABLE
        ),
    }[result]
    return VerificationCheck.model_construct(
        check_key=f"sgcheckkey_{ordinal:032x}",
        scenario_id=ScenarioId.SG_04,
        assertion_key=f"ASSERTION_{ordinal}",
        applicability=ApplicabilityEvidenceSnapshot.model_construct(role=role),
        result=result,
        reason=reason,
    )


def _ci_run(*checks: VerificationCheck) -> VerificationRun:
    return VerificationRun.model_construct(
        run_id="sgvrun_" + "1" * 32,
        run_fingerprint="sha256:" + "2" * 64,
        checks=checks,
    )


def test_verify_ci_json_uses_role_sensitive_gate_and_calls_verifier_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, _ = _repository(tmp_path)
    calls = 0
    completed = _ci_run(
        _ci_check(1, AssertionRole.CORE, VerificationResultState.VERIFIED_PASS),
        _ci_check(2, AssertionRole.OPTIONAL, VerificationResultState.VERIFIED_FAIL),
    )

    def verify(self: object) -> VerificationRun:
        nonlocal calls
        calls += 1
        return completed

    monkeypatch.setattr("stateguard.cli.main.StateGuardControl.verify", verify)

    assert main(["verify", str(repository), "--ci", "--json"]) == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert captured.err == ""
    assert calls == 1
    assert payload["schema_version"] == 1
    assert payload["status"] == "VERIFIED_FAILURE"
    assert payload["proven_failure_count"] == 1
    assert payload["blocking_checks"][0]["role"] == "OPTIONAL"
    assert "runtime_evidence" not in captured.out


def test_verify_ci_optional_unverified_does_not_block_core_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, _ = _repository(tmp_path)
    completed = _ci_run(
        _ci_check(1, AssertionRole.CORE, VerificationResultState.VERIFIED_PASS),
        _ci_check(2, AssertionRole.OPTIONAL, VerificationResultState.UNVERIFIED),
    )
    monkeypatch.setattr(
        "stateguard.cli.main.StateGuardControl.verify",
        lambda self: completed,
    )

    assert main(["verify", str(repository), "--ci", "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "PASSED"
    assert captured.err == ""


def test_verify_ci_real_static_run_materializes_not_proven_gate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, _ = _repository(tmp_path)

    assert main(["verify", str(repository), "--ci", "--json"]) == 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert captured.err == ""
    assert payload["status"] == "NOT_PROVEN"
    assert payload["reason"] == "REQUIRED_CHECKS_NOT_PROVEN"
    assert payload["core_not_proven_count"] > 0
    assert (repository / ".stateguard" / "runs" / payload["run_id"] / "run.json").is_file()


def test_verify_ci_no_applicable_core_is_not_proven_in_human_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, _ = _repository(tmp_path)
    completed = _ci_run(_ci_check(1, AssertionRole.CORE, VerificationResultState.NOT_APPLICABLE))
    monkeypatch.setattr(
        "stateguard.cli.main.StateGuardControl.verify",
        lambda self: completed,
    )

    assert main(["verify", str(repository), "--ci"]) == 2
    captured = capsys.readouterr()
    assert "StateGuard CI gate: NOT_PROVEN" in captured.out
    assert "reason: NO_APPLICABLE_REQUIRED_CHECKS" in captured.out
    assert "not_applicable=1" in captured.out
    assert "exit_code: 2" in captured.out
    assert captured.err == ""


def test_verify_ci_uses_distinct_safe_tool_error_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, _ = _repository(tmp_path)

    def operational_failure(self: object) -> VerificationRun:
        raise ControlOperationError(ControlErrorCode.CONFIG_INVALID)

    monkeypatch.setattr(
        "stateguard.cli.main.StateGuardControl.verify",
        operational_failure,
    )
    assert main(["verify", str(repository), "--ci", "--json"]) == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["code"] == "CONFIG_INVALID"

    secret = "unexpected-secret-sentinel"

    def unexpected_failure(self: object) -> VerificationRun:
        raise RuntimeError(secret)

    monkeypatch.setattr(
        "stateguard.cli.main.StateGuardControl.verify",
        unexpected_failure,
    )
    assert main(["verify", str(repository), "--ci", "--json"]) == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["code"] == "INTERNAL_ERROR"
    assert secret not in captured.err


def test_malformed_ci_uses_exit_three_without_changing_non_ci_parser_errors(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["verify", "--ci", "--unknown", "--json"]) == 3
    ci_error = capsys.readouterr()
    assert ci_error.out == ""
    assert json.loads(ci_error.err)["code"] == "INVALID_REQUEST"

    assert main(["verify", "--unknown", "--json"]) == 2
    ordinary_error = capsys.readouterr()
    assert ordinary_error.out == ""
    assert json.loads(ordinary_error.err)["code"] == "INVALID_REQUEST"

    secret = "parser-secret-sentinel"
    assert main(["verify", "--ci", f"--unknown={secret}"]) == 3
    human_ci_error = capsys.readouterr()
    assert human_ci_error.out == ""
    assert "INVALID_REQUEST" in human_ci_error.err
    assert secret not in human_ci_error.err
