from __future__ import annotations

import asyncio
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from stateguard.applicability.contracts import ScenarioId
from stateguard.application.applicability import confirm_merchant_policy, inspect_applicability
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.application.verification import create_verification_run
from stateguard.contracts.config import FulfilmentPolicy, LateAuthorisationPolicy
from stateguard.contracts.identity import new_project_id
from stateguard.evidence.contracts import Finding, FindingKind
from stateguard.failure_lab.contracts import EvidenceTier, VerificationResultState
from stateguard.remediation.context_builder import (
    RemediationNotEligibleError,
    _select_verified_failure,
    build_remediation_context,
    rebuild_current_finding_authority,
    relevant_authority_blockers,
)
from stateguard.remediation.contracts import AssistanceMode
from stateguard.workspace.config import load_config

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos" / "failure_lab_batch_a"
)
NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def _run(tmp_path: Path):
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
  mode: static
""",
        encoding="utf-8",
    )
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
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        late_authorisation=LateAuthorisationPolicy.FULFIL_LATER,
        generated_at=NOW,
    )
    run = create_verification_run(repository, config, created_at=NOW).artifact
    check = next(item for item in run.checks if item.source_references)
    assert check.relevant_authority is not None
    return repository, config, run, check


def _eligible_run(run, check):
    failed = check.model_copy(
        update={
            "result": VerificationResultState.VERIFIED_FAIL,
            "evidence_tier": EvidenceTier.E3_DYNAMIC_VERIFIED,
        }
    )
    finding = Finding.model_construct(
        occurrence_id="sgfinding_" + "a" * 32,
        finding_key="sgfindingkey_" + "b" * 32,
        check_id=failed.check_id,
        check_key=failed.check_key,
        kind=FindingKind.VERIFIED_FAILURE,
        critical=True,
    )
    return run.model_copy(update={"checks": (failed,), "findings": (finding,)}), finding


def test_unrelated_file_drift_does_not_block_current_relevant_authority(tmp_path: Path) -> None:
    repository, config_path, run, check = _run(tmp_path)
    (repository / "unrelated.py").write_text("def unrelated():\n    return 1\n", encoding="utf-8")
    current = inspect_applicability(repository, config_path, generated_at=NOW)
    rebuilt = rebuild_current_finding_authority(
        repository,
        load_config(config_path),
        check,
        current,
    )
    assert current.snapshot.source_index.project_source_fingerprint != (
        run.authority.project_source_fingerprint
    )
    assert relevant_authority_blockers(check.relevant_authority, rebuilt) == ()


def test_relevant_symbol_content_drift_blocks_v2_authority(tmp_path: Path) -> None:
    repository, config_path, _, check = _run(tmp_path)
    target = check.source_references[0].source_location.path
    path = repository / target
    original = path.read_text(encoding="utf-8")
    path.write_text(original.replace("return", "return  # relevant drift", 1), encoding="utf-8")
    current = inspect_applicability(repository, config_path, generated_at=NOW)
    with pytest.raises(ValueError, match="exact current applicability assertion"):
        rebuild_current_finding_authority(
            repository,
            load_config(config_path),
            check,
            current,
        )


def test_context_separates_current_source_from_historical_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, config_path, run, check = _run(tmp_path)
    eligible, finding = _eligible_run(run, check)
    monkeypatch.setattr(
        "stateguard.remediation.context_builder.load_verification_run",
        lambda repository_root, run_id: eligible,
    )
    current = build_remediation_context(
        repository, config_path, eligible.run_id, finding.occurrence_id
    )
    assert current.mode == AssistanceMode.CURRENT_SOURCE_REMEDIATION
    assert current.editable_regions
    assert "merchant_source" in current.provider_input

    target = check.source_references[0].source_location.path
    path = repository / target
    path.write_text(
        path.read_text(encoding="utf-8").replace("return", "return  # drift", 1),
        encoding="utf-8",
    )
    historical = build_remediation_context(
        repository, config_path, eligible.run_id, finding.occurrence_id
    )
    assert historical.mode == AssistanceMode.HISTORICAL_EXPLANATION_ONLY
    assert historical.editable_regions == ()
    assert "merchant_source" not in historical.provider_input


@pytest.mark.parametrize("schema_version", [2, 3])
def test_current_schema_sg02_verified_fail_is_eligible_with_current_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    schema_version: int,
) -> None:
    repository, config_path, run, _ = _run(tmp_path)
    check = next(item for item in run.checks if item.scenario_id == ScenarioId.SG_02)
    eligible, finding = _eligible_run(run, check)
    eligible = eligible.model_copy(update={"schema_version": schema_version})
    assert eligible.schema_version == schema_version
    assert eligible.checks[0].scenario_id == ScenarioId.SG_02
    assert eligible.checks[0].check_key == check.check_key
    monkeypatch.setattr(
        "stateguard.remediation.context_builder.load_verification_run",
        lambda repository_root, run_id: eligible,
    )

    context = build_remediation_context(
        repository, config_path, eligible.run_id, finding.occurrence_id
    )

    assert context.mode == AssistanceMode.CURRENT_SOURCE_REMEDIATION
    assert context.check.check_key == check.check_key
    assert context.current_relevant_fingerprint == context.historical_relevant_fingerprint


@pytest.mark.parametrize(
    "state",
    [
        VerificationResultState.VERIFIED_PASS,
        VerificationResultState.STATIC_WARNING,
        VerificationResultState.NEEDS_INPUT,
        VerificationResultState.UNVERIFIED,
        VerificationResultState.NOT_APPLICABLE,
    ],
)
def test_non_verified_fail_check_results_remain_ineligible(
    tmp_path: Path,
    state: VerificationResultState,
) -> None:
    _, _, run, check = _run(tmp_path)
    ineligible_check = check.model_copy(
        update={
            "result": state,
            "evidence_tier": (
                EvidenceTier.E3_DYNAMIC_VERIFIED
                if state == VerificationResultState.VERIFIED_PASS
                else None
            ),
        }
    )
    finding = Finding.model_construct(
        occurrence_id="sgfinding_" + "c" * 32,
        finding_key="sgfindingkey_" + "d" * 32,
        check_id=ineligible_check.check_id,
        check_key=ineligible_check.check_key,
        kind=FindingKind.VERIFIED_FAILURE,
        critical=True,
    )
    ineligible = run.model_copy(update={"checks": (ineligible_check,), "findings": (finding,)})

    with pytest.raises(
        RemediationNotEligibleError,
        match="only critical VERIFIED FAIL findings are eligible",
    ):
        _select_verified_failure(ineligible, finding.occurrence_id)


def test_noncritical_finding_remains_ineligible(tmp_path: Path) -> None:
    _, _, run, check = _run(tmp_path)
    eligible, finding = _eligible_run(run, check)
    noncritical = finding.model_copy(update={"kind": FindingKind.STATIC_WARNING, "critical": False})
    ineligible = eligible.model_copy(update={"findings": (noncritical,)})

    with pytest.raises(
        RemediationNotEligibleError,
        match="only critical VERIFIED FAIL findings are eligible",
    ):
        _select_verified_failure(ineligible, noncritical.occurrence_id)


def test_legacy_run_uses_whole_authority_only_as_conservative_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, config_path, run, check = _run(tmp_path)
    eligible, finding = _eligible_run(run, check)
    legacy_check = eligible.checks[0].model_copy(update={"relevant_authority": None})
    legacy = eligible.model_copy(update={"schema_version": 1, "checks": (legacy_check,)})
    monkeypatch.setattr(
        "stateguard.remediation.context_builder.load_verification_run",
        lambda repository_root, run_id: legacy,
    )
    unchanged = build_remediation_context(
        repository, config_path, legacy.run_id, finding.occurrence_id
    )
    assert unchanged.mode == AssistanceMode.CURRENT_SOURCE_REMEDIATION

    (repository / "unrelated.py").write_text("value = 1\n", encoding="utf-8")
    drifted = build_remediation_context(
        repository, config_path, legacy.run_id, finding.occurrence_id
    )
    assert drifted.mode == AssistanceMode.HISTORICAL_EXPLANATION_ONLY
    assert any(item.dimension == "LEGACY_WHOLE_AUTHORITY_DRIFT" for item in drifted.drift)
