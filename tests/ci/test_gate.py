from __future__ import annotations

import pytest

from stateguard.applicability.contracts import AssertionRole, ScenarioId
from stateguard.ci import CIGateBlockerClass, CIGateReason, CIGateStatus, evaluate_ci_gate
from stateguard.evidence.contracts import (
    ApplicabilityEvidenceSnapshot,
    VerificationCheck,
    VerificationRun,
)
from stateguard.failure_lab.contracts import (
    ScenarioResultReasonCode,
    VerificationResultState,
)

RUN_ID = "sgvrun_" + "1" * 32
RUN_FINGERPRINT = "sha256:" + "2" * 64


def _reason(state: VerificationResultState) -> ScenarioResultReasonCode:
    return {
        VerificationResultState.VERIFIED_PASS: (ScenarioResultReasonCode.EXACT_TARGET_ENTERED_ONCE),
        VerificationResultState.VERIFIED_FAIL: (
            ScenarioResultReasonCode.MERCHANT_STATE_REGRESSED_TO_AUTHORIZED
        ),
        VerificationResultState.STATIC_WARNING: (
            ScenarioResultReasonCode.APPLICABILITY_INDETERMINATE
        ),
        VerificationResultState.NEEDS_INPUT: (ScenarioResultReasonCode.APPLICABILITY_NEEDS_INPUT),
        VerificationResultState.UNVERIFIED: (
            ScenarioResultReasonCode.RUNTIME_CAPABILITY_INSUFFICIENT
        ),
        VerificationResultState.NOT_APPLICABLE: (
            ScenarioResultReasonCode.APPLICABILITY_NOT_APPLICABLE
        ),
    }[state]


def _check(
    ordinal: int,
    role: AssertionRole,
    result: VerificationResultState,
    *,
    scenario_id: ScenarioId = ScenarioId.SG_04,
) -> VerificationCheck:
    return VerificationCheck.model_construct(
        check_key=f"sgcheckkey_{ordinal:032x}",
        scenario_id=scenario_id,
        assertion_key=f"ASSERTION_{ordinal}",
        applicability=ApplicabilityEvidenceSnapshot.model_construct(role=role),
        result=result,
        reason=_reason(result),
    )


def _run(*checks: VerificationCheck) -> VerificationRun:
    return VerificationRun.model_construct(
        run_id=RUN_ID,
        run_fingerprint=RUN_FINGERPRINT,
        checks=checks,
    )


@pytest.mark.parametrize(
    ("state", "expected_status", "expected_exit"),
    [
        (VerificationResultState.VERIFIED_PASS, CIGateStatus.PASSED, 0),
        (VerificationResultState.VERIFIED_FAIL, CIGateStatus.VERIFIED_FAILURE, 1),
        (VerificationResultState.STATIC_WARNING, CIGateStatus.NOT_PROVEN, 2),
        (VerificationResultState.NEEDS_INPUT, CIGateStatus.NOT_PROVEN, 2),
        (VerificationResultState.UNVERIFIED, CIGateStatus.NOT_PROVEN, 2),
    ],
)
def test_core_result_matrix(
    state: VerificationResultState,
    expected_status: CIGateStatus,
    expected_exit: int,
) -> None:
    gate = evaluate_ci_gate(_run(_check(1, AssertionRole.CORE, state)))

    assert gate.status == expected_status
    assert gate.exit_code == expected_exit


def test_optional_failure_blocks_but_optional_not_proven_states_do_not() -> None:
    optional_states = (
        VerificationResultState.STATIC_WARNING,
        VerificationResultState.NEEDS_INPUT,
        VerificationResultState.UNVERIFIED,
        VerificationResultState.NOT_APPLICABLE,
    )
    passing = evaluate_ci_gate(
        _run(
            _check(1, AssertionRole.CORE, VerificationResultState.VERIFIED_PASS),
            *(
                _check(ordinal, AssertionRole.OPTIONAL, state)
                for ordinal, state in enumerate(optional_states, start=2)
            ),
        )
    )
    assert passing.status == CIGateStatus.PASSED
    assert passing.exit_code == 0
    assert passing.blocking_checks == ()

    failed = evaluate_ci_gate(
        _run(
            _check(1, AssertionRole.CORE, VerificationResultState.VERIFIED_PASS),
            _check(2, AssertionRole.OPTIONAL, VerificationResultState.VERIFIED_FAIL),
        )
    )
    assert failed.status == CIGateStatus.VERIFIED_FAILURE
    assert failed.exit_code == 1
    assert failed.proven_failure_count == 1
    assert failed.blocking_checks[0].role == AssertionRole.OPTIONAL
    assert failed.blocking_checks[0].blocker_class == CIGateBlockerClass.PROVEN_FAILURE


def test_no_applicable_core_checks_is_not_proven_without_relabeling() -> None:
    gate = evaluate_ci_gate(
        _run(
            _check(1, AssertionRole.CORE, VerificationResultState.NOT_APPLICABLE),
            _check(2, AssertionRole.OPTIONAL, VerificationResultState.VERIFIED_PASS),
        )
    )

    assert gate.status == CIGateStatus.NOT_PROVEN
    assert gate.reason == CIGateReason.NO_APPLICABLE_REQUIRED_CHECKS
    assert gate.exit_code == 2
    assert gate.applicable_core_check_count == 0
    assert gate.core_check_counts.not_applicable == 1
    assert gate.core_check_counts.verified_pass == 0


def test_not_applicable_core_is_exempt_when_another_core_check_passes() -> None:
    gate = evaluate_ci_gate(
        _run(
            _check(1, AssertionRole.CORE, VerificationResultState.NOT_APPLICABLE),
            _check(2, AssertionRole.CORE, VerificationResultState.VERIFIED_PASS),
        )
    )

    assert gate.status == CIGateStatus.PASSED
    assert gate.exit_code == 0
    assert gate.applicable_core_check_count == 1


def test_failure_precedence_retains_core_not_proven_and_orders_blockers() -> None:
    checks = (
        _check(
            3,
            AssertionRole.CORE,
            VerificationResultState.UNVERIFIED,
            scenario_id=ScenarioId.SG_04,
        ),
        _check(
            2,
            AssertionRole.OPTIONAL,
            VerificationResultState.VERIFIED_FAIL,
            scenario_id=ScenarioId.SG_04,
        ),
        _check(
            1,
            AssertionRole.CORE,
            VerificationResultState.VERIFIED_FAIL,
            scenario_id=ScenarioId.SG_02,
        ),
    )
    before = tuple((item.check_key, item.result, item.applicability.role) for item in checks)

    gate = evaluate_ci_gate(_run(*checks))

    assert gate.status == CIGateStatus.VERIFIED_FAILURE
    assert gate.reason == CIGateReason.PROVEN_FAILURE
    assert gate.exit_code == 1
    assert gate.proven_failure_count == 2
    assert gate.core_not_proven_count == 1
    assert tuple(item.check_key for item in gate.blocking_checks) == (
        "sgcheckkey_00000000000000000000000000000001",
        "sgcheckkey_00000000000000000000000000000002",
        "sgcheckkey_00000000000000000000000000000003",
    )
    assert before == tuple(
        (item.check_key, item.result, item.applicability.role) for item in checks
    )


def test_gate_json_is_bounded_to_allowlisted_factual_fields() -> None:
    gate = evaluate_ci_gate(
        _run(_check(1, AssertionRole.CORE, VerificationResultState.VERIFIED_PASS))
    )
    payload = gate.model_dump_json()

    assert RUN_ID in payload
    assert RUN_FINGERPRINT in payload
    for forbidden in (
        "source_references",
        "runtime_evidence",
        "raw_body",
        "signature",
        "exception",
        "/Users/",
    ):
        assert forbidden not in payload
