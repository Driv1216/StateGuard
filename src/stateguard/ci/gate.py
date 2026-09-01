"""Pure deterministic evaluation of a completed immutable verification run."""

from __future__ import annotations

from collections.abc import Iterable

from stateguard.applicability.contracts import AssertionRole
from stateguard.evidence.contracts import VerificationCheck, VerificationRun
from stateguard.failure_lab.contracts import VerificationResultState

from .contracts import (
    CIGateBlockerClass,
    CIGateBlockingCheckV1,
    CIGateReason,
    CIGateResultV1,
    CIGateStatus,
    VerificationResultCountsV1,
)

_NOT_PROVEN_STATES = {
    VerificationResultState.STATIC_WARNING,
    VerificationResultState.NEEDS_INPUT,
    VerificationResultState.UNVERIFIED,
}


def _result_counts(checks: Iterable[VerificationCheck]) -> VerificationResultCountsV1:
    counts = {state: 0 for state in VerificationResultState}
    for check in checks:
        counts[check.result] += 1
    return VerificationResultCountsV1(
        verified_pass=counts[VerificationResultState.VERIFIED_PASS],
        verified_fail=counts[VerificationResultState.VERIFIED_FAIL],
        static_warning=counts[VerificationResultState.STATIC_WARNING],
        needs_input=counts[VerificationResultState.NEEDS_INPUT],
        unverified=counts[VerificationResultState.UNVERIFIED],
        not_applicable=counts[VerificationResultState.NOT_APPLICABLE],
    )


def _blocker(check: VerificationCheck) -> CIGateBlockingCheckV1:
    blocker_class = (
        CIGateBlockerClass.PROVEN_FAILURE
        if check.result == VerificationResultState.VERIFIED_FAIL
        else CIGateBlockerClass.REQUIRED_NOT_PROVEN
    )
    return CIGateBlockingCheckV1(
        blocker_class=blocker_class,
        role=check.applicability.role,
        check_key=check.check_key,
        scenario_id=check.scenario_id,
        assertion_key=check.assertion_key,
        result=check.result,
        reason=check.reason,
    )


def evaluate_ci_gate(run: VerificationRun) -> CIGateResultV1:
    """Project existing check truth into release semantics without changing the run."""

    core_checks = tuple(
        check for check in run.checks if check.applicability.role == AssertionRole.CORE
    )
    proven_failures = tuple(
        check for check in run.checks if check.result == VerificationResultState.VERIFIED_FAIL
    )
    core_not_proven = tuple(check for check in core_checks if check.result in _NOT_PROVEN_STATES)
    blockers = tuple(
        sorted(
            (_blocker(check) for check in (*proven_failures, *core_not_proven)),
            key=lambda item: (
                item.scenario_id.value,
                item.assertion_key,
                item.check_key,
            ),
        )
    )
    core_counts = _result_counts(core_checks)
    applicable_core_count = core_counts.total() - core_counts.not_applicable

    if proven_failures:
        status = CIGateStatus.VERIFIED_FAILURE
        reason = CIGateReason.PROVEN_FAILURE
        exit_code = 1
    elif core_not_proven:
        status = CIGateStatus.NOT_PROVEN
        reason = CIGateReason.REQUIRED_CHECKS_NOT_PROVEN
        exit_code = 2
    elif applicable_core_count == 0:
        status = CIGateStatus.NOT_PROVEN
        reason = CIGateReason.NO_APPLICABLE_REQUIRED_CHECKS
        exit_code = 2
    else:
        status = CIGateStatus.PASSED
        reason = CIGateReason.REQUIRED_CHECKS_PASSED
        exit_code = 0

    return CIGateResultV1(
        status=status,
        reason=reason,
        exit_code=exit_code,
        run_id=run.run_id,
        run_fingerprint=run.run_fingerprint,
        all_check_counts=_result_counts(run.checks),
        core_check_counts=core_counts,
        proven_failure_count=len(proven_failures),
        core_not_proven_count=len(core_not_proven),
        applicable_core_check_count=applicable_core_count,
        blocking_checks=blockers,
    )
