"""Exact logical-key comparison of historical and freshly verified checks."""

from __future__ import annotations

from stateguard.evidence.contracts import VerificationCheck, VerificationRun
from stateguard.failure_lab.contracts import VerificationResultState

from .contracts import ComparisonOutcome, FindingComparison


def compare_exact_check(
    historical_run: VerificationRun,
    historical_check: VerificationCheck,
    current_run: VerificationRun,
) -> FindingComparison:
    """Correlate only exact VerificationCheckKey identity; never infer similarity."""

    matches = tuple(
        item for item in current_run.checks if item.check_key == historical_check.check_key
    )
    if len(matches) != 1:
        return FindingComparison(
            historical_run_id=historical_run.run_id,
            current_run_id=current_run.run_id,
            check_key=historical_check.check_key,
            outcome=ComparisonOutcome.NOT_DIRECTLY_COMPARABLE,
        )
    current = matches[0]
    outcome = {
        VerificationResultState.VERIFIED_PASS: ComparisonOutcome.PROVEN_RESOLVED,
        VerificationResultState.VERIFIED_FAIL: ComparisonOutcome.STILL_VERIFIED_FAIL,
        VerificationResultState.NOT_APPLICABLE: ComparisonOutcome.NOT_APPLICABLE,
        VerificationResultState.UNVERIFIED: ComparisonOutcome.NOT_PROVEN,
        VerificationResultState.NEEDS_INPUT: ComparisonOutcome.NOT_PROVEN,
        VerificationResultState.STATIC_WARNING: ComparisonOutcome.NOT_PROVEN,
    }[current.result]
    return FindingComparison(
        historical_run_id=historical_run.run_id,
        current_run_id=current_run.run_id,
        check_key=historical_check.check_key,
        outcome=outcome,
        current_check_id=current.check_id,
    )
