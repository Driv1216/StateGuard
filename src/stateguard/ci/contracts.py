"""Stable typed contract for one completed StateGuard CI-gate evaluation."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from stateguard.applicability.contracts import AssertionRole, ScenarioId
from stateguard.contracts.common import Sha256Digest, VerificationCheckKey, VerificationRunId
from stateguard.failure_lab.contracts import (
    ScenarioResultReasonCode,
    VerificationResultState,
)


class _CIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CIGateStatus(StrEnum):
    PASSED = "PASSED"
    VERIFIED_FAILURE = "VERIFIED_FAILURE"
    NOT_PROVEN = "NOT_PROVEN"


class CIGateReason(StrEnum):
    REQUIRED_CHECKS_PASSED = "REQUIRED_CHECKS_PASSED"
    NO_APPLICABLE_REQUIRED_CHECKS = "NO_APPLICABLE_REQUIRED_CHECKS"
    PROVEN_FAILURE = "PROVEN_FAILURE"
    REQUIRED_CHECKS_NOT_PROVEN = "REQUIRED_CHECKS_NOT_PROVEN"


class CIGateBlockerClass(StrEnum):
    PROVEN_FAILURE = "PROVEN_FAILURE"
    REQUIRED_NOT_PROVEN = "REQUIRED_NOT_PROVEN"


class VerificationResultCountsV1(_CIModel):
    schema_version: Literal[1] = 1
    verified_pass: int = Field(ge=0)
    verified_fail: int = Field(ge=0)
    static_warning: int = Field(ge=0)
    needs_input: int = Field(ge=0)
    unverified: int = Field(ge=0)
    not_applicable: int = Field(ge=0)

    def total(self) -> int:
        return (
            self.verified_pass
            + self.verified_fail
            + self.static_warning
            + self.needs_input
            + self.unverified
            + self.not_applicable
        )


class CIGateBlockingCheckV1(_CIModel):
    schema_version: Literal[1] = 1
    blocker_class: CIGateBlockerClass
    role: AssertionRole
    check_key: VerificationCheckKey
    scenario_id: ScenarioId
    assertion_key: str = Field(min_length=1, max_length=128)
    result: VerificationResultState
    reason: ScenarioResultReasonCode

    @model_validator(mode="after")
    def validate_blocker(self) -> CIGateBlockingCheckV1:
        if self.blocker_class == CIGateBlockerClass.PROVEN_FAILURE:
            if self.result != VerificationResultState.VERIFIED_FAIL:
                raise ValueError("proven-failure blockers must be VERIFIED FAIL")
        elif self.role != AssertionRole.CORE or self.result not in {
            VerificationResultState.STATIC_WARNING,
            VerificationResultState.NEEDS_INPUT,
            VerificationResultState.UNVERIFIED,
        }:
            raise ValueError("required-not-proven blockers must be unresolved core checks")
        return self


class CIGateResultV1(_CIModel):
    schema_version: Literal[1] = 1
    status: CIGateStatus
    reason: CIGateReason
    exit_code: Literal[0, 1, 2]
    run_id: VerificationRunId
    run_fingerprint: Sha256Digest
    all_check_counts: VerificationResultCountsV1
    core_check_counts: VerificationResultCountsV1
    proven_failure_count: int = Field(ge=0)
    core_not_proven_count: int = Field(ge=0)
    applicable_core_check_count: int = Field(ge=0)
    blocking_checks: tuple[CIGateBlockingCheckV1, ...] = ()

    @model_validator(mode="after")
    def validate_gate(self) -> CIGateResultV1:
        if self.core_check_counts.total() > self.all_check_counts.total():
            raise ValueError("core check counts cannot exceed all check counts")
        for field in (
            "verified_pass",
            "verified_fail",
            "static_warning",
            "needs_input",
            "unverified",
            "not_applicable",
        ):
            if getattr(self.core_check_counts, field) > getattr(self.all_check_counts, field):
                raise ValueError("core result-state counts cannot exceed all-check counts")
        if self.proven_failure_count != self.all_check_counts.verified_fail:
            raise ValueError("proven-failure count must include every verified failure")
        expected_not_proven = (
            self.core_check_counts.static_warning
            + self.core_check_counts.needs_input
            + self.core_check_counts.unverified
        )
        if self.core_not_proven_count != expected_not_proven:
            raise ValueError("core not-proven count must match unresolved core states")
        if self.applicable_core_check_count != (
            self.core_check_counts.total() - self.core_check_counts.not_applicable
        ):
            raise ValueError("applicable core count must exclude only NOT APPLICABLE checks")

        expected_order = tuple(
            sorted(
                self.blocking_checks,
                key=lambda item: (
                    item.scenario_id.value,
                    item.assertion_key,
                    item.check_key,
                ),
            )
        )
        if self.blocking_checks != expected_order:
            raise ValueError("CI blockers must be deterministically ordered")
        keys = tuple(item.check_key for item in self.blocking_checks)
        if len(keys) != len(set(keys)):
            raise ValueError("CI blockers must have unique logical check keys")
        if (
            sum(
                item.blocker_class == CIGateBlockerClass.PROVEN_FAILURE
                for item in self.blocking_checks
            )
            != self.proven_failure_count
        ):
            raise ValueError("every proven failure must be represented as a blocker")
        if (
            sum(
                item.blocker_class == CIGateBlockerClass.REQUIRED_NOT_PROVEN
                for item in self.blocking_checks
            )
            != self.core_not_proven_count
        ):
            raise ValueError("every unresolved core check must be represented as a blocker")

        expected_outcome: tuple[CIGateStatus, CIGateReason, int]
        if self.proven_failure_count:
            expected_outcome = (
                CIGateStatus.VERIFIED_FAILURE,
                CIGateReason.PROVEN_FAILURE,
                1,
            )
        elif self.core_not_proven_count:
            expected_outcome = (
                CIGateStatus.NOT_PROVEN,
                CIGateReason.REQUIRED_CHECKS_NOT_PROVEN,
                2,
            )
        elif self.applicable_core_check_count == 0:
            expected_outcome = (
                CIGateStatus.NOT_PROVEN,
                CIGateReason.NO_APPLICABLE_REQUIRED_CHECKS,
                2,
            )
        else:
            expected_outcome = (
                CIGateStatus.PASSED,
                CIGateReason.REQUIRED_CHECKS_PASSED,
                0,
            )
        if (self.status, self.reason, self.exit_code) != expected_outcome:
            raise ValueError("CI gate status, reason, and exit code are inconsistent")
        return self
