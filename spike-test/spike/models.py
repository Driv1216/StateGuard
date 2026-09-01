from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date
from decimal import Decimal
from enum import Enum
from typing import Any


class Direction(str, Enum):
    CREDIT = "CREDIT"
    DEBIT = "DEBIT"


class ComponentType(str, Enum):
    CREDIT = "CREDIT"
    DEBIT = "DEBIT"


class DecisionStatus(str, Enum):
    VERIFIED = "VERIFIED"
    REVIEW = "REVIEW"
    EXCEPTION = "EXCEPTION"


@dataclass(frozen=True)
class MerchantLedgerRecord:
    ledger_id: str
    booked_on: date
    amount: Decimal
    currency: str
    direction: Direction
    reference: str
    description: str


@dataclass(frozen=True)
class ReconComponent:
    component_id: str
    settlement_id: str
    settled_on: date
    component_type: ComponentType
    amount: Decimal
    currency: str
    reference: str
    description: str


@dataclass(frozen=True)
class BankTransaction:
    bank_id: str
    posted_on: date
    amount: Decimal
    currency: str
    direction: Direction
    reference: str
    description: str


@dataclass(frozen=True)
class SettlementGroup:
    settlement_id: str
    components: tuple[ReconComponent, ...]

    @property
    def settled_on(self) -> date:
        return min(component.settled_on for component in self.components)

    @property
    def references(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(c.reference for c in self.components if c.reference))

    @property
    def description(self) -> str:
        return " ".join(dict.fromkeys(c.description for c in self.components if c.description))

    @property
    def currencies(self) -> set[str]:
        return {component.currency for component in self.components}

    @property
    def reconstructed_amount(self) -> Decimal:
        credits = sum(
            (c.amount for c in self.components if c.component_type == ComponentType.CREDIT),
            Decimal("0"),
        )
        debits = sum(
            (c.amount for c in self.components if c.component_type == ComponentType.DEBIT),
            Decimal("0"),
        )
        return credits - debits


@dataclass(frozen=True)
class Candidate:
    ledger_id: str
    settlement_id: str
    bank_id: str
    source: str
    semantic_score: float | None = None

    @property
    def identity(self) -> tuple[str, str]:
        return (self.settlement_id, self.bank_id)


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    kind: str
    detail: str


@dataclass
class CandidateEvidence:
    candidate: Candidate
    checks: list[CheckResult]
    viable: bool
    sufficient: bool
    strong_source_link: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate": asdict(self.candidate),
            "checks": [asdict(check) for check in self.checks],
            "viable": self.viable,
            "sufficient": self.sufficient,
            "strong_source_link": self.strong_source_link,
            "reason": self.reason,
        }


@dataclass
class Decision:
    ledger_id: str
    status: DecisionStatus
    selected_candidate: Candidate | None
    reason: str
    candidate_evidence: list[CandidateEvidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ledger_id": self.ledger_id,
            "status": self.status.value,
            "selected_candidate": (
                asdict(self.selected_candidate) if self.selected_candidate else None
            ),
            "reason": self.reason,
            "candidate_evidence": [evidence.to_dict() for evidence in self.candidate_evidence],
        }


def group_settlements(components: list[ReconComponent]) -> dict[str, SettlementGroup]:
    grouped: dict[str, list[ReconComponent]] = {}
    for component in components:
        grouped.setdefault(component.settlement_id, []).append(component)
    return {
        settlement_id: SettlementGroup(settlement_id, tuple(rows))
        for settlement_id, rows in grouped.items()
    }

