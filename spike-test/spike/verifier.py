from __future__ import annotations

from collections.abc import Iterable
from decimal import Decimal

from .baseline_matcher import compare_references
from .models import (
    BankTransaction,
    Candidate,
    CandidateEvidence,
    CheckResult,
    ComponentType,
    Decision,
    DecisionStatus,
    Direction,
    MerchantLedgerRecord,
    SettlementGroup,
)
from .normalize import BANK_DATE_WINDOW_DAYS, DATE_WINDOW_DAYS, date_distance


HARD_CONTRADICTION_CHECKS = {
    "recon_structure",
    "recon_currency_consistency",
    "ledger_recon_amount",
    "recon_bank_amount",
    "ledger_recon_currency",
    "recon_bank_currency",
    "bank_direction",
}


def _reference_edges(
    ledger: MerchantLedgerRecord,
    settlement: SettlementGroup,
    bank: BankTransaction,
) -> list:
    settlement_references = settlement.references or ("",)
    ledger_settlement = max(
        (compare_references(ledger.reference, reference) for reference in settlement_references),
        key=lambda result: result.score,
    )
    settlement_bank = max(
        (compare_references(reference, bank.reference) for reference in settlement_references),
        key=lambda result: result.score,
    )
    ledger_bank = compare_references(ledger.reference, bank.reference)
    return [ledger_settlement, ledger_bank, settlement_bank]


def _strong_source_link(
    ledger: MerchantLedgerRecord,
    settlement: SettlementGroup,
    bank: BankTransaction,
) -> tuple[bool, str]:
    edges = _reference_edges(ledger, settlement, bank)
    strong_edges = [edge for edge in edges if edge.level in {"exact", "normalized"}]
    detail = ", ".join(edge.level for edge in edges)
    return len(strong_edges) >= 2, f"reference edges: {detail}"


def _structure_ok(settlement: SettlementGroup) -> bool:
    types = {component.component_type for component in settlement.components}
    amounts_nonnegative = all(component.amount >= Decimal("0") for component in settlement.components)
    return (
        bool(settlement.components)
        and ComponentType.CREDIT in types
        and ComponentType.DEBIT in types
        and amounts_nonnegative
        and settlement.reconstructed_amount > Decimal("0")
    )


def _hard_pair_compatible(
    ledger: MerchantLedgerRecord,
    settlement: SettlementGroup,
    bank: BankTransaction,
) -> bool:
    return all(
        (
            _structure_ok(settlement),
            len(settlement.currencies) == 1,
            settlement.reconstructed_amount == ledger.amount,
            bank.amount == settlement.reconstructed_amount,
            settlement.currencies == {ledger.currency},
            bank.currency == ledger.currency,
            ledger.direction == Direction.CREDIT and bank.direction == Direction.CREDIT,
            date_distance(ledger.booked_on, settlement.settled_on) <= DATE_WINDOW_DAYS,
            date_distance(settlement.settled_on, bank.posted_on) <= BANK_DATE_WINDOW_DAYS,
        )
    )


def _financial_pair_count(
    ledger: MerchantLedgerRecord,
    settlements: dict[str, SettlementGroup],
    banks: dict[str, BankTransaction],
) -> int:
    return sum(
        _hard_pair_compatible(ledger, settlement, bank)
        for settlement in settlements.values()
        for bank in banks.values()
    )


def evaluate_candidate(
    ledger: MerchantLedgerRecord,
    candidate: Candidate,
    settlements: dict[str, SettlementGroup],
    banks: dict[str, BankTransaction],
    financial_pair_count: int,
) -> CandidateEvidence:
    settlement = settlements[candidate.settlement_id]
    bank = banks[candidate.bank_id]
    strong_link, link_detail = _strong_source_link(ledger, settlement, bank)

    checks = [
        CheckResult(
            "recon_structure",
            _structure_ok(settlement),
            "hard",
            "settlement has credit/debit components, non-negative components, and positive net",
        ),
        CheckResult(
            "recon_currency_consistency",
            len(settlement.currencies) == 1,
            "hard",
            f"component currencies={sorted(settlement.currencies)}",
        ),
        CheckResult(
            "ledger_recon_amount",
            ledger.amount == settlement.reconstructed_amount,
            "hard",
            f"ledger={ledger.amount}; reconstructed={settlement.reconstructed_amount}",
        ),
        CheckResult(
            "recon_bank_amount",
            settlement.reconstructed_amount == bank.amount,
            "hard",
            f"reconstructed={settlement.reconstructed_amount}; bank={bank.amount}",
        ),
        CheckResult(
            "ledger_recon_currency",
            settlement.currencies == {ledger.currency},
            "hard",
            f"ledger={ledger.currency}; components={sorted(settlement.currencies)}",
        ),
        CheckResult(
            "recon_bank_currency",
            len(settlement.currencies) == 1 and bank.currency in settlement.currencies,
            "hard",
            f"components={sorted(settlement.currencies)}; bank={bank.currency}",
        ),
        CheckResult(
            "bank_direction",
            ledger.direction == Direction.CREDIT and bank.direction == Direction.CREDIT,
            "hard",
            f"ledger={ledger.direction.value}; bank={bank.direction.value}",
        ),
        CheckResult(
            "ledger_settlement_date",
            date_distance(ledger.booked_on, settlement.settled_on) <= DATE_WINDOW_DAYS,
            "hard",
            f"distance_days={date_distance(ledger.booked_on, settlement.settled_on)}; max={DATE_WINDOW_DAYS}",
        ),
        CheckResult(
            "settlement_bank_date",
            date_distance(settlement.settled_on, bank.posted_on) <= BANK_DATE_WINDOW_DAYS,
            "hard",
            f"distance_days={date_distance(settlement.settled_on, bank.posted_on)}; max={BANK_DATE_WINDOW_DAYS}",
        ),
        CheckResult("reference_evidence", strong_link, "support", link_detail),
        CheckResult(
            "financial_uniqueness",
            financial_pair_count == 1,
            "support",
            f"hard-compatible settlement/bank pairs={financial_pair_count}",
        ),
    ]
    hard_pass = all(check.passed for check in checks if check.kind == "hard")
    sufficient = hard_pass and (strong_link or financial_pair_count == 1)
    if not hard_pass:
        failed = [check.name for check in checks if check.kind == "hard" and not check.passed]
        reason = "candidate rejected: " + ", ".join(failed)
    elif not sufficient:
        reason = "candidate is financially viable but lacks independent identifying evidence"
    else:
        reason = "all hard invariants and independent deterministic evidence passed"
    return CandidateEvidence(
        candidate=candidate,
        checks=checks,
        viable=hard_pass,
        sufficient=sufficient,
        strong_source_link=strong_link,
        reason=reason,
    )


def verify_case(
    ledger: MerchantLedgerRecord,
    candidates: Iterable[Candidate],
    settlements: dict[str, SettlementGroup],
    banks: dict[str, BankTransaction],
) -> Decision:
    pair_count = _financial_pair_count(ledger, settlements, banks)
    evidence = [
        evaluate_candidate(ledger, candidate, settlements, banks, pair_count)
        for candidate in candidates
    ]
    sufficient_by_identity = {
        item.candidate.identity: item for item in evidence if item.sufficient
    }
    if len(sufficient_by_identity) == 1:
        selected = next(iter(sufficient_by_identity.values())).candidate
        return Decision(
            ledger_id=ledger.ledger_id,
            status=DecisionStatus.VERIFIED,
            selected_candidate=selected,
            reason="exactly one candidate passed deterministic verification",
            candidate_evidence=evidence,
        )
    if len(sufficient_by_identity) > 1:
        return Decision(
            ledger_id=ledger.ledger_id,
            status=DecisionStatus.REVIEW,
            selected_candidate=None,
            reason="multiple candidates passed deterministic verification",
            candidate_evidence=evidence,
        )

    linked_contradictions = []
    for item in evidence:
        if not item.strong_source_link:
            continue
        failed = {
            check.name for check in item.checks if check.kind == "hard" and not check.passed
        }
        if failed & HARD_CONTRADICTION_CHECKS:
            linked_contradictions.append(item)
    if linked_contradictions and not any(item.viable for item in evidence):
        return Decision(
            ledger_id=ledger.ledger_id,
            status=DecisionStatus.EXCEPTION,
            selected_candidate=None,
            reason="strongly linked source records contain an unresolved financial or structural contradiction",
            candidate_evidence=evidence,
        )
    return Decision(
        ledger_id=ledger.ledger_id,
        status=DecisionStatus.REVIEW,
        selected_candidate=None,
        reason=(
            "no candidate had sufficient deterministic evidence"
            if evidence
            else "no candidate was discovered"
        ),
        candidate_evidence=evidence,
    )


def verify_all(
    ledger_records: list[MerchantLedgerRecord],
    candidates_by_ledger: dict[str, list[Candidate]],
    settlements: dict[str, SettlementGroup],
    bank_transactions: list[BankTransaction],
) -> dict[str, Decision]:
    banks = {bank.bank_id: bank for bank in bank_transactions}
    return {
        ledger.ledger_id: verify_case(
            ledger,
            candidates_by_ledger.get(ledger.ledger_id, []),
            settlements,
            banks,
        )
        for ledger in ledger_records
    }
