from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

from .models import BankTransaction, Candidate, MerchantLedgerRecord, SettlementGroup
from .normalize import FUZZY_REFERENCE_THRESHOLD, normalize_reference, normalize_text


@dataclass(frozen=True)
class ReferenceEvidence:
    level: str
    score: float


def compare_references(left: str, right: str) -> ReferenceEvidence:
    if not left or not right:
        return ReferenceEvidence("none", 0.0)
    if normalize_text(left) == normalize_text(right):
        return ReferenceEvidence("exact", 1.0)
    normalized_left = normalize_reference(left)
    normalized_right = normalize_reference(right)
    if normalized_left and normalized_left == normalized_right:
        return ReferenceEvidence("normalized", 1.0)
    score = SequenceMatcher(None, normalized_left, normalized_right).ratio()
    if score >= FUZZY_REFERENCE_THRESHOLD:
        return ReferenceEvidence("fuzzy", score)
    return ReferenceEvidence("none", score)


def _best_settlement_edge(ledger: MerchantLedgerRecord, settlement: SettlementGroup) -> ReferenceEvidence:
    edges = [compare_references(ledger.reference, reference) for reference in settlement.references]
    return max(edges, key=lambda edge: edge.score, default=ReferenceEvidence("none", 0.0))


def _best_bank_edge(ledger: MerchantLedgerRecord, bank: BankTransaction) -> ReferenceEvidence:
    return compare_references(ledger.reference, bank.reference)


def _settlement_bank_edge(settlement: SettlementGroup, bank: BankTransaction) -> ReferenceEvidence:
    edges = [compare_references(reference, bank.reference) for reference in settlement.references]
    return max(edges, key=lambda edge: edge.score, default=ReferenceEvidence("none", 0.0))


def generate_baseline_candidates(
    ledger_records: list[MerchantLedgerRecord],
    settlements: dict[str, SettlementGroup],
    bank_transactions: list[BankTransaction],
) -> dict[str, list[Candidate]]:
    results: dict[str, list[Candidate]] = {record.ledger_id: [] for record in ledger_records}
    for ledger in ledger_records:
        for settlement in settlements.values():
            ledger_settlement = _best_settlement_edge(ledger, settlement)
            if ledger_settlement.level == "none":
                continue
            for bank in bank_transactions:
                ledger_bank = _best_bank_edge(ledger, bank)
                settlement_bank = _settlement_bank_edge(settlement, bank)
                edges = (ledger_settlement, ledger_bank, settlement_bank)
                if sum(edge.level != "none" for edge in edges) < 2:
                    continue
                levels = {edge.level for edge in edges if edge.level != "none"}
                source = "deterministic_" + (
                    "exact" if levels == {"exact"} else "normalized" if "fuzzy" not in levels else "fuzzy"
                )
                results[ledger.ledger_id].append(
                    Candidate(
                        ledger_id=ledger.ledger_id,
                        settlement_id=settlement.settlement_id,
                        bank_id=bank.bank_id,
                        source=source,
                    )
                )
    return results

