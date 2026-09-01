from __future__ import annotations

import unittest
from datetime import date, timedelta
from decimal import Decimal

from spike.models import (
    BankTransaction,
    Candidate,
    ComponentType,
    DecisionStatus,
    Direction,
    MerchantLedgerRecord,
    ReconComponent,
    SettlementGroup,
)
from spike.verifier import verify_case


class VerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.day = date(2026, 1, 1)
        self.ledger = MerchantLedgerRecord(
            "LED", self.day, Decimal("100.00"), "INR", Direction.CREDIT, "UTR-ONE", "payout"
        )

    def settlement(
        self,
        settlement_id: str = "SET",
        reference: str = "UTR-ONE",
        net: Decimal = Decimal("100.00"),
        fee_currency: str = "INR",
    ) -> SettlementGroup:
        return SettlementGroup(
            settlement_id,
            (
                ReconComponent("C", settlement_id, self.day + timedelta(days=1), ComponentType.CREDIT, net + Decimal("10"), "INR", reference, "payout"),
                ReconComponent("F", settlement_id, self.day + timedelta(days=1), ComponentType.DEBIT, Decimal("10"), fee_currency, reference, "fee"),
            ),
        )

    def bank(
        self,
        bank_id: str = "BNK",
        reference: str = "UTR-ONE",
        amount: Decimal = Decimal("100.00"),
    ) -> BankTransaction:
        return BankTransaction(
            bank_id,
            self.day + timedelta(days=2),
            amount,
            "INR",
            Direction.CREDIT,
            reference,
            "payout",
        )

    def candidate(self, settlement_id: str = "SET", bank_id: str = "BNK", source: str = "deterministic_exact") -> Candidate:
        return Candidate("LED", settlement_id, bank_id, source, 0.99 if source == "semantic" else None)

    def test_valid_candidate_is_verified(self) -> None:
        decision = verify_case(self.ledger, [self.candidate()], {"SET": self.settlement()}, {"BNK": self.bank()})
        self.assertEqual(DecisionStatus.VERIFIED, decision.status)

    def test_invalid_candidate_does_not_block_later_valid_candidate(self) -> None:
        settlements = {"BAD": self.settlement("BAD", "WRONG"), "SET": self.settlement()}
        banks = {"BADBNK": self.bank("BADBNK", "WRONG", Decimal("99.00")), "BNK": self.bank()}
        candidates = [self.candidate("BAD", "BADBNK"), self.candidate()]
        decision = verify_case(self.ledger, candidates, settlements, banks)
        self.assertEqual(DecisionStatus.VERIFIED, decision.status)
        self.assertEqual(("SET", "BNK"), decision.selected_candidate.identity)
        self.assertFalse(decision.candidate_evidence[0].viable)

    def test_semantic_similarity_alone_cannot_verify(self) -> None:
        settlements = {
            "SET": self.settlement("SET", "NO-LINK"),
            "SET2": self.settlement("SET2", "ALSO-NO-LINK"),
        }
        banks = {
            "BNK": self.bank("BNK", "BANK-A"),
            "BNK2": self.bank("BNK2", "BANK-B"),
        }
        decision = verify_case(
            self.ledger,
            [self.candidate(source="semantic")],
            settlements,
            banks,
        )
        self.assertEqual(DecisionStatus.REVIEW, decision.status)

    def test_unlinked_candidate_mismatch_is_review_not_exception(self) -> None:
        decision = verify_case(
            self.ledger,
            [self.candidate(source="semantic")],
            {"SET": self.settlement(reference="NO-LINK")},
            {"BNK": self.bank(reference="BANK-OTHER", amount=Decimal("99.00"))},
        )
        self.assertEqual(DecisionStatus.REVIEW, decision.status)

    def test_viable_but_insufficient_candidate_prevents_exception(self) -> None:
        settlements = {
            "BAD": self.settlement("BAD"),
            "POSSIBLE": self.settlement("POSSIBLE", "NO-LINK-A"),
            "OTHER": self.settlement("OTHER", "NO-LINK-B"),
        }
        banks = {
            "BADBNK": self.bank("BADBNK", amount=Decimal("99.00")),
            "POSSIBLEBNK": self.bank("POSSIBLEBNK", "BANK-A"),
            "OTHERBNK": self.bank("OTHERBNK", "BANK-B"),
        }
        candidates = [
            self.candidate("BAD", "BADBNK"),
            self.candidate("POSSIBLE", "POSSIBLEBNK", source="semantic"),
        ]
        decision = verify_case(self.ledger, candidates, settlements, banks)
        self.assertEqual(DecisionStatus.REVIEW, decision.status)
        self.assertTrue(decision.candidate_evidence[1].viable)
        self.assertFalse(decision.candidate_evidence[1].sufficient)

    def test_strongly_linked_financial_contradiction_is_exception(self) -> None:
        decision = verify_case(
            self.ledger,
            [self.candidate()],
            {"SET": self.settlement()},
            {"BNK": self.bank(amount=Decimal("99.00"))},
        )
        self.assertEqual(DecisionStatus.EXCEPTION, decision.status)

    def test_mixed_recon_currencies_are_exception(self) -> None:
        decision = verify_case(
            self.ledger,
            [self.candidate()],
            {"SET": self.settlement(fee_currency="USD")},
            {"BNK": self.bank()},
        )
        self.assertEqual(DecisionStatus.EXCEPTION, decision.status)

    def test_multiple_viable_candidates_are_review(self) -> None:
        settlements = {"SET": self.settlement(), "SET2": self.settlement("SET2")}
        banks = {"BNK": self.bank(), "BNK2": self.bank("BNK2")}
        candidates = [self.candidate(), self.candidate("SET2", "BNK2")]
        decision = verify_case(self.ledger, candidates, settlements, banks)
        self.assertEqual(DecisionStatus.REVIEW, decision.status)

    def test_decision_trace_is_structured(self) -> None:
        decision = verify_case(self.ledger, [self.candidate()], {"SET": self.settlement()}, {"BNK": self.bank()})
        trace = decision.to_dict()
        self.assertEqual("VERIFIED", trace["status"])
        self.assertTrue(trace["reason"])
        self.assertTrue(trace["candidate_evidence"][0]["checks"])


if __name__ == "__main__":
    unittest.main()
