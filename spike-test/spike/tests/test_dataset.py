from __future__ import annotations

import unittest
from collections import Counter

from spike.generate_dataset import DATASET_SEED, build_dataset


class DatasetTests(unittest.TestCase):
    def test_exact_frozen_distribution(self) -> None:
        ledger, recon, bank, truth = build_dataset(DATASET_SEED)
        self.assertEqual(30, len(ledger))
        self.assertEqual(90, len(recon))
        self.assertEqual(30, len(bank))
        self.assertEqual(
            {"clean": 15, "normalized": 5, "semantic": 5, "ambiguous": 3, "corrupted": 2},
            dict(Counter(case["category"] for case in truth["cases"])),
        )

    def test_generation_is_deterministic(self) -> None:
        self.assertEqual(build_dataset(DATASET_SEED), build_dataset(DATASET_SEED))

    def test_hidden_truth_fields_do_not_leak_into_runtime_rows(self) -> None:
        ledger, recon, bank, _ = build_dataset(DATASET_SEED)
        forbidden = {"case_id", "category", "expected_status", "settlement_id", "bank_id"}
        self.assertFalse(forbidden.intersection(ledger[0]))
        self.assertNotIn("case_id", recon[0])
        self.assertNotIn("category", recon[0])
        self.assertNotIn("case_id", bank[0])
        self.assertNotIn("category", bank[0])


if __name__ == "__main__":
    unittest.main()

