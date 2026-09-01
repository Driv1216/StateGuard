from __future__ import annotations

import json
import unittest
from pathlib import Path


ARTIFACT = Path(__file__).resolve().parents[1] / "artifacts" / "metrics.json"


class MetricsArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with ARTIFACT.open(encoding="utf-8") as handle:
            cls.metrics = json.load(handle)

    def test_artifact_has_required_schema_and_trace_counts(self) -> None:
        self.assertTrue(
            {
                "reproducibility",
                "definitions",
                "baseline",
                "hybrid",
                "comparison",
                "pass_conditions",
                "result",
            }.issubset(self.metrics)
        )
        required_reproducibility = {
            "python_version",
            "sentence_transformers_version",
            "embedding_model",
            "model_revision",
            "dataset_seed",
            "device",
            "semantic_top_k",
            "thresholds",
            "normalization",
        }
        self.assertTrue(required_reproducibility.issubset(self.metrics["reproducibility"]))
        self.assertEqual(30, len(self.metrics["baseline"]["decisions"]))
        self.assertEqual(30, len(self.metrics["hybrid"]["decisions"]))
        self.assertEqual(1.0, self.metrics["baseline"]["trace_completeness"])
        self.assertEqual(1.0, self.metrics["hybrid"]["trace_completeness"])

    def test_go_no_go_is_exact_conjunction_of_frozen_conditions(self) -> None:
        expected = "GO" if all(self.metrics["pass_conditions"].values()) else "NO-GO"
        self.assertEqual(expected, self.metrics["result"])


if __name__ == "__main__":
    unittest.main()

