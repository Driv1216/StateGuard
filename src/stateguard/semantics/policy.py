"""Versioned tactical guardrails for Step 3 semantic provider bundles."""

from __future__ import annotations

from dataclasses import dataclass

from stateguard.model_providers.bounds import (
    DEFAULT_STRUCTURED_GENERATION_BOUNDS,
    StructuredGenerationBoundsPolicy,
)


@dataclass(frozen=True)
class SemanticBundlePolicy:
    version: str = "semantic-bundle-policy-v1"
    max_presented_candidates: int = 64
    generation: StructuredGenerationBoundsPolicy = DEFAULT_STRUCTURED_GENERATION_BOUNDS

    @property
    def max_excerpt_bytes(self) -> int:
        return self.generation.max_excerpt_material_bytes

    @property
    def max_output_tokens(self) -> int:
        return self.generation.max_output_tokens

    @property
    def max_response_bytes(self) -> int:
        return self.generation.max_serialized_response_bytes


DEFAULT_SEMANTIC_BUNDLE_POLICY = SemanticBundlePolicy()
