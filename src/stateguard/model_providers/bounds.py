"""Domain-free bounded structured-generation policy shared by provider use cases."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StructuredGenerationBoundsPolicy:
    version: str = "structured-generation-bounds-v1"
    max_excerpt_material_bytes: int = 256 * 1024
    max_output_tokens: int = 2048
    max_serialized_response_bytes: int = 16 * 1024
    max_structured_items: int = 8
    max_references_per_item: int = 4
    max_explanation_characters: int = 512
    max_reference_characters: int = 128


DEFAULT_STRUCTURED_GENERATION_BOUNDS = StructuredGenerationBoundsPolicy()
