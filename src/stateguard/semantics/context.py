"""Canonical semantic fingerprints and relevance-scoped staleness checks."""

from __future__ import annotations

from stateguard.contracts.common import Sha256Digest
from stateguard.contracts.identity import fingerprint_json

from .contracts import (
    CustomerValueMappingInput,
    CustomerValueResolution,
    SemanticContextDescriptor,
    SemanticContextEvidence,
    SemanticDiagnosticCode,
)

_PRESENTATION_DIAGNOSTICS = frozenset(
    {
        SemanticDiagnosticCode.CANDIDATE_LIMIT_REACHED,
        SemanticDiagnosticCode.EXCERPT_BYTE_LIMIT_REACHED,
    }
)


def _canonical_evidence(records: tuple[SemanticContextEvidence, ...]) -> list[dict[str, str]]:
    return [
        {"kind": item.kind.value, "reference": item.reference, "fingerprint": item.fingerprint}
        for item in sorted(
            records, key=lambda value: (value.kind.value, value.reference, value.fingerprint)
        )
    ]


def semantic_context_fingerprint(descriptor: SemanticContextDescriptor) -> Sha256Digest:
    """Fingerprint full relevant evidence, excluding presentation and any decision."""

    return fingerprint_json(
        {
            "schema_version": descriptor.schema_version,
            "payment_ingress_symbol_ids": sorted(descriptor.payment_ingress_symbol_ids),
            "relevant_symbol_ids": sorted(descriptor.relevant_symbol_ids),
            "diagnostics": sorted(
                (
                    item.model_dump(mode="json")
                    for item in descriptor.diagnostics
                    if item.code not in _PRESENTATION_DIAGNOSTICS
                ),
                key=lambda item: str(item),
            ),
            "source_excerpts": _canonical_evidence(descriptor.source_excerpts),
            "payment_calls": _canonical_evidence(descriptor.payment_calls),
            "graph_neighborhood": _canonical_evidence(descriptor.graph_neighborhood),
        }
    )


def provider_bundle_fingerprint(
    mapping_input: CustomerValueMappingInput,
    *,
    mapper_version: str,
    instructions_version: str,
    serialized_provider_input: str,
) -> Sha256Digest:
    """Fingerprint the exact bounded input shown to a configured provider."""

    return fingerprint_json(
        {
            "mapper_version": mapper_version,
            "instructions_version": instructions_version,
            "presented_symbol_ids": sorted(mapping_input.semantic_context.presented_symbol_ids),
            "catalog": [item.model_dump(mode="json") for item in mapping_input.catalog],
            "excerpts": [item.model_dump(mode="json") for item in mapping_input.excerpts],
            "serialized_provider_input": serialized_provider_input,
        }
    )


def resolution_fingerprint(
    resolution: CustomerValueResolution,
    semantic_fingerprint: Sha256Digest,
) -> Sha256Digest:
    return fingerprint_json(
        {
            "semantic_context_fingerprint": semantic_fingerprint,
            "resolution": resolution.model_dump(mode="json"),
        }
    )


def is_semantic_confirmation_stale(
    stored_fingerprint: Sha256Digest, current_fingerprint: Sha256Digest
) -> bool:
    return stored_fingerprint != current_fingerprint
