from __future__ import annotations

from ..contract import sha256_json
from ..schemas import MapperKind, MappingResolutionTrace, ResolutionState, RoleMapping, SourceBundle


def resolve_mapping(
    mapping: RoleMapping,
    bundle: SourceBundle,
    contract_hash: str,
) -> MappingResolutionTrace:
    catalogue = {symbol.qualified_name for symbol in bundle.symbols}
    valid = sorted({candidate.symbol for candidate in mapping.candidates if candidate.symbol in catalogue})
    hallucinated = sorted({candidate.symbol for candidate in mapping.candidates if candidate.symbol not in catalogue})
    if not valid:
        resolution = ResolutionState.UNMAPPED
        selected = None
        explanation = (
            "No valid existing IRREVERSIBLE_FULFILMENT symbol was returned; "
            "fulfilment-specific execution was skipped."
        )
    elif len(valid) == 1:
        resolution = ResolutionState.UNIQUE
        selected = valid[0]
        explanation = "Exactly one valid role symbol was selected for deterministic instrumentation."
    else:
        resolution = ResolutionState.AMBIGUOUS
        selected = None
        explanation = (
            f"{len(valid)} valid role symbols were returned; no unique instrumentation target exists, "
            "so fulfilment-specific execution was skipped."
        )
    return MappingResolutionTrace(
        mapper_kind=mapping.mapper_kind,
        family_id=bundle.application_id,
        mapping_hash=sha256_json(mapping),
        source_bundle_hash=sha256_json(bundle),
        contract_hash=contract_hash,
        raw_candidate_count=len(mapping.candidates),
        valid_symbols=valid,
        hallucinated_symbols=hallucinated,
        resolution=resolution,
        selected_symbol=selected,
        explanation=explanation,
    )

