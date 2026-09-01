from __future__ import annotations

import json

from ..contract import canonical_json, sha256_text
from ..schemas import RoleMapping, SourceBundle


ROLE_DEFINITION = (
    "A merchant-side business action that grants, provides, issues, activates, allocates, ships, "
    "unlocks or otherwise delivers the product, service, or value the customer paid for."
)


def build_prompt(bundle: SourceBundle) -> str:
    schema = RoleMapping.model_json_schema()
    source_payload = bundle.model_dump(mode="json")
    return "\n".join([
        "You are a semantic code mapper. Your only task is to map one semantic role in merchant code.",
        "ROLE: IRREVERSIBLE_FULFILMENT",
        f"DEFINITION: {ROLE_DEFINITION}",
        "Select zero or more exact, fully-qualified function symbols from SYMBOL_CATALOG.",
        "Understand the business effect, not merely identifier words or control-flow position.",
        "Do not assess vulnerabilities, correctness, payment safety, severity, PASS, or FAIL.",
        "Do not create, choose, or discuss test scenarios.",
        "Every returned symbol must exist exactly in SYMBOL_CATALOG. Do not invent or repair symbols.",
        "Return only JSON conforming to OUTPUT_SCHEMA.",
        "SOURCE_BUNDLE=" + canonical_json(source_payload),
        "SYMBOL_CATALOG=" + canonical_json([item.qualified_name for item in bundle.symbols]),
        "OUTPUT_SCHEMA=" + canonical_json(schema),
    ])


def prompt_hash(bundle: SourceBundle) -> str:
    return sha256_text(build_prompt(bundle))

