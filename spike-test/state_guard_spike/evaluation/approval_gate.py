from __future__ import annotations

import json
from pathlib import Path


def require_evaluation_approval(
    approval_path: Path,
    contract_hash: str,
    compliance_hash: str,
) -> None:
    if not approval_path.is_file():
        raise PermissionError("frozen evaluation is blocked: evaluation_approval.json is absent")
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    if approval != {
        "approved_contract_sha256": contract_hash,
        "approved_compliance_sha256": compliance_hash,
    }:
        raise PermissionError("frozen evaluation is blocked: approval hashes do not match")

