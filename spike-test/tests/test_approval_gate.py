import json

import pytest

from state_guard_spike.evaluation.approval_gate import require_evaluation_approval


def test_evaluation_requires_exact_approval_hashes(tmp_path) -> None:
    path = tmp_path / "evaluation_approval.json"
    with pytest.raises(PermissionError):
        require_evaluation_approval(path, "contract", "compliance")
    path.write_text(json.dumps({"approved_contract_sha256": "wrong", "approved_compliance_sha256": "compliance"}))
    with pytest.raises(PermissionError):
        require_evaluation_approval(path, "contract", "compliance")
    path.write_text(json.dumps({"approved_contract_sha256": "contract", "approved_compliance_sha256": "compliance"}))
    require_evaluation_approval(path, "contract", "compliance")

