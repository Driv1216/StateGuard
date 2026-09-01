from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from stateguard.contracts.config import (
    ConfirmedCustomerValueConfig,
    HumanResolutionBasis,
)
from stateguard.contracts.identity import new_project_id, sha256_digest, source_file_id, symbol_id
from stateguard.semantics.context import semantic_context_fingerprint
from stateguard.semantics.contracts import (
    BundleCompleteness,
    CustomerValueSemanticArtifact,
    SemanticBundleAudit,
    SemanticContextDescriptor,
)
from stateguard.workspace.config import ConfigLoadError, load_config
from stateguard.workspace.config_edit import (
    ConcurrentConfigEditError,
    write_customer_value_confirmation,
)
from stateguard.workspace.semantic_artifacts import (
    load_semantic_artifact,
    write_semantic_artifact,
)


def _confirmation() -> ConfirmedCustomerValueConfig:
    project = new_project_id()
    selected = symbol_id(source_file_id(project, "domain.py"), "domain.grant", "FUNCTION")
    return ConfirmedCustomerValueConfig(
        symbol_id=selected,
        semantic_context_fingerprint=sha256_digest("semantic"),
        basis=HumanResolutionBasis.MANUAL_SELECTION,
    )


def _config(path: Path) -> None:
    path.write_text(
        f"""# merchant comment
schema_version: 2
project:
  id: {new_project_id()} # keep inline comment
analysis:
  include: ["**/*.py"]
  exclude: []
""",
        encoding="utf-8",
    )


def test_round_trip_editor_changes_only_customer_value_and_preserves_comments(
    tmp_path: Path,
) -> None:
    path = tmp_path / "stateguard.yaml"
    _config(path)
    confirmation = _confirmation()
    write_customer_value_confirmation(path, confirmation)
    edited = path.read_text(encoding="utf-8")
    assert "# merchant comment" in edited
    assert "# keep inline comment" in edited
    assert 'include: ["**/*.py"]' in edited
    loaded = load_config(path)
    assert loaded.semantics is not None
    assert loaded.semantics.customer_value == confirmation
    assert "source_index_fingerprint" not in edited


def test_authoritative_temporary_validation_prevents_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "stateguard.yaml"
    _config(path)
    original = path.read_bytes()
    from stateguard.workspace import config_edit

    real_loader = config_edit.load_config

    def rejecting_loader(candidate: Path):
        if candidate.suffix == ".tmp":
            raise ConfigLoadError("temporary rejected")
        return real_loader(candidate)

    monkeypatch.setattr(config_edit, "load_config", rejecting_loader)
    with pytest.raises(ConfigLoadError, match="temporary rejected"):
        write_customer_value_confirmation(path, _confirmation())
    assert path.read_bytes() == original


def test_concurrent_configuration_change_prevents_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "stateguard.yaml"
    _config(path)
    original = path.read_bytes()
    real_read_bytes = Path.read_bytes
    reads = 0

    def changed_second_read(candidate: Path) -> bytes:
        nonlocal reads
        value = real_read_bytes(candidate)
        if candidate == path:
            reads += 1
            if reads == 2:
                return value + b"# concurrent\n"
        return value

    monkeypatch.setattr(Path, "read_bytes", changed_second_read)
    with pytest.raises(ConcurrentConfigEditError):
        write_customer_value_confirmation(path, _confirmation())
    assert real_read_bytes(path) == original


def test_semantic_artifact_is_atomic_restricted_and_contains_no_source(tmp_path: Path) -> None:
    project = new_project_id()
    context = SemanticContextDescriptor(
        relevant_symbol_ids=(),
        presented_symbol_ids=(),
        bundle_completeness=BundleCompleteness.BUNDLE_COMPLETE,
    )
    semantic_fp = semantic_context_fingerprint(context)
    artifact = CustomerValueSemanticArtifact(
        producer_version="0.1.0",
        generated_at=datetime(2026, 8, 25, tzinfo=UTC),
        project_id=project,
        project_source_fingerprint=sha256_digest("project"),
        source_index_fingerprint=sha256_digest("index"),
        structural_graph_fingerprint=sha256_digest("graph"),
        context=context,
        semantic_context_fingerprint=semantic_fp,
        bundle_policy=SemanticBundleAudit(
            policy_version="test-v1",
            max_presented_candidates=64,
            max_excerpt_bytes=262144,
            max_output_tokens=2048,
            max_response_bytes=16384,
        ),
    )
    path = write_semantic_artifact(tmp_path, artifact)
    assert load_semantic_artifact(tmp_path) == artifact
    assert path.stat().st_mode & 0o777 == 0o600
    payload = path.read_text(encoding="utf-8")
    assert "merchant_source" not in payload
    assert "instructions" not in payload
    assert "api_key" not in payload
