"""Restricted local persistence for the Step 4 applicability artifact."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from stateguard.applicability.contracts import ScenarioApplicabilityArtifact
from stateguard.contracts.identity import canonical_json

APPLICABILITY_ARTIFACT_RELATIVE_PATH = Path(".stateguard/applicability.json")


def applicability_artifact_path(repository_root: Path) -> Path:
    return repository_root / APPLICABILITY_ARTIFACT_RELATIVE_PATH


def load_applicability_artifact(
    repository_root: Path,
) -> ScenarioApplicabilityArtifact | None:
    path = applicability_artifact_path(repository_root)
    if not path.exists():
        return None
    try:
        return ScenarioApplicabilityArtifact.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("invalid StateGuard applicability artifact") from exc


def write_applicability_artifact(
    repository_root: Path,
    artifact: ScenarioApplicabilityArtifact,
) -> Path:
    directory = repository_root / ".stateguard"
    if directory.is_symlink():
        raise ValueError("refusing to persist through a symlinked .stateguard directory")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = applicability_artifact_path(repository_root)
    if path.is_symlink():
        raise ValueError("refusing to replace a symlinked applicability artifact")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".applicability.", suffix=".tmp", dir=directory
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(canonical_json(artifact) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        load_applicability_artifact(repository_root)
        return path
    finally:
        if temporary.exists():
            temporary.unlink()
