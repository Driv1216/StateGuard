"""Restricted local persistence for the Step 3 semantic audit artifact."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from stateguard.contracts.identity import canonical_json
from stateguard.semantics.contracts import CustomerValueSemanticArtifact

SEMANTIC_ARTIFACT_RELATIVE_PATH = Path(".stateguard/semantics.json")


def semantic_artifact_path(repository_root: Path) -> Path:
    return repository_root / SEMANTIC_ARTIFACT_RELATIVE_PATH


def load_semantic_artifact(repository_root: Path) -> CustomerValueSemanticArtifact | None:
    path = semantic_artifact_path(repository_root)
    if not path.exists():
        return None
    try:
        return CustomerValueSemanticArtifact.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("invalid StateGuard semantic artifact") from exc


def write_semantic_artifact(
    repository_root: Path,
    artifact: CustomerValueSemanticArtifact,
) -> Path:
    directory = repository_root / ".stateguard"
    if directory.is_symlink():
        raise ValueError("refusing to persist through a symlinked .stateguard directory")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = semantic_artifact_path(repository_root)
    if path.is_symlink():
        raise ValueError("refusing to replace a symlinked semantic artifact")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".semantics.", suffix=".tmp", dir=directory
    )
    temporary = Path(temporary_name)
    try:
        payload = canonical_json(artifact) + "\n"
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        load_semantic_artifact(repository_root)
        return path
    finally:
        if temporary.exists():
            temporary.unlink()
