"""Restricted local persistence for historical Step 5 capability assessment."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from stateguard.contracts.identity import canonical_json
from stateguard.runtime.contracts import RuntimeCapabilityArtifact

RUNTIME_ARTIFACT_RELATIVE_PATH = Path(".stateguard/runtime.json")


def runtime_artifact_path(repository_root: Path) -> Path:
    return repository_root / RUNTIME_ARTIFACT_RELATIVE_PATH


def load_runtime_artifact(repository_root: Path) -> RuntimeCapabilityArtifact | None:
    path = runtime_artifact_path(repository_root)
    if not path.exists():
        return None
    try:
        return RuntimeCapabilityArtifact.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("invalid StateGuard runtime capability artifact") from exc


def write_runtime_artifact(
    repository_root: Path,
    artifact: RuntimeCapabilityArtifact,
) -> Path:
    directory = repository_root / ".stateguard"
    if directory.is_symlink():
        raise ValueError("refusing to persist through a symlinked .stateguard directory")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = runtime_artifact_path(repository_root)
    if path.is_symlink():
        raise ValueError("refusing to replace a symlinked runtime capability artifact")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".runtime.", suffix=".tmp", dir=directory)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(canonical_json(artifact) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        load_runtime_artifact(repository_root)
        return path
    finally:
        if temporary.exists():
            temporary.unlink()
