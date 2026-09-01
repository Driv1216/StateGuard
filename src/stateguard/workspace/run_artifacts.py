"""Restricted immutable persistence for completed Step 7 verification runs."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from pydantic import TypeAdapter

from stateguard.contracts.common import VerificationRunId
from stateguard.contracts.identity import canonical_json
from stateguard.evidence.contracts import VerificationRun

RUNS_RELATIVE_DIRECTORY = Path(".stateguard/runs")
_RUN_ID_ADAPTER = TypeAdapter(VerificationRunId)


class InvalidVerificationRunIdError(ValueError):
    """A caller supplied a non-canonical verification run ID."""


class VerificationRunNotFoundError(ValueError):
    """The requested immutable verification run does not exist."""


class VerificationRunArtifactError(ValueError):
    """Stored verification-run structure or content is invalid."""


def _validated_run_id(run_id: VerificationRunId | str) -> VerificationRunId:
    try:
        return _RUN_ID_ADAPTER.validate_python(run_id)
    except ValueError as exc:
        raise InvalidVerificationRunIdError("invalid verification run ID") from exc


def verification_runs_directory(repository_root: Path) -> Path:
    return repository_root / RUNS_RELATIVE_DIRECTORY


def verification_run_directory(
    repository_root: Path,
    run_id: VerificationRunId | str,
) -> Path:
    return verification_runs_directory(repository_root) / _validated_run_id(run_id)


def verification_run_path(
    repository_root: Path,
    run_id: VerificationRunId | str,
) -> Path:
    return verification_run_directory(repository_root, run_id) / "run.json"


def _reject_symlink(path: Path, description: str) -> None:
    if path.is_symlink():
        raise VerificationRunArtifactError(f"refusing to use symlinked {description}")


def _validate_storage_parents(repository_root: Path, *, create: bool) -> Path:
    state_directory = repository_root / ".stateguard"
    _reject_symlink(state_directory, ".stateguard directory")
    if create:
        state_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(state_directory, 0o700)
    elif not state_directory.exists():
        return verification_runs_directory(repository_root)
    runs = verification_runs_directory(repository_root)
    _reject_symlink(runs, "verification-runs directory")
    if create:
        runs.mkdir(mode=0o700, exist_ok=True)
        if os.name == "posix":
            os.chmod(runs, 0o700)
    return runs


def _load_artifact_file(path: Path) -> VerificationRun:
    _reject_symlink(path, "verification-run artifact")
    if not path.is_file():
        raise VerificationRunArtifactError("verification-run artifact is missing")
    try:
        return VerificationRun.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise VerificationRunArtifactError("invalid StateGuard verification-run artifact") from exc


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_verification_run(repository_root: Path, artifact: VerificationRun) -> Path:
    """Atomically publish one completed immutable run without overwriting history."""

    runs = _validate_storage_parents(repository_root, create=True)
    final_directory = verification_run_directory(repository_root, artifact.run_id)
    _reject_symlink(final_directory, "verification-run directory")
    if final_directory.exists():
        raise FileExistsError("verification run ID already exists")
    staging = Path(tempfile.mkdtemp(prefix=f".{artifact.run_id}.", suffix=".tmp", dir=runs))
    try:
        if os.name == "posix":
            os.chmod(staging, 0o700)
        staged_path = staging / "run.json"
        descriptor = os.open(staged_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(canonical_json(artifact) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            # fdopen owns the descriptor after successful construction.
            raise
        if os.name == "posix":
            os.chmod(staged_path, 0o600)
        staged = _load_artifact_file(staged_path)
        if staged != artifact:
            raise VerificationRunArtifactError(
                "staged verification run differs from requested artifact"
            )
        _fsync_directory(staging)
        if final_directory.exists():
            raise FileExistsError("verification run ID already exists")
        os.rename(staging, final_directory)
        _fsync_directory(runs)
        published = load_verification_run(repository_root, artifact.run_id)
        if published != artifact:
            raise VerificationRunArtifactError(
                "published verification run differs from requested artifact"
            )
        return final_directory / "run.json"
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def load_verification_run(
    repository_root: Path,
    run_id: VerificationRunId | str,
) -> VerificationRun:
    selected_id = _validated_run_id(run_id)
    _validate_storage_parents(repository_root, create=False)
    directory = verification_run_directory(repository_root, selected_id)
    _reject_symlink(directory, "verification-run directory")
    if not directory.exists():
        raise VerificationRunNotFoundError("verification-run directory is missing")
    if not directory.is_dir():
        raise VerificationRunArtifactError("verification-run directory is not a directory")
    if {item.name for item in directory.iterdir()} != {"run.json"}:
        raise VerificationRunArtifactError("verification-run directory must contain only run.json")
    artifact = _load_artifact_file(directory / "run.json")
    if artifact.run_id != selected_id:
        raise VerificationRunArtifactError(
            "verification-run directory and artifact identities differ"
        )
    return artifact


def list_verification_runs(repository_root: Path) -> tuple[VerificationRun, ...]:
    runs = _validate_storage_parents(repository_root, create=False)
    if not runs.exists():
        return ()
    if not runs.is_dir():
        raise VerificationRunArtifactError("verification-runs path is not a directory")
    artifacts: list[VerificationRun] = []
    for entry in sorted(runs.iterdir(), key=lambda item: item.name):
        if entry.name.startswith("."):
            continue
        try:
            run_id = _validated_run_id(entry.name)
        except InvalidVerificationRunIdError as exc:
            raise VerificationRunArtifactError(
                "verification-runs directory contains an invalid run identity"
            ) from exc
        artifacts.append(load_verification_run(repository_root, run_id))
    return tuple(
        sorted(
            artifacts,
            key=lambda item: (item.completed_at, item.run_id),
            reverse=True,
        )
    )


def load_latest_verification_run(repository_root: Path) -> VerificationRun | None:
    runs = list_verification_runs(repository_root)
    return runs[0] if runs else None
