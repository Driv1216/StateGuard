"""Batch 0 application use cases."""

from __future__ import annotations

from pathlib import Path

from stateguard.contracts.config import StateGuardConfig
from stateguard.workspace.config import load_config


def validate_project_config(path: Path) -> StateGuardConfig:
    """Load and validate a merchant project's StateGuard configuration."""

    return load_config(path)
