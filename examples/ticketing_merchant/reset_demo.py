"""Restore the bounded ticketing demo source and clear demo-local state."""

from __future__ import annotations

import argparse
import os
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TEMPLATES = ROOT / "templates"
SOURCE = ROOT / "app" / "main.py"
CONFIG = ROOT / "stateguard.yaml"
ARTIFACTS = ROOT / ".stateguard"
DATABASE_FILES = tuple(
    ROOT / ".demo" / name
    for name in ("merchant.sqlite3", "merchant.sqlite3-wal", "merchant.sqlite3-shm")
)


def _atomic_restore(template: Path, target: Path) -> None:
    if template.resolve().parent != TEMPLATES.resolve():
        raise ValueError("reset template escaped the demo template directory")
    if target.resolve().parent not in {ROOT.resolve(), (ROOT / "app").resolve()}:
        raise ValueError("reset target escaped the demo directory")
    payload = template.read_bytes()
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def reset(mode: str) -> None:
    source_template = TEMPLATES / f"main.{mode}.py"
    _atomic_restore(source_template, SOURCE)
    _atomic_restore(TEMPLATES / "stateguard.base.yaml", CONFIG)
    if ARTIFACTS.exists():
        shutil.rmtree(ARTIFACTS)
    for database in DATABASE_FILES:
        database.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("vulnerable", "fixed"))
    args = parser.parse_args()
    reset(args.mode)
    print(f"ticketing demo reset to {args.mode}; provider credentials were not read")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
