from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_frozen_spike_is_not_importable_from_production_test_path() -> None:
    assert importlib.util.find_spec("state_guard_spike") is None


def test_production_package_configuration_excludes_spike() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'packages = ["src/stateguard"]' in pyproject
    assert 'testpaths = ["tests"]' in pyproject
    assert '"spike-test"' in pyproject
    assert (ROOT / "spike-test" / "contract.sha256").read_text(encoding="utf-8").strip() == (
        "3454f599945434d7dfbe3cf0eb42ad504bb007f63305453095ce38d07c73e62a"
    )
