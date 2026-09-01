from __future__ import annotations

import ast
import importlib
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "stateguard"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            result.add(node.module or "")
    return result


def test_model_provider_boundary_has_no_stateguard_domain_imports() -> None:
    forbidden = (
        "stateguard.semantics",
        "stateguard.graph",
        "stateguard.evidence",
        "stateguard.invariants",
        "stateguard.remediation",
    )
    for path in (SOURCE / "model_providers").glob("*.py"):
        assert all(not name.startswith(forbidden) for name in _imports(path))


def test_production_source_has_no_frozen_spike_imports() -> None:
    forbidden = ("state_guard_spike", "spike")
    for path in SOURCE.rglob("*.py"):
        assert all(not name.startswith(forbidden) for name in _imports(path))


def test_vendor_imports_are_confined_to_provider_adapters() -> None:
    http_adapters = {
        "grounding/razorpay.py",
        "model_providers/openai_compatible.py",
        "runtime/session.py",
    }
    for path in SOURCE.rglob("*.py"):
        imports = _imports(path)
        if any(name.startswith("google.genai") for name in imports):
            assert path.name == "gemini.py"
        if any(name == "httpx" or name.startswith("httpx.") for name in imports):
            assert path.relative_to(SOURCE).as_posix() in http_adapters


def test_provider_protocol_contains_no_domain_operations_or_verdicts() -> None:
    source = (SOURCE / "model_providers" / "protocol.py").read_text(encoding="utf-8").casefold()
    for forbidden in ("customer_value", "pass_fail", "remediation", "finding"):
        assert forbidden not in source
    assert "generate_structured" in source


def test_managed_framework_dependencies_are_optional_and_adapter_scoped() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    mandatory = "\n".join(project["project"]["dependencies"]).casefold()
    assert "fastapi" not in mandatory
    assert "uvicorn" not in mandatory
    optional = project["project"]["optional-dependencies"]["managed-fastapi"]
    assert any(item.startswith("fastapi") for item in optional)
    assert any(item.startswith("uvicorn") for item in optional)

    for path in SOURCE.rglob("*.py"):
        imports = _imports(path)
        if any(name == "uvicorn" or name.startswith("uvicorn.") for name in imports):
            assert path == SOURCE / "runtime" / "worker.py"


def test_control_http_adapter_depends_only_on_the_application_facade() -> None:
    api = SOURCE / "control_api"
    forbidden = (
        "stateguard.application.applicability",
        "stateguard.application.failure_lab",
        "stateguard.application.runtime",
        "stateguard.application.semantics",
        "stateguard.application.verification",
        "stateguard.discovery",
        "stateguard.evidence.normalization",
        "stateguard.runtime",
        "stateguard.workspace",
    )
    web_frameworks = ("fastapi", "starlette", "uvicorn", "flask")
    for path in api.glob("*.py"):
        imports = _imports(path)
        assert all(not name.startswith(forbidden) for name in imports)
        assert all(not name.startswith(web_frameworks) for name in imports)


def test_control_http_import_does_not_change_managed_runtime_compatibility() -> None:
    from stateguard.runtime.compatibility import detect_runtime_compatibility

    before = detect_runtime_compatibility()
    importlib.import_module("stateguard.control_api.server")
    assert detect_runtime_compatibility() == before
