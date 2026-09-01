"""Managed FastAPI adapter compatibility without importing optional packages."""

from __future__ import annotations

import platform
from importlib import metadata

from .contracts import RuntimeCapabilityReasonCode, RuntimeCompatibility

_TESTED_FASTAPI_PREFIXES = ("0.141.",)
_TESTED_STARLETTE_PREFIXES = ("1.6.",)
_TESTED_UVICORN_PREFIXES = ("0.52.",)


def _version(distribution: str) -> str | None:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return None


def detect_runtime_compatibility() -> RuntimeCompatibility:
    return RuntimeCompatibility(
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(),
        fastapi_version=_version("fastapi"),
        starlette_version=_version("starlette"),
        uvicorn_version=_version("uvicorn"),
    )


def managed_compatibility_reason(
    compatibility: RuntimeCompatibility,
) -> RuntimeCapabilityReasonCode:
    if (
        compatibility.python_implementation != "CPython"
        or not compatibility.python_version.startswith("3.11.")
    ):
        return RuntimeCapabilityReasonCode.UNSUPPORTED_PYTHON_RUNTIME
    if (
        compatibility.fastapi_version is None
        or compatibility.starlette_version is None
        or compatibility.uvicorn_version is None
    ):
        return RuntimeCapabilityReasonCode.RUNTIME_DEPENDENCY_MISSING
    if not compatibility.fastapi_version.startswith(_TESTED_FASTAPI_PREFIXES):
        return RuntimeCapabilityReasonCode.RUNTIME_VERSION_UNTESTED
    if not compatibility.starlette_version.startswith(_TESTED_STARLETTE_PREFIXES):
        return RuntimeCapabilityReasonCode.RUNTIME_VERSION_UNTESTED
    if not compatibility.uvicorn_version.startswith(_TESTED_UVICORN_PREFIXES):
        return RuntimeCapabilityReasonCode.RUNTIME_VERSION_UNTESTED
    return RuntimeCapabilityReasonCode.AVAILABLE
