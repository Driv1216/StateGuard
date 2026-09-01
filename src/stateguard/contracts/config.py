"""User-authored stateguard.yaml contract."""

from __future__ import annotations

import re
from enum import StrEnum
from ipaddress import ip_address
from pathlib import PurePosixPath
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .common import (
    ProjectId,
    Sha256Digest,
    SymbolId,
    is_cross_platform_absolute_path,
    normalize_relative_path,
)

_APP_TARGET = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PROVIDER_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class ConfigModel(BaseModel):
    """Normalization-friendly boundary for user-authored configuration."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Framework(StrEnum):
    FASTAPI = "fastapi"


class ProjectConfig(ConfigModel):
    id: ProjectId
    source_root: str = "."
    framework: Framework = Framework.FASTAPI
    app_target: str | None = None

    @field_validator("source_root", mode="before")
    @classmethod
    def normalize_source_root(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("source_root must be a string")
        return normalize_relative_path(value)

    @field_validator("framework", mode="before")
    @classmethod
    def normalize_framework(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("app_target", mode="before")
    @classmethod
    def validate_app_target(cls, value: object) -> object:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("app_target must be a string")
        stripped = value.strip()
        if not _APP_TARGET.fullmatch(stripped):
            raise ValueError("app_target must use module.path:attribute syntax")
        return stripped


def _normalize_glob(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    if not normalized:
        raise ValueError("glob must not be blank")
    path = PurePosixPath(normalized)
    if is_cross_platform_absolute_path(value) or ".." in path.parts:
        raise ValueError("glob must be project-relative and must not traverse parents")
    return normalized


class AnalysisConfig(ConfigModel):
    include: tuple[str, ...] = Field(default=("**/*.py",), min_length=1)
    exclude: tuple[str, ...] = Field(default=(".venv/**", "venv/**", ".git/**", ".stateguard/**"))

    @field_validator("include", "exclude", mode="before")
    @classmethod
    def normalize_globs(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            raise ValueError("glob collections must be YAML lists")
        return tuple(_normalize_glob(item) if isinstance(item, str) else item for item in value)


class AIConfig(ConfigModel):
    provider: Literal["gemini", "openai-compatible"]
    model: str
    api_key_env: str
    base_url: str | None = None

    @field_validator("provider", mode="before")
    @classmethod
    def validate_provider(cls, value: object) -> object:
        if not isinstance(value, str):
            raise ValueError("provider must be a string")
        stripped = value.strip().lower()
        if not _PROVIDER_ID.fullmatch(stripped):
            raise ValueError("provider must be a lowercase slug")
        return stripped

    @field_validator("model", mode="before")
    @classmethod
    def validate_model(cls, value: object) -> object:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("model must not be blank")
        return value.strip()

    @field_validator("api_key_env", mode="before")
    @classmethod
    def validate_api_key_env(cls, value: object) -> object:
        if not isinstance(value, str):
            raise ValueError("api_key_env must be a string")
        stripped = value.strip()
        if not _ENV_NAME.fullmatch(stripped):
            raise ValueError("api_key_env must be a portable environment-variable name")
        return stripped

    @field_validator("base_url", mode="before")
    @classmethod
    def validate_base_url(cls, value: object) -> object:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("base_url must be a string")
        stripped = value.strip()
        parsed = urlsplit(stripped)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain a query string or fragment")
        return stripped.rstrip("/")

    @model_validator(mode="after")
    def validate_provider_endpoint(self) -> AIConfig:
        if self.provider == "gemini" and self.base_url is not None:
            raise ValueError("gemini does not accept base_url in Step 3")
        if self.provider == "openai-compatible" and self.base_url is None:
            raise ValueError("openai-compatible requires base_url")
        return self


class HumanResolutionBasis(StrEnum):
    HUMAN_CONFIRMED = "HUMAN_CONFIRMED"
    MANUAL_SELECTION = "MANUAL_SELECTION"


class ConfirmedCustomerValueConfig(ConfigModel):
    symbol_id: SymbolId
    semantic_context_fingerprint: Sha256Digest
    basis: HumanResolutionBasis


class SemanticsConfig(ConfigModel):
    customer_value: ConfirmedCustomerValueConfig | None = None


class FulfilmentPolicy(StrEnum):
    CAPTURE_REQUIRED = "CAPTURE_REQUIRED"
    AUTHORIZED_ALLOWED = "AUTHORIZED_ALLOWED"


class LateAuthorisationPolicy(StrEnum):
    FULFIL_LATER = "FULFIL_LATER"
    DO_NOT_FULFIL = "DO_NOT_FULFIL"


class ConfirmedFulfilmentPolicyConfig(ConfigModel):
    value: FulfilmentPolicy
    evidence_fingerprint: Sha256Digest


class ConfirmedLateAuthorisationPolicyConfig(ConfigModel):
    value: LateAuthorisationPolicy
    evidence_fingerprint: Sha256Digest


class MerchantPolicyConfig(ConfigModel):
    fulfilment: ConfirmedFulfilmentPolicyConfig | None = None
    late_authorisation: ConfirmedLateAuthorisationPolicyConfig | None = None


class RuntimeMode(StrEnum):
    MANAGED = "managed"
    BYO = "byo"
    STATIC = "static"


class RuntimeTargetKind(StrEnum):
    LOCAL = "local"
    DECLARED_TEST = "declared_test"


class RuntimeReadinessConfig(ConfigModel):
    path: str = "/"
    accepted_statuses: tuple[int, ...] = Field(default=(200,), min_length=1, max_length=32)

    @field_validator("path", mode="before")
    @classmethod
    def validate_path(cls, value: object) -> str:
        if not isinstance(value, str) or not value.strip().startswith("/"):
            raise ValueError("readiness path must begin with '/'")
        stripped = value.strip()
        if "?" in stripped or "#" in stripped:
            raise ValueError("readiness path must not contain query or fragment")
        return stripped

    @field_validator("accepted_statuses", mode="before")
    @classmethod
    def validate_statuses(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            raise ValueError("accepted_statuses must be a YAML list")
        statuses = tuple(value)
        if any(not isinstance(item, int) or not 100 <= item <= 599 for item in statuses):
            raise ValueError("readiness statuses must be HTTP status codes")
        if len(set(statuses)) != len(statuses):
            raise ValueError("readiness statuses must be unique")
        return statuses


def _validate_runtime_base_url(value: object, *, local_only: bool) -> str:
    if not isinstance(value, str):
        raise ValueError("runtime base_url must be a string")
    stripped = value.strip()
    parsed = urlsplit(stripped)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("runtime base_url must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("runtime base_url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("runtime base_url must not contain query or fragment")
    if local_only:
        hostname = parsed.hostname.casefold()
        is_loopback = hostname == "localhost"
        if not is_loopback:
            try:
                is_loopback = ip_address(hostname).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            raise ValueError("local runtime targets must use a loopback host")
    return stripped.rstrip("/")


class LocalRuntimeTargetConfig(ConfigModel):
    kind: Literal[RuntimeTargetKind.LOCAL] = RuntimeTargetKind.LOCAL
    base_url: str

    @field_validator("base_url", mode="before")
    @classmethod
    def validate_base_url(cls, value: object) -> str:
        return _validate_runtime_base_url(value, local_only=True)


class DeclaredTestRuntimeTargetConfig(ConfigModel):
    kind: Literal[RuntimeTargetKind.DECLARED_TEST]
    base_url: str
    declaration: Literal["NON_PRODUCTION_TEST_ENVIRONMENT"]

    @field_validator("base_url", mode="before")
    @classmethod
    def validate_base_url(cls, value: object) -> str:
        return _validate_runtime_base_url(value, local_only=False)


RuntimeTargetConfig = Annotated[
    LocalRuntimeTargetConfig | DeclaredTestRuntimeTargetConfig,
    Field(discriminator="kind"),
]


class RuntimeProcessConfig(ConfigModel):
    working_directory: str = "."
    env_from_host: dict[str, str] = Field(default_factory=dict)
    startup_timeout_seconds: float = Field(default=20.0, ge=0.1, le=300.0)
    request_timeout_seconds: float = Field(default=10.0, ge=0.1, le=300.0)
    shutdown_timeout_seconds: float = Field(default=5.0, ge=0.1, le=60.0)

    @field_validator("working_directory", mode="before")
    @classmethod
    def normalize_working_directory(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("runtime working_directory must be a string")
        return normalize_relative_path(value)

    @field_validator("env_from_host", mode="before")
    @classmethod
    def validate_environment_names(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise ValueError("env_from_host must be a YAML mapping")
        normalized: dict[str, str] = {}
        for child_name, host_name in value.items():
            if not isinstance(child_name, str) or not isinstance(host_name, str):
                raise ValueError("environment mappings must contain string names")
            child = child_name.strip()
            host = host_name.strip()
            if not _ENV_NAME.fullmatch(child) or not _ENV_NAME.fullmatch(host):
                raise ValueError("environment mappings must use portable variable names")
            normalized[child] = host
        return normalized


class ManagedRuntimeConfig(RuntimeProcessConfig):
    mode: Literal[RuntimeMode.MANAGED] = RuntimeMode.MANAGED


class BringYourOwnRuntimeConfig(RuntimeProcessConfig):
    mode: Literal[RuntimeMode.BYO] = RuntimeMode.BYO
    target: RuntimeTargetConfig
    readiness: RuntimeReadinessConfig
    launch_argv: tuple[str, ...] | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("launch_argv", mode="before")
    @classmethod
    def validate_launch_argv(cls, value: object) -> object:
        if value is None:
            return None
        if not isinstance(value, (list, tuple)):
            raise ValueError("launch_argv must be a YAML list, not a shell string")
        result: list[str] = []
        for token in value:
            if not isinstance(token, str) or not token.strip() or "\x00" in token:
                raise ValueError("launch_argv tokens must be non-blank strings without NUL")
            if len(token) > 4096:
                raise ValueError("launch_argv token is too long")
            result.append(token)
        return tuple(result)


class StaticRuntimeConfig(ConfigModel):
    mode: Literal[RuntimeMode.STATIC] = RuntimeMode.STATIC


RuntimeConfig = Annotated[
    ManagedRuntimeConfig | BringYourOwnRuntimeConfig | StaticRuntimeConfig,
    Field(discriminator="mode"),
]


class StateGuardConfig(ConfigModel):
    schema_version: Literal[2] = 2
    project: ProjectConfig
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    ai: AIConfig | None = None
    semantics: SemanticsConfig | None = None
    policy: MerchantPolicyConfig | None = None
    runtime: RuntimeConfig | None = None
