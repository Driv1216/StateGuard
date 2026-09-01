"""Minimal provider-agnostic structured-generation contract."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator


class ProviderBoundaryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class StructuredGenerationRequest(ProviderBoundaryModel):
    request_id: str = Field(min_length=1)
    model: str = Field(min_length=1)
    instructions: str = Field(min_length=1)
    input_text: str = Field(min_length=1)
    response_schema: dict[str, JsonValue]
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_output_tokens: int | None = Field(default=None, gt=0)

    @field_validator("request_id", "model", "instructions", "input_text")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("structured-generation text fields must not be blank")
        return stripped


class TokenUsage(ProviderBoundaryModel):
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)


class StructuredGenerationResult(ProviderBoundaryModel):
    request_id: str = Field(min_length=1)
    provider_id: str = Field(min_length=1)
    model: str = Field(min_length=1)
    output: dict[str, JsonValue]
    latency_ms: int = Field(ge=0)
    token_usage: TokenUsage | None = None

    @field_validator("request_id", "provider_id", "model")
    @classmethod
    def reject_blank_metadata(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("provider result metadata must not be blank")
        return stripped


class ModelProviderCapabilities(ProviderBoundaryModel):
    provider_id: str = Field(min_length=1)
    model: str = Field(min_length=1)
    structured_output: bool
    max_context_tokens: int | None = Field(default=None, gt=0)
    max_output_tokens: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def require_structured_output(self) -> ModelProviderCapabilities:
        if not self.structured_output:
            raise ValueError("StateGuard providers must support structured output")
        return self


class ProviderFailureCode(StrEnum):
    AUTHENTICATION = "AUTHENTICATION"
    UNAVAILABLE = "UNAVAILABLE"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    INCOMPATIBLE_MODEL = "INCOMPATIBLE_MODEL"
    CONTEXT_LIMIT = "CONTEXT_LIMIT"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"
    REFUSED = "REFUSED"
    INVALID_STRUCTURED_OUTPUT = "INVALID_STRUCTURED_OUTPUT"
    TRANSPORT_FAILURE = "TRANSPORT_FAILURE"


class ModelProviderError(RuntimeError):
    """Normalized provider failure; callers must supply only redacted detail."""

    def __init__(
        self,
        code: ProviderFailureCode,
        *,
        detail: str | None = None,
        status_code: int | None = None,
    ) -> None:
        message = code.value if detail is None else f"{code.value}: {detail}"
        super().__init__(message)
        self.code = code
        self.detail = detail
        self.status_code = status_code


@runtime_checkable
class ModelProvider(Protocol):
    def capabilities(self) -> ModelProviderCapabilities: ...

    async def generate_structured(
        self, request: StructuredGenerationRequest
    ) -> StructuredGenerationResult: ...
