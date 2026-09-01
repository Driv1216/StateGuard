"""Google Gen AI SDK adapter using one-shot generate_content."""

from __future__ import annotations

import json
import time
from typing import Any

from google.genai.types import GenerateContentConfigDict

from .protocol import (
    ModelProviderCapabilities,
    ModelProviderError,
    ProviderFailureCode,
    StructuredGenerationRequest,
    StructuredGenerationResult,
    TokenUsage,
)


class GeminiProvider:
    provider_id = "gemini"

    def __init__(self, *, api_key: str, model: str, client: Any | None = None) -> None:
        if not api_key:
            raise ValueError("provider API key must not be blank")
        self._model = model
        self._owns_client = client is None
        if client is None:
            try:
                from google import genai
                from google.genai import types
            except ImportError as exc:  # pragma: no cover - packaging/install guard
                raise RuntimeError("google-genai is required for the Gemini provider") from exc
            http_options = types.HttpOptions(retry_options=types.HttpRetryOptions(attempts=1))
            client = genai.Client(api_key=api_key, http_options=http_options)
        self._client = client

    def capabilities(self) -> ModelProviderCapabilities:
        return ModelProviderCapabilities(
            provider_id=self.provider_id,
            model=self._model,
            structured_output=True,
        )

    async def aclose(self) -> None:
        if not self._owns_client:
            return
        aio = getattr(self._client, "aio", None)
        close = getattr(aio, "aclose", None)
        if close is not None:
            await close()

    async def generate_structured(
        self, request: StructuredGenerationRequest
    ) -> StructuredGenerationResult:
        config: GenerateContentConfigDict = {
            "system_instruction": request.instructions,
            "response_mime_type": "application/json",
            "response_json_schema": request.response_schema,
            "http_options": {"extra_body": {"store": False}},
        }
        if request.max_output_tokens is not None:
            config["max_output_tokens"] = request.max_output_tokens
        if request.temperature is not None:
            config["temperature"] = request.temperature
        started = time.monotonic()
        try:
            response = await self._client.aio.models.generate_content(
                model=request.model,
                contents=request.input_text,
                config=config,
            )
        except Exception as exc:
            raise ModelProviderError(
                _failure_for_exception(exc),
                status_code=_status_code(exc),
            ) from exc
        latency_ms = round((time.monotonic() - started) * 1000)
        finish_reason = _finish_reason(response)
        if finish_reason == "INVALID_CANDIDATE_COUNT":
            raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT)
        if finish_reason in {"MAX_TOKENS", "MAX_OUTPUT_TOKENS"}:
            raise ModelProviderError(ProviderFailureCode.OUTPUT_LIMIT)
        if finish_reason in {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT"}:
            raise ModelProviderError(ProviderFailureCode.REFUSED)
        if finish_reason != "STOP":
            raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT)
        parsed = getattr(response, "parsed", None)
        if parsed is not None and hasattr(parsed, "model_dump"):
            parsed = parsed.model_dump(mode="json")
        if not isinstance(parsed, dict):
            text = getattr(response, "text", None)
            if not isinstance(text, str):
                raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT)
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT) from exc
        if not isinstance(parsed, dict):
            raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT)
        usage = getattr(response, "usage_metadata", None)
        token_usage = None
        if usage is not None:
            token_usage = TokenUsage(
                input_tokens=_non_negative_int(getattr(usage, "prompt_token_count", None)),
                output_tokens=_non_negative_int(getattr(usage, "candidates_token_count", None)),
            )
        return StructuredGenerationResult(
            request_id=request.request_id,
            provider_id=self.provider_id,
            model=request.model,
            output=parsed,
            latency_ms=latency_ms,
            token_usage=token_usage,
        )


def _non_negative_int(value: object) -> int | None:
    return value if isinstance(value, int) and value >= 0 else None


def _status_code(exc: Exception) -> int | None:
    value = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    return value if isinstance(value, int) else None


def _failure_for_exception(exc: Exception) -> ProviderFailureCode:
    status = _status_code(exc)
    name = type(exc).__name__.casefold()
    text = str(exc).casefold()
    if status in {401, 403}:
        return ProviderFailureCode.AUTHENTICATION
    if status == 429:
        return ProviderFailureCode.RATE_LIMITED
    if status in {408, 504} or "timeout" in name:
        return ProviderFailureCode.TIMEOUT
    if status is not None and status >= 500:
        return ProviderFailureCode.UNAVAILABLE
    if "context" in text and ("limit" in text or "length" in text):
        return ProviderFailureCode.CONTEXT_LIMIT
    if "safety" in text or "refus" in text or "blocked" in text:
        return ProviderFailureCode.REFUSED
    if status == 400:
        return ProviderFailureCode.INCOMPATIBLE_MODEL
    return ProviderFailureCode.TRANSPORT_FAILURE


def _finish_reason(response: object) -> str | None:
    candidates = getattr(response, "candidates", None)
    if not isinstance(candidates, (list, tuple)) or len(candidates) != 1:
        return "INVALID_CANDIDATE_COUNT"
    value = getattr(candidates[0], "finish_reason", None)
    return getattr(value, "name", None) or (str(value) if value is not None else None)
