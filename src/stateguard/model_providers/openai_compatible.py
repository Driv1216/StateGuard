"""Strict Chat Completions adapter for the explicit Step 3 wire contract."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from .protocol import (
    ModelProviderCapabilities,
    ModelProviderError,
    ProviderFailureCode,
    StructuredGenerationRequest,
    StructuredGenerationResult,
    TokenUsage,
)


class OpenAICompatibleProvider:
    provider_id = "openai-compatible"

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        if not api_key:
            raise ValueError("provider API key must not be blank")
        self._model = model
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=timeout_seconds,
            headers={"Authorization": f"Bearer {api_key}"},
        )
        self._endpoint = f"{base_url.rstrip('/')}/chat/completions"

    def capabilities(self) -> ModelProviderCapabilities:
        return ModelProviderCapabilities(
            provider_id=self.provider_id,
            model=self._model,
            structured_output=True,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def generate_structured(
        self, request: StructuredGenerationRequest
    ) -> StructuredGenerationResult:
        payload: dict[str, Any] = {
            "model": request.model,
            "messages": [
                {"role": "system", "content": request.instructions},
                {"role": "user", "content": request.input_text},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "stateguard_customer_value",
                    "strict": True,
                    "schema": request.response_schema,
                },
            },
        }
        if request.max_output_tokens is not None:
            payload["max_completion_tokens"] = request.max_output_tokens
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        started = time.monotonic()
        try:
            response = await self._client.post(self._endpoint, json=payload)
        except httpx.TimeoutException as exc:
            raise ModelProviderError(ProviderFailureCode.TIMEOUT) from exc
        except httpx.HTTPError as exc:
            raise ModelProviderError(ProviderFailureCode.TRANSPORT_FAILURE) from exc
        latency_ms = round((time.monotonic() - started) * 1000)
        if response.status_code >= 400:
            raise ModelProviderError(
                _failure_for_status(response.status_code, response.text),
                status_code=response.status_code,
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT) from exc
        if not isinstance(body, dict):
            raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT)
        choices = body.get("choices")
        if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
            raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT)
        choice = choices[0]
        finish_reason = choice.get("finish_reason")
        if finish_reason == "length":
            raise ModelProviderError(ProviderFailureCode.OUTPUT_LIMIT)
        if finish_reason in {"content_filter", "refusal"}:
            raise ModelProviderError(ProviderFailureCode.REFUSED)
        if finish_reason != "stop":
            raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT)
        message = choice.get("message")
        if not isinstance(message, dict):
            raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT)
        if message.get("refusal"):
            raise ModelProviderError(ProviderFailureCode.REFUSED)
        content = message.get("content")
        if not isinstance(content, str):
            raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT)
        try:
            output = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT) from exc
        if not isinstance(output, dict):
            raise ModelProviderError(ProviderFailureCode.INVALID_STRUCTURED_OUTPUT)
        usage = body.get("usage")
        token_usage = None
        if isinstance(usage, dict):
            token_usage = TokenUsage(
                input_tokens=_non_negative_int(usage.get("prompt_tokens")),
                output_tokens=_non_negative_int(usage.get("completion_tokens")),
            )
        return StructuredGenerationResult(
            request_id=request.request_id,
            provider_id=self.provider_id,
            model=request.model,
            output=output,
            latency_ms=latency_ms,
            token_usage=token_usage,
        )


def _non_negative_int(value: object) -> int | None:
    return value if isinstance(value, int) and value >= 0 else None


def _failure_for_status(status: int, response_text: str) -> ProviderFailureCode:
    text = response_text.casefold()
    if status in {401, 403}:
        return ProviderFailureCode.AUTHENTICATION
    if status == 429:
        return ProviderFailureCode.RATE_LIMITED
    if status in {408, 504}:
        return ProviderFailureCode.TIMEOUT
    if status >= 500:
        return ProviderFailureCode.UNAVAILABLE
    if "context" in text and ("limit" in text or "length" in text):
        return ProviderFailureCode.CONTEXT_LIMIT
    if "schema" in text or "response_format" in text or "json_schema" in text:
        return ProviderFailureCode.INCOMPATIBLE_MODEL
    return ProviderFailureCode.TRANSPORT_FAILURE
