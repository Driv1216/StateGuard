from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from stateguard.model_providers.protocol import (
    ModelProvider,
    ModelProviderCapabilities,
    StructuredGenerationRequest,
    StructuredGenerationResult,
)


class FakeProvider:
    def capabilities(self) -> ModelProviderCapabilities:
        return ModelProviderCapabilities(
            provider_id="fake",
            model="fake-model",
            structured_output=True,
            max_context_tokens=10_000,
        )

    async def generate_structured(
        self, request: StructuredGenerationRequest
    ) -> StructuredGenerationResult:
        return StructuredGenerationResult(
            request_id=request.request_id,
            provider_id="fake",
            model=request.model,
            output={"items": []},
            latency_ms=1,
        )


def test_provider_protocol_is_only_structured_generation() -> None:
    provider = FakeProvider()
    assert isinstance(provider, ModelProvider)
    request = StructuredGenerationRequest(
        request_id="request-1",
        model="fake-model",
        instructions="Return data matching the supplied schema.",
        input_text="Bounded StateGuard-owned context",
        response_schema={"type": "object", "properties": {"items": {"type": "array"}}},
    )
    result = asyncio.run(provider.generate_structured(request))
    assert result.output == {"items": []}


def test_provider_boundary_rejects_domain_or_verdict_fields() -> None:
    with pytest.raises(ValidationError):
        StructuredGenerationResult.model_validate(
            {
                "request_id": "request-1",
                "provider_id": "fake",
                "model": "fake-model",
                "output": {},
                "latency_ms": 1,
                "verdict": "PASS",
            }
        )
    with pytest.raises(ValidationError):
        ModelProviderCapabilities(provider_id="fake", model="fake-model", structured_output=False)
