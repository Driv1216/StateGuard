"""Exact provider creation with no provider/model/endpoint substitution."""

from __future__ import annotations

import os

from stateguard.contracts.config import AIConfig

from .gemini import GeminiProvider
from .openai_compatible import OpenAICompatibleProvider
from .protocol import ModelProvider, ModelProviderError, ProviderFailureCode


def create_model_provider(config: AIConfig) -> ModelProvider:
    api_key = os.environ.get(config.api_key_env)
    if not api_key:
        raise ModelProviderError(ProviderFailureCode.AUTHENTICATION)
    if config.provider == "gemini":
        if config.base_url is not None:
            raise ValueError("gemini does not accept a custom base_url in Step 3")
        return GeminiProvider(api_key=api_key, model=config.model)
    if config.provider == "openai-compatible":
        if config.base_url is None:
            raise ValueError("openai-compatible requires base_url")
        return OpenAICompatibleProvider(
            api_key=api_key,
            base_url=config.base_url,
            model=config.model,
        )
    raise ValueError(f"unsupported model provider: {config.provider}")
