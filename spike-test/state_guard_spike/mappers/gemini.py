from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from ..contract import canonical_json, sha256_json, sha256_text
from ..schemas import MapperKind, RoleMapping, SourceBundle
from .prompt import build_prompt


FROZEN_SETTINGS = {
    "provider": "Google Gemini",
    "model": "gemini-3.6-flash",
    "temperature": 0,
    "candidate_count": 1,
    "max_output_tokens": 4096,
    "response_mime_type": "application/json",
    "tools": [],
    "search": False,
    "code_execution": False,
    "embeddings": False,
    "max_transport_retries": 2,
}


class Transport(Protocol):
    def generate(self, request: dict[str, Any]) -> str: ...


class MappingInconclusive(RuntimeError):
    def __init__(self, category: str, metadata: dict[str, Any]) -> None:
        super().__init__(category)
        self.category = category
        self.metadata = metadata


@dataclass(frozen=True)
class TransportFailure(Exception):
    category: str
    status_code: int | None = None


class _GoogleTransport:
    def __init__(self) -> None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise MappingInconclusive("MISSING_API_KEY", {"attempt_count": 0, "transport_retry_count": 0})
        from google import genai
        from google.genai import types

        self._types = types
        self._client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(
                retry_options=types.HttpRetryOptions(attempts=1),
            ),
        )

    def generate(self, request: dict[str, Any]) -> str:
        try:
            response = self._client.models.generate_content(
                model=request["model"],
                contents=request["prompt"],
                config=self._types.GenerateContentConfig(
                    temperature=request["settings"]["temperature"],
                    candidate_count=request["settings"]["candidate_count"],
                    max_output_tokens=request["settings"]["max_output_tokens"],
                    response_mime_type="application/json",
                    response_json_schema=request["schema"],
                    tools=[],
                ),
            )
            return response.text
        except Exception as exc:  # normalized without persisting raw provider errors
            status = getattr(exc, "status_code", getattr(exc, "code", None))
            if isinstance(exc, (ConnectionError, TimeoutError)):
                raise TransportFailure("CONNECTION", None) from None
            if status == 429:
                raise TransportFailure("HTTP_429", 429) from None
            if isinstance(status, int) and 500 <= status <= 599:
                raise TransportFailure("HTTP_5XX", status) from None
            raise TransportFailure("NON_RETRYABLE", status if isinstance(status, int) else None) from None


def _request(bundle: SourceBundle) -> dict[str, Any]:
    return {
        "model": FROZEN_SETTINGS["model"],
        "prompt": build_prompt(bundle),
        "schema": RoleMapping.model_json_schema(),
        "settings": FROZEN_SETTINGS,
        "source_bundle_hash": sha256_json(bundle),
    }


def map_roles(
    bundle: SourceBundle,
    *,
    transport: Transport | None = None,
    approved: bool = False,
    sleep: Any = time.sleep,
) -> RoleMapping:
    if not approved:
        raise PermissionError("Gemini mapping is blocked until pre-evaluation approval")
    request = _request(bundle)
    digest = sha256_text(canonical_json(request))
    active_transport = transport or _GoogleTransport()
    retries: list[str] = []
    attempts = 0
    while True:
        attempts += 1
        if sha256_text(canonical_json(request)) != digest:
            raise RuntimeError("Gemini request changed between transport attempts")
        try:
            response_text = active_transport.generate(request)
        except TransportFailure as exc:
            retryable = exc.category in {"CONNECTION", "HTTP_429", "HTTP_5XX"}
            if not retryable or len(retries) >= FROZEN_SETTINGS["max_transport_retries"]:
                raise MappingInconclusive(exc.category, {
                    "attempt_count": attempts,
                    "transport_retry_count": len(retries),
                    "retry_reasons": retries,
                    "request_digests": [digest] * attempts,
                }) from None
            retries.append(exc.category)
            sleep(1 if len(retries) == 1 else 2)
            continue
        try:
            mapping = RoleMapping.model_validate_json(response_text)
        except (ValidationError, ValueError, json.JSONDecodeError):
            raise MappingInconclusive("AI_OUTPUT_INVALID", {
                "attempt_count": attempts,
                "transport_retry_count": len(retries),
                "retry_reasons": retries,
                "request_digests": [digest] * attempts,
            }) from None
        if mapping.mapper_kind != MapperKind.GEMINI or mapping.application_id != bundle.application_id:
            raise MappingInconclusive("AI_OUTPUT_INVALID", {
                "attempt_count": attempts,
                "transport_retry_count": len(retries),
                "retry_reasons": retries,
                "request_digests": [digest] * attempts,
            })
        return mapping.model_copy(update={"metadata": {
            **mapping.metadata,
            "attempt_count": attempts,
            "transport_retry_count": len(retries),
            "retry_reasons": retries,
            "request_digests": [digest] * attempts,
        }})

