from __future__ import annotations

import json

import pytest

from state_guard_spike.contract import ROOT
from state_guard_spike.mappers.gemini import MappingInconclusive, TransportFailure, map_roles
from state_guard_spike.schemas import MapperKind
from state_guard_spike.source_index import build_source_bundle


class FakeTransport:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def generate(self, request):
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def response(application_id: str) -> str:
    return json.dumps({
        "schema_version": "1.0",
        "application_id": application_id,
        "mapper_kind": "GEMINI",
        "candidates": [],
        "metadata": {},
    })


def test_gemini_is_blocked_without_approval() -> None:
    bundle = build_source_bundle("ecommerce", ROOT / "benchmarks" / "ecommerce" / "family_source")
    with pytest.raises(PermissionError):
        map_roles(bundle, transport=FakeTransport([response("ecommerce")]))


def test_transport_retries_are_bounded_and_byte_identical() -> None:
    bundle = build_source_bundle("ecommerce", ROOT / "benchmarks" / "ecommerce" / "family_source")
    transport = FakeTransport([
        TransportFailure("CONNECTION"), TransportFailure("HTTP_429", 429), response("ecommerce")
    ])
    mapping = map_roles(bundle, transport=transport, approved=True, sleep=lambda _: None)
    assert mapping.mapper_kind == MapperKind.GEMINI
    assert mapping.metadata["transport_retry_count"] == 2
    assert len({json.dumps(item, sort_keys=True) for item in transport.requests}) == 1


def test_no_retry_after_valid_but_invalid_response() -> None:
    bundle = build_source_bundle("ecommerce", ROOT / "benchmarks" / "ecommerce" / "family_source")
    transport = FakeTransport(["not-json", response("ecommerce")])
    with pytest.raises(MappingInconclusive) as error:
        map_roles(bundle, transport=transport, approved=True, sleep=lambda _: None)
    assert error.value.category == "AI_OUTPUT_INVALID"
    assert len(transport.requests) == 1


def test_non_retryable_error_stops_immediately() -> None:
    bundle = build_source_bundle("ecommerce", ROOT / "benchmarks" / "ecommerce" / "family_source")
    transport = FakeTransport([TransportFailure("NON_RETRYABLE", 401)])
    with pytest.raises(MappingInconclusive):
        map_roles(bundle, transport=transport, approved=True, sleep=lambda _: None)
    assert len(transport.requests) == 1

