from __future__ import annotations

import asyncio
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.contracts.identity import new_project_id, sha256_digest
from stateguard.model_providers.protocol import (
    ModelProviderCapabilities,
    StructuredGenerationRequest,
    StructuredGenerationResult,
)
from stateguard.semantics.contracts import ResolutionBasis, ResolutionState
from stateguard.workspace.config import load_config
from stateguard.workspace.semantic_artifacts import load_semantic_artifact, write_semantic_artifact

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"
NOW = datetime(2026, 8, 25, tzinfo=UTC)


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "semantic_app", repository)
    config = repository / "stateguard.yaml"
    config.write_text(
        f"""# merchant-owned
schema_version: 2
project:
  id: {new_project_id()}
  app_target: main:app
analysis:
  include: ["**/*.py"]
  exclude: []
""",
        encoding="utf-8",
    )
    return repository, config


def _configure_ai(config: Path, *, provider: str = "gemini", model: str = "model-1") -> None:
    endpoint = (
        "\n  base_url: https://provider.example/v1" if provider == "openai-compatible" else ""
    )
    with config.open("a", encoding="utf-8") as handle:
        handle.write(
            f"""ai:
  provider: {provider}
  model: {model}
  api_key_env: TEST_API_KEY{endpoint}
"""
        )


class _UniqueCandidateProvider:
    provider_id = "gemini"

    def capabilities(self) -> ModelProviderCapabilities:
        return ModelProviderCapabilities(
            provider_id=self.provider_id,
            model="model-1",
            structured_output=True,
        )

    async def generate_structured(
        self, request: StructuredGenerationRequest
    ) -> StructuredGenerationResult:
        catalog = json.loads(request.input_text)["catalog"]
        selected = next(item for item in catalog if item["qualified_name"] == "domain.grant_ticket")
        return StructuredGenerationResult(
            request_id=request.request_id,
            provider_id=self.provider_id,
            model=request.model,
            output={
                "candidates": [
                    {
                        "symbol_reference": selected["catalog_reference"],
                        "rationale": "Creates the paid admission",
                        "excerpt_references": selected["allowed_excerpt_references"],
                        "provider_confidence": None,
                    }
                ]
            },
            latency_ms=1,
        )

    async def aclose(self) -> None:
        return None


def test_resolve_without_provider_records_absence_not_unmapped(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path)
    result = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    assert result.artifact.resolution is None
    assert result.artifact.model_attempt is None
    assert load_semantic_artifact(repository) == result.artifact


def test_unconnected_manual_confirmation_persists_minimal_yaml_and_human_authority(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path)
    initial = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    selected = next(
        item.symbol_id
        for item in initial.source_index.symbols
        if item.qualified_name == "domain.unused_imported_helper"
    )
    confirmed = asyncio.run(confirm_customer_value(repository, config, selected, generated_at=NOW))
    assert confirmed.artifact.resolution is not None
    assert confirmed.artifact.resolution.state == ResolutionState.UNIQUE
    assert confirmed.artifact.resolution.basis == ResolutionBasis.MANUAL_SELECTION
    customer = load_config(config).semantics
    assert customer is not None and customer.customer_value is not None
    stored = customer.customer_value
    assert stored.symbol_id == selected
    yaml_text = config.read_text(encoding="utf-8")
    assert "source_index_fingerprint" not in yaml_text
    assert "confirmed_at" not in yaml_text
    assert "qualified_name" not in yaml_text

    (repository / "unrelated.py").write_text("VALUE = 2\n", encoding="utf-8")
    refreshed = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    assert refreshed.artifact.resolution is not None
    assert refreshed.artifact.resolution.selected_symbol_id == selected
    assert refreshed.artifact.resolution.basis == ResolutionBasis.MANUAL_SELECTION


def test_route_confirmation_is_rejected_as_unsupported_inline_action(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path)
    initial = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    route = initial.source_index.routes[0].owner_symbol_id
    with pytest.raises(ValueError, match="unsupported inline"):
        asyncio.run(confirm_customer_value(repository, config, route, generated_at=NOW))


def test_confirmation_reuses_matching_ai_identity_without_provider_staleness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, config = _repository(tmp_path)
    _configure_ai(config)
    monkeypatch.setattr(
        "stateguard.application.semantics.create_model_provider",
        lambda configured: _UniqueCandidateProvider(),
    )
    mapped = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    assert mapped.artifact.resolution is not None
    selected = mapped.artifact.resolution.selected_symbol_id
    assert selected is not None

    confirmed = asyncio.run(confirm_customer_value(repository, config, selected, generated_at=NOW))
    assert confirmed.artifact.resolution is not None
    assert confirmed.artifact.resolution.basis == ResolutionBasis.HUMAN_CONFIRMED
    assert (
        confirmed.artifact.provider_bundle_fingerprint
        == mapped.artifact.provider_bundle_fingerprint
    )
    assert confirmed.artifact.model_attempt == mapped.artifact.model_attempt

    config.write_text(
        config.read_text(encoding="utf-8").replace("model: model-1", "model: model-2"),
        encoding="utf-8",
    )
    refreshed = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    assert refreshed.artifact.resolution is not None
    assert refreshed.artifact.resolution.selected_symbol_id == selected
    assert refreshed.artifact.resolution.basis == ResolutionBasis.HUMAN_CONFIRMED


@pytest.mark.parametrize(
    "mismatch",
    ["provider", "model", "request_fingerprint", "provider_bundle_fingerprint"],
)
def test_confirmation_does_not_reuse_stale_provider_candidate_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    repository, config = _repository(tmp_path)
    _configure_ai(config)
    monkeypatch.setattr(
        "stateguard.application.semantics.create_model_provider",
        lambda configured: _UniqueCandidateProvider(),
    )
    mapped = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    assert mapped.artifact.resolution is not None
    selected = mapped.artifact.resolution.selected_symbol_id
    assert selected is not None
    prior = mapped.artifact
    assert prior.model_attempt is not None

    if mismatch == "provider":
        config.write_text(
            config.read_text(encoding="utf-8").replace(
                "provider: gemini",
                "provider: openai-compatible\n  base_url: https://provider.example/v1",
            ),
            encoding="utf-8",
        )
    elif mismatch == "model":
        config.write_text(
            config.read_text(encoding="utf-8").replace("model: model-1", "model: model-2"),
            encoding="utf-8",
        )
    elif mismatch == "request_fingerprint":
        prior = prior.model_copy(
            update={
                "model_attempt": prior.model_attempt.model_copy(
                    update={"request_fingerprint": sha256_digest("different request")}
                )
            }
        )
        write_semantic_artifact(repository, prior)
    else:
        prior = prior.model_copy(
            update={"provider_bundle_fingerprint": sha256_digest("different bundle")}
        )
        write_semantic_artifact(repository, prior)

    confirmed = asyncio.run(confirm_customer_value(repository, config, selected, generated_at=NOW))
    assert confirmed.artifact.resolution is not None
    assert confirmed.artifact.resolution.basis == ResolutionBasis.MANUAL_SELECTION
    assert confirmed.artifact.valid_candidates == ()
    assert confirmed.artifact.partial_bundle_suggestions == ()
    assert confirmed.artifact.provider_bundle_fingerprint is None
    assert confirmed.artifact.model_attempt is None
