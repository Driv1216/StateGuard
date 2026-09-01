from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from stateguard.contracts.identity import sha256_digest
from stateguard.evidence.contracts import VerificationCheck, VerificationRun
from stateguard.failure_lab.contracts import VerificationResultState
from stateguard.model_providers.protocol import (
    ModelProviderCapabilities,
    ModelProviderError,
    StructuredGenerationRequest,
    StructuredGenerationResult,
)
from stateguard.remediation.comparison import compare_exact_check
from stateguard.remediation.context_builder import RemediationContext
from stateguard.remediation.contracts import (
    AssistanceMode,
    ComparisonOutcome,
    EditableRegion,
    EditableRegionKind,
)
from stateguard.remediation.generator import generate_assistance
from stateguard.remediation.patch_validation import UnsafePatchError, validate_and_render_patch

RUN_ID = "sgvrun_" + "1" * 32
CURRENT_RUN_ID = "sgvrun_" + "2" * 32
CHECK_ID = "sgcheck_" + "3" * 32
CURRENT_CHECK_ID = "sgcheck_" + "4" * 32
CHECK_KEY = "sgcheckkey_" + "5" * 32
OCCURRENCE_ID = "sgfinding_" + "6" * 32


class FakeProvider:
    def __init__(self, output: dict[str, object]) -> None:
        self.output = output
        self.request: StructuredGenerationRequest | None = None

    def capabilities(self) -> ModelProviderCapabilities:
        return ModelProviderCapabilities(
            provider_id="fake",
            model="fake-model",
            structured_output=True,
        )

    async def generate_structured(
        self, request: StructuredGenerationRequest
    ) -> StructuredGenerationResult:
        self.request = request
        return StructuredGenerationResult(
            request_id=request.request_id,
            provider_id="fake",
            model="fake-model",
            output=self.output,
            latency_ms=1,
        )


def _region(repository: Path) -> EditableRegion:
    path = repository / "merchant.py"
    content = "def deliver():\n    return 'once'\n"
    path.write_text(content, encoding="utf-8")
    return EditableRegion(
        region_reference="region-1",
        kind=EditableRegionKind.FULL_SYMBOL,
        path="merchant.py",
        start_offset=0,
        end_offset=len(content),
        file_fingerprint=sha256_digest(content.encode()),
        region_fingerprint=sha256_digest(content),
        content=content,
    )


def _context(
    repository: Path,
    *,
    mode: AssistanceMode,
) -> RemediationContext:
    regions = (_region(repository),) if mode == AssistanceMode.CURRENT_SOURCE_REMEDIATION else ()
    references = frozenset({"historical-result", *(item.region_reference for item in regions)})
    return RemediationContext(
        run=SimpleNamespace(run_id=RUN_ID),
        finding=SimpleNamespace(occurrence_id=OCCURRENCE_ID),
        check=SimpleNamespace(
            check_id=CHECK_ID,
            check_key=CHECK_KEY,
            invariant_id="DUPLICATE_DELIVERY_VALUE_AT_MOST_ONCE",
            invariant_version=1,
        ),
        config=SimpleNamespace(),
        mode=mode,
        mode_label=(
            f"HISTORICAL EXPLANATION — REFERS TO RUN {RUN_ID}; CURRENT SOURCE NOT USED"
            if mode == AssistanceMode.HISTORICAL_EXPLANATION_ONLY
            else "CURRENT SOURCE REMEDIATION — AI-GENERATED AND NOT VERIFIED"
        ),
        references=(),
        provider_input='{"mode":"bounded"}',
        allowed_reference_ids=references,
        editable_regions=regions,
        historical_relevant_fingerprint=None,
        current_relevant_fingerprint=None,
        drift=(),
    )


def test_current_proposal_is_rendered_in_memory_without_writing(tmp_path: Path) -> None:
    context = _context(tmp_path, mode=AssistanceMode.CURRENT_SOURCE_REMEDIATION)
    provider = FakeProvider(
        {
            "causal_summary": "Duplicate delivery entered the proven target twice.",
            "grounded_claims": [
                {"text": "The second delivery repeated value.", "references": ["historical-result"]}
            ],
            "remediation_rationale": "Make the delivery operation idempotent.",
            "proposal_state": "PROPOSED",
            "edits": [
                {
                    "region_reference": "region-1",
                    "replacement_content": "def deliver():\n    return 'idempotent'\n",
                }
            ],
            "limitations": [],
        }
    )
    original = (tmp_path / "merchant.py").read_text(encoding="utf-8")
    assistance = asyncio.run(generate_assistance(tmp_path, context, provider))
    assert assistance.patch is not None
    assert "AI_GENERATED_NOT_VERIFIED" == assistance.patch.verification_state
    assert "+    return 'idempotent'" in assistance.patch.diff
    assert (tmp_path / "merchant.py").read_text(encoding="utf-8") == original
    assert provider.request is not None
    assert "untrusted data" in provider.request.instructions


def test_historical_explanation_has_no_patch_or_current_source(tmp_path: Path) -> None:
    context = _context(tmp_path, mode=AssistanceMode.HISTORICAL_EXPLANATION_ONLY)
    provider = FakeProvider(
        {
            "causal_summary": "The immutable run proved a duplicate effect.",
            "grounded_claims": [
                {"text": "This claim is historical.", "references": ["historical-result"]}
            ],
            "remediation_rationale": None,
            "proposal_state": "BLOCKED_CURRENT_SOURCE_AUTHORITY",
            "edits": [],
            "limitations": ["Current source was not used."],
        }
    )
    assistance = asyncio.run(generate_assistance(tmp_path, context, provider))
    assert assistance.patch is None
    assert assistance.mode == AssistanceMode.HISTORICAL_EXPLANATION_ONLY
    assert "merchant_source" not in context.provider_input


def test_unknown_grounding_reference_rejects_provider_output(tmp_path: Path) -> None:
    context = _context(tmp_path, mode=AssistanceMode.HISTORICAL_EXPLANATION_ONLY)
    provider = FakeProvider(
        {
            "causal_summary": "Unsupported claim.",
            "grounded_claims": [{"text": "Invented.", "references": ["unknown"]}],
            "remediation_rationale": None,
            "proposal_state": "BLOCKED_CURRENT_SOURCE_AUTHORITY",
            "edits": [],
            "limitations": [],
        }
    )
    with pytest.raises(ModelProviderError):
        asyncio.run(generate_assistance(tmp_path, context, provider))


def test_stale_region_and_invalid_python_are_rejected(tmp_path: Path) -> None:
    region = _region(tmp_path)
    (tmp_path / "merchant.py").write_text(
        "def deliver():\n    return 'changed'\n", encoding="utf-8"
    )
    with pytest.raises(UnsafePatchError, match="changed"):
        validate_and_render_patch(
            tmp_path,
            (region,),
            (SimpleNamespace(region_reference="region-1", replacement_content="pass"),),
        )
    region = _region(tmp_path)
    with pytest.raises(UnsafePatchError, match="Python 3.11"):
        validate_and_render_patch(
            tmp_path,
            (region,),
            (SimpleNamespace(region_reference="region-1", replacement_content="def broken(:\n"),),
        )


@pytest.mark.parametrize(
    ("state", "outcome"),
    [
        (VerificationResultState.VERIFIED_PASS, ComparisonOutcome.PROVEN_RESOLVED),
        (VerificationResultState.VERIFIED_FAIL, ComparisonOutcome.STILL_VERIFIED_FAIL),
        (VerificationResultState.UNVERIFIED, ComparisonOutcome.NOT_PROVEN),
        (VerificationResultState.NEEDS_INPUT, ComparisonOutcome.NOT_PROVEN),
        (VerificationResultState.STATIC_WARNING, ComparisonOutcome.NOT_PROVEN),
        (VerificationResultState.NOT_APPLICABLE, ComparisonOutcome.NOT_APPLICABLE),
    ],
)
def test_comparison_uses_exact_logical_key(
    state: VerificationResultState,
    outcome: ComparisonOutcome,
) -> None:
    historical_check = VerificationCheck.model_construct(check_key=CHECK_KEY)
    current_check = VerificationCheck.model_construct(
        check_key=CHECK_KEY,
        check_id=CURRENT_CHECK_ID,
        result=state,
    )
    historical = VerificationRun.model_construct(run_id=RUN_ID, checks=(historical_check,))
    current = VerificationRun.model_construct(run_id=CURRENT_RUN_ID, checks=(current_check,))
    assert compare_exact_check(historical, historical_check, current).outcome == outcome


def test_missing_exact_key_is_not_directly_comparable() -> None:
    historical_check = VerificationCheck.model_construct(check_key=CHECK_KEY)
    other = VerificationCheck.model_construct(
        check_key="sgcheckkey_" + "9" * 32,
        check_id=CURRENT_CHECK_ID,
        result=VerificationResultState.VERIFIED_PASS,
    )
    historical = VerificationRun.model_construct(run_id=RUN_ID, checks=(historical_check,))
    current = VerificationRun.model_construct(run_id=CURRENT_RUN_ID, checks=(other,))
    comparison = compare_exact_check(historical, historical_check, current)
    assert comparison.outcome == ComparisonOutcome.NOT_DIRECTLY_COMPARABLE
    assert comparison.changed_dimension is None
