"""Step 10 provider assistance and canonical current-verification use cases."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from stateguard.application.verification import (
    VerificationRunUseCaseResult,
    create_verification_run,
)
from stateguard.model_providers.factory import create_model_provider
from stateguard.model_providers.protocol import ModelProviderError, ProviderFailureCode
from stateguard.remediation.comparison import compare_exact_check
from stateguard.remediation.context_builder import (
    _select_verified_failure,
    build_remediation_context,
)
from stateguard.remediation.contracts import RemediationAssistance, ReverificationResult
from stateguard.remediation.generator import generate_assistance
from stateguard.workspace.config import load_config
from stateguard.workspace.run_artifacts import load_verification_run

CanonicalCurrentVerifier = Callable[[Path, Path], VerificationRunUseCaseResult]


async def generate_remediation_assistance(
    repository_root: Path,
    config_path: Path,
    run_id: str,
    occurrence_id: str,
) -> RemediationAssistance:
    context = build_remediation_context(repository_root, config_path, run_id, occurrence_id)
    if context.config.ai is None:
        raise ModelProviderError(ProviderFailureCode.INCOMPATIBLE_MODEL)
    provider = create_model_provider(context.config.ai)
    try:
        return await generate_assistance(repository_root, context, provider)
    finally:
        close = getattr(provider, "aclose", None)
        if close is not None:
            await close()


def verify_current_authority(
    repository_root: Path,
    config_path: Path,
) -> VerificationRunUseCaseResult:
    """Canonical seam; Step 10 intentionally delegates to the complete verifier today."""

    return create_verification_run(repository_root, config_path)


def verify_current_finding(
    repository_root: Path,
    config_path: Path,
    run_id: str,
    occurrence_id: str,
    *,
    verifier: CanonicalCurrentVerifier = verify_current_authority,
) -> ReverificationResult:
    historical = load_verification_run(repository_root, run_id)
    _, check = _select_verified_failure(historical, occurrence_id)
    # Validate configuration before entering the canonical verifier so adapters receive
    # the same bounded configuration failure semantics as other operations.
    load_config(config_path)
    current = verifier(repository_root, config_path).artifact
    return ReverificationResult(
        run=current,
        comparison=compare_exact_check(historical, check, current),
    )
