from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from stateguard.contracts.common import SourceLocation
from stateguard.contracts.identity import (
    framework_instance_id,
    new_project_id,
    sha256_digest,
    source_file_id,
    symbol_id,
)
from stateguard.discovery.contracts import (
    AnalysisDiagnosticCode,
    AnalysisDiagnosticRecord,
    AppTargetRecord,
    AppTargetSelection,
    ArtifactCompleteness,
    CallSiteRecord,
    DetectedFramework,
    FrameworkInstanceRecord,
    FrameworkKind,
    PaymentLiteralKind,
    ProjectDiscoveryArtifact,
    RouteRecord,
    SourceFileRecord,
    SourceIndexArtifact,
    SourceLanguage,
    SourceReferenceKind,
    SourceReferenceRecord,
    SymbolKind,
    SymbolRecord,
    project_source_fingerprint,
    source_index_fingerprint,
    source_reference_for_payment_literal,
)

NOW = datetime(2026, 8, 24, tzinfo=UTC)


def _fixture() -> tuple[object, SourceFileRecord, SymbolRecord, SourceLocation]:
    project = new_project_id()
    location = SourceLocation(
        path="app/main.py", line_start=1, column_start=0, line_end=4, column_end=0
    )
    file = SourceFileRecord(
        file_id=source_file_id(project, location.path),
        path=location.path,
        language=SourceLanguage.PYTHON,
        content_fingerprint=sha256_digest("source"),
        byte_size=20,
    )
    symbol = SymbolRecord(
        symbol_id=symbol_id(file.file_id, "app.main.webhook", SymbolKind.ASYNC_FUNCTION.value),
        source_file_id=file.file_id,
        qualified_name="app.main.webhook",
        kind=SymbolKind.ASYNC_FUNCTION,
        signature="(request)",
        source_location=location,
    )
    return project, file, symbol, location


def _framework(file: SourceFileRecord, location: SourceLocation) -> FrameworkInstanceRecord:
    qualified = "app.main.app"
    return FrameworkInstanceRecord(
        framework_instance_id=framework_instance_id(
            file.file_id,
            qualified,
            FrameworkKind.FASTAPI_APP.value,
        ),
        source_file_id=file.file_id,
        qualified_binding_name=qualified,
        kind=FrameworkKind.FASTAPI_APP,
        source_location=location,
    )


def test_discovery_and_source_index_round_trip() -> None:
    project, file, symbol, location = _fixture()
    framework = _framework(file, location)
    app_targets = (
        AppTargetRecord(
            framework=DetectedFramework.FASTAPI,
            import_target="app.main:app",
            framework_instance_id=framework.framework_instance_id,
            selection=AppTargetSelection.AUTO_SELECTED,
            source_location=location,
        ),
    )
    discovery = ProjectDiscoveryArtifact(
        producer_version="0.1.0",
        generated_at=NOW,
        project_id=project,
        source_root=".",
        project_source_fingerprint=project_source_fingerprint((file,)),
        files=(file,),
        app_targets=app_targets,
    )
    routes = (
        RouteRecord(
            owner_symbol_id=symbol.symbol_id,
            registrar_instance_id=framework.framework_instance_id,
            method="post",
            route_path="/webhooks",
            source_location=location,
        ),
    )
    call_sites = (
        CallSiteRecord(
            caller_symbol_id=symbol.symbol_id,
            callee_reference="razorpay.utility.verify_webhook_signature",
            source_location=location,
        ),
    )
    references = (
        SourceReferenceRecord(
            kind=SourceReferenceKind.IMPORT,
            value="razorpay",
            source_location=location,
        ),
    )
    index_fingerprint = source_index_fingerprint(
        project_id=project,
        project_source_fingerprint=discovery.project_source_fingerprint,
        indexed_files=(file,),
        symbols=(symbol,),
        framework_instances=(framework,),
        app_targets=app_targets,
        routes=routes,
        call_sites=call_sites,
        references=references,
    )
    index = SourceIndexArtifact(
        producer_version="0.1.0",
        generated_at=NOW,
        project_id=project,
        project_source_fingerprint=discovery.project_source_fingerprint,
        source_index_fingerprint=index_fingerprint,
        indexed_files=(file,),
        symbols=(symbol,),
        framework_instances=(framework,),
        app_targets=app_targets,
        routes=routes,
        call_sites=call_sites,
        references=references,
    )
    restored = SourceIndexArtifact.model_validate_json(index.model_dump_json())
    assert restored == index
    assert restored.routes[0].method == "POST"


def test_source_index_rejects_unknown_internal_references_and_versions() -> None:
    project, file, symbol, location = _fixture()
    unknown = symbol_id(file.file_id, "app.main.unknown", SymbolKind.FUNCTION.value)
    with pytest.raises(ValidationError):
        SourceIndexArtifact(
            producer_version="0.1.0",
            generated_at=NOW,
            project_id=project,
            project_source_fingerprint=project_source_fingerprint((file,)),
            source_index_fingerprint=sha256_digest("index"),
            indexed_files=(file,),
            symbols=(symbol,),
            routes=(),
            call_sites=(
                CallSiteRecord(
                    caller_symbol_id=symbol.symbol_id,
                    callee_symbol_id=unknown,
                    callee_reference="app.main.unknown",
                    source_location=location,
                ),
            ),
        )
    with pytest.raises(ValidationError):
        ProjectDiscoveryArtifact.model_validate(
            {
                "artifact_type": "PROJECT_DISCOVERY",
                "schema_version": 3,
                "producer_version": "0.1.0",
                "generated_at": NOW,
                "project_id": project,
                "source_root": ".",
                "project_source_fingerprint": project_source_fingerprint(()),
                "files": [],
            }
        )


def test_line_movement_preserves_symbol_identity_but_backing_mismatches_fail() -> None:
    project, file, symbol, _ = _fixture()
    moved_location = SourceLocation(
        path=file.path, line_start=40, column_start=0, line_end=44, column_end=0
    )
    moved_symbol = SymbolRecord(
        symbol_id=symbol.symbol_id,
        source_file_id=file.file_id,
        qualified_name=symbol.qualified_name,
        kind=symbol.kind,
        signature=symbol.signature,
        source_location=moved_location,
    )
    assert moved_symbol.symbol_id == symbol.symbol_id

    wrong_file_id = source_file_id(project, "app/other.py")
    mismatched_file = file.model_copy(update={"file_id": wrong_file_id})
    with pytest.raises(ValidationError, match="file ID must match"):
        ProjectDiscoveryArtifact(
            producer_version="0.1.0",
            generated_at=NOW,
            project_id=project,
            source_root=".",
            project_source_fingerprint=project_source_fingerprint((mismatched_file,)),
            files=(mismatched_file,),
        )

    wrong_symbol_id = symbol_id(file.file_id, "app.main.different", symbol.kind.value)
    mismatched_symbol = symbol.model_copy(update={"symbol_id": wrong_symbol_id})
    with pytest.raises(ValidationError, match="symbol ID must match"):
        SourceIndexArtifact(
            producer_version="0.1.0",
            generated_at=NOW,
            project_id=project,
            project_source_fingerprint=project_source_fingerprint((file,)),
            source_index_fingerprint=sha256_digest("placeholder"),
            indexed_files=(file,),
            symbols=(mismatched_symbol,),
        )


def test_symbol_route_and_call_locations_must_match_their_owning_file() -> None:
    project, file, symbol, _ = _fixture()
    framework = _framework(file, symbol.source_location)
    other_location = SourceLocation(
        path="app/other.py", line_start=1, column_start=0, line_end=1, column_end=1
    )
    other_file = SourceFileRecord(
        file_id=source_file_id(project, other_location.path),
        path=other_location.path,
        content_fingerprint=sha256_digest("other source"),
        byte_size=12,
    )
    project_fingerprint = project_source_fingerprint((file, other_file))

    def validate_with(
        *,
        symbols: tuple[SymbolRecord, ...] = (symbol,),
        routes: tuple[RouteRecord, ...] = (),
        calls: tuple[CallSiteRecord, ...] = (),
    ) -> None:
        SourceIndexArtifact(
            producer_version="0.1.0",
            generated_at=NOW,
            project_id=project,
            project_source_fingerprint=project_fingerprint,
            source_index_fingerprint=sha256_digest("placeholder"),
            indexed_files=(file, other_file),
            symbols=symbols,
            framework_instances=(framework,),
            routes=routes,
            call_sites=calls,
        )

    misplaced_symbol = symbol.model_copy(update={"source_location": other_location})
    with pytest.raises(ValidationError, match="symbol location must match"):
        validate_with(symbols=(misplaced_symbol,))
    with pytest.raises(ValidationError, match="route location must match"):
        validate_with(
            routes=(
                RouteRecord(
                    owner_symbol_id=symbol.symbol_id,
                    registrar_instance_id=framework.framework_instance_id,
                    method="POST",
                    route_path="/webhooks",
                    source_location=other_location,
                ),
            )
        )
    with pytest.raises(ValidationError, match="call-site location must match"):
        validate_with(
            calls=(
                CallSiteRecord(
                    caller_symbol_id=symbol.symbol_id,
                    callee_reference="grant_value",
                    source_location=other_location,
                ),
            )
        )


def test_only_recognized_bounded_payment_literals_are_persistable() -> None:
    _, _, _, location = _fixture()
    evidence = source_reference_for_payment_literal(" Payment.Captured ", location)
    assert evidence is not None
    assert evidence.kind == SourceReferenceKind.PAYMENT_LITERAL
    assert evidence.payment_literal_kind == PaymentLiteralKind.PAYMENT_EVENT
    assert evidence.value == "payment.captured"

    assert source_reference_for_payment_literal("sk_live_private_secret", location) is None
    assert source_reference_for_payment_literal("unrelated merchant copy", location) is None
    assert source_reference_for_payment_literal("x" * 10_000, location) is None
    with pytest.raises(ValidationError, match="recognized safe payment constant"):
        SourceReferenceRecord(
            kind=SourceReferenceKind.PAYMENT_LITERAL,
            value="sk_live_private_secret",
            payment_literal_kind=PaymentLiteralKind.RAZORPAY_IDENTIFIER,
            source_location=location,
        )


def test_partial_completeness_requires_coverage_diagnostic() -> None:
    project, file, _, _ = _fixture()
    diagnostic = AnalysisDiagnosticRecord(
        code=AnalysisDiagnosticCode.SYNTAX_ERROR,
        path=file.path,
    )
    partial = ProjectDiscoveryArtifact(
        producer_version="0.1.0",
        generated_at=NOW,
        project_id=project,
        source_root=".",
        project_source_fingerprint=project_source_fingerprint((file,)),
        files=(file,),
        diagnostics=(diagnostic,),
        completeness=ArtifactCompleteness.PARTIAL,
    )
    assert partial.completeness == ArtifactCompleteness.PARTIAL
    with pytest.raises(ValidationError, match="completeness"):
        partial.model_copy(update={"completeness": ArtifactCompleteness.COMPLETE}).model_validate(
            partial.model_copy(update={"completeness": ArtifactCompleteness.COMPLETE}).model_dump()
        )


def test_project_and_source_index_fingerprints_are_canonical_and_relevance_scoped() -> None:
    project, file, symbol, location = _fixture()
    other_file = SourceFileRecord(
        file_id=source_file_id(project, "app/other.py"),
        path="app/other.py",
        content_fingerprint=sha256_digest("other source"),
        byte_size=12,
    )
    first_project = project_source_fingerprint((file, other_file))
    assert project_source_fingerprint((other_file, file)) == first_project
    changed_file = file.model_copy(update={"content_fingerprint": sha256_digest("changed")})
    assert project_source_fingerprint((changed_file, other_file)) != first_project

    import_reference = SourceReferenceRecord(
        kind=SourceReferenceKind.IMPORT, value="razorpay", source_location=location
    )
    attribute_reference = SourceReferenceRecord(
        kind=SourceReferenceKind.ATTRIBUTE,
        value="razorpay.utility",
        source_location=location,
    )
    source_fingerprint = project_source_fingerprint((file,))

    def fingerprint_for(references: tuple[SourceReferenceRecord, ...]) -> str:
        return source_index_fingerprint(
            project_id=project,
            project_source_fingerprint=source_fingerprint,
            indexed_files=(file,),
            symbols=(symbol,),
            references=references,
        )

    references = (import_reference, attribute_reference)
    first_index = fingerprint_for(references)
    assert fingerprint_for(tuple(reversed(references))) == first_index
    changed_reference = import_reference.model_copy(update={"value": "razorpay.client"})
    assert fingerprint_for((changed_reference, attribute_reference)) != first_index

    artifact = SourceIndexArtifact(
        producer_version="0.1.0",
        generated_at=NOW,
        project_id=project,
        project_source_fingerprint=source_fingerprint,
        source_index_fingerprint=first_index,
        indexed_files=(file,),
        symbols=(symbol,),
        references=references,
    )
    changed_metadata = artifact.model_dump(mode="python")
    changed_metadata["producer_version"] = "9.9.9"
    changed_metadata["generated_at"] = datetime(2030, 1, 1, tzinfo=UTC)
    assert (
        SourceIndexArtifact.model_validate(changed_metadata).source_index_fingerprint == first_index
    )
