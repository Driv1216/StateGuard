"""Persisted contracts for Project Discovery and the Python Source Index."""

from __future__ import annotations

import re
from collections.abc import Iterable
from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from stateguard.contracts.common import (
    ArtifactFields,
    FrameworkInstanceId,
    PersistedArtifactModel,
    ProjectId,
    Sha256Digest,
    SourceFileId,
    SourceLocation,
    SymbolId,
    normalize_relative_path,
)
from stateguard.contracts.identity import (
    canonical_json,
    fingerprint_json,
    framework_instance_id,
    source_file_id,
    symbol_id,
)

_PAYMENT_EVENTS = frozenset({"payment.authorized", "payment.captured", "payment.failed"})
_PAYMENT_STATES = frozenset({"authorized", "captured", "failed"})
_RAZORPAY_IDENTIFIERS = frozenset(
    {"razorpay_event_id", "razorpay_order_id", "razorpay_payment_id", "razorpay_signature"}
)
_WEBHOOK_HEADERS = frozenset({"x-razorpay-event-id", "x-razorpay-signature"})
_DOTTED_PYTHON_REFERENCE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")
_PYTHON_NAME = re.compile(r"^[A-Za-z_]\w*$")
_SYNTACTIC_IMPORT_REFERENCE = re.compile(r"^(?:\.*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\.\*)?|\.+\*)$")


class SourceLanguage(StrEnum):
    PYTHON = "PYTHON"


class DetectedFramework(StrEnum):
    FASTAPI = "FASTAPI"


class ArtifactCompleteness(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


class DiagnosticImpact(StrEnum):
    COVERAGE_REDUCED = "COVERAGE_REDUCED"
    NOTICE = "NOTICE"


class AnalysisDiagnosticCode(StrEnum):
    UNREADABLE_DIRECTORY = "UNREADABLE_DIRECTORY"
    UNREADABLE_FILE = "UNREADABLE_FILE"
    SYMLINK_SKIPPED = "SYMLINK_SKIPPED"
    INVALID_SOURCE_ENCODING = "INVALID_SOURCE_ENCODING"
    SYNTAX_ERROR = "SYNTAX_ERROR"
    MODULE_NAME_COLLISION = "MODULE_NAME_COLLISION"
    UNRESOLVED_RELATIVE_IMPORT = "UNRESOLVED_RELATIVE_IMPORT"
    WILDCARD_IMPORT = "WILDCARD_IMPORT"
    AMBIGUOUS_FRAMEWORK_BINDING = "AMBIGUOUS_FRAMEWORK_BINDING"
    DYNAMIC_FRAMEWORK_CONSTRUCTION = "DYNAMIC_FRAMEWORK_CONSTRUCTION"
    DYNAMIC_ROUTER_PREFIX = "DYNAMIC_ROUTER_PREFIX"
    DYNAMIC_ROUTE_PATH = "DYNAMIC_ROUTE_PATH"
    DYNAMIC_ROUTE_METHODS = "DYNAMIC_ROUTE_METHODS"
    DYNAMIC_ROUTE_REGISTRATION = "DYNAMIC_ROUTE_REGISTRATION"
    UNRESOLVED_ROUTER_INCLUDE = "UNRESOLVED_ROUTER_INCLUDE"
    AUTOMATIC_APP_TARGET_MISSING = "AUTOMATIC_APP_TARGET_MISSING"
    AUTOMATIC_APP_TARGET_AMBIGUOUS = "AUTOMATIC_APP_TARGET_AMBIGUOUS"
    CONFIGURED_APP_TARGET_MISSING = "CONFIGURED_APP_TARGET_MISSING"
    CONFIGURED_APP_TARGET_AMBIGUOUS = "CONFIGURED_APP_TARGET_AMBIGUOUS"
    CONFIGURED_APP_TARGET_UNPARSABLE = "CONFIGURED_APP_TARGET_UNPARSABLE"
    CONFIGURED_APP_TARGET_NOT_FASTAPI = "CONFIGURED_APP_TARGET_NOT_FASTAPI"


class AnalysisDiagnosticRecord(PersistedArtifactModel):
    code: AnalysisDiagnosticCode
    impact: DiagnosticImpact = DiagnosticImpact.COVERAGE_REDUCED
    path: str | None = None
    source_location: SourceLocation | None = None

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str | None) -> str | None:
        return normalize_relative_path(value) if value is not None else None

    @model_validator(mode="after")
    def validate_location_path(self) -> AnalysisDiagnosticRecord:
        if (
            self.path is not None
            and self.source_location is not None
            and self.path != self.source_location.path
        ):
            raise ValueError("diagnostic path must match its source-location path")
        return self


def completeness_for(
    diagnostics: Iterable[AnalysisDiagnosticRecord],
) -> ArtifactCompleteness:
    if any(item.impact == DiagnosticImpact.COVERAGE_REDUCED for item in diagnostics):
        return ArtifactCompleteness.PARTIAL
    return ArtifactCompleteness.COMPLETE


class SourceFileRecord(PersistedArtifactModel):
    file_id: SourceFileId
    path: str
    language: SourceLanguage = SourceLanguage.PYTHON
    content_fingerprint: Sha256Digest
    byte_size: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return normalize_relative_path(value)


def project_source_fingerprint(files: Iterable[SourceFileRecord]) -> Sha256Digest:
    """Fingerprint selected project files without depending on input ordering."""

    payload = [
        {"path": item.path, "content_fingerprint": item.content_fingerprint}
        for item in sorted(files, key=lambda record: record.path)
    ]
    return fingerprint_json(payload)


class FrameworkKind(StrEnum):
    FASTAPI_APP = "FASTAPI_APP"
    API_ROUTER = "API_ROUTER"


class AppTargetSelection(StrEnum):
    CONFIGURED = "CONFIGURED"
    AUTO_SELECTED = "AUTO_SELECTED"
    AUTO_CANDIDATE = "AUTO_CANDIDATE"


class AppTargetRecord(PersistedArtifactModel):
    framework: DetectedFramework = DetectedFramework.FASTAPI
    import_target: str = Field(min_length=3, max_length=512)
    framework_instance_id: FrameworkInstanceId
    selection: AppTargetSelection
    source_location: SourceLocation

    @field_validator("import_target")
    @classmethod
    def normalize_import_target(cls, value: str) -> str:
        stripped = value.strip()
        if ":" not in stripped:
            raise ValueError("application target must use module:attribute syntax")
        return stripped


class ProjectDiscoveryArtifact(ArtifactFields):
    artifact_type: Literal["PROJECT_DISCOVERY"] = "PROJECT_DISCOVERY"
    schema_version: Literal[2] = 2
    project_id: ProjectId
    source_root: str
    project_source_fingerprint: Sha256Digest
    files: tuple[SourceFileRecord, ...]
    app_targets: tuple[AppTargetRecord, ...] = ()
    diagnostics: tuple[AnalysisDiagnosticRecord, ...] = ()
    completeness: ArtifactCompleteness = ArtifactCompleteness.COMPLETE

    @field_validator("source_root")
    @classmethod
    def validate_source_root(cls, value: str) -> str:
        return normalize_relative_path(value)

    @model_validator(mode="after")
    def validate_discovery(self) -> ProjectDiscoveryArtifact:
        file_ids = [item.file_id for item in self.files]
        paths = [item.path for item in self.files]
        if len(file_ids) != len(set(file_ids)):
            raise ValueError("discovery file IDs must be unique")
        if len(paths) != len(set(paths)):
            raise ValueError("discovery file paths must be unique")
        for item in self.files:
            if item.file_id != source_file_id(self.project_id, item.path):
                raise ValueError("discovery file ID must match its project and path")
        if self.project_source_fingerprint != project_source_fingerprint(self.files):
            raise ValueError("project-source fingerprint must match discovered files")
        known_paths = set(paths)
        for target in self.app_targets:
            if target.source_location.path not in known_paths:
                raise ValueError("application target must refer to a discovered file")
        if self.completeness != completeness_for(self.diagnostics):
            raise ValueError("discovery completeness must match diagnostic impact")
        return self


class SymbolKind(StrEnum):
    FUNCTION = "FUNCTION"
    ASYNC_FUNCTION = "ASYNC_FUNCTION"
    METHOD = "METHOD"
    ASYNC_METHOD = "ASYNC_METHOD"
    CLASS = "CLASS"
    MODULE = "MODULE"


class SymbolRecord(PersistedArtifactModel):
    symbol_id: SymbolId
    source_file_id: SourceFileId
    qualified_name: str = Field(min_length=1, max_length=512)
    kind: SymbolKind
    signature: str = Field(max_length=2048)
    definition_ordinal: int = Field(default=0, ge=0)
    source_location: SourceLocation

    @field_validator("qualified_name", "signature")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


class ImportKind(StrEnum):
    IMPORT = "IMPORT"
    FROM_IMPORT = "FROM_IMPORT"


class ImportBindingRecord(PersistedArtifactModel):
    owner_symbol_id: SymbolId
    kind: ImportKind
    syntactic_reference: str = Field(min_length=1, max_length=512)
    local_name: str | None = Field(default=None, max_length=256)
    canonical_reference: str | None = Field(default=None, max_length=512)
    resolved_symbol_id: SymbolId | None = None
    source_location: SourceLocation

    @field_validator("syntactic_reference")
    @classmethod
    def validate_syntactic_reference(cls, value: str) -> str:
        stripped = value.strip()
        if not _SYNTACTIC_IMPORT_REFERENCE.fullmatch(stripped):
            raise ValueError("syntactic import reference must be normalized Python import syntax")
        return stripped

    @field_validator("local_name")
    @classmethod
    def validate_local_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not _PYTHON_NAME.fullmatch(stripped):
            raise ValueError("local import name must be a Python identifier")
        return stripped

    @field_validator("canonical_reference")
    @classmethod
    def validate_canonical_reference(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not _DOTTED_PYTHON_REFERENCE.fullmatch(stripped):
            raise ValueError("canonical import reference must be a dotted Python name")
        return stripped

    @model_validator(mode="after")
    def validate_resolution(self) -> ImportBindingRecord:
        if self.resolved_symbol_id is not None and self.canonical_reference is None:
            raise ValueError("resolved import symbol requires a canonical reference")
        if self.syntactic_reference.endswith(".*") and self.local_name is not None:
            raise ValueError("wildcard imports do not bind one local name")
        if not self.syntactic_reference.endswith(".*") and self.local_name is None:
            raise ValueError("non-wildcard imports must record their local name")
        return self


class FrameworkInstanceRecord(PersistedArtifactModel):
    framework_instance_id: FrameworkInstanceId
    source_file_id: SourceFileId
    qualified_binding_name: str = Field(min_length=1, max_length=512)
    kind: FrameworkKind
    definition_ordinal: int = Field(default=0, ge=0)
    prefix: str | None = Field(default="", max_length=2048)
    source_location: SourceLocation

    @field_validator("qualified_binding_name")
    @classmethod
    def validate_qualified_binding_name(cls, value: str) -> str:
        stripped = value.strip()
        if not _DOTTED_PYTHON_REFERENCE.fullmatch(stripped):
            raise ValueError("framework binding must be a dotted Python name")
        return stripped

    @field_validator("prefix")
    @classmethod
    def validate_prefix(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if stripped and not stripped.startswith("/"):
            raise ValueError("framework route prefix must be empty or begin with '/'")
        return stripped


class RouteRecord(PersistedArtifactModel):
    owner_symbol_id: SymbolId
    registrar_instance_id: FrameworkInstanceId
    method: str = Field(min_length=1)
    route_path: str = Field(max_length=2048)
    source_location: SourceLocation

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        stripped = value.strip().upper()
        if not stripped:
            raise ValueError("HTTP method must not be blank")
        return stripped

    @field_validator("route_path")
    @classmethod
    def normalize_route_path(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped.startswith("/"):
            raise ValueError("route path must begin with '/'")
        return stripped


class RouterIncludeRecord(PersistedArtifactModel):
    parent_instance_id: FrameworkInstanceId
    included_router_instance_id: FrameworkInstanceId
    prefix: str | None = Field(default="", max_length=2048)
    source_location: SourceLocation

    @field_validator("prefix")
    @classmethod
    def validate_prefix(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if stripped and not stripped.startswith("/"):
            raise ValueError("router include prefix must be empty or begin with '/'")
        return stripped


class CallSiteRecord(PersistedArtifactModel):
    caller_symbol_id: SymbolId
    callee_symbol_id: SymbolId | None = None
    callee_reference: str = Field(min_length=1, max_length=512)
    source_location: SourceLocation

    @field_validator("callee_reference")
    @classmethod
    def strip_callee_reference(cls, value: str) -> str:
        return value.strip()


class SourceReferenceKind(StrEnum):
    IMPORT = "IMPORT"
    ATTRIBUTE = "ATTRIBUTE"
    IDENTIFIER = "IDENTIFIER"
    PAYMENT_LITERAL = "PAYMENT_LITERAL"


class PaymentLiteralKind(StrEnum):
    PAYMENT_EVENT = "PAYMENT_EVENT"
    PAYMENT_STATE = "PAYMENT_STATE"
    RAZORPAY_IDENTIFIER = "RAZORPAY_IDENTIFIER"
    WEBHOOK_HEADER = "WEBHOOK_HEADER"


def classify_payment_literal(raw_value: str) -> tuple[PaymentLiteralKind, str] | None:
    """Return a bounded, recognized payment literal or omit arbitrary source text."""

    normalized = raw_value.strip().casefold()
    if not normalized or len(normalized) > 256:
        return None
    if normalized in _PAYMENT_EVENTS:
        return PaymentLiteralKind.PAYMENT_EVENT, normalized
    if normalized in _PAYMENT_STATES:
        return PaymentLiteralKind.PAYMENT_STATE, normalized
    if normalized in _RAZORPAY_IDENTIFIERS:
        return PaymentLiteralKind.RAZORPAY_IDENTIFIER, normalized
    if normalized in _WEBHOOK_HEADERS:
        return PaymentLiteralKind.WEBHOOK_HEADER, normalized
    return None


class SourceReferenceRecord(PersistedArtifactModel):
    kind: SourceReferenceKind
    value: str = Field(min_length=1, max_length=256)
    payment_literal_kind: PaymentLiteralKind | None = None
    source_location: SourceLocation

    @field_validator("value")
    @classmethod
    def strip_value(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def validate_reference(self) -> SourceReferenceRecord:
        if self.kind == SourceReferenceKind.PAYMENT_LITERAL:
            classified = classify_payment_literal(self.value)
            if classified is None:
                raise ValueError("payment literal must be a recognized safe payment constant")
            literal_kind, normalized = classified
            if self.payment_literal_kind != literal_kind or self.value.casefold() != normalized:
                raise ValueError(
                    "payment literal kind/value must match deterministic classification"
                )
        elif self.payment_literal_kind is not None:
            raise ValueError("payment_literal_kind is valid only for payment literal references")
        elif self.kind == SourceReferenceKind.IDENTIFIER:
            if self.value not in _RAZORPAY_IDENTIFIERS:
                raise ValueError("identifier reference must be a recognized Razorpay identifier")
        elif not _DOTTED_PYTHON_REFERENCE.fullmatch(self.value):
            raise ValueError("import and attribute references must be dotted Python names")
        return self


def source_reference_for_payment_literal(
    raw_value: str, source_location: SourceLocation
) -> SourceReferenceRecord | None:
    """Create persisted evidence only when a raw AST string is recognized and bounded."""

    classified = classify_payment_literal(raw_value)
    if classified is None:
        return None
    literal_kind, normalized = classified
    return SourceReferenceRecord(
        kind=SourceReferenceKind.PAYMENT_LITERAL,
        value=normalized,
        payment_literal_kind=literal_kind,
        source_location=source_location,
    )


def source_reference_for_payment_identifier(
    raw_name: str, source_location: SourceLocation
) -> SourceReferenceRecord | None:
    normalized = raw_name.strip().casefold()
    if normalized not in _RAZORPAY_IDENTIFIERS:
        return None
    return SourceReferenceRecord(
        kind=SourceReferenceKind.IDENTIFIER,
        value=normalized,
        source_location=source_location,
    )


def _ordered_records(records: Iterable[PersistedArtifactModel]) -> list[dict[str, object]]:
    return [
        record.model_dump(mode="json")
        for record in sorted(records, key=lambda item: canonical_json(item))
    ]


def source_index_fingerprint(
    *,
    project_id: ProjectId,
    project_source_fingerprint: Sha256Digest,
    indexed_files: Iterable[SourceFileRecord],
    symbols: Iterable[SymbolRecord],
    imports: Iterable[ImportBindingRecord] = (),
    call_sites: Iterable[CallSiteRecord] = (),
    references: Iterable[SourceReferenceRecord] = (),
    framework_instances: Iterable[FrameworkInstanceRecord] = (),
    app_targets: Iterable[AppTargetRecord] = (),
    routes: Iterable[RouteRecord] = (),
    router_includes: Iterable[RouterIncludeRecord] = (),
    diagnostics: Iterable[AnalysisDiagnosticRecord] = (),
    completeness: ArtifactCompleteness = ArtifactCompleteness.COMPLETE,
) -> Sha256Digest:
    """Fingerprint semantic Source Index contents, excluding artifact metadata and itself."""

    return fingerprint_json(
        {
            "schema_version": 2,
            "project_id": project_id,
            "project_source_fingerprint": project_source_fingerprint,
            "indexed_files": _ordered_records(indexed_files),
            "symbols": _ordered_records(symbols),
            "imports": _ordered_records(imports),
            "call_sites": _ordered_records(call_sites),
            "references": _ordered_records(references),
            "framework_instances": _ordered_records(framework_instances),
            "app_targets": _ordered_records(app_targets),
            "routes": _ordered_records(routes),
            "router_includes": _ordered_records(router_includes),
            "diagnostics": _ordered_records(diagnostics),
            "completeness": completeness,
        }
    )


class SourceIndexArtifact(ArtifactFields):
    artifact_type: Literal["SOURCE_INDEX"] = "SOURCE_INDEX"
    schema_version: Literal[2] = 2
    project_id: ProjectId
    project_source_fingerprint: Sha256Digest
    source_index_fingerprint: Sha256Digest
    indexed_files: tuple[SourceFileRecord, ...]
    symbols: tuple[SymbolRecord, ...]
    imports: tuple[ImportBindingRecord, ...] = ()
    call_sites: tuple[CallSiteRecord, ...] = ()
    references: tuple[SourceReferenceRecord, ...] = ()
    framework_instances: tuple[FrameworkInstanceRecord, ...] = ()
    app_targets: tuple[AppTargetRecord, ...] = ()
    routes: tuple[RouteRecord, ...] = ()
    router_includes: tuple[RouterIncludeRecord, ...] = ()
    diagnostics: tuple[AnalysisDiagnosticRecord, ...] = ()
    completeness: ArtifactCompleteness = ArtifactCompleteness.COMPLETE

    @model_validator(mode="after")
    def validate_index(self) -> SourceIndexArtifact:
        file_ids = [item.file_id for item in self.indexed_files]
        file_paths = [item.path for item in self.indexed_files]
        symbol_ids = [item.symbol_id for item in self.symbols]
        framework_ids = [item.framework_instance_id for item in self.framework_instances]
        if len(file_ids) != len(set(file_ids)):
            raise ValueError("indexed file IDs must be unique")
        if len(file_paths) != len(set(file_paths)):
            raise ValueError("indexed file paths must be unique")
        if len(symbol_ids) != len(set(symbol_ids)):
            raise ValueError("symbol IDs must be unique")
        if len(framework_ids) != len(set(framework_ids)):
            raise ValueError("framework-instance IDs must be unique")

        known_files = set(file_ids)
        known_paths = set(file_paths)
        known_symbols = set(symbol_ids)
        known_framework = set(framework_ids)
        path_by_file_id = {item.file_id: item.path for item in self.indexed_files}
        symbol_by_id = {item.symbol_id: item for item in self.symbols}
        framework_by_id = {item.framework_instance_id: item for item in self.framework_instances}
        for item in self.indexed_files:
            if item.file_id != source_file_id(self.project_id, item.path):
                raise ValueError("indexed file ID must match its project and path")
        if self.project_source_fingerprint != project_source_fingerprint(self.indexed_files):
            raise ValueError("project-source fingerprint must match indexed files")
        for symbol in self.symbols:
            if symbol.source_file_id not in known_files:
                raise ValueError("symbol must refer to an indexed file")
            if symbol.source_location.path != path_by_file_id[symbol.source_file_id]:
                raise ValueError("symbol location must match its source file")
            expected_symbol_id = symbol_id(
                symbol.source_file_id,
                symbol.qualified_name,
                symbol.kind.value,
                symbol.definition_ordinal,
            )
            if symbol.symbol_id != expected_symbol_id:
                raise ValueError("symbol ID must match its backing fields")
        for binding in self.imports:
            if binding.owner_symbol_id not in known_symbols:
                raise ValueError("import owner must refer to an indexed symbol")
            if (
                binding.resolved_symbol_id is not None
                and binding.resolved_symbol_id not in known_symbols
            ):
                raise ValueError("resolved import must refer to an indexed symbol")
            owner = symbol_by_id[binding.owner_symbol_id]
            if binding.source_location.path != path_by_file_id[owner.source_file_id]:
                raise ValueError("import location must match its owning scope file")
        for framework_instance in self.framework_instances:
            if framework_instance.source_file_id not in known_files:
                raise ValueError("framework instance must refer to an indexed file")
            if (
                framework_instance.source_location.path
                != path_by_file_id[framework_instance.source_file_id]
            ):
                raise ValueError("framework-instance location must match its source file")
            expected_id = framework_instance_id(
                framework_instance.source_file_id,
                framework_instance.qualified_binding_name,
                framework_instance.kind.value,
                framework_instance.definition_ordinal,
            )
            if framework_instance.framework_instance_id != expected_id:
                raise ValueError("framework-instance ID must match its backing fields")
        for target in self.app_targets:
            if target.framework_instance_id not in known_framework:
                raise ValueError("application target must refer to a framework instance")
            instance = framework_by_id[target.framework_instance_id]
            if instance.kind != FrameworkKind.FASTAPI_APP:
                raise ValueError("application target must refer to a FastAPI app")
            if target.source_location != instance.source_location:
                raise ValueError("application target location must match its framework instance")
        for route in self.routes:
            if route.owner_symbol_id not in known_symbols:
                raise ValueError("route must refer to an indexed symbol")
            if route.registrar_instance_id not in known_framework:
                raise ValueError("route must refer to a framework instance")
            owner = symbol_by_id[route.owner_symbol_id]
            if route.source_location.path != path_by_file_id[owner.source_file_id]:
                raise ValueError("route location must match its owning symbol file")
        for include in self.router_includes:
            if include.parent_instance_id not in known_framework:
                raise ValueError("router include parent must refer to a framework instance")
            if include.included_router_instance_id not in known_framework:
                raise ValueError("included router must refer to a framework instance")
            included_kind = framework_by_id[include.included_router_instance_id].kind
            if included_kind != FrameworkKind.API_ROUTER:
                raise ValueError("included framework instance must be an API router")
            parent = framework_by_id[include.parent_instance_id]
            if include.source_location.path != path_by_file_id[parent.source_file_id]:
                raise ValueError("router include location must match its parent instance file")
        for call in self.call_sites:
            if call.caller_symbol_id not in known_symbols:
                raise ValueError("call site caller must refer to an indexed symbol")
            if call.callee_symbol_id is not None and call.callee_symbol_id not in known_symbols:
                raise ValueError("resolved call-site callee must refer to an indexed symbol")
            caller = symbol_by_id[call.caller_symbol_id]
            if call.source_location.path != path_by_file_id[caller.source_file_id]:
                raise ValueError("call-site location must match its caller symbol file")
        for reference in self.references:
            if reference.source_location.path not in known_paths:
                raise ValueError("source reference must refer to an indexed file path")
        if self.completeness != completeness_for(self.diagnostics):
            raise ValueError("source-index completeness must match diagnostic impact")
        expected_fingerprint = source_index_fingerprint(
            project_id=self.project_id,
            project_source_fingerprint=self.project_source_fingerprint,
            indexed_files=self.indexed_files,
            symbols=self.symbols,
            imports=self.imports,
            call_sites=self.call_sites,
            references=self.references,
            framework_instances=self.framework_instances,
            app_targets=self.app_targets,
            routes=self.routes,
            router_includes=self.router_includes,
            diagnostics=self.diagnostics,
            completeness=self.completeness,
        )
        if self.source_index_fingerprint != expected_fingerprint:
            raise ValueError("source-index fingerprint must match indexed contents")
        return self
