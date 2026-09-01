from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from stateguard.contracts.config import StateGuardConfig
from stateguard.contracts.identity import new_project_id
from stateguard.discovery.contracts import (
    AnalysisDiagnosticCode,
    AppTargetSelection,
    ArtifactCompleteness,
    FrameworkKind,
    SourceReferenceKind,
    SymbolKind,
)
from stateguard.discovery.files import ProjectDiscoveryError, matches_glob
from stateguard.discovery.service import (
    StaleSourceIndexError,
    discover_and_index_project,
    validate_indexed_source_snapshot,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"
NOW = datetime(2026, 8, 24, tzinfo=UTC)


def _copy_fixture(tmp_path: Path, name: str) -> Path:
    destination = tmp_path / name
    shutil.copytree(FIXTURES / name, destination)
    return destination


def _config(
    *,
    app_target: str | None = None,
    exclude: tuple[str, ...] = (".venv/**", "venv/**", ".git/**", ".stateguard/**"),
) -> StateGuardConfig:
    project: dict[str, object] = {
        "id": new_project_id(),
        "source_root": ".",
        "framework": "fastapi",
    }
    if app_target is not None:
        project["app_target"] = app_target
    return StateGuardConfig.model_validate(
        {
            "schema_version": 2,
            "project": project,
            "analysis": {"include": ["**/*.py"], "exclude": list(exclude)},
        }
    )


def test_glob_double_star_matches_zero_or_more_segments() -> None:
    assert matches_glob("main.py", "**/*.py")
    assert matches_glob("app/main.py", "**/*.py")
    assert not matches_glob("app/main.txt", "**/*.py")


def test_simple_fastapi_app_produces_structural_index_without_source_leak(
    tmp_path: Path,
) -> None:
    repository = _copy_fixture(tmp_path, "simple_app")
    artifacts = discover_and_index_project(repository, _config(), generated_at=NOW)
    index = artifacts.source_index

    assert artifacts.discovery.schema_version == 2
    assert index.schema_version == 2
    assert index.completeness == ArtifactCompleteness.COMPLETE
    assert {item.kind for item in index.framework_instances} == {
        FrameworkKind.FASTAPI_APP,
        FrameworkKind.API_ROUTER,
    }
    assert len(index.routes) == 4
    assert {item.method for item in index.routes} == {"GET", "POST", "PUT"}
    assert len(index.router_includes) == 1
    assert index.app_targets[0].selection == AppTargetSelection.AUTO_SELECTED
    assert all(
        item.registrar_instance_id
        in {instance.framework_instance_id for instance in index.framework_instances}
        for item in index.routes
    )

    persisted = index.model_dump_json()
    assert "sk_live_private_secret" not in persisted
    assert "should never be indexed" not in persisted
    assert any(
        item.kind == SourceReferenceKind.IDENTIFIER and item.value == "razorpay_payment_id"
        for item in index.references
    )
    assert any(
        item.kind == SourceReferenceKind.PAYMENT_LITERAL and item.value == "payment.captured"
        for item in index.references
    )


def test_imported_router_and_aliased_domain_call_resolve(tmp_path: Path) -> None:
    repository = _copy_fixture(tmp_path, "router_package")
    index = discover_and_index_project(repository, _config(), generated_at=NOW).source_index

    assert index.completeness == ArtifactCompleteness.COMPLETE
    assert index.app_targets[0].import_target == "app.main:app"
    assert index.app_targets[0].selection == AppTargetSelection.AUTO_SELECTED
    assert len(index.router_includes) == 1
    router = next(
        item for item in index.framework_instances if item.kind == FrameworkKind.API_ROUTER
    )
    assert index.router_includes[0].included_router_instance_id == router.framework_instance_id
    fulfil_import = next(item for item in index.imports if item.local_name == "fulfil")
    assert fulfil_import.syntactic_reference == "..domain.ship_order"
    assert fulfil_import.canonical_reference == "app.domain.ship_order"
    ship_order = next(
        item for item in index.symbols if item.qualified_name == "app.domain.ship_order"
    )
    fulfil_call = next(
        item for item in index.call_sites if item.callee_reference.endswith("ship_order")
    )
    assert fulfil_call.callee_symbol_id == ship_order.symbol_id


def test_duplicate_names_remain_unresolved_but_self_method_resolves(tmp_path: Path) -> None:
    repository = _copy_fixture(tmp_path, "calls_and_scopes")
    index = discover_and_index_project(repository, _config(), generated_at=NOW).source_index

    duplicate_helpers = [item for item in index.symbols if item.qualified_name == "main.helper"]
    assert [item.definition_ordinal for item in duplicate_helpers] == [0, 1]
    helper_call = next(
        item
        for item in index.call_sites
        if item.callee_reference == "helper" and item.source_location.line_start > 20
    )
    assert helper_call.callee_symbol_id is None
    grant = next(item for item in index.symbols if item.qualified_name == "main.Service.grant")
    self_call = next(item for item in index.call_sites if item.callee_reference == "self.grant")
    assert self_call.callee_symbol_id == grant.symbol_id
    nested = next(item for item in index.symbols if item.qualified_name.endswith("<locals>.nested"))
    nested_call = next(item for item in index.call_sites if item.callee_reference == "nested")
    assert nested_call.callee_symbol_id == nested.symbol_id
    assert any(item.callee_reference == "<dynamic-call>" for item in index.call_sites)


def test_syntax_error_is_partial_when_other_source_is_usable(tmp_path: Path) -> None:
    repository = _copy_fixture(tmp_path, "partial_repo")
    (repository / "broken.txt").rename(repository / "broken.py")
    index = discover_and_index_project(
        repository,
        _config(exclude=("excluded/**",)),
        generated_at=NOW,
    ).source_index

    assert index.completeness == ArtifactCompleteness.PARTIAL
    assert {item.path for item in index.indexed_files} == {"broken.py", "main.py"}
    assert AnalysisDiagnosticCode.SYNTAX_ERROR in {item.code for item in index.diagnostics}
    assert "excluded/ignored.py" not in index.model_dump_json()


def test_unresolvable_configured_target_is_partial_without_fallback(tmp_path: Path) -> None:
    repository = _copy_fixture(tmp_path, "simple_app")
    index = discover_and_index_project(
        repository,
        _config(app_target="main:missing"),
        generated_at=NOW,
    ).source_index

    assert index.completeness == ArtifactCompleteness.PARTIAL
    assert AnalysisDiagnosticCode.CONFIGURED_APP_TARGET_MISSING in {
        item.code for item in index.diagnostics
    }
    assert all(item.selection == AppTargetSelection.AUTO_CANDIDATE for item in index.app_targets)


def test_framework_identity_survives_line_movement(tmp_path: Path) -> None:
    repository = tmp_path / "merchant"
    repository.mkdir()
    source = repository / "main.py"
    source.write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    config = _config()
    first = discover_and_index_project(repository, config, generated_at=NOW).source_index
    source.write_text("\n\nfrom fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    second = discover_and_index_project(repository, config, generated_at=NOW).source_index

    assert (
        first.framework_instances[0].framework_instance_id
        == second.framework_instances[0].framework_instance_id
    )
    assert first.project_source_fingerprint != second.project_source_fingerprint


def test_redefined_framework_instances_have_exact_route_ownership(tmp_path: Path) -> None:
    repository = tmp_path / "redefined"
    repository.mkdir()
    (repository / "main.py").write_text(
        """\
from fastapi import FastAPI
app = FastAPI()
@app.get("/first")
def first():
    return 1
app = FastAPI()
@app.post("/second")
def second():
    return 2
""",
        encoding="utf-8",
    )
    index = discover_and_index_project(repository, _config(), generated_at=NOW).source_index
    apps = [item for item in index.framework_instances if item.kind == FrameworkKind.FASTAPI_APP]
    assert [item.definition_ordinal for item in apps] == [0, 1]
    routes = {item.route_path: item for item in index.routes}
    assert routes["/first"].registrar_instance_id == apps[0].framework_instance_id
    assert routes["/second"].registrar_instance_id == apps[1].framework_instance_id
    assert index.app_targets[0].framework_instance_id == apps[1].framework_instance_id


def test_conditional_framework_rebinding_remains_unresolved(tmp_path: Path) -> None:
    repository = tmp_path / "conditional"
    repository.mkdir()
    (repository / "main.py").write_text(
        """\
from fastapi import FastAPI
app = FastAPI()
if object():
    app = FastAPI()
@app.get("/uncertain")
def uncertain():
    return True
""",
        encoding="utf-8",
    )
    index = discover_and_index_project(repository, _config(), generated_at=NOW).source_index
    codes = {item.code for item in index.diagnostics}
    assert index.completeness == ArtifactCompleteness.PARTIAL
    assert AnalysisDiagnosticCode.AMBIGUOUS_FRAMEWORK_BINDING in codes
    assert AnalysisDiagnosticCode.DYNAMIC_ROUTE_REGISTRATION in codes
    assert not index.routes


def test_source_encoding_and_symlink_diagnostics(tmp_path: Path) -> None:
    repository = tmp_path / "encoding"
    repository.mkdir()
    (repository / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n",
        encoding="utf-8",
    )
    (repository / "latin.py").write_bytes(b"# coding: latin-1\nmerchant_name = 'caf\xe9'\n")
    (repository / "invalid.py").write_bytes(b"merchant_name = '\xff'\n")
    try:
        (repository / "linked.py").symlink_to(repository / "main.py")
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")

    index = discover_and_index_project(repository, _config(), generated_at=NOW).source_index
    codes = {item.code for item in index.diagnostics}
    assert AnalysisDiagnosticCode.INVALID_SOURCE_ENCODING in codes
    assert AnalysisDiagnosticCode.SYMLINK_SKIPPED in codes
    assert {item.path for item in index.indexed_files} == {
        "invalid.py",
        "latin.py",
        "main.py",
    }
    assert "café" not in index.model_dump_json()


def test_discovery_never_executes_merchant_source(tmp_path: Path) -> None:
    repository = tmp_path / "no_execution"
    repository.mkdir()
    marker = repository / "executed.txt"
    (repository / "main.py").write_text(
        """\
from pathlib import Path
from fastapi import FastAPI
Path("executed.txt").write_text("executed")
app = FastAPI()
raise RuntimeError("must not execute")
""",
        encoding="utf-8",
    )
    discover_and_index_project(repository, _config(), generated_at=NOW)
    assert not marker.exists()


def test_multiple_apps_are_candidates_without_selection(tmp_path: Path) -> None:
    repository = tmp_path / "multiple"
    repository.mkdir()
    (repository / "first.py").write_text(
        "from fastapi import FastAPI\nfirst = FastAPI()\n",
        encoding="utf-8",
    )
    (repository / "second.py").write_text(
        "from fastapi import FastAPI\nsecond = FastAPI()\n",
        encoding="utf-8",
    )
    index = discover_and_index_project(repository, _config(), generated_at=NOW).source_index
    assert index.completeness == ArtifactCompleteness.PARTIAL
    assert len(index.app_targets) == 2
    assert all(item.selection == AppTargetSelection.AUTO_CANDIDATE for item in index.app_targets)
    assert AnalysisDiagnosticCode.AUTOMATIC_APP_TARGET_AMBIGUOUS in {
        item.code for item in index.diagnostics
    }


def test_decorator_alias_and_imported_route_constant_are_bounded(tmp_path: Path) -> None:
    repository = tmp_path / "alias_route"
    repository.mkdir()
    (repository / "paths.py").write_text('CALLBACK = "/callback"\n', encoding="utf-8")
    (repository / "main.py").write_text(
        """\
from fastapi import FastAPI
from paths import CALLBACK
app = FastAPI()
post = app.post
@post(CALLBACK)
def callback():
    return True
""",
        encoding="utf-8",
    )
    index = discover_and_index_project(repository, _config(), generated_at=NOW).source_index
    assert [(item.method, item.route_path) for item in index.routes] == [("POST", "/callback")]


def test_source_root_is_import_root_but_artifact_paths_are_project_relative(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "src_layout"
    source_root = repository / "src"
    source_root.mkdir(parents=True)
    (source_root / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n",
        encoding="utf-8",
    )
    config = _config().model_copy(
        update={"project": _config().project.model_copy(update={"source_root": "src"})}
    )
    index = discover_and_index_project(repository, config, generated_at=NOW).source_index
    assert [item.path for item in index.indexed_files] == ["src/main.py"]
    assert any(item.qualified_name == "main" for item in index.symbols)
    assert index.app_targets[0].import_target == "main:app"


def test_stale_source_snapshot_stops_graph_preflight(tmp_path: Path) -> None:
    repository = _copy_fixture(tmp_path, "simple_app")
    index = discover_and_index_project(repository, _config(), generated_at=NOW).source_index
    validate_indexed_source_snapshot(repository, index)

    (repository / "main.py").write_text("app = object()\n", encoding="utf-8")
    with pytest.raises(StaleSourceIndexError, match="re-indexing"):
        validate_indexed_source_snapshot(repository, index)


def test_no_usable_source_is_fatal(tmp_path: Path) -> None:
    repository = tmp_path / "invalid"
    repository.mkdir()
    (repository / "broken.py").write_text("def broken(\n", encoding="utf-8")
    with pytest.raises(ProjectDiscoveryError, match="no usable"):
        discover_and_index_project(repository, _config(), generated_at=NOW)


def test_source_index_is_structural_not_control_flow_ir() -> None:
    fields = set(
        __import__(
            "stateguard.discovery.contracts",
            fromlist=["SourceIndexArtifact"],
        ).SourceIndexArtifact.model_fields
    )
    assert fields.isdisjoint({"branches", "returns", "mutations", "exceptions", "control_flow"})


def test_module_and_class_symbols_do_not_persist_signatures(tmp_path: Path) -> None:
    repository = _copy_fixture(tmp_path, "calls_and_scopes")
    symbols = discover_and_index_project(
        repository,
        _config(),
        generated_at=NOW,
    ).source_index.symbols
    assert all(
        item.signature == ""
        for item in symbols
        if item.kind in {SymbolKind.MODULE, SymbolKind.CLASS}
    )
