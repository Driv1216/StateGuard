from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from stateguard.contracts.config import StateGuardConfig
from stateguard.contracts.identity import new_project_id
from stateguard.discovery.service import discover_and_index_project
from stateguard.graph.contracts import GraphDiagnosticCode
from stateguard.graph.reachability import compose_effective_routes

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"
NOW = datetime(2026, 8, 24, tzinfo=UTC)


def _config(project_id: str) -> StateGuardConfig:
    return StateGuardConfig.model_validate(
        {
            "schema_version": 2,
            "project": {
                "id": project_id,
                "source_root": ".",
                "framework": "fastapi",
                "app_target": "main:app",
            },
            "analysis": {"include": ["**/*.py"], "exclude": []},
        }
    )


def test_nested_repeated_and_cyclic_router_composition(tmp_path: Path) -> None:
    repository = tmp_path / "graph_routers"
    shutil.copytree(FIXTURES / "graph_routers", repository)
    index = discover_and_index_project(
        repository, _config(new_project_id()), generated_at=NOW
    ).source_index

    result = compose_effective_routes(index)
    paths = [item.registration.effective_path for item in result.routes]

    assert paths.count("/same/outer/nested/inner/hook/") == 2
    assert "/one/outer/nested/inner/hook/" in paths
    assert "/two/outer/nested/inner/hook/" in paths
    assert len({item.registration.route_registration_id for item in result.routes}) == 4
    assert all(item.registration.component_path == "/hook/" for item in result.routes)
    assert GraphDiagnosticCode.ROUTE_COMPOSITION_CYCLE in {item.code for item in result.diagnostics}


def test_route_registration_identity_ignores_line_only_movement(tmp_path: Path) -> None:
    repository = tmp_path / "graph_routers"
    shutil.copytree(FIXTURES / "graph_routers", repository)
    project_id = new_project_id()
    first_index = discover_and_index_project(
        repository, _config(project_id), generated_at=NOW
    ).source_index
    first = compose_effective_routes(first_index)

    source = repository / "main.py"
    source.write_text("\n\n" + source.read_text(encoding="utf-8"), encoding="utf-8")
    second_index = discover_and_index_project(
        repository, _config(project_id), generated_at=NOW
    ).source_index
    second = compose_effective_routes(second_index)

    assert {item.registration.route_registration_id for item in first.routes} == {
        item.registration.route_registration_id for item in second.routes
    }
