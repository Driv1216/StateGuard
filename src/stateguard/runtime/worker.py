"""Internal managed FastAPI worker. This module is not a public CLI surface."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import os
import queue
import socket
import sys
import threading
from pathlib import Path
from typing import Any

from pydantic import Field

from stateguard.applicability.contracts import ScenarioApplicabilityArtifact
from stateguard.contracts.common import PersistedArtifactModel, RuntimeSessionId, Sha256Digest
from stateguard.contracts.identity import canonical_json, fingerprint_json
from stateguard.discovery.contracts import SourceIndexArtifact
from stateguard.discovery.service import StaleSourceIndexError, validate_indexed_source_snapshot
from stateguard.graph.contracts import PaymentSafetyGraphArtifact
from stateguard.workspace.config import ConfigLoadError, load_config

from .capability import prepare_instrumentation, reconcile_live_instrumentation
from .contracts import RuntimeCapabilityReasonCode, RuntimeObservationEvent
from .instrumentation import ExactTraceEngine, ObservationCollector
from .planning import build_runtime_target_plan
from .routes import RouteAttachment, attach_exact_routes


class ManagedWorkerPlan(PersistedArtifactModel):
    repository_root: str = Field(min_length=1, max_length=4096)
    source_root: str = Field(min_length=1, max_length=4096)
    config_path: str = Field(min_length=1, max_length=4096)
    normalized_config_fingerprint: Sha256Digest
    app_target: str = Field(min_length=3, max_length=512)
    session_id: RuntimeSessionId
    status_path: str = Field(min_length=1, max_length=4096)
    stop_path: str = Field(min_length=1, max_length=4096)
    observation_path: str = Field(min_length=1, max_length=4096)
    source_index: SourceIndexArtifact
    structural_graph: PaymentSafetyGraphArtifact
    graph: PaymentSafetyGraphArtifact
    applicability: ScenarioApplicabilityArtifact


def _write_status(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(canonical_json(payload) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _attachment_payload(attachments: tuple[RouteAttachment, ...]) -> list[dict[str, Any]]:
    return [
        {
            "binding": item.binding.model_dump(mode="json"),
            "attached": item.attached,
            "reason": item.reason.value,
        }
        for item in attachments
    ]


class _ObservationWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.items: queue.Queue[RuntimeObservationEvent | None] = queue.Queue(maxsize=10_001)
        self.failed = False
        self.thread = threading.Thread(target=self._run, name="stateguard-observations")

    def start(self) -> None:
        self.thread.start()

    def submit(self, event: RuntimeObservationEvent) -> None:
        self.items.put_nowait(event)

    def close(self) -> None:
        try:
            self.items.put(None, timeout=1)
        except queue.Full:
            self.failed = True
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            self.failed = True

    def _run(self) -> None:
        try:
            with self.path.open("w", encoding="utf-8") as handle:
                os.chmod(self.path, 0o600)
                while True:
                    item = self.items.get()
                    if item is None:
                        break
                    handle.write(item.model_dump_json() + "\n")
                    handle.flush()
        except BaseException:
            self.failed = True


def _import_target(plan: ManagedWorkerPlan) -> Any:
    repository_root = Path(plan.repository_root).resolve(strict=True)
    source_root = (repository_root / plan.source_root).resolve(strict=True)
    source_root.relative_to(repository_root)
    sys.path.insert(0, str(source_root))
    module_name, attribute_path = plan.app_target.split(":", 1)
    value: Any = importlib.import_module(module_name)
    for attribute in attribute_path.split("."):
        value = getattr(value, attribute)
    if not callable(value):
        raise TypeError("configured app target is not callable")
    return value


class _StaleRuntimeConfigError(ValueError):
    pass


class _UnexpectedServerTermination(RuntimeError):
    pass


def _validate_inputs(plan: ManagedWorkerPlan, repository_root: Path) -> None:
    validate_indexed_source_snapshot(repository_root, plan.source_index)
    try:
        current_config = load_config(Path(plan.config_path))
    except ConfigLoadError as exc:
        raise _StaleRuntimeConfigError("normalized runtime configuration is invalid") from exc
    if fingerprint_json(current_config) != plan.normalized_config_fingerprint:
        raise _StaleRuntimeConfigError("normalized runtime configuration changed")


def _failure_reason(exc: BaseException) -> RuntimeCapabilityReasonCode:
    if isinstance(exc, StaleSourceIndexError):
        return RuntimeCapabilityReasonCode.SOURCE_STALE
    if isinstance(exc, _StaleRuntimeConfigError):
        return RuntimeCapabilityReasonCode.CONFIG_STALE
    if isinstance(exc, _UnexpectedServerTermination):
        return RuntimeCapabilityReasonCode.PROCESS_CRASHED
    return RuntimeCapabilityReasonCode.STARTUP_FAILED


async def _serve(plan: ManagedWorkerPlan) -> int:
    import uvicorn

    repository_root = Path(plan.repository_root).resolve(strict=True)
    status_path = Path(plan.status_path)
    writer = _ObservationWriter(Path(plan.observation_path))
    collector = ObservationCollector(event_sink=writer.submit)
    writer.start()
    failure: BaseException | None = None
    try:
        _validate_inputs(plan, repository_root)
        targets = build_runtime_target_plan(plan.source_index, plan.graph, plan.applicability)
        statically_prepared = prepare_instrumentation(
            repository_root,
            plan.source_index,
            plan.graph,
            targets,
        )
        merchant_app = _import_target(plan)
        _validate_inputs(plan, repository_root)
        prepared = reconcile_live_instrumentation(
            repository_root,
            plan.source_index,
            targets,
            statically_prepared,
        )
        with ExactTraceEngine(
            collector,
            repository_root=repository_root,
            customers=prepared.customers,
            mutations=prepared.mutations,
        ):
            attachment = attach_exact_routes(
                merchant_app,
                repository_root=repository_root,
                source_index=plan.source_index,
                plan=targets,
                session_id=plan.session_id,
                collector=collector,
            )
            _validate_inputs(plan, repository_root)
            listening = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listening.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listening.bind(("127.0.0.1", 0))
            listening.listen(2048)
            port = int(listening.getsockname()[1])
            config = uvicorn.Config(
                attachment.app,
                host="127.0.0.1",
                port=port,
                log_config=None,
                access_log=False,
                lifespan="on",
            )
            server = uvicorn.Server(config)
            task = asyncio.create_task(server.serve(sockets=[listening]))
            while not server.started and not task.done():
                await asyncio.sleep(0.01)
            if task.done() and not server.started:
                await task
                raise RuntimeError("managed ASGI server exited before readiness")
            _write_status(
                status_path,
                {
                    "state": "READY",
                    "port": port,
                    "attachments": _attachment_payload(attachment.attachments),
                    "live_customer_ids": [item.normal_control_id for item in prepared.customers],
                    "live_mutation_ids": [item.mutation_node_id for item in prepared.mutations],
                },
            )
            stop_path = Path(plan.stop_path)
            while not task.done() and not stop_path.exists():
                await asyncio.sleep(0.02)
            if stop_path.exists():
                server.should_exit = True
            elif task.done():
                await task
                raise _UnexpectedServerTermination(
                    "managed ASGI server exited unexpectedly after readiness"
                )
            await task
            _validate_inputs(plan, repository_root)
        return 0
    except BaseException as exc:
        failure = exc
        return 2
    finally:
        writer.close()
        if writer.failed:
            collector.fail(RuntimeCapabilityReasonCode.OBSERVATION_CHANNEL_FAILED)
        events, complete, diagnostics = collector.snapshot()
        payload: dict[str, Any] = {
            "state": "CLOSED" if failure is None else "FAILED",
            "complete": complete and failure is None,
            "diagnostics": [item.value for item in diagnostics],
            "event_count": len(events),
        }
        if failure is not None:
            payload.update(
                reason=_failure_reason(failure).value,
                reference=type(failure).__name__,
            )
        _write_status(status_path, payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stateguard-runtime-worker")
    parser.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args(argv)
    plan = ManagedWorkerPlan.model_validate_json(args.plan.read_text(encoding="utf-8"))
    return asyncio.run(_serve(plan))


if __name__ == "__main__":
    raise SystemExit(main())
