"""Managed and BYO runtime sessions with non-persisted observation streams."""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from stateguard.applicability.contracts import ScenarioApplicabilityArtifact
from stateguard.contracts.common import (
    GraphNodeId,
    RuntimeRequestId,
    RuntimeSessionId,
    Sha256Digest,
)
from stateguard.contracts.config import (
    BringYourOwnRuntimeConfig,
    LocalRuntimeTargetConfig,
    ManagedRuntimeConfig,
    RuntimeTargetConfig,
)
from stateguard.contracts.identity import (
    fingerprint_json,
    runtime_request_id,
)
from stateguard.discovery.contracts import SourceIndexArtifact
from stateguard.graph.contracts import PaymentSafetyGraphArtifact
from stateguard.workspace.config import load_config

from .capability import (
    PreparedInstrumentation,
    prepare_instrumentation,
    restrict_prepared_instrumentation,
)
from .contracts import (
    IngressRuntimeBinding,
    ManagedAcknowledgementFailureMode,
    RuntimeCapabilityReasonCode,
    RuntimeObservationEvent,
    RuntimeObservationKind,
    RuntimeObservationTranscript,
)
from .instrumentation import ObservationCollector, RuntimeRequestContext
from .planning import RuntimeTargetPlan
from .routes import RouteAttachment
from .worker import ManagedWorkerPlan


class RuntimeSessionError(RuntimeError):
    def __init__(
        self,
        reason: RuntimeCapabilityReasonCode,
        reference: str | None = None,
    ) -> None:
        super().__init__(reason.value if reference is None else f"{reason.value}: {reference}")
        self.reason = reason
        self.reference = reference


@dataclass(frozen=True)
class RuntimeRequestResult:
    request_id: RuntimeRequestId
    binding: IngressRuntimeBinding
    response: httpx.Response


def _sanitized_environment(env_from_host: dict[str, str]) -> dict[str, str]:
    safe_names = {
        "PATH",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "PATHEXT",
    }
    result = {name: os.environ[name] for name in safe_names if name in os.environ}
    for child_name, host_name in env_from_host.items():
        if host_name not in os.environ:
            raise RuntimeSessionError(
                RuntimeCapabilityReasonCode.RUNTIME_DEPENDENCY_MISSING,
                f"required environment name is unset: {host_name}",
            )
        result[child_name] = os.environ[host_name]
    return result


def _terminate_process(process: subprocess.Popen[bytes], timeout: float) -> bool:
    if process.poll() is not None:
        return True
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:  # pragma: no cover - Windows lifecycle defense
            process.terminate()
        process.wait(timeout=timeout)
        return True
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:  # pragma: no cover
                process.kill()
            process.wait(timeout=timeout)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return False


def _request_graceful_stop(
    process: subprocess.Popen[bytes], stop_path: Path, timeout: float
) -> bool:
    if process.poll() is not None:
        return True
    try:
        stop_path.write_text("stop\n", encoding="utf-8")
        os.chmod(stop_path, 0o600)
        process.wait(timeout=timeout)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return _terminate_process(process, timeout)


def _parse_attachments(payload: dict[str, Any]) -> tuple[RouteAttachment, ...]:
    result: list[RouteAttachment] = []
    for item in payload.get("attachments", []):
        result.append(
            RouteAttachment(
                binding=IngressRuntimeBinding.model_validate(item["binding"]),
                attached=bool(item["attached"]),
                reason=RuntimeCapabilityReasonCode(item["reason"]),
            )
        )
    return tuple(result)


@dataclass(frozen=True)
class ManagedSessionStart:
    session: ManagedRuntimeSession
    attachments: tuple[RouteAttachment, ...]
    prepared: PreparedInstrumentation


class ManagedRuntimeSession:
    def __init__(
        self,
        *,
        session_id: RuntimeSessionId,
        process: subprocess.Popen[bytes],
        temporary_directory: Path,
        status_path: Path,
        stop_path: Path,
        observation_path: Path,
        base_url: str,
        request_timeout: float,
        shutdown_timeout: float,
    ) -> None:
        self.session_id = session_id
        self.process = process
        self.temporary_directory = temporary_directory
        self.status_path = status_path
        self.stop_path = stop_path
        self.observation_path = observation_path
        self.base_url = base_url
        self.request_timeout = request_timeout
        self.shutdown_timeout = shutdown_timeout
        self._request_ordinal = 0
        self._request_lock = threading.Lock()
        self._closed = False
        self._complete = True
        self._diagnostics: set[RuntimeCapabilityReasonCode] = set()

    @classmethod
    def start(
        cls,
        *,
        repository_root: Path,
        config_path: Path,
        config: ManagedRuntimeConfig,
        source_root: str,
        session_id: RuntimeSessionId,
        source_index: SourceIndexArtifact,
        structural_graph: PaymentSafetyGraphArtifact,
        graph: PaymentSafetyGraphArtifact,
        applicability: ScenarioApplicabilityArtifact,
        plan: RuntimeTargetPlan,
    ) -> ManagedSessionStart:
        if plan.app_target is None:
            raise RuntimeSessionError(RuntimeCapabilityReasonCode.APP_TARGET_UNRESOLVED)
        statically_prepared = prepare_instrumentation(
            repository_root,
            source_index,
            graph,
            plan,
        )
        temp = Path(tempfile.mkdtemp(prefix="stateguard-runtime-"))
        os.chmod(temp, 0o700)
        status_path = temp / "status.json"
        stop_path = temp / "stop"
        observation_path = temp / "observations.jsonl"
        plan_path = temp / "plan.json"
        worker_plan = ManagedWorkerPlan(
            repository_root=str(repository_root.resolve(strict=True)),
            source_root=source_root,
            config_path=str(config_path.resolve(strict=True)),
            normalized_config_fingerprint=fingerprint_json(load_config(config_path)),
            app_target=plan.app_target.import_target,
            session_id=session_id,
            status_path=str(status_path),
            stop_path=str(stop_path),
            observation_path=str(observation_path),
            source_index=source_index,
            structural_graph=structural_graph,
            graph=graph,
            applicability=applicability,
        )
        plan_path.write_text(worker_plan.model_dump_json(), encoding="utf-8")
        os.chmod(plan_path, 0o600)
        environment = _sanitized_environment(config.env_from_host)
        package_source = Path(__file__).resolve().parents[2]
        environment["PYTHONPATH"] = str(package_source)
        working_directory = (repository_root / config.working_directory).resolve(strict=True)
        working_directory.relative_to(repository_root.resolve(strict=True))
        try:
            process = subprocess.Popen(
                [sys.executable, "-m", "stateguard.runtime.worker", "--plan", str(plan_path)],
                cwd=working_directory,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            shutil.rmtree(temp, ignore_errors=True)
            raise RuntimeSessionError(
                RuntimeCapabilityReasonCode.STARTUP_FAILED, type(exc).__name__
            ) from exc
        try:
            deadline = time.monotonic() + config.startup_timeout_seconds
            payload: dict[str, Any] | None = None
            while time.monotonic() < deadline:
                if status_path.exists():
                    try:
                        payload = json.loads(status_path.read_text(encoding="utf-8"))
                        break
                    except (OSError, ValueError):
                        pass
                if process.poll() is not None:
                    break
                time.sleep(0.02)
            if payload is None or payload.get("state") != "READY":
                if payload is not None and payload.get("reason") is not None:
                    try:
                        reason = RuntimeCapabilityReasonCode(payload["reason"])
                    except ValueError:
                        reason = RuntimeCapabilityReasonCode.STARTUP_FAILED
                else:
                    reason = (
                        RuntimeCapabilityReasonCode.STARTUP_TIMEOUT
                        if process.poll() is None and payload is None
                        else RuntimeCapabilityReasonCode.STARTUP_FAILED
                    )
                raise RuntimeSessionError(
                    reason,
                    str(payload.get("reference")) if payload is not None else None,
                )
            session = cls(
                session_id=session_id,
                process=process,
                temporary_directory=temp,
                status_path=status_path,
                stop_path=stop_path,
                observation_path=observation_path,
                base_url=f"http://127.0.0.1:{int(payload['port'])}",
                request_timeout=config.request_timeout_seconds,
                shutdown_timeout=config.shutdown_timeout_seconds,
            )
            prepared = restrict_prepared_instrumentation(
                statically_prepared,
                live_customer_ids=set(payload.get("live_customer_ids", [])),
                live_mutation_ids=set(payload.get("live_mutation_ids", [])),
            )
            return ManagedSessionStart(
                session=session,
                attachments=_parse_attachments(payload),
                prepared=prepared,
            )
        except BaseException:
            _terminate_process(process, config.shutdown_timeout_seconds)
            shutil.rmtree(temp, ignore_errors=True)
            raise

    def request(
        self,
        binding: IngressRuntimeBinding,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        params: dict[str, str] | None = None,
        acknowledgement_failure: ManagedAcknowledgementFailureMode | None = None,
        acknowledgement_node_id: GraphNodeId | None = None,
    ) -> RuntimeRequestResult:
        if self._closed or self.process.poll() is not None:
            self._complete = False
            self._diagnostics.add(RuntimeCapabilityReasonCode.PROCESS_CRASHED)
            raise RuntimeSessionError(RuntimeCapabilityReasonCode.PROCESS_CRASHED)
        with self._request_lock:
            request_id = runtime_request_id(self.session_id, self._request_ordinal)
            self._request_ordinal += 1
        safe_headers = {
            name: value
            for name, value in (headers or {}).items()
            if name.casefold()
            not in {
                "x-stateguard-request-id",
                "x-stateguard-acknowledgement-failure",
            }
        }
        safe_headers["x-stateguard-request-id"] = request_id
        if (acknowledgement_failure is None) != (acknowledgement_node_id is None):
            raise ValueError("acknowledgement failure mode requires one exact node")
        if acknowledgement_failure is not None and acknowledgement_node_id is not None:
            safe_headers["x-stateguard-acknowledgement-failure"] = (
                f"{acknowledgement_failure.value}:{acknowledgement_node_id}"
            )
        try:
            response = httpx.request(
                binding.method,
                f"{self.base_url}{binding.effective_path}",
                headers=safe_headers,
                content=content,
                params=params,
                timeout=self.request_timeout,
                follow_redirects=False,
            )
            return RuntimeRequestResult(
                request_id=request_id,
                binding=binding,
                response=response,
            )
        except httpx.HTTPError as exc:
            self._complete = False
            raise RuntimeSessionError(
                RuntimeCapabilityReasonCode.EXTERNAL_RUNTIME_UNAVAILABLE,
                type(exc).__name__,
            ) from exc

    def _read_events(self) -> tuple[RuntimeObservationEvent, ...]:
        if not self.observation_path.exists():
            self._complete = False
            self._diagnostics.add(RuntimeCapabilityReasonCode.OBSERVATION_CHANNEL_FAILED)
            return ()
        events: list[RuntimeObservationEvent] = []
        try:
            for line in self.observation_path.read_text(encoding="utf-8").splitlines():
                events.append(RuntimeObservationEvent.model_validate_json(line))
        except (OSError, ValueError):
            self._complete = False
            self._diagnostics.add(RuntimeCapabilityReasonCode.OBSERVATION_CHANNEL_FAILED)
        return tuple(events)

    def close(self, capability_fingerprint: Sha256Digest) -> RuntimeObservationTranscript:
        if not self._closed:
            if not _request_graceful_stop(self.process, self.stop_path, self.shutdown_timeout):
                self._complete = False
                self._diagnostics.add(RuntimeCapabilityReasonCode.CLEANUP_FAILED)
            self._closed = True
        events = self._read_events()
        try:
            status = json.loads(self.status_path.read_text(encoding="utf-8"))
            for value in status.get("diagnostics", []):
                self._diagnostics.add(RuntimeCapabilityReasonCode(value))
            if status.get("state") != "CLOSED" or not bool(status.get("complete")):
                self._complete = False
                reason = status.get("reason")
                self._diagnostics.add(
                    RuntimeCapabilityReasonCode(reason)
                    if reason is not None
                    else RuntimeCapabilityReasonCode.PROCESS_CRASHED
                )
            if status.get("event_count") != len(events):
                self._complete = False
                self._diagnostics.add(RuntimeCapabilityReasonCode.OBSERVATION_CHANNEL_FAILED)
        except (OSError, ValueError):
            self._complete = False
            self._diagnostics.add(RuntimeCapabilityReasonCode.OBSERVATION_CHANNEL_FAILED)
        payload = {
            "session_id": self.session_id,
            "capability_fingerprint": capability_fingerprint,
            "complete": self._complete,
            "events": events,
            "diagnostics": tuple(sorted(self._diagnostics)),
        }
        transcript = RuntimeObservationTranscript(
            **payload,
            transcript_fingerprint=fingerprint_json(payload),
        )
        shutil.rmtree(self.temporary_directory, ignore_errors=True)
        return transcript


def _validate_local_resolution(base_url: str) -> None:
    parsed = urlsplit(base_url)
    assert parsed.hostname is not None
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(parsed.hostname, parsed.port, type=socket.SOCK_STREAM)
        }
    except OSError as exc:
        raise RuntimeSessionError(
            RuntimeCapabilityReasonCode.TARGET_POLICY_REJECTED, type(exc).__name__
        ) from exc
    if not addresses or any(not ip_address(item).is_loopback for item in addresses):
        raise RuntimeSessionError(RuntimeCapabilityReasonCode.TARGET_POLICY_REJECTED)


def _validate_target_policy(target: RuntimeTargetConfig) -> None:
    try:
        type(target).model_validate(target.model_dump())
    except ValueError as exc:
        raise RuntimeSessionError(
            RuntimeCapabilityReasonCode.TARGET_POLICY_REJECTED,
            type(exc).__name__,
        ) from exc
    if isinstance(target, LocalRuntimeTargetConfig):
        _validate_local_resolution(target.base_url)


class BringYourOwnRuntimeSession:
    def __init__(
        self,
        *,
        session_id: RuntimeSessionId,
        config: BringYourOwnRuntimeConfig,
        process: subprocess.Popen[bytes] | None,
    ) -> None:
        self.session_id = session_id
        self.config = config
        self.process = process
        self.collector = ObservationCollector()
        self._request_ordinal = 0
        self._request_lock = threading.Lock()
        self._closed = False

    @property
    def base_url(self) -> str:
        return self.config.target.base_url

    @classmethod
    def start(
        cls,
        *,
        repository_root: Path,
        config: BringYourOwnRuntimeConfig,
        session_id: RuntimeSessionId,
    ) -> BringYourOwnRuntimeSession:
        _validate_target_policy(config.target)
        process: subprocess.Popen[bytes] | None = None
        if config.launch_argv is not None:
            environment = _sanitized_environment(config.env_from_host)
            working_directory = (repository_root / config.working_directory).resolve(strict=True)
            working_directory.relative_to(repository_root.resolve(strict=True))
            try:
                process = subprocess.Popen(
                    list(config.launch_argv),
                    cwd=working_directory,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except OSError as exc:
                raise RuntimeSessionError(
                    RuntimeCapabilityReasonCode.STARTUP_FAILED, type(exc).__name__
                ) from exc
        session = cls(session_id=session_id, config=config, process=process)
        deadline = time.monotonic() + config.startup_timeout_seconds
        readiness_url = f"{config.target.base_url}{config.readiness.path}"
        while time.monotonic() < deadline:
            if process is not None and process.poll() is not None:
                break
            try:
                _validate_target_policy(config.target)
                response = httpx.get(
                    readiness_url,
                    timeout=min(config.request_timeout_seconds, 1.0),
                    follow_redirects=False,
                )
                if 300 <= response.status_code < 400:
                    raise RuntimeSessionError(
                        RuntimeCapabilityReasonCode.TARGET_POLICY_REJECTED,
                        "readiness redirect refused",
                    )
                if response.status_code in config.readiness.accepted_statuses:
                    return session
            except RuntimeSessionError:
                if process is not None:
                    _terminate_process(process, config.shutdown_timeout_seconds)
                raise
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        if process is not None:
            _terminate_process(process, config.shutdown_timeout_seconds)
        raise RuntimeSessionError(RuntimeCapabilityReasonCode.EXTERNAL_RUNTIME_UNAVAILABLE)

    def request(
        self,
        binding: IngressRuntimeBinding,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        params: dict[str, str] | None = None,
    ) -> RuntimeRequestResult:
        if self._closed:
            raise RuntimeSessionError(RuntimeCapabilityReasonCode.EXTERNAL_RUNTIME_UNAVAILABLE)
        _validate_target_policy(self.config.target)
        with self._request_lock:
            request_id = runtime_request_id(self.session_id, self._request_ordinal)
            self._request_ordinal += 1
        context = RuntimeRequestContext(
            session_id=self.session_id,
            request_id=request_id,
            ingress=binding,
        )
        self.collector.emit(RuntimeObservationKind.REQUEST_DISPATCHED, context)
        try:
            response = httpx.request(
                binding.method,
                f"{self.base_url}{binding.effective_path}",
                headers=headers,
                content=content,
                params=params,
                timeout=self.config.request_timeout_seconds,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            self.collector.fail(RuntimeCapabilityReasonCode.EXTERNAL_RUNTIME_UNAVAILABLE)
            raise RuntimeSessionError(
                RuntimeCapabilityReasonCode.EXTERNAL_RUNTIME_UNAVAILABLE,
                type(exc).__name__,
            ) from exc
        self.collector.emit(
            RuntimeObservationKind.RESPONSE_RECEIVED,
            context,
            status_code=response.status_code,
        )
        return RuntimeRequestResult(
            request_id=request_id,
            binding=binding,
            response=response,
        )

    def close(self, capability_fingerprint: Sha256Digest) -> RuntimeObservationTranscript:
        complete = True
        diagnostics: tuple[RuntimeCapabilityReasonCode, ...] = ()
        if self.process is not None and not _terminate_process(
            self.process, self.config.shutdown_timeout_seconds
        ):
            complete = False
            diagnostics = (RuntimeCapabilityReasonCode.CLEANUP_FAILED,)
        self._closed = True
        events, collector_complete, collector_diagnostics = self.collector.snapshot()
        complete = complete and collector_complete
        diagnostics = tuple(sorted({*diagnostics, *collector_diagnostics}))
        payload = {
            "session_id": self.session_id,
            "capability_fingerprint": capability_fingerprint,
            "complete": complete,
            "events": events,
            "diagnostics": diagnostics,
        }
        return RuntimeObservationTranscript(
            **payload,
            transcript_fingerprint=fingerprint_json(payload),
        )
