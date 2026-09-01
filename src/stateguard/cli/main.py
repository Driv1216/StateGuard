"""Stable StateGuard command-line control adapter."""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
from collections.abc import Sequence
from pathlib import Path
from threading import Event
from types import FrameType
from typing import Any, NoReturn

from pydantic import BaseModel, ValidationError

from stateguard import __version__
from stateguard.application.control import (
    ControlOperationError,
    StateGuardControl,
    validate_configuration,
)
from stateguard.ci import evaluate_ci_gate
from stateguard.contracts.config import (
    AIConfig,
    BringYourOwnRuntimeConfig,
    DeclaredTestRuntimeTargetConfig,
    FulfilmentPolicy,
    LateAuthorisationPolicy,
    LocalRuntimeTargetConfig,
    ManagedRuntimeConfig,
    RuntimeConfig,
    RuntimeReadinessConfig,
    RuntimeTargetConfig,
    RuntimeTargetKind,
    StaticRuntimeConfig,
)
from stateguard.control.contracts import (
    ControlErrorCode,
    ControlErrorV1,
    RunReportV1,
    control_error,
)
from stateguard.control_api.server import serve_control_api
from stateguard.grounding.contracts import RazorpayTestGroundingRequest

from .rendering import (
    json_text,
    render_analysis,
    render_applicability,
    render_ci_gate,
    render_config_validation,
    render_project_setup,
    render_run_list,
    render_run_report,
    render_runtime,
    render_semantics,
    render_verification,
)


class CliUsageError(ValueError):
    """Argument parsing failed without terminating the hosting process."""


class StateGuardArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> NoReturn:
        raise CliUsageError(message)


def _add_project_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("project", nargs="?", type=Path)
    parser.add_argument(
        "--repository",
        dest="legacy_repository",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--config", type=Path, default=Path("stateguard.yaml"))
    parser.add_argument("--json", action="store_true", dest="json_output")


def _add_serve_project_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("project", nargs="?", type=Path)
    parser.add_argument(
        "--repository",
        dest="legacy_repository",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--config", type=Path, default=Path("stateguard.yaml"))


def _serve_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _environment_name(value: str) -> str:
    try:
        return RazorpayTestGroundingRequest(payment_id_env=value).payment_id_env
    except ValidationError as exc:
        raise argparse.ArgumentTypeError("must be a portable environment variable name") from exc


def _add_runtime_process_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--working-directory", default=".")
    parser.add_argument(
        "--env-from-host",
        action="append",
        default=[],
        metavar="CHILD=HOST",
    )
    parser.add_argument("--startup-timeout-seconds", type=float, default=20.0)
    parser.add_argument("--request-timeout-seconds", type=float, default=10.0)
    parser.add_argument("--shutdown-timeout-seconds", type=float, default=5.0)


def build_parser() -> argparse.ArgumentParser:
    parser = StateGuardArgumentParser(
        prog="stateguard",
        description="Local-first reliability auditor for Razorpay integrations",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", parser_class=StateGuardArgumentParser)

    config = commands.add_parser("config", help="work with stateguard.yaml")
    config_commands = config.add_subparsers(
        dest="config_command", required=True, parser_class=StateGuardArgumentParser
    )
    validate = config_commands.add_parser("validate", help="validate a configuration file")
    validate.add_argument("path", type=Path)
    validate.add_argument("--json", action="store_true", dest="json_output")

    configure = commands.add_parser("configure", help="configure bounded project setup sections")
    configure_commands = configure.add_subparsers(
        dest="configure_command", required=True, parser_class=StateGuardArgumentParser
    )
    configure_ai = configure_commands.add_parser("ai", help="configure model-provider metadata")
    _add_project_arguments(configure_ai)
    configure_ai.add_argument(
        "--provider",
        required=True,
        choices=("gemini", "openai-compatible"),
    )
    configure_ai.add_argument("--model", required=True)
    configure_ai.add_argument("--api-key-env", required=True)
    configure_ai.add_argument("--base-url")

    configure_runtime = configure_commands.add_parser(
        "runtime", help="configure bounded runtime behavior"
    )
    runtime_modes = configure_runtime.add_subparsers(
        dest="runtime_mode", required=True, parser_class=StateGuardArgumentParser
    )
    runtime_static = runtime_modes.add_parser("static", help="configure static-only mode")
    _add_project_arguments(runtime_static)
    runtime_managed = runtime_modes.add_parser("managed", help="configure managed local mode")
    _add_project_arguments(runtime_managed)
    _add_runtime_process_arguments(runtime_managed)
    runtime_byo = runtime_modes.add_parser("byo", help="configure bring-your-own test runtime")
    _add_project_arguments(runtime_byo)
    _add_runtime_process_arguments(runtime_byo)
    runtime_byo.add_argument(
        "--target-kind",
        required=True,
        type=RuntimeTargetKind,
        choices=tuple(RuntimeTargetKind),
    )
    runtime_byo.add_argument("--base-url", required=True)
    runtime_byo.add_argument(
        "--declaration",
        choices=("NON_PRODUCTION_TEST_ENVIRONMENT",),
    )
    runtime_byo.add_argument("--readiness-path", default="/")
    runtime_byo.add_argument(
        "--readiness-status",
        action="append",
        type=int,
        default=[],
    )
    runtime_byo.add_argument("--launch-arg", action="append", default=[])

    analyze = commands.add_parser("analyze", help="inspect current project safety authority")
    _add_project_arguments(analyze)

    semantics = commands.add_parser("semantics", help="resolve customer-value semantics")
    semantic_commands = semantics.add_subparsers(
        dest="semantics_command", required=True, parser_class=StateGuardArgumentParser
    )
    resolve = semantic_commands.add_parser("resolve", help="resolve customer value")
    _add_project_arguments(resolve)
    confirm = semantic_commands.add_parser(
        "confirm", help="confirm an exact customer-value callable"
    )
    _add_project_arguments(confirm)
    confirm.add_argument("--symbol", required=True)

    policy = commands.add_parser("policy", help="confirm explicit merchant policy")
    policy_commands = policy.add_subparsers(
        dest="policy_command", required=True, parser_class=StateGuardArgumentParser
    )
    policy_confirm = policy_commands.add_parser(
        "confirm", help="confirm one or more merchant policy values"
    )
    _add_project_arguments(policy_confirm)
    policy_confirm.add_argument(
        "--fulfilment",
        type=FulfilmentPolicy,
        choices=tuple(FulfilmentPolicy),
    )
    policy_confirm.add_argument(
        "--late-authorisation",
        type=LateAuthorisationPolicy,
        choices=tuple(LateAuthorisationPolicy),
    )

    applicability = commands.add_parser(
        "applicability", help="inspect deterministic scenario applicability"
    )
    applicability_commands = applicability.add_subparsers(
        dest="applicability_command", required=True, parser_class=StateGuardArgumentParser
    )
    applicability_analyze = applicability_commands.add_parser(
        "analyze", help="analyze policy evidence and scenario applicability"
    )
    _add_project_arguments(applicability_analyze)

    runtime = commands.add_parser("runtime", help="assess local/test runtime capability")
    runtime_commands = runtime.add_subparsers(
        dest="runtime_command", required=True, parser_class=StateGuardArgumentParser
    )
    assess = runtime_commands.add_parser(
        "assess", help="execute the configured runtime capability probe"
    )
    _add_project_arguments(assess)

    verify = commands.add_parser("verify", help="create one canonical verification run")
    _add_project_arguments(verify)
    verify.add_argument("--ci", action="store_true", help="apply release-gate exit semantics")
    verify.add_argument(
        "--razorpay-test-payment-id-env",
        type=_environment_name,
        help="opt in to fetch-only SG-01 grounding using this Payment ID environment variable",
    )
    verify.add_argument(
        "--razorpay-test-key-id-env",
        type=_environment_name,
        default="RAZORPAY_KEY_ID",
        help="Test key ID environment variable name",
    )
    verify.add_argument(
        "--razorpay-test-key-secret-env",
        type=_environment_name,
        default="RAZORPAY_KEY_SECRET",
        help="Test key secret environment variable name",
    )

    serve = commands.add_parser("serve", help="serve the local StateGuard control API")
    _add_serve_project_arguments(serve)
    serve.add_argument("--host", choices=("127.0.0.1", "::1"), default="127.0.0.1")
    serve.add_argument("--port", type=_serve_port, default=8765)

    runs = commands.add_parser("runs", help="inspect immutable verification-run history")
    run_commands = runs.add_subparsers(
        dest="runs_command", required=True, parser_class=StateGuardArgumentParser
    )
    run_list = run_commands.add_parser("list", help="list completed verification runs")
    _add_project_arguments(run_list)
    latest = run_commands.add_parser("latest", help="load the latest verification run")
    _add_project_arguments(latest)
    latest.add_argument("--full", action="store_true")
    show = run_commands.add_parser("show", help="load a specific verification run")
    show.add_argument("run_id")
    _add_project_arguments(show)
    show.add_argument("--full", action="store_true")
    return parser


def _control(args: argparse.Namespace) -> StateGuardControl:
    project = args.project
    legacy = args.legacy_repository
    if project is not None and legacy is not None:
        raise ControlOperationError(ControlErrorCode.INVALID_REQUEST)
    return StateGuardControl(project or legacy or Path("."), args.config)


def _write_json(model: BaseModel, *, stderr: bool = False, indent: int | None = None) -> None:
    print(json_text(model, indent=indent), file=sys.stderr if stderr else sys.stdout)


def _write_human(lines: tuple[str, ...]) -> None:
    for line in lines:
        print(line)


def _usage_error() -> ControlErrorV1:
    return ControlErrorV1(
        code=ControlErrorCode.INVALID_REQUEST,
        message="the requested control operation is invalid",
    )


def _serve(control: StateGuardControl, args: argparse.Namespace) -> None:
    setup = control.project_setup()
    stop_event = Event()

    def request_stop(signum: int, frame: FrameType | None) -> None:
        stop_event.set()

    handled_signals = (signal.SIGINT, signal.SIGTERM)
    previous = {item: signal.getsignal(item) for item in handled_signals}
    for item in handled_signals:
        signal.signal(item, request_stop)

    def announce(port: int) -> None:
        host = f"[{args.host}]" if args.host == "::1" else args.host
        print(f"StateGuard dashboard: http://{host}:{port}")
        print(f"StateGuard local control API: http://{host}:{port}/api/v1")
        print(f"project_id: {setup.project_id}")

    try:
        serve_control_api(
            control,
            args.host,
            args.port,
            stop_event,
            on_started=announce,
        )
    except (OSError, ValueError) as exc:
        raise ControlOperationError(ControlErrorCode.OPERATION_FAILED) from exc
    except ControlOperationError:
        raise
    except Exception as exc:
        raise ControlOperationError(ControlErrorCode.INTERNAL_ERROR) from exc
    finally:
        for item, handler in previous.items():
            signal.signal(item, handler)


def _environment_mapping(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        child, separator, host = value.partition("=")
        if not separator or not child or not host or child in result:
            raise ControlOperationError(ControlErrorCode.CONFIG_INVALID)
        result[child] = host
    return result


def _ai_configuration(args: argparse.Namespace) -> AIConfig:
    try:
        return AIConfig(
            provider=args.provider,
            model=args.model,
            api_key_env=args.api_key_env,
            base_url=args.base_url,
        )
    except ValidationError as exc:
        raise ControlOperationError(ControlErrorCode.CONFIG_INVALID) from exc


def _runtime_configuration(args: argparse.Namespace) -> RuntimeConfig:
    try:
        if args.runtime_mode == "static":
            return StaticRuntimeConfig()
        process = {
            "working_directory": args.working_directory,
            "env_from_host": _environment_mapping(args.env_from_host),
            "startup_timeout_seconds": args.startup_timeout_seconds,
            "request_timeout_seconds": args.request_timeout_seconds,
            "shutdown_timeout_seconds": args.shutdown_timeout_seconds,
        }
        if args.runtime_mode == "managed":
            return ManagedRuntimeConfig(**process)
        target: RuntimeTargetConfig
        if args.target_kind == RuntimeTargetKind.LOCAL:
            if args.declaration is not None:
                raise ControlOperationError(ControlErrorCode.CONFIG_INVALID)
            target = LocalRuntimeTargetConfig(base_url=args.base_url)
        else:
            target = DeclaredTestRuntimeTargetConfig(
                kind=RuntimeTargetKind.DECLARED_TEST,
                base_url=args.base_url,
                declaration=args.declaration,
            )
        return BringYourOwnRuntimeConfig(
            **process,
            target=target,
            readiness=RuntimeReadinessConfig(
                path=args.readiness_path,
                accepted_statuses=tuple(args.readiness_status or [200]),
            ),
            launch_argv=tuple(args.launch_arg) if args.launch_arg else None,
        )
    except ControlOperationError:
        raise
    except (ValidationError, ValueError) as exc:
        raise ControlOperationError(ControlErrorCode.CONFIG_INVALID) from exc


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv) if argv is not None else sys.argv[1:]
    json_requested = "--json" in arguments
    ci_requested = bool(arguments[:1] == ["verify"] and "--ci" in arguments)
    parser = build_parser()
    try:
        args = parser.parse_args(arguments)
    except CliUsageError as exc:
        if json_requested:
            _write_json(_usage_error(), stderr=True)
        elif ci_requested:
            error = _usage_error()
            print(f"{error.code.value}: {error.message}", file=sys.stderr)
        else:
            print(f"stateguard: error: {exc}", file=sys.stderr)
        return 3 if ci_requested else 2

    if args.command is None:
        parser.print_help()
        return 0

    try:
        if args.command == "config":
            result = validate_configuration(args.path)
            if args.json_output:
                _write_json(result)
            else:
                _write_human(render_config_validation(result))
            return 0

        control = _control(args)
        if args.command == "serve":
            _serve(control, args)
            return 0
        if args.command == "configure":
            setup = (
                control.configure_ai(_ai_configuration(args))
                if args.configure_command == "ai"
                else control.configure_runtime(_runtime_configuration(args))
            )
            if args.json_output:
                _write_json(setup)
            else:
                _write_human(render_project_setup(setup))
            return 0
        if args.command == "analyze":
            analysis = control.analyze_project()
            if args.json_output:
                _write_json(analysis)
            else:
                _write_human(render_analysis(analysis))
            return 0

        if args.command == "semantics":
            semantic = (
                asyncio.run(control.resolve_semantics())
                if args.semantics_command == "resolve"
                else asyncio.run(control.confirm_semantics(args.symbol))
            )
            if args.json_output:
                _write_json(semantic)
            else:
                _write_human(render_semantics(semantic))
            return 0

        if args.command == "policy":
            applicability = control.confirm_policy(
                fulfilment=args.fulfilment,
                late_authorisation=args.late_authorisation,
            )
            if args.json_output:
                _write_json(applicability)
            else:
                _write_human(render_applicability(applicability))
            return 0

        if args.command == "applicability":
            applicability = control.analyze_applicability()
            if args.json_output:
                _write_json(applicability)
            else:
                _write_human(render_applicability(applicability))
            return 0

        if args.command == "runtime":
            runtime = control.assess_runtime()
            if args.json_output:
                _write_json(runtime)
            else:
                _write_human(render_runtime(runtime))
            return 0

        if args.command == "verify":
            grounding_request = (
                RazorpayTestGroundingRequest(
                    payment_id_env=args.razorpay_test_payment_id_env,
                    key_id_env=args.razorpay_test_key_id_env,
                    key_secret_env=args.razorpay_test_key_secret_env,
                )
                if args.razorpay_test_payment_id_env is not None
                else None
            )
            verification = (
                control.verify(razorpay_grounding_request=grounding_request)
                if grounding_request is not None
                else control.verify()
            )
            if args.ci:
                gate = evaluate_ci_gate(verification)
                if args.json_output:
                    _write_json(gate)
                else:
                    _write_human(render_ci_gate(gate))
                return gate.exit_code
            if args.json_output:
                _write_json(verification)
            else:
                _write_human(render_verification(verification))
            return 0

        if args.runs_command == "list":
            run_list = control.list_runs()
            if args.json_output:
                _write_json(run_list)
            else:
                _write_human(render_run_list(run_list))
            return 0
        if args.runs_command == "latest":
            selected: BaseModel = control.latest_run() if args.full else control.report_latest_run()
        else:
            selected = (
                control.load_run(args.run_id) if args.full else control.report_run(args.run_id)
            )
        if args.json_output or args.full:
            _write_json(selected, indent=2 if args.full and not args.json_output else None)
        else:
            if not isinstance(selected, RunReportV1):
                raise AssertionError("bounded human run output requires a run report")
            _write_human(render_run_report(selected))
        return 0
    except ControlOperationError as exc:
        if getattr(args, "json_output", False):
            _write_json(exc.error, stderr=True)
        else:
            print(f"{exc.error.code.value}: {exc.error.message}", file=sys.stderr)
        return 3 if args.command == "verify" and args.ci else 2
    except Exception:
        if args.command != "verify" or not args.ci:
            raise
        error = control_error(ControlErrorCode.INTERNAL_ERROR)
        if args.json_output:
            _write_json(error, stderr=True)
        else:
            print(f"{error.code.value}: {error.message}", file=sys.stderr)
        return 3


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
