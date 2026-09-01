"""Plain terminal rendering for typed StateGuard control results."""

from __future__ import annotations

from pydantic import BaseModel

from stateguard.applicability.contracts import ScenarioApplicabilityArtifact
from stateguard.ci import CIGateResultV1, VerificationResultCountsV1
from stateguard.control.contracts import (
    ConfigValidationV1,
    ProjectAnalysisV1,
    ProjectSetupV1,
    RunListV1,
    RunReportV1,
    SemanticOperationV1,
)
from stateguard.evidence.contracts import VerificationRun, VerificationRunSummary
from stateguard.runtime.contracts import RuntimeCapabilityArtifact


def json_text(model: BaseModel, *, indent: int | None = None) -> str:
    return model.model_dump_json(indent=indent)


def render_config_validation(result: ConfigValidationV1) -> tuple[str, ...]:
    return (
        "valid StateGuard configuration",
        f"project_id: {result.project_id}",
        f"config_schema_version: {result.config_schema_version}",
    )


def render_project_setup(result: ProjectSetupV1) -> tuple[str, ...]:
    lines = [
        "StateGuard project setup configured",
        f"project_id: {result.project_id}",
    ]
    if result.ai_provider is not None:
        lines.extend(
            (
                f"ai_provider: {result.ai_provider}",
                f"ai_model: {result.ai_model}",
                f"ai_api_key_env: {result.ai_api_key_env}",
            )
        )
        if result.ai_base_url is not None:
            lines.append(f"ai_base_url: {result.ai_base_url}")
    lines.append(f"runtime_mode: {result.runtime_mode.value}")
    if result.runtime is not None:
        lines.extend(
            f"runtime_env: {item.child_name}<-{item.host_name}"
            for item in result.runtime.environment_bindings
        )
        if result.runtime.target is not None:
            lines.append(f"runtime_target: {result.runtime.target.base_url}")
        lines.append(f"runtime_launch_configured: {str(result.runtime.launch_configured).lower()}")
    return tuple(lines)


def render_analysis(result: ProjectAnalysisV1) -> tuple[str, ...]:
    semantic_state = (
        result.semantics.state.value if result.semantics.state is not None else "UNMAPPED"
    )
    lines = [
        "StateGuard project analysis",
        f"project_id: {result.project_id}",
        f"source_completeness: {result.source_completeness.value}",
        f"indexed_files: {result.indexed_file_count}",
        f"indexed_symbols: {result.indexed_symbol_count}",
        f"graph_completeness: {result.graph_completeness.value}",
        f"graph_nodes: {sum(item.count for item in result.graph_nodes)}",
        f"graph_edges: {sum(item.count for item in result.graph_edges)}",
        f"semantic_state: {semantic_state}",
    ]
    if result.semantics.selected_symbol_id is not None:
        lines.append(f"customer_value_symbol: {result.semantics.selected_symbol_id}")
    fulfilment = result.policy.fulfilment
    late = result.policy.late_authorisation
    lines.append(
        "fulfilment_policy: "
        + (
            fulfilment.confirmed_policy.value
            if fulfilment.confirmed_policy is not None
            else "UNCONFIRMED"
        )
    )
    lines.append(
        "late_authorisation_policy: "
        + (late.confirmed_policy.value if late.confirmed_policy is not None else "UNCONFIRMED")
    )
    lines.extend(
        f"{scenario.scenario_id.value}: {scenario.state.value}"
        for scenario in result.applicability.scenarios
    )
    return tuple(lines)


def render_semantics(result: SemanticOperationV1) -> tuple[str, ...]:
    resolution = result.artifact.resolution
    lines = [
        "StateGuard semantic resolution",
        f"state: {resolution.state.value if resolution is not None else 'NO_RESOLUTION'}",
    ]
    if resolution is not None and resolution.selected_symbol_id is not None:
        lines.append(f"symbol_id: {resolution.selected_symbol_id}")
    lines.append(f"graph_fingerprint: {result.graph_fingerprint}")
    return tuple(lines)


def render_applicability(result: ScenarioApplicabilityArtifact) -> tuple[str, ...]:
    fulfilment = result.policy.fulfilment
    lines = ["StateGuard scenario applicability"]
    lines.append(f"policy_evidence: {fulfilment.evidence_status.value}")
    if fulfilment.suggested_policy is not None:
        lines.append(f"implementation_suggestion: {fulfilment.suggested_policy.value}")
        lines.append("confirmation_required: true")
    lines.extend(
        f"{scenario.scenario_id.value}: {scenario.state.value}" for scenario in result.scenarios
    )
    return tuple(lines)


def render_runtime(result: RuntimeCapabilityArtifact) -> tuple[str, ...]:
    lines = [
        "StateGuard runtime capability assessment",
        f"mode: {result.mode}",
        f"lifecycle: {result.lifecycle.value}",
    ]
    lines.extend(
        f"{ingress.binding.method} {ingress.binding.effective_path}: "
        f"{ingress.addressability.state.value}"
        for ingress in result.ingresses
    )
    if result.diagnostics:
        lines.append("diagnostics: " + ",".join(item.code.value for item in result.diagnostics))
    return tuple(lines)


def _summary_lines(summary: VerificationRunSummary) -> tuple[str, ...]:
    return (
        f"verified_pass: {summary.verified_pass}",
        f"verified_fail: {summary.verified_fail}",
        f"static_warning: {summary.static_warning}",
        f"needs_input: {summary.needs_input}",
        f"unverified: {summary.unverified}",
        f"not_applicable: {summary.not_applicable}",
        "dynamic_coverage: "
        f"{summary.dynamic_coverage_numerator}/{summary.dynamic_coverage_denominator}",
    )


def _ci_count_line(label: str, counts: VerificationResultCountsV1) -> str:
    return (
        f"{label}: verified_pass={counts.verified_pass} "
        f"verified_fail={counts.verified_fail} "
        f"static_warning={counts.static_warning} "
        f"needs_input={counts.needs_input} "
        f"unverified={counts.unverified} "
        f"not_applicable={counts.not_applicable}"
    )


def render_ci_gate(result: CIGateResultV1) -> tuple[str, ...]:
    lines = [
        f"StateGuard CI gate: {result.status.value}",
        f"reason: {result.reason.value}",
        f"run_id: {result.run_id}",
        _ci_count_line("all_checks", result.all_check_counts),
        _ci_count_line("core_checks", result.core_check_counts),
        f"applicable_core_checks: {result.applicable_core_check_count}",
        f"proven_failures: {result.proven_failure_count}",
        f"core_not_proven: {result.core_not_proven_count}",
    ]
    if result.blocking_checks:
        lines.append("blocking_checks:")
        lines.extend(
            f"- {check.scenario_id.value} {check.assertion_key} "
            f"role={check.role.value} check_key={check.check_key} "
            f"result={check.result.value} reason={check.reason.value}"
            for check in result.blocking_checks
        )
    else:
        lines.append("blocking_checks: none")
    lines.extend(
        (
            f"artifact: .stateguard/runs/{result.run_id}/run.json",
            f"exit_code: {result.exit_code}",
        )
    )
    return tuple(lines)


def render_verification(result: VerificationRun) -> tuple[str, ...]:
    return (
        "StateGuard verification completed",
        f"run_id: {result.run_id}",
        *_summary_lines(result.summary),
        f"findings: {len(result.findings)}",
        f"artifact: .stateguard/runs/{result.run_id}/run.json",
    )


def render_run_list(result: RunListV1) -> tuple[str, ...]:
    if not result.runs:
        return ("No StateGuard verification runs found.",)
    lines = ["StateGuard verification runs"]
    lines.extend(
        f"{item.run_id} {item.completed_at.isoformat()} findings={item.finding_count} "
        f"verified_fail={item.summary.verified_fail}"
        for item in result.runs
    )
    return tuple(lines)


def render_run_report(result: RunReportV1) -> tuple[str, ...]:
    lines = [
        "StateGuard verification run",
        f"run_id: {result.run_id}",
        f"status: {result.status.value}",
        *_summary_lines(result.summary),
        f"findings: {len(result.findings)}",
    ]
    lines.extend(
        f"{check.scenario_id.value} {check.assertion_key}: {check.result.value}"
        for check in result.checks
    )
    return tuple(lines)
