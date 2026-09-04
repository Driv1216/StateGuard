import { useMemo, useState } from "react";

import { useDashboardActions, useDashboardState, useServerActionDisabled } from "../../app/state";
import type { Finding, FullRun, JsonRecord, RunCheck } from "../../api/contracts";
import { Button, DefinitionList, Dialog, EvidenceBadge, PageHeader, Panel, StateMessage, StatusBadge, formatDate, formatLocation } from "../../components/ui";

export function FindingsPage() {
  const state = useDashboardState();
  const actions = useDashboardActions();
  const disabled = useServerActionDisabled();
  const [openFinding, setOpenFinding] = useState<Finding | null>(null);
  const report = state.selectedReport;
  const checks = useMemo(() => new Map(report?.checks.map((check) => [check.check_id, check])), [report]);
  const openDetail = (finding: Finding) => {
    setOpenFinding(finding);
    if (report && !state.fullRuns[report.run_id]) void actions.loadFullRun(report.run_id);
  };
  return (
    <div className="page">
      <PageHeader eyebrow="Backend-derived evidence" title="Findings">
        Every row is returned by the verification artifact and joined to its exact backend check. StateGuard does not derive findings in the browser.
      </PageHeader>
      <Panel className="run-toolbar">
        <div><p className="eyebrow">Evidence source</p><strong>{report ? `${formatDate(report.completed_at)} · ${report.findings.length} findings` : "No recorded run"}</strong></div>
        <label><span>History</span><select disabled={disabled || state.runs.length === 0} value={state.selectedRunId ?? ""} onChange={(event) => void actions.selectRun(event.target.value)}><option value="" disabled>Select a run</option>{state.runs.map((run) => <option key={run.run_id} value={run.run_id}>{formatDate(run.completed_at)} · {run.finding_count} findings</option>)}</select></label>
      </Panel>
      {state.verificationPending && !report ? <StateMessage kind="blocked" title="Findings unavailable during verification">No report request can be sent while the synchronous server is occupied.</StateMessage> : null}
      {!report ? <StateMessage title="No run report loaded">Run verification or select recorded history to inspect backend findings.</StateMessage> : report.findings.length === 0 ? <StateMessage title="This run returned zero findings">No browser-generated success claim is added. Review the run checks in Failure Lab for their exact result states.</StateMessage> : <div className="findings-list">
        {report.findings.map((finding) => {
          const check = checks.get(finding.check_id);
          return <article className={`finding-row ${finding.critical ? "finding-critical" : ""}`} key={finding.occurrence_id}>
            <div className="finding-kind"><span className="finding-glyph" aria-hidden="true">{finding.critical ? "!" : "·"}</span><div><StatusBadge value={check?.result ?? finding.kind} /><span>{finding.kind.replaceAll("_", " ")}</span></div></div>
            <div className="finding-main"><p className="eyebrow">{check?.scenario_id ?? "Recorded check"}</p><h2>{check?.expected_invariant ?? finding.check_key}</h2><p>{check?.reason.replaceAll("_", " ") ?? "Exact check detail is unavailable."}</p></div>
            <div className="finding-evidence">{check ? <EvidenceBadge value={check.evidence_tier} /> : null}<code>{finding.occurrence_id.slice(0, 16)}…</code></div>
            <Button variant="quiet" disabled={state.verificationPending && !state.fullRuns[report.run_id]} onClick={() => openDetail(finding)}>Evidence detail</Button>
          </article>;
        })}
      </div>}
      {openFinding && report ? <FindingDialog finding={openFinding} check={checks.get(openFinding.check_id)} fullRun={state.fullRuns[report.run_id]} onClose={() => setOpenFinding(null)} /> : null}
    </div>
  );
}

interface RuntimeRequestItem {
  request_id?: string;
  role?: string;
  ordinal?: number;
  http_status?: number | null;
  customer?: {
    entered_count?: number;
    returned_normally_count?: number;
  } | null;
}

function SafeRuntimeEvidenceView({ runtimeEvidence }: { runtimeEvidence?: JsonRecord }) {
  if (!runtimeEvidence) return <p className="muted">No runtime evidence recorded for this check.</p>;
  const requests = (Array.isArray(runtimeEvidence.requests) ? runtimeEvidence.requests : []) as RuntimeRequestItem[];
  return (
    <div className="safe-runtime-view">
      {requests.length > 0 ? (
        <div className="request-evidence-table-container">
          <table className="request-evidence-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Role</th>
                <th>HTTP Status</th>
                <th>Target Entered</th>
                <th>Target Returned</th>
              </tr>
            </thead>
            <tbody>
              {requests.map((req, idx) => (
                <tr key={req.request_id ?? idx}>
                  <td><code>{(req.ordinal ?? idx) + 1}</code></td>
                  <td><strong>{String(req.role ?? "").replaceAll("_", " ")}</strong></td>
                  <td><span className="badge badge-neutral">{req.http_status ?? "—"}</span></td>
                  <td>{req.customer ? `${req.customer.entered_count ?? 0}×` : "—"}</td>
                  <td>{req.customer ? `${req.customer.returned_normally_count ?? 0}×` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <details className="full-evidence-details">
        <summary><strong>Full safe structured evidence</strong></summary>
        <pre>{JSON.stringify(runtimeEvidence, null, 2)}</pre>
      </details>
    </div>
  );
}

function SafeGroundingEvidenceView({ grounding }: { grounding?: JsonRecord | null }) {
  if (!grounding) return <p className="muted">This check has no Razorpay Test Mode resource grounding.</p>;
  return <div>
    <p><strong>TEST MODE RESOURCE PROFILE GROUNDED</strong></p>
    <p className="muted">A freshly fetched captured Payment and linked paid Order shaped the safe synthetic SG-01 profile. This is not webhook-delivery or provider-execution evidence.</p>
    <details className="full-evidence-details">
      <summary><strong>Safe grounding fingerprints</strong></summary>
      <pre>{JSON.stringify(grounding, null, 2)}</pre>
    </details>
  </div>;
}

export function isRemediationEligible(finding: Finding, check?: RunCheck): boolean {
  return finding.critical && check?.result === "VERIFIED FAIL";
}

function FindingDialog({ finding, check, fullRun, onClose }: { finding: Finding; check?: RunCheck; fullRun?: FullRun; onClose(): void }) {
  const state = useDashboardState();
  const actions = useDashboardActions();
  const disabled = useServerActionDisabled();
  const [copied, setCopied] = useState(false);
  const fullCheck = fullRun?.checks.find((item) => item.check_id === finding.check_id);
  const rules = fullRun?.authority.razorpay_rules?.referenced_rules.filter((rule) => check?.razorpay_rule_ids.includes(rule.rule_id)) ?? [];
  const assistance = state.remediation[finding.occurrence_id];
  const comparison = state.comparisons[finding.occurrence_id];
  const eligible = isRemediationEligible(finding, check);
  return <Dialog title="Finding evidence" onClose={onClose}>
    {!check ? <StateMessage kind="error" title="Exact check unavailable">This finding could not be joined to a check in the selected backend report.</StateMessage> : <>
      <div className="button-row"><StatusBadge value={check.result} /><EvidenceBadge value={check.evidence_tier} /></div>
      <DefinitionList items={[["Scenario / assertion", `${check.scenario_id} · ${check.assertion_key}`], ["Invariant", `${check.invariant_id} v${check.invariant_version}`], ["Expected", check.expected_invariant], ["Reason", check.reason.replaceAll("_", " ")], ["Applicability", check.applicability.state], ["Check ID", <code>{check.check_id}</code>]]} />
      <div className="evidence-sections">
        <section><h3>Policy authority</h3><pre>{JSON.stringify(check.policy_authority, null, 2)}</pre></section>
        <section><h3>Graph references</h3>{check.graph_node_ids.length || check.graph_edge_ids.length ? <><p>Nodes: {check.graph_node_ids.join(", ") || "None"}</p><p>Edges: {check.graph_edge_ids.join(", ") || "None"}</p></> : <p className="muted">No graph references recorded.</p>}</section>
        <section><h3>Source references</h3>{check.source_references.length ? <ul>{check.source_references.map((source, index) => <li key={`${source.symbol_id}-${index}`}><code>{source.symbol_id}</code> · {formatLocation(source.source_location)}</li>)}</ul> : <p className="muted">No source references recorded.</p>}</section>
        <section><h3>Safe runtime observations</h3>{!fullRun ? <StateMessage kind="loading" title="Loading full evidence">The bounded full-run artifact is requested only when this detail opens.</StateMessage> : <SafeRuntimeEvidenceView runtimeEvidence={fullCheck?.runtime_evidence} />}</section>
        <section><h3>Razorpay Test Mode grounding</h3>{!fullRun ? <p className="muted">Loading bounded grounding evidence…</p> : <SafeGroundingEvidenceView grounding={fullCheck?.grounding} />}</section>
        <section><h3>Razorpay rule authority</h3>{!fullRun ? <p className="muted">Loading recorded rule facts…</p> : rules.length ? <ul className="rule-list">{rules.map((rule) => <li key={rule.rule_id}><strong>{rule.rule_id}</strong><p>{rule.fact}</p><a href={rule.source_url} target="_blank" rel="noreferrer">Official Razorpay source ↗</a><small>Verified {rule.verified_on}</small></li>)}</ul> : <p className="muted">No rule facts referenced by this check.</p>}</section>
      </div>
      <div className="remediation-workflow">
        <section>
          <p className="eyebrow">Grounded developer assistance</p>
          <h3>Explanation and bounded proposal</h3>
          {!eligible ? <StateMessage title="Remediation not eligible">Only critical VERIFIED FAIL findings can request model assistance.</StateMessage> : !assistance ? <><p className="muted">StateGuard will first prove whether finding-relevant current authority still matches. Historical evidence may still support an explanation when source-grounded patching is blocked.</p><Button disabled={disabled} onClick={() => void actions.requestRemediation(fullRun?.run_id ?? state.selectedRunId ?? "", finding.occurrence_id)}>Generate grounded assistance</Button></> : <div className="assistance-result">
            <StateMessage kind={assistance.mode === "CURRENT_SOURCE_REMEDIATION" ? "loading" : "blocked"} title={assistance.mode.replaceAll("_", " ")}>{assistance.mode_label}</StateMessage>
            {assistance.drift.length ? <><h4>Authority drift</h4><ul>{assistance.drift.map((item, index) => <li key={`${item.dimension}-${index}`}>{item.dimension.replaceAll("_", " ")} · {item.blocking ? "blocks current-source patching" : "diagnostic only"}</li>)}</ul></> : <p className="muted">No material finding-authority drift was detected.</p>}
            <h4>Grounded explanation</h4>
            <p>{assistance.causal_summary}</p>
            <ul>{assistance.grounded_claims.map((claim, index) => <li key={`${claim.text}-${index}`}>{claim.text}<small>References: {claim.references.join(", ")}</small></li>)}</ul>
            <h4>Proposal</h4>
            <StatusBadge value={assistance.proposal_state} />
            {assistance.remediation_rationale ? <p>{assistance.remediation_rationale}</p> : null}
            {assistance.limitations.length ? <ul>{assistance.limitations.map((item) => <li key={item}>{item}</li>)}</ul> : null}
            {assistance.patch ? <div className="patch-preview"><div className="patch-preview-header"><strong className="patch-warning-label">AI-GENERATED — NOT VERIFIED</strong><span className="patch-subtitle">No merchant file modified</span></div><pre>{assistance.patch.diff}</pre><p className="patch-instructions">StateGuard did not change your merchant files. Review and apply this diff explicitly in your editor.</p><Button variant="quiet" onClick={() => { void navigator.clipboard.writeText(assistance.patch?.diff ?? ""); setCopied(true); }}>{copied ? "Copied" : "Copy diff"}</Button></div> : null}
          </div>}
        </section>
        {eligible && assistance ? <section className="reverify-section"><p className="eyebrow">Developer-controlled verification</p><h3>Verify current authority</h3><p className="muted">After you explicitly edit the merchant code, StateGuard runs the canonical verifier and correlates only the exact logical check key.</p><Button variant="primary" disabled={disabled} onClick={() => void actions.reverifyFinding(fullRun?.run_id ?? state.selectedRunId ?? "", finding.occurrence_id)}>Re-verify current source</Button>{comparison ? <div className="comparison-card">{comparison.outcome === "PROVEN_RESOLVED" ? <div className="reverification-banner reverification-resolved"><div className="reverification-status-row"><span className="reverification-transition">VERIFIED FAIL → VERIFIED PASS</span><StatusBadge value="PROVEN_RESOLVED" /></div><p><strong>PROVEN_RESOLVED</strong> — The verified failure was deterministically proven resolved against current authority.</p>{comparison.current_check_id ? <p className="muted">Exact check ID: <code>{comparison.current_check_id}</code></p> : null}<details className="check-key-details"><summary>Exact check key</summary><code>{comparison.check_key}</code></details></div> : <div className="reverification-banner reverification-unresolved"><div className="reverification-status-row"><StatusBadge value={comparison.outcome} /></div><p>{comparison.current_check_id ? `Exact check: ${comparison.current_check_id}` : "The exact historical logical key was not present; no similarity match was inferred."}</p><details className="check-key-details"><summary>Exact check key</summary><code>{comparison.check_key}</code></details></div>}</div> : null}</section> : null}
      </div>
    </>}
  </Dialog>;
}
