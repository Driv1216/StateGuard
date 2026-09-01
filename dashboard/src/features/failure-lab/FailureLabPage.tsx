import { useState } from "react";

import { useDashboardActions, useDashboardState, useServerActionDisabled } from "../../app/state";
import type { ApplicabilityScenario, RunCheck } from "../../api/contracts";
import { Button, Dialog, EvidenceBadge, PageHeader, Panel, StateMessage, StatusBadge, formatDate } from "../../components/ui";

const catalog = [
  ["SG-01", "Normal capture", "Customer value occurs exactly once at the configured policy threshold."],
  ["SG-02", "Duplicate delivery", "A duplicate webhook adds no second customer-value action."],
  ["SG-03", "Acknowledgement retry", "A modeled retry after an unsuccessful acknowledgement adds no second value action."],
  ["SG-04", "Out-of-order event", "A stale authorized event neither adds value nor regresses merchant state."],
  ["SG-05", "Forged webhook", "Rejected webhook trust prevents protected mutation and customer value."],
  ["SG-06", "Tampered Checkout callback", "Invalid callback trust prevents protected mutation and customer value."],
  ["SG-07", "Webhook without callback", "The webhook outcome remains correct without browser callback completion."],
  ["SG-08", "Late authorisation", "Pre-capture and post-capture value behavior follows confirmed late-payment policy."],
] as const;

export function FailureLabPage() {
  const state = useDashboardState();
  const actions = useDashboardActions();
  const disabled = useServerActionDisabled();
  const [openScenario, setOpenScenario] = useState<string | null>(null);
  const applicabilityByScenario = new Map(state.applicability?.scenarios.map((item) => [item.scenario_id, item]));
  const checksByScenario = new Map<string, RunCheck[]>();
  for (const check of state.selectedReport?.checks ?? []) {
    checksByScenario.set(check.scenario_id, [...(checksByScenario.get(check.scenario_id) ?? []), check]);
  }
  const selectedCatalog = catalog.find(([id]) => id === openScenario);
  return (
    <div className="page">
      <PageHeader eyebrow="Deterministic scenario runner" title="Failure Lab" actions={<div className="button-row"><Button disabled={disabled} onClick={() => void actions.analyzeApplicability()}>Analyze applicability</Button><Button variant="primary" disabled={disabled} onClick={() => void actions.runVerification()}>Run verification</Button></div>}>
        Eight fixed scenarios, exact backend applicability, and recorded run evidence. Current applicability never rewrites historical results.
      </PageHeader>
      {state.verificationPending ? <StateMessage kind="blocked" title="Verification running">The single-threaded server is occupied. Navigation and loaded evidence remain available; no progress requests will be made.</StateMessage> : null}
      <Panel className="run-toolbar">
        <div><p className="eyebrow">Recorded run</p><strong>{state.selectedReport ? formatDate(state.selectedReport.completed_at) : "No run selected"}</strong></div>
        <label><span>History</span><select disabled={disabled || state.runs.length === 0} value={state.selectedRunId ?? ""} onChange={(event) => void actions.selectRun(event.target.value)}><option value="" disabled>Select a run</option>{state.runs.map((run) => <option key={run.run_id} value={run.run_id}>{formatDate(run.completed_at)} · {run.finding_count} findings</option>)}</select></label>
      </Panel>
      {!state.applicability ? <StateMessage title="Current applicability not analyzed">Choose Analyze applicability to establish current source, graph, semantic, and policy authority. Historical run results below, if present, remain recorded evidence.</StateMessage> : null}
      <div className="scenario-grid">
        {catalog.map(([id, title, description]) => {
          const applicability = applicabilityByScenario.get(id);
          const checks = checksByScenario.get(id) ?? [];
          return <article className="scenario-card" key={id}>
            <div className="scenario-card-head"><span>{id}</span>{applicability ? <StatusBadge value={applicability.state} /> : <span className="badge badge-neutral">NOT ANALYZED</span>}</div>
            <h2>{title}</h2><p>{description}</p>
            <div className="authority-separator"><span>Current applicability</span><span>Recorded result</span></div>
            <div className="scenario-outcomes">
              <div>{applicability ? <><StatusBadge value={applicability.state} /><small>{applicability.instances.length} instance{applicability.instances.length === 1 ? "" : "s"}</small></> : <span className="muted">Not established</span>}</div>
              <div>{checks.length ? checks.map((check) => <span className="check-result" key={check.check_id}><StatusBadge value={check.result} /><EvidenceBadge value={check.evidence_tier} /></span>) : <span className="muted">No selected run evidence</span>}</div>
            </div>
            <Button variant="quiet" onClick={() => setOpenScenario(id)}>Inspect scenario</Button>
          </article>;
        })}
      </div>
      {openScenario && selectedCatalog ? <Dialog title={`${selectedCatalog[0]} · ${selectedCatalog[1]}`} onClose={() => setOpenScenario(null)}>
        <p>{selectedCatalog[2]}</p>
        <ScenarioDetail applicability={applicabilityByScenario.get(openScenario)} checks={checksByScenario.get(openScenario) ?? []} />
      </Dialog> : null}
    </div>
  );
}

function ScenarioDetail({ applicability, checks }: { applicability?: ApplicabilityScenario; checks: RunCheck[] }) {
  return <div className="scenario-detail">
    <section><p className="eyebrow">Current applicability</p>{applicability ? applicability.instances.map((instance) => <div className="assertion-group" key={instance.instance_id}><StatusBadge value={instance.state} /><code>{instance.instance_id}</code>{instance.assertions.map((assertion) => <div key={assertion.assertion_id}><strong>{assertion.key.replaceAll("_", " ")}</strong><StatusBadge value={assertion.state} /><ul>{assertion.reasons.map((reason, index) => <li key={`${reason.code}-${index}`}>{reason.code.replaceAll("_", " ")}</li>)}</ul></div>)}</div>) : <p className="muted">Not analyzed in this session.</p>}</section>
    <section><p className="eyebrow">Selected recorded run</p>{checks.length ? checks.map((check) => <div className="assertion-group" key={check.check_id}><div className="button-row"><StatusBadge value={check.result} /><EvidenceBadge value={check.evidence_tier} /></div>{String(check.evidence_tier).replaceAll("_", " ") === "E4 RAZORPAY GROUNDED" ? <p><strong>TEST MODE RESOURCE PROFILE GROUNDED</strong> · not webhook-delivery evidence</p> : null}<strong>{check.expected_invariant}</strong><p>{check.reason.replaceAll("_", " ")}</p><code>{check.check_id}</code></div>) : <p className="muted">No recorded check for this scenario.</p>}</section>
  </div>;
}
