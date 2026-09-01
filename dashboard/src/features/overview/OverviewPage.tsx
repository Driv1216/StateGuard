import { Link } from "react-router-dom";

import { useDashboardActions, useDashboardState, useServerActionDisabled } from "../../app/state";
import { Button, DefinitionList, Fingerprint, PageHeader, Panel, StateMessage, StatusBadge, formatDate } from "../../components/ui";

const summaryRows = [
  ["verified_pass", "VERIFIED PASS"],
  ["verified_fail", "VERIFIED FAIL"],
  ["static_warning", "STATIC WARNING"],
  ["needs_input", "NEEDS INPUT"],
  ["unverified", "UNVERIFIED"],
  ["not_applicable", "NOT APPLICABLE"],
] as const;

export function OverviewPage() {
  const state = useDashboardState();
  const actions = useDashboardActions();
  const disabled = useServerActionDisabled();
  const latest = state.selectedReport;
  return (
    <div className="page">
      <PageHeader eyebrow="Command center" title="Payment reliability, without invented certainty" actions={
        <div className="button-row">
          <Button variant="primary" disabled={disabled} onClick={() => void actions.analyze()}>Analyze</Button>
          <Button disabled={disabled} onClick={() => void actions.assessRuntime()}>Assess runtime</Button>
        </div>
      }>
        Recorded evidence and current analysis stay visibly separate. Nothing on this page turns AI confidence into verification authority.
      </PageHeader>

      {state.verificationPending ? <StateMessage kind="blocked" title="Verification is occupying the server">You can inspect this loaded state and move between pages. All server actions remain disabled until the synchronous run returns.</StateMessage> : null}

      <div className="overview-grid">
        <Panel eyebrow="Configured project" title="Project binding">
          {state.project ? <DefinitionList items={[
            ["Project ID", <code>{state.project.project_id}</code>],
            ["Application target", state.project.configured_app_target],
            ["Configuration schema", `v${state.project.config_schema_version}`],
            ["Runtime mode", state.project.runtime_mode],
          ]} /> : <StateMessage kind="loading" title="Loading project">Reading the bounded project setup contract.</StateMessage>}
          <Link className="text-link" to="/setup">Review Project Setup →</Link>
        </Panel>

        <Panel eyebrow="Recorded authority" title="Customer-value semantics">
          {state.semantics?.recorded ? <>
            <div className="split-status"><StatusBadge value={state.semantics.state ?? "UNMAPPED"} /><span className="currentness">Source currentness not checked</span></div>
            <DefinitionList items={[
              ["Recorded", formatDate(state.semantics.recorded_at)],
              ["Basis", state.semantics.basis],
              ["Selected symbol", state.semantics.selected_symbol_id ? <Fingerprint value={state.semantics.selected_symbol_id} /> : "No selected symbol"],
              ["Bundle", state.semantics.bundle_completeness],
            ]} />
          </> : <StateMessage title="No recorded semantic resolution">Analyze, then explicitly resolve customer value before confirmation.</StateMessage>}
          {state.analysis ? <div className="fresh-authority"><strong>Fresh analysis established</strong><span>{formatDate(state.analysis.generated_at)} · {state.analysis.semantics.matching_artifact_current ? "recorded semantics match current source" : "recorded semantics are not current"}</span></div> : null}
        </Panel>

        <Panel eyebrow="Current source authority" title="Analysis">
          {state.analysis ? <>
            <div className="metric-pair"><div><strong>{state.analysis.indexed_file_count}</strong><span>indexed files</span></div><div><strong>{state.analysis.indexed_symbol_count}</strong><span>indexed symbols</span></div></div>
            <DefinitionList items={[
              ["Source", state.analysis.source_completeness],
              ["Graph", state.analysis.graph_completeness],
              ["Source fingerprint", <Fingerprint value={state.analysis.project_source_fingerprint} />],
              ["Graph fingerprint", <Fingerprint value={state.analysis.graph_fingerprint} />],
            ]} />
          </> : <StateMessage title="Analysis has not run in this session">Opening the dashboard does not inspect source. Choose Analyze to establish current project, source, graph, semantic, and applicability authority.</StateMessage>}
        </Panel>

        <Panel eyebrow="Runtime" title="Configured vs assessed">
          <DefinitionList items={[
            ["Configured", state.project?.runtime_configured ? state.project.runtime_mode : "No runtime configuration"],
            ["Assessed capability", state.runtime ? state.runtime.lifecycle : "Not assessed in this session"],
            ["Process ownership", state.runtime?.ownership ?? "Not assessed"],
          ]} />
          {!state.runtime ? <p className="muted">Configuration describes intent. Only an explicit runtime assessment reports capability.</p> : null}
        </Panel>
      </div>

      <Panel eyebrow="Latest recorded run" title={latest ? `Run ${latest.run_id.slice(0, 18)}…` : "No verification history"}>
        {latest ? <>
          <div className="result-strip">
            {summaryRows.map(([key, label]) => <div key={key}><StatusBadge value={label.replaceAll(" ", "_")} /><strong>{latest.summary[key]}</strong></div>)}
          </div>
          <div className="evidence-distribution" aria-label="Evidence tier distribution">
            {Object.entries(latest.summary.evidence_tiers).map(([tier, count]) => <div key={tier}><span>{tier.replaceAll("_", " ")}</span><strong>{count}</strong></div>)}
          </div>
          <div className="button-row"><Link className="button button-secondary" to="/failure-lab">Inspect run results</Link><Link className="button button-secondary" to="/findings">Review findings</Link></div>
        </> : <StateMessage title="No recorded runs">Analyze authority and resolve required inputs before starting verification.</StateMessage>}
      </Panel>

      <Panel eyebrow="Next actions" title="Factual workflow">
        <ol className="workflow-list">
          <li className={state.analysis ? "done" : ""}><span>01</span><div><strong>Establish current authority</strong><p>Analyze the project explicitly; passive loading never does this.</p></div></li>
          <li className={state.analysis?.semantics.matching_artifact_current ? "done" : ""}><span>02</span><div><strong>Resolve required semantics and policy</strong><p>Review model suggestions as non-authoritative until confirmed.</p></div></li>
          <li className={state.runtime ? "done" : ""}><span>03</span><div><strong>Assess runtime capability</strong><p>Keep configured runtime separate from proven capability.</p></div></li>
          <li className={latest ? "done" : ""}><span>04</span><div><strong>Run verification</strong><p>The synchronous server is occupied until the complete evidence artifact returns.</p></div></li>
        </ol>
      </Panel>
    </div>
  );
}
