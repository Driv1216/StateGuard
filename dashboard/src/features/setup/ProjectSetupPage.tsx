import { type FormEvent, useEffect, useState } from "react";

import { useDashboardActions, useDashboardState, useServerActionDisabled } from "../../app/state";
import type { RuntimeConfigRequest } from "../../api/contracts";
import { Button, DefinitionList, Field, Fingerprint, PageHeader, Panel, StateMessage, StatusBadge, formatDate, formatLocation } from "../../components/ui";

export function ProjectSetupPage() {
  const state = useDashboardState();
  return (
    <div className="page">
      <PageHeader eyebrow="Bounded configuration" title="Project Setup">
        Configure safe metadata and environment-variable names only. Secrets, raw YAML, artifacts, launch arguments, and source files never enter this dashboard.
      </PageHeader>
      <div className="setup-grid">
        <AiForm />
        <RuntimeForm />
      </div>
      <SemanticSetup />
      <PolicySetup />
      <Panel eyebrow="Project identity" title="Read-only binding">
        {state.project ? <DefinitionList items={[["Project ID", <code>{state.project.project_id}</code>], ["Application target", state.project.configured_app_target], ["Config schema", `v${state.project.config_schema_version}`]]} /> : <StateMessage kind="loading" title="Loading setup">Reading the safe setup projection.</StateMessage>}
      </Panel>
    </div>
  );
}

function AiForm() {
  const { project } = useDashboardState();
  const actions = useDashboardActions();
  const disabled = useServerActionDisabled();
  const [provider, setProvider] = useState<"gemini" | "openai-compatible">("gemini");
  const [model, setModel] = useState("");
  const [apiKeyEnv, setApiKeyEnv] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [errors, setErrors] = useState<string[]>([]);
  useEffect(() => {
    if (!project) return;
    setProvider(project.ai_provider ?? "gemini");
    setModel(project.ai_model ?? "");
    setApiKeyEnv(project.ai_api_key_env ?? "");
    setBaseUrl(project.ai_base_url ?? "");
  }, [project]);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const next: string[] = [];
    if (!model.trim()) next.push("Model is required.");
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(apiKeyEnv)) next.push("API key environment variable must be a portable name.");
    if (provider === "openai-compatible" && !/^https?:\/\//.test(baseUrl)) next.push("OpenAI-compatible providers require an absolute HTTP(S) base URL.");
    setErrors(next);
    if (next.length) return;
    void actions.configureAi({ provider, model: model.trim(), api_key_env: apiKeyEnv, ...(provider === "openai-compatible" ? { base_url: baseUrl.trim() } : {}) });
  };
  return <Panel eyebrow="Model provider" title="AI metadata">
    <form onSubmit={submit} noValidate>
      {errors.length ? <div className="form-summary" role="alert"><strong>Check this form</strong><ul>{errors.map((error) => <li key={error}>{error}</li>)}</ul></div> : null}
      <Field label="Provider"><select value={provider} onChange={(event) => setProvider(event.target.value as typeof provider)}><option value="gemini">Gemini</option><option value="openai-compatible">OpenAI-compatible</option></select></Field>
      <Field label="Model"><input value={model} onChange={(event) => setModel(event.target.value)} autoComplete="off" /></Field>
      <Field label="API key environment variable" hint="The environment-variable name is stored; its value is never read by this form."><input value={apiKeyEnv} onChange={(event) => setApiKeyEnv(event.target.value)} autoComplete="off" spellCheck={false} /></Field>
      {provider === "openai-compatible" ? <Field label="Base URL" hint="Absolute HTTP(S), without credentials, query, or fragment."><input type="url" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} autoComplete="off" /></Field> : null}
      <Button variant="primary" disabled={disabled} type="submit">Save AI configuration</Button>
    </form>
  </Panel>;
}

function RuntimeForm() {
  const { project } = useDashboardState();
  const actions = useDashboardActions();
  const disabled = useServerActionDisabled();
  const [mode, setMode] = useState<"static" | "managed" | "byo">("static");
  const [workingDirectory, setWorkingDirectory] = useState(".");
  const [childEnv, setChildEnv] = useState("");
  const [hostEnv, setHostEnv] = useState("");
  const [targetKind, setTargetKind] = useState<"local" | "declared_test">("local");
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:8000");
  const [readinessPath, setReadinessPath] = useState("/");
  const hiddenLaunch = project?.runtime_mode === "byo" && project.runtime?.launch_configured;
  useEffect(() => {
    if (!project) return;
    setMode(project.runtime_mode);
    setWorkingDirectory(project.runtime?.working_directory ?? ".");
    const binding = project.runtime?.environment_bindings[0];
    setChildEnv(binding?.child_name ?? "");
    setHostEnv(binding?.host_name ?? "");
    setTargetKind(project.runtime?.target?.kind ?? "local");
    setBaseUrl(project.runtime?.target?.base_url ?? "http://127.0.0.1:8000");
    setReadinessPath(project.runtime?.readiness?.path ?? "/");
  }, [project]);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (hiddenLaunch) return;
    let body: RuntimeConfigRequest = { mode: "static" };
    if (mode !== "static") {
      const common = { working_directory: workingDirectory || ".", env_from_host: childEnv && hostEnv ? { [childEnv]: hostEnv } : {}, startup_timeout_seconds: 20, request_timeout_seconds: 10, shutdown_timeout_seconds: 5 };
      body = mode === "managed" ? { mode, ...common } : { mode, ...common, target: targetKind === "local" ? { kind: "local", base_url: baseUrl } : { kind: "declared_test", base_url: baseUrl, declaration: "NON_PRODUCTION_TEST_ENVIRONMENT" }, readiness: { path: readinessPath, accepted_statuses: [200] } };
    }
    void actions.configureRuntime(body);
  };
  return <Panel eyebrow="Execution boundary" title="Runtime metadata">
    {hiddenLaunch ? <StateMessage kind="blocked" title="BYO runtime is read-only">This configuration contains hidden launch arguments. The dashboard will not submit a form that could erase or replace undisclosed values.</StateMessage> : null}
    <form onSubmit={submit}>
      <Field label="Runtime mode"><select disabled={hiddenLaunch} value={mode} onChange={(event) => setMode(event.target.value as typeof mode)}><option value="static">Static only</option><option value="managed">Managed local</option><option value="byo">Bring your own runtime</option></select></Field>
      {mode !== "static" ? <>
        <Field label="Working directory" hint="Project-relative path only."><input disabled={hiddenLaunch} value={workingDirectory} onChange={(event) => setWorkingDirectory(event.target.value)} /></Field>
        <div className="form-pair"><Field label="Child env name"><input disabled={hiddenLaunch} value={childEnv} onChange={(event) => setChildEnv(event.target.value)} /></Field><Field label="Host env name"><input disabled={hiddenLaunch} value={hostEnv} onChange={(event) => setHostEnv(event.target.value)} /></Field></div>
      </> : null}
      {mode === "byo" ? <>
        <Field label="Target kind"><select disabled={hiddenLaunch} value={targetKind} onChange={(event) => setTargetKind(event.target.value as typeof targetKind)}><option value="local">Loopback local</option><option value="declared_test">Declared non-production test</option></select></Field>
        <Field label="Base URL"><input disabled={hiddenLaunch} type="url" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} /></Field>
        <Field label="Readiness path"><input disabled={hiddenLaunch} value={readinessPath} onChange={(event) => setReadinessPath(event.target.value)} /></Field>
      </> : null}
      <Button variant="primary" disabled={disabled || hiddenLaunch} type="submit">Save runtime configuration</Button>
    </form>
  </Panel>;
}

function SemanticSetup() {
  const state = useDashboardState();
  const actions = useDashboardActions();
  const disabled = useServerActionDisabled();
  const [selected, setSelected] = useState("");
  const options = state.semanticOperation?.selection_options ?? [];
  return <Panel eyebrow="Customer-value authority" title="Semantic resolution">
    <div className="semantic-columns">
      <section><h3>Configured / recorded</h3>{state.semantics?.recorded ? <><div className="button-row"><StatusBadge value={state.semantics.state ?? "UNMAPPED"} /><span className="currentness">Source currentness not checked</span></div><DefinitionList items={[["Recorded", formatDate(state.semantics.recorded_at)], ["Basis", state.semantics.basis], ["Selected symbol ID", <Fingerprint value={state.semantics.selected_symbol_id} />], ["Context fingerprint", <Fingerprint value={state.semantics.semantic_context_fingerprint} />], ["Provider failure", state.semantics.provider_failure_code ?? "None recorded"]]} />{state.semantics.candidates.length ? <ul className="candidate-list recorded">{state.semantics.candidates.map((candidate) => <li key={`${candidate.kind}-${candidate.symbol_id}`}><strong>{candidate.kind.replaceAll("_", " ")}</strong><code>{candidate.symbol_id}</code><p>{candidate.rationale}</p>{candidate.provider_confidence !== null ? <small>Provider confidence {Math.round(candidate.provider_confidence * 100)}% · non-authoritative</small> : null}</li>)}</ul> : null}</> : <StateMessage title="No recorded semantic artifact">Nothing has been persisted yet.</StateMessage>}</section>
      <section><h3>Fresh current operation</h3>{!state.analysis ? <StateMessage title="Analyze required">Establish current project/source/graph authority before requesting enriched candidates.</StateMessage> : <><p className="fresh-authority"><strong>Current analysis available</strong><span><Fingerprint value={state.analysis.source_index_fingerprint} /></span></p><Button disabled={disabled} onClick={() => void actions.resolveSemantics()}>Resolve customer value</Button></>}
        {state.semanticOperation ? <div className="candidate-workflow"><p>{state.semanticOperation.artifact.provider_failure ? "Provider resolution failed safely. Current bounded manual options remain available." : "Provider-backed candidates are suggestions, not verification authority."}</p>{options.length ? <><div className="candidate-list">{options.map((option) => <label key={option.symbol_id} className={selected === option.symbol_id ? "selected" : ""}><input type="radio" name="semantic-symbol" value={option.symbol_id} checked={selected === option.symbol_id} onChange={() => setSelected(option.symbol_id)} /><span><strong>{option.qualified_name}</strong><small>{option.symbol_kind} · {formatLocation(option.source_location)}</small><code>{option.symbol_id}</code>{option.rationale ? <p>{option.rationale}</p> : null}{option.provider_confidence !== null ? <em>Provider confidence {Math.round(option.provider_confidence * 100)}% · non-authoritative</em> : null}</span></label>)}</div><Button variant="primary" disabled={disabled || !selected} onClick={() => void actions.confirmSemantics(selected)}>Confirm selected symbol</Button></> : <StateMessage title="No eligible current candidates">The current source analysis returned no bounded selection options.</StateMessage>}</div> : null}
      </section>
    </div>
  </Panel>;
}

function PolicySetup() {
  const state = useDashboardState();
  const actions = useDashboardActions();
  const disabled = useServerActionDisabled();
  const [fulfilment, setFulfilment] = useState<"CAPTURE_REQUIRED" | "AUTHORIZED_ALLOWED">("CAPTURE_REQUIRED");
  const [late, setLate] = useState<"FULFIL_LATER" | "DO_NOT_FULFIL">("DO_NOT_FULFIL");
  return <Panel eyebrow="Merchant declaration" title="Payment policy">
    <p className="muted">StateGuard never assumes one universal fulfilment or late-authorisation policy. Confirmation is explicit and re-bound to current analysis authority.</p>
    {!state.analysis ? <StateMessage title="Analyze before confirming policy">Current implementation evidence is required before policy confirmation.</StateMessage> : <form className="policy-form" onSubmit={(event) => { event.preventDefault(); void actions.confirmPolicy({ fulfilment, late_authorisation: late }); }}>
      <Field label="Fulfilment threshold"><select value={fulfilment} onChange={(event) => setFulfilment(event.target.value as typeof fulfilment)}><option value="CAPTURE_REQUIRED">Capture required</option><option value="AUTHORIZED_ALLOWED">Authorized allowed</option></select></Field>
      <Field label="Late authorisation"><select value={late} onChange={(event) => setLate(event.target.value as typeof late)}><option value="DO_NOT_FULFIL">Do not fulfil</option><option value="FULFIL_LATER">Fulfil later</option></select></Field>
      <Button variant="primary" disabled={disabled} type="submit">Confirm policy</Button>
    </form>}
  </Panel>;
}
