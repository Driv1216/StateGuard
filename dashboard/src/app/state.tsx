import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useReducer,
  useRef,
} from "react";

import { ApiBlockedError, api, errorMessage } from "../api/client";
import type {
  ApplicabilityArtifact,
  FindingComparison,
  FullRun,
  GraphArtifact,
  ProjectAnalysis,
  ProjectSetup,
  RemediationAssistance,
  RunListItem,
  RunReport,
  RuntimeCapability,
  RuntimeConfigRequest,
  SemanticOperation,
  SemanticSnapshot,
} from "../api/contracts";

interface DashboardState {
  loading: boolean;
  startupError: string | null;
  actionError: string | null;
  busyAction: string | null;
  verificationPending: boolean;
  announcement: string;
  project: ProjectSetup | null;
  semantics: SemanticSnapshot | null;
  analysis: ProjectAnalysis | null;
  semanticOperation: SemanticOperation | null;
  graph: GraphArtifact | null;
  applicability: ApplicabilityArtifact | null;
  runtime: RuntimeCapability | null;
  runs: RunListItem[];
  selectedRunId: string | null;
  selectedReport: RunReport | null;
  fullRuns: Record<string, FullRun>;
  remediation: Record<string, RemediationAssistance>;
  comparisons: Record<string, FindingComparison>;
}

const initialState: DashboardState = {
  loading: true,
  startupError: null,
  actionError: null,
  busyAction: null,
  verificationPending: false,
  announcement: "Loading recorded StateGuard state.",
  project: null,
  semantics: null,
  analysis: null,
  semanticOperation: null,
  graph: null,
  applicability: null,
  runtime: null,
  runs: [],
  selectedRunId: null,
  selectedReport: null,
  fullRuns: {},
  remediation: {},
  comparisons: {},
};

type Action =
  | { type: "startup_ok"; project: ProjectSetup; semantics: SemanticSnapshot; runs: RunListItem[]; report: RunReport | null }
  | { type: "startup_error"; message: string }
  | { type: "busy"; action: string }
  | { type: "idle"; announcement: string }
  | { type: "error"; message: string }
  | { type: "verification_start" }
  | { type: "verification_finish" }
  | { type: "project"; value: ProjectSetup }
  | { type: "semantics"; value: SemanticSnapshot }
  | { type: "analysis"; value: ProjectAnalysis }
  | { type: "semantic_operation"; value: SemanticOperation }
  | { type: "graph"; value: GraphArtifact }
  | { type: "applicability"; value: ApplicabilityArtifact }
  | { type: "runtime"; value: RuntimeCapability }
  | { type: "runs"; value: RunListItem[] }
  | { type: "report"; value: RunReport }
  | { type: "full_run"; value: FullRun }
  | { type: "remediation"; occurrenceId: string; value: RemediationAssistance }
  | { type: "reverification"; occurrenceId: string; run: FullRun; comparison: FindingComparison };

function reducer(state: DashboardState, action: Action): DashboardState {
  switch (action.type) {
    case "startup_ok":
      return {
        ...state,
        loading: false,
        project: action.project,
        semantics: action.semantics,
        runs: action.runs,
        selectedRunId: action.report?.run_id ?? null,
        selectedReport: action.report,
        announcement: "Recorded StateGuard state loaded.",
      };
    case "startup_error":
      return { ...state, loading: false, startupError: action.message, announcement: action.message };
    case "busy":
      return { ...state, busyAction: action.action, actionError: null, announcement: `${action.action}.` };
    case "idle":
      return { ...state, busyAction: null, actionError: null, announcement: action.announcement };
    case "error":
      return { ...state, busyAction: null, actionError: action.message, announcement: action.message };
    case "verification_start":
      return {
        ...state,
        verificationPending: true,
        busyAction: "Verification running",
        actionError: null,
        announcement: "Verification running. Server actions are temporarily unavailable.",
      };
    case "verification_finish":
      return { ...state, verificationPending: false, busyAction: null };
    case "project":
      return {
        ...state,
        project: action.value,
        analysis: null,
        semanticOperation: null,
        graph: null,
        applicability: null,
        runtime: null,
      };
    case "semantics":
      return { ...state, semantics: action.value };
    case "analysis":
      return { ...state, analysis: action.value, applicability: action.value.applicability };
    case "semantic_operation":
      return {
        ...state,
        semanticOperation: action.value,
        analysis:
          state.analysis && action.value.artifact.resolution?.selected_symbol_id
            ? {
                ...state.analysis,
                semantics: {
                  ...state.analysis.semantics,
                  state: action.value.artifact.resolution.state,
                  basis: action.value.artifact.resolution.basis,
                  selected_symbol_id: action.value.artifact.resolution.selected_symbol_id,
                  resolution_fingerprint:
                    action.value.artifact.resolution_fingerprint ?? null,
                  matching_artifact_current: true,
                },
              }
            : state.analysis,
      };
    case "graph":
      return { ...state, graph: action.value };
    case "applicability":
      return { ...state, applicability: action.value };
    case "runtime":
      return { ...state, runtime: action.value };
    case "runs":
      return { ...state, runs: action.value };
    case "report":
      return { ...state, selectedRunId: action.value.run_id, selectedReport: action.value };
    case "full_run":
      return {
        ...state,
        selectedRunId: action.value.run_id,
        selectedReport: action.value,
        fullRuns: { ...state.fullRuns, [action.value.run_id]: action.value },
      };
    case "remediation":
      return {
        ...state,
        remediation: { ...state.remediation, [action.occurrenceId]: action.value },
      };
    case "reverification":
      return {
        ...state,
        fullRuns: { ...state.fullRuns, [action.run.run_id]: action.run },
        comparisons: { ...state.comparisons, [action.occurrenceId]: action.comparison },
      };
  }
}

interface DashboardActions {
  analyze(): Promise<void>;
  resolveSemantics(): Promise<void>;
  confirmSemantics(symbolId: string): Promise<void>;
  assessRuntime(): Promise<void>;
  loadGraph(): Promise<void>;
  analyzeApplicability(): Promise<void>;
  selectRun(runId: string): Promise<void>;
  loadFullRun(runId: string): Promise<void>;
  runVerification(): Promise<void>;
  requestRemediation(runId: string, occurrenceId: string): Promise<void>;
  reverifyFinding(runId: string, occurrenceId: string): Promise<void>;
  configureAi(body: Parameters<typeof api.configureAi>[0]): Promise<void>;
  configureRuntime(body: RuntimeConfigRequest): Promise<void>;
  confirmPolicy(body: Parameters<typeof api.confirmPolicy>[0]): Promise<void>;
}

const StateContext = createContext<DashboardState | null>(null);
const ActionsContext = createContext<DashboardActions | null>(null);

export function DashboardProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const stateRef = useRef(state);
  stateRef.current = state;

  useEffect(() => {
    let current = true;
    void (async () => {
      try {
        const [project, semantics, runList] = await Promise.all([
          api.project(),
          api.semantics(),
          api.runs(),
        ]);
        const report = runList.runs.length > 0 ? await api.latestRun() : null;
        if (current) dispatch({ type: "startup_ok", project, semantics, runs: runList.runs, report });
      } catch (error) {
        if (current) dispatch({ type: "startup_error", message: errorMessage(error) });
      }
    })();
    return () => {
      current = false;
    };
  }, []);

  const ensureAvailable = useCallback(() => {
    if (stateRef.current.verificationPending) throw new ApiBlockedError();
  }, []);

  const perform = useCallback(
    async <T,>(label: string, operation: () => Promise<T>, apply: (value: T) => void) => {
      ensureAvailable();
      dispatch({ type: "busy", action: label });
      try {
        const value = await operation();
        apply(value);
        dispatch({ type: "idle", announcement: `${label} complete.` });
      } catch (error) {
        dispatch({ type: "error", message: errorMessage(error) });
      }
    },
    [ensureAvailable],
  );

  const actions = useMemo<DashboardActions>(
    () => ({
      analyze: () => perform("Analyzing project", api.analyze, (value) => dispatch({ type: "analysis", value })),
      resolveSemantics: () =>
        perform("Resolving customer value", api.resolveSemantics, (value) =>
          dispatch({ type: "semantic_operation", value }),
        ),
      confirmSemantics: async (symbolId) => {
        await perform(
          "Confirming customer value",
          () => api.confirmSemantics(symbolId),
          (value) => dispatch({ type: "semantic_operation", value }),
        );
        if (!stateRef.current.actionError && !stateRef.current.verificationPending) {
          try {
            dispatch({ type: "semantics", value: await api.semantics() });
          } catch (error) {
            dispatch({ type: "error", message: errorMessage(error) });
          }
        }
      },
      assessRuntime: () =>
        perform("Assessing runtime", api.assessRuntime, (value) => dispatch({ type: "runtime", value })),
      loadGraph: () => perform("Loading Safety Graph", api.graph, (value) => dispatch({ type: "graph", value })),
      analyzeApplicability: () =>
        perform("Analyzing applicability", api.applicability, (value) =>
          dispatch({ type: "applicability", value }),
        ),
      selectRun: (runId) =>
        perform("Loading run report", () => api.runReport(runId), (value) =>
          dispatch({ type: "report", value }),
        ),
      loadFullRun: async (runId) => {
        if (stateRef.current.fullRuns[runId]) return;
        await perform("Loading full evidence", () => api.fullRun(runId), (value) =>
          dispatch({ type: "full_run", value }),
        );
      },
      runVerification: async () => {
        ensureAvailable();
        dispatch({ type: "verification_start" });
        try {
          const run = await api.createRun();
          dispatch({ type: "full_run", value: run });
          dispatch({ type: "runs", value: (await api.runs()).runs });
          dispatch({ type: "verification_finish" });
          dispatch({ type: "idle", announcement: "Verification complete." });
        } catch (error) {
          dispatch({ type: "verification_finish" });
          dispatch({ type: "error", message: errorMessage(error) });
        }
      },
      requestRemediation: (runId, occurrenceId) =>
        perform(
          "Generating grounded assistance",
          () => api.remediationAssistance(runId, occurrenceId),
          (value) => dispatch({ type: "remediation", occurrenceId, value }),
        ),
      reverifyFinding: async (runId, occurrenceId) => {
        ensureAvailable();
        dispatch({ type: "verification_start" });
        try {
          const result = await api.reverifyFinding(runId, occurrenceId);
          dispatch({
            type: "reverification",
            occurrenceId,
            run: result.run,
            comparison: result.comparison,
          });
          dispatch({ type: "runs", value: (await api.runs()).runs });
          dispatch({ type: "verification_finish" });
          dispatch({ type: "idle", announcement: "Canonical re-verification complete." });
        } catch (error) {
          dispatch({ type: "verification_finish" });
          dispatch({ type: "error", message: errorMessage(error) });
        }
      },
      configureAi: (body) =>
        perform("Saving AI configuration", () => api.configureAi(body), (value) =>
          dispatch({ type: "project", value }),
        ),
      configureRuntime: (body) =>
        perform("Saving runtime configuration", () => api.configureRuntime(body), (value) =>
          dispatch({ type: "project", value }),
        ),
      confirmPolicy: (body) =>
        perform("Confirming merchant policy", () => api.confirmPolicy(body), (value) =>
          dispatch({ type: "applicability", value }),
        ),
    }),
    [ensureAvailable, perform],
  );

  return (
    <StateContext.Provider value={state}>
      <ActionsContext.Provider value={actions}>{children}</ActionsContext.Provider>
    </StateContext.Provider>
  );
}

export function useDashboardState() {
  const value = useContext(StateContext);
  if (!value) throw new Error("Dashboard state is unavailable");
  return value;
}

export function useDashboardActions() {
  const value = useContext(ActionsContext);
  if (!value) throw new Error("Dashboard actions are unavailable");
  return value;
}

export function useServerActionDisabled() {
  const { loading, busyAction, verificationPending } = useDashboardState();
  return loading || busyAction !== null || verificationPending;
}
