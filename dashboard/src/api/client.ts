import type {
  ApplicabilityArtifact,
  FullRun,
  GraphArtifact,
  ProjectAnalysis,
  ProjectSetup,
  RemediationAssistance,
  ReverificationResult,
  RunList,
  RunReport,
  RuntimeCapability,
  RuntimeConfigRequest,
  SemanticOperation,
  SemanticSnapshot,
} from "./contracts";

export class ApiControlError extends Error {
  constructor(public readonly code: string, message: string, public readonly status: number) {
    super(message);
    this.name = "ApiControlError";
  }
}

export class ApiNetworkError extends Error {
  constructor() {
    super("StateGuard could not be reached on this origin.");
    this.name = "ApiNetworkError";
  }
}

export class ApiMalformedResponseError extends Error {
  constructor() {
    super("StateGuard returned a malformed response.");
    this.name = "ApiMalformedResponseError";
  }
}

export class ApiBlockedError extends Error {
  constructor() {
    super("Server data is unavailable while verification is running.");
    this.name = "ApiBlockedError";
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

async function request<T>(
  path: string,
  options: RequestInit = {},
  validate: (value: Record<string, unknown>) => boolean = () => true,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...options,
      headers: options.body
        ? { "Content-Type": "application/json", ...(options.headers ?? {}) }
        : options.headers,
    });
  } catch {
    throw new ApiNetworkError();
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new ApiMalformedResponseError();
  }
  if (!isRecord(payload)) throw new ApiMalformedResponseError();
  if (!response.ok) {
    if (typeof payload.code !== "string" || typeof payload.message !== "string") {
      throw new ApiMalformedResponseError();
    }
    throw new ApiControlError(payload.code, payload.message, response.status);
  }
  if (!validate(payload)) throw new ApiMalformedResponseError();
  return payload as T;
}

const v1 = (value: Record<string, unknown>) => value.schema_version === 1;
const v2 = (value: Record<string, unknown>) => value.schema_version === 2;
const v3 = (value: Record<string, unknown>) => value.schema_version === 3;
const emptyBody = JSON.stringify({});
const runArtifact = (value: Record<string, unknown>) =>
  (v1(value) || v2(value) || v3(value)) && typeof value.run_id === "string";

export const api = {
  project: () => request<ProjectSetup>("/api/v1/project", {}, v1),
  semantics: () => request<SemanticSnapshot>("/api/v1/semantics", {}, v1),
  runs: () =>
    request<RunList>("/api/v1/runs", {}, (value) => v1(value) && Array.isArray(value.runs)),
  latestRun: () => request<RunReport>("/api/v1/runs/latest", {}, v1),
  analyze: () =>
    request<ProjectAnalysis>("/api/v1/analysis", { method: "POST", body: emptyBody }, v1),
  resolveSemantics: () =>
    request<SemanticOperation>(
      "/api/v1/semantics/resolve",
      { method: "POST", body: emptyBody },
      v1,
    ),
  confirmSemantics: (symbolId: string) =>
    request<SemanticOperation>(
      "/api/v1/semantics/confirm",
      { method: "POST", body: JSON.stringify({ symbol_id: symbolId }) },
      v1,
    ),
  graph: () => request<GraphArtifact>("/api/v1/graph", {}, v2),
  applicability: () =>
    request<ApplicabilityArtifact>(
      "/api/v1/applicability/analyze",
      { method: "POST", body: emptyBody },
      v2,
    ),
  assessRuntime: () =>
    request<RuntimeCapability>(
      "/api/v1/runtime/assess",
      { method: "POST", body: emptyBody },
      v1,
    ),
  createRun: () =>
    request<FullRun>("/api/v1/runs", { method: "POST", body: emptyBody }, runArtifact),
  runReport: (runId: string) =>
    request<RunReport>(`/api/v1/runs/${encodeURIComponent(runId)}/report`, {}, v1),
  fullRun: (runId: string) =>
    request<FullRun>(`/api/v1/runs/${encodeURIComponent(runId)}`, {}, runArtifact),
  remediationAssistance: (runId: string, occurrenceId: string) =>
    request<RemediationAssistance>(
      `/api/v1/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(occurrenceId)}/assistance`,
      { method: "POST", body: emptyBody },
      (value) => typeof value.mode === "string" && typeof value.proposal_state === "string",
    ),
  reverifyFinding: (runId: string, occurrenceId: string) =>
    request<ReverificationResult>(
      `/api/v1/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(occurrenceId)}/reverify`,
      { method: "POST", body: emptyBody },
      (value) => isRecord(value.run) && isRecord(value.comparison),
    ),
  configureAi: (body: {
    provider: "gemini" | "openai-compatible";
    model: string;
    api_key_env: string;
    base_url?: string;
  }) =>
    request<ProjectSetup>(
      "/api/v1/config/ai",
      { method: "PUT", body: JSON.stringify(body) },
      v1,
    ),
  configureRuntime: (body: RuntimeConfigRequest) =>
    request<ProjectSetup>(
      "/api/v1/config/runtime",
      { method: "PUT", body: JSON.stringify(body) },
      v1,
    ),
  confirmPolicy: (body: {
    fulfilment?: "CAPTURE_REQUIRED" | "AUTHORIZED_ALLOWED";
    late_authorisation?: "FULFIL_LATER" | "DO_NOT_FULFIL";
  }) =>
    request<ApplicabilityArtifact>(
      "/api/v1/policy/confirm",
      { method: "POST", body: JSON.stringify(body) },
      v2,
    ),
};

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "StateGuard encountered an unexpected error.";
}
