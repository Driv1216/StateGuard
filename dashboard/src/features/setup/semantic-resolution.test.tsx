import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SemanticOperation } from "../../api/contracts";
import { AppRoutes } from "../../app/AppRoutes";
import { DashboardProvider } from "../../app/state";
import { getSemanticWorkflowMessage } from "./ProjectSetupPage";

afterEach(() => vi.unstubAllGlobals());

const json = (value: object, status = 200) =>
  Promise.resolve(new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } }));

describe("getSemanticWorkflowMessage unit tests", () => {
  const dummyLocation = { path: "app/main.py", line_start: 1, column_start: 1, line_end: 10, column_end: 1 };

  it("returns failure copy when there is an actual provider failure", () => {
    const op: SemanticOperation = {
      schema_version: 1,
      graph_fingerprint: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      artifact: {
        provider_failure: { code: "PROVIDER_RATE_LIMIT", status_code: 429 },
        context: { bundle_completeness: "BUNDLE_PARTIAL", presented_symbol_ids: ["sym_1"] },
        resolution: null,
      },
      selection_options: [
        {
          kind: "PRESENTED",
          symbol_id: "sym_1",
          qualified_name: "app.main.order",
          symbol_kind: "function",
          source_location: dummyLocation,
          rationale: null,
          provider_confidence: null,
        },
      ],
    };

    expect(getSemanticWorkflowMessage(op)).toBe(
      "Provider resolution failed safely. Current bounded manual options remain available."
    );
  });

  it("returns partial-coverage copy when provider succeeded but bundle is partial with suggestions", () => {
    const op: SemanticOperation = {
      schema_version: 1,
      graph_fingerprint: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      artifact: {
        provider_failure: null,
        context: { bundle_completeness: "BUNDLE_PARTIAL", presented_symbol_ids: ["sym_1"] },
        partial_bundle_suggestions: [
          {
            symbol_id: "sym_1",
            catalog_reference: "ref_1",
            rationale: "Issues ticket pass",
            excerpt_references: ["exc_1"],
            provider_confidence: 0.9,
          },
        ],
        resolution: null,
      },
      selection_options: [
        {
          kind: "PARTIAL_SUGGESTION",
          symbol_id: "sym_1",
          qualified_name: "app.main.order",
          symbol_kind: "function",
          source_location: dummyLocation,
          rationale: "Issues ticket pass",
          provider_confidence: 0.9,
        },
      ],
    };

    expect(getSemanticWorkflowMessage(op)).toBe(
      "AI resolution completed, but source coverage is partial. Provider suggestions require human confirmation."
    );
  });

  it("returns default suggestion copy without false provider-failure wording when provider succeeds on complete bundle", () => {
    const op: SemanticOperation = {
      schema_version: 1,
      graph_fingerprint: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      artifact: {
        provider_failure: null,
        context: { bundle_completeness: "BUNDLE_COMPLETE", presented_symbol_ids: ["sym_1"] },
        valid_candidates: [
          {
            symbol_id: "sym_1",
            catalog_reference: "ref_1",
            rationale: "Identified customer value",
            excerpt_references: ["exc_1"],
            provider_confidence: 0.95,
          },
        ],
        resolution: { state: "AMBIGUOUS", basis: "UNRESOLVED", selected_symbol_id: null },
      },
      selection_options: [
        {
          kind: "VALID",
          symbol_id: "sym_1",
          qualified_name: "app.main.order",
          symbol_kind: "function",
          source_location: dummyLocation,
          rationale: "Identified customer value",
          provider_confidence: 0.95,
        },
      ],
    };

    const message = getSemanticWorkflowMessage(op);
    expect(message).toBe("Provider-backed candidates are suggestions, not verification authority.");
    expect(message).not.toContain("failed safely");
  });
});

describe("ProjectSetupPage semantic workflow integration", () => {
  const setupMocks = (semanticOpResult: object) => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === "/api/v1/project") {
        return json({
          schema_version: 1,
          project_id: "sgproj_test",
          config_schema_version: 2,
          configured_app_target: "main:app",
          ai_provider: "gemini",
          ai_model: "gemini-2.5-flash",
          ai_api_key_env: "GEMINI_API_KEY",
          ai_base_url: null,
          runtime_configured: true,
          runtime_mode: "managed",
          runtime: {
            mode: "managed",
            working_directory: null,
            environment_bindings: [],
            startup_timeout_seconds: null,
            request_timeout_seconds: null,
            shutdown_timeout_seconds: null,
            target: null,
            readiness: null,
            launch_configured: false,
          },
          configured_customer_value_symbol_id: null,
          configured_fulfilment_policy: null,
          configured_late_authorisation_policy: null,
        });
      }
      if (path === "/api/v1/semantics/resolve" && init?.method === "POST") {
        return json(semanticOpResult);
      }
      if (path === "/api/v1/semantics") {
        return json({
          schema_version: 1,
          source_currentness: "NOT_CHECKED",
          project_id: "sgproj_test",
          recorded: false,
          recorded_at: null,
          state: null,
          basis: null,
          selected_symbol_id: null,
          semantic_context_fingerprint: null,
          resolution_fingerprint: null,
          bundle_completeness: null,
          provider_id: null,
          model: null,
          provider_failure_code: null,
          provider_failure_status_code: null,
          presented_symbol_ids: [],
          candidates: [],
          human_basis: null,
          human_acted_at: null,
        });
      }
      if (path === "/api/v1/runs") {
        return json({ schema_version: 1, runs: [] });
      }
      if (path === "/api/v1/analysis" && init?.method === "POST") {
        return json({
          schema_version: 1,
          generated_at: "2026-09-01T12:00:00Z",
          project_id: "sgproj_test",
          project_source_fingerprint: "sha256:1111",
          source_index_fingerprint: "sha256:2222",
          source_completeness: "COMPLETE",
          indexed_file_count: 1,
          indexed_symbol_count: 2,
          source_diagnostics: [],
          graph_fingerprint: "sha256:3333",
          graph_completeness: "COMPLETE",
          graph_nodes: [],
          graph_edges: [],
          graph_diagnostics: [],
          semantics: {
            state: null,
            basis: null,
            selected_symbol_id: null,
            resolution_fingerprint: null,
            selected_target_provenance: [],
            matching_artifact_current: false,
          },
          policy: {
            fulfilment: null,
            late_authorisation: null,
            policy_version: "2",
          },
          applicability: {
            schema_version: 1,
            project_id: "sgproj_test",
            overall_state: "APPLICABLE",
            scenarios: [],
          },
        });
      }
      throw new Error(`unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  };

  it("renders partial bundle copy when provider succeeded with partial coverage", async () => {
    const partialOp = {
      schema_version: 1,
      graph_fingerprint: "sha256:3333",
      artifact: {
        provider_failure: null,
        context: { bundle_completeness: "BUNDLE_PARTIAL", presented_symbol_ids: ["sym_ticket"] },
        partial_bundle_suggestions: [
          {
            symbol_id: "sym_ticket",
            catalog_reference: "ref_1",
            rationale: "Issues ticket pass",
            excerpt_references: ["exc_1"],
            provider_confidence: 0.9,
          },
        ],
        resolution: null,
      },
      selection_options: [
        {
          kind: "PARTIAL_SUGGESTION",
          symbol_id: "sym_ticket",
          qualified_name: "app.domain.mint_pass",
          symbol_kind: "function",
          source_location: { path: "app/domain.py", line_start: 10, column_start: 1, line_end: 20, column_end: 1 },
          rationale: "Issues ticket pass",
          provider_confidence: 0.9,
        },
      ],
    };

    setupMocks(partialOp);
    const user = userEvent.setup();

    render(
      <MemoryRouter initialEntries={["/setup"]}>
        <DashboardProvider>
          <AppRoutes />
        </DashboardProvider>
      </MemoryRouter>
    );

    // Establish analysis authority
    await user.click(screen.getAllByRole("link", { name: /Overview/ })[0]);
    await user.click(screen.getByRole("button", { name: "Analyze" }));

    await user.click(screen.getAllByRole("link", { name: /Project Setup/ })[0]);
    await user.click(screen.getByRole("button", { name: "Resolve customer value" }));

    expect(
      await screen.findByText(
        "AI resolution completed, but source coverage is partial. Provider suggestions require human confirmation."
      )
    ).toBeInTheDocument();
    expect(
      screen.queryByText("Provider resolution failed safely. Current bounded manual options remain available.")
    ).not.toBeInTheDocument();
  });

  it("renders failure copy when provider resolution failed safely", async () => {
    const failureOp = {
      schema_version: 1,
      graph_fingerprint: "sha256:3333",
      artifact: {
        provider_failure: { code: "PROVIDER_RATE_LIMIT", status_code: 429 },
        context: { bundle_completeness: "BUNDLE_PARTIAL", presented_symbol_ids: ["sym_ticket"] },
        resolution: null,
      },
      selection_options: [
        {
          kind: "PRESENTED",
          symbol_id: "sym_ticket",
          qualified_name: "app.domain.mint_pass",
          symbol_kind: "function",
          source_location: { path: "app/domain.py", line_start: 10, column_start: 1, line_end: 20, column_end: 1 },
          rationale: null,
          provider_confidence: null,
        },
      ],
    };

    setupMocks(failureOp);
    const user = userEvent.setup();

    render(
      <MemoryRouter initialEntries={["/setup"]}>
        <DashboardProvider>
          <AppRoutes />
        </DashboardProvider>
      </MemoryRouter>
    );

    await user.click(screen.getAllByRole("link", { name: /Overview/ })[0]);
    await user.click(screen.getByRole("button", { name: "Analyze" }));

    await user.click(screen.getAllByRole("link", { name: /Project Setup/ })[0]);
    await user.click(screen.getByRole("button", { name: "Resolve customer value" }));

    expect(
      await screen.findByText(
        "Provider resolution failed safely. Current bounded manual options remain available."
      )
    ).toBeInTheDocument();
  });
});
