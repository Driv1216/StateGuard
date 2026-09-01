import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";

import { AppRoutes } from "./AppRoutes";
import { DashboardProvider } from "./state";

afterEach(() => vi.unstubAllGlobals());

const json = (value: object, status = 200) => Promise.resolve(new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } }));

it("locks every server action while preserving eager client-side navigation", async () => {
  const verification = new Promise<Response>(() => undefined);
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/project") return json({ schema_version: 1, project_id: "sgproj_test", config_schema_version: 2, configured_app_target: "main:app", ai_provider: null, ai_model: null, ai_api_key_env: null, ai_base_url: null, runtime_configured: true, runtime_mode: "static", runtime: { mode: "static", working_directory: null, environment_bindings: [], startup_timeout_seconds: null, request_timeout_seconds: null, shutdown_timeout_seconds: null, target: null, readiness: null, launch_configured: false }, configured_customer_value_symbol_id: null, configured_fulfilment_policy: null, configured_late_authorisation_policy: null });
    if (path === "/api/v1/semantics") return json({ schema_version: 1, source_currentness: "NOT_CHECKED", project_id: "sgproj_test", recorded: false, recorded_at: null, state: null, basis: null, selected_symbol_id: null, semantic_context_fingerprint: null, resolution_fingerprint: null, bundle_completeness: null, provider_id: null, model: null, provider_failure_code: null, provider_failure_status_code: null, presented_symbol_ids: [], candidates: [], human_basis: null, human_acted_at: null });
    if (path === "/api/v1/runs" && init?.method !== "POST") return json({ schema_version: 1, runs: [] });
    if (path === "/api/v1/runs" && init?.method === "POST") return verification;
    throw new Error(`unexpected request: ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  const user = userEvent.setup();
  render(<MemoryRouter initialEntries={["/"]}><DashboardProvider><AppRoutes /></DashboardProvider></MemoryRouter>);
  await screen.findByText("Dashboard ready");
  expect(fetchMock).toHaveBeenCalledTimes(3);

  await user.click(screen.getByRole("link", { name: /Failure Lab/ }));
  await user.click(screen.getByRole("button", { name: "Run verification" }));
  await screen.findByText("Verification running", { selector: ".verification-indicator" });
  expect(fetchMock).toHaveBeenCalledTimes(4);

  await user.click(screen.getByRole("link", { name: /Safety Graph/ }));
  expect(await screen.findByRole("heading", { name: "Payment Safety Graph" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Load graph" })).toBeDisabled();
  await user.click(screen.getByRole("link", { name: /Project Setup/ }));
  expect(await screen.findByRole("heading", { name: "Project Setup" })).toBeInTheDocument();
  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(4));
});
