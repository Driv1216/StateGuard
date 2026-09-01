import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiControlError, ApiMalformedResponseError, ApiNetworkError, api } from "./client";

afterEach(() => vi.unstubAllGlobals());

describe("typed API client", () => {
  it("uses same-origin relative URLs and accepts a bounded v1 response", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ schema_version: 1, runs: [] }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(api.runs()).resolves.toEqual({ schema_version: 1, runs: [] });
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/runs", expect.any(Object));
  });

  it("keeps control, network, and malformed response failures distinct", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ code: "CONFIG_INVALID", message: "configuration invalid" }), { status: 409 })));
    await expect(api.project()).rejects.toBeInstanceOf(ApiControlError);

    vi.stubGlobal("fetch", vi.fn().mockRejectedValueOnce(new TypeError("offline")));
    await expect(api.project()).rejects.toBeInstanceOf(ApiNetworkError);

    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response("[]", { status: 200 })));
    await expect(api.project()).rejects.toBeInstanceOf(ApiMalformedResponseError);
  });

  it("accepts a schema-v3 full run with safe grounding evidence", async () => {
    const run = {
      schema_version: 3,
      run_id: "sgvrun_test",
      authority: {
        razorpay_grounding: {
          mode: "TEST",
          status: "GROUNDED",
          grounding_fingerprint: "sha256:test",
        },
      },
      checks: [
        {
          check_id: "sgcheck_test",
          grounding: {
            label: "TEST MODE RESOURCE PROFILE GROUNDED",
            grounding_fingerprint: "sha256:test",
          },
        },
      ],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify(run), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    await expect(api.fullRun("sgvrun_test")).resolves.toEqual(run);
  });

  it("uses exact empty-body finding assistance and re-verification routes", async () => {
    const assistance = {
      mode: "HISTORICAL_EXPLANATION_ONLY",
      proposal_state: "BLOCKED_CURRENT_SOURCE_AUTHORITY",
    };
    const reverify = { run: { schema_version: 2 }, comparison: { outcome: "NOT_PROVEN" } };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(assistance), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify(reverify), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    await api.remediationAssistance("run", "finding");
    await api.reverifyFinding("run", "finding");
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "/api/v1/runs/run/findings/finding/assistance",
      expect.objectContaining({ method: "POST", body: "{}" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "/api/v1/runs/run/findings/finding/reverify",
      expect.objectContaining({ method: "POST", body: "{}" }),
    );
  });
});
