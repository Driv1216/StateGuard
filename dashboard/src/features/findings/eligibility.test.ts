import { describe, expect, it } from "vitest";

import type { Finding, ResultState, RunCheck } from "../../api/contracts";
import { isRemediationEligible } from "./FindingsPage";

const finding: Finding = {
  occurrence_id: "sgfinding_schema_v3_sg02",
  finding_key: "sgfindingkey_schema_v3_sg02",
  check_id: "sgcheck_schema_v3_sg02",
  check_key: "sgcheckkey_schema_v3_sg02",
  kind: "VERIFIED_FAILURE",
  critical: true,
};

const check: RunCheck = {
  check_id: finding.check_id,
  check_key: finding.check_key,
  scenario_id: "SG-02",
  scenario_instance_id: "sgscenario_schema_v3_sg02",
  assertion_id: "sgassert_schema_v3_sg02",
  assertion_key: "DUPLICATE_VALUE_AT_MOST_ONCE",
  invariant_id: "DUPLICATE_DELIVERY_VALUE_AT_MOST_ONCE",
  invariant_version: 1,
  expected_invariant: "A duplicate captured webhook adds no customer-value target entry.",
  applicability: { state: "APPLICABLE", role: "CORE", reasons: [] },
  targets: {},
  policy_authority: {},
  razorpay_rule_ids: [],
  source_references: [],
  graph_node_ids: [],
  graph_edge_ids: [],
  result: "VERIFIED FAIL",
  evidence_tier: "E3 DYNAMIC VERIFIED",
  reason: "DUPLICATE_DELIVERY_ADDED_TARGET_ENTRY",
};

const ineligibleResults: ResultState[] = [
  "VERIFIED PASS",
  "STATIC WARNING",
  "NEEDS INPUT",
  "UNVERIFIED",
  "NOT APPLICABLE",
];

describe("finding remediation eligibility", () => {
  it("keeps a schema-v3 SG-02 critical VERIFIED FAIL eligible", () => {
    expect(isRemediationEligible(finding, check)).toBe(true);
  });

  it.each(ineligibleResults)("keeps %s ineligible", (result) => {
    expect(isRemediationEligible(finding, { ...check, result })).toBe(false);
  });

  it("requires backend-projected criticality", () => {
    expect(isRemediationEligible({ ...finding, critical: false }, check)).toBe(false);
  });
});
