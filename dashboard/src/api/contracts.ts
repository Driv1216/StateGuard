export type JsonRecord = Record<string, unknown>;

export type ResultState =
  | "VERIFIED_PASS"
  | "VERIFIED_FAIL"
  | "STATIC_WARNING"
  | "NEEDS_INPUT"
  | "UNVERIFIED"
  | "NOT_APPLICABLE";

export type EvidenceTier =
  | "E0_DISCOVERED"
  | "E1_RESOLVED"
  | "E2_STATIC_VERIFIED"
  | "E3_DYNAMIC_VERIFIED"
  | "E4_RAZORPAY_GROUNDED";

export type ApplicabilityState =
  | "APPLICABLE"
  | "NOT_APPLICABLE"
  | "NEEDS_INPUT"
  | "INDETERMINATE";

export interface ProjectSetup {
  schema_version: 1;
  project_id: string;
  config_schema_version: 2;
  configured_app_target: string | null;
  ai_provider: "gemini" | "openai-compatible" | null;
  ai_model: string | null;
  ai_api_key_env: string | null;
  ai_base_url: string | null;
  runtime_configured: boolean;
  runtime_mode: "managed" | "byo" | "static";
  runtime: RuntimeSetup | null;
  configured_customer_value_symbol_id: string | null;
  configured_fulfilment_policy: "CAPTURE_REQUIRED" | "AUTHORIZED_ALLOWED" | null;
  configured_late_authorisation_policy: "FULFIL_LATER" | "DO_NOT_FULFIL" | null;
}

export interface RuntimeSetup {
  mode: "managed" | "byo" | "static";
  working_directory: string | null;
  environment_bindings: Array<{ child_name: string; host_name: string }>;
  startup_timeout_seconds: number | null;
  request_timeout_seconds: number | null;
  shutdown_timeout_seconds: number | null;
  target: {
    kind: "local" | "declared_test";
    base_url: string;
    non_production_declaration: boolean;
  } | null;
  readiness: { path: string; accepted_statuses: number[] } | null;
  launch_configured: boolean;
}

export interface RecordedSemanticCandidate {
  kind: "VALID" | "PARTIAL_SUGGESTION";
  symbol_id: string;
  rationale: string;
  provider_confidence: number | null;
}

export interface SemanticSnapshot {
  schema_version: 1;
  source_currentness: "NOT_CHECKED";
  project_id: string;
  recorded: boolean;
  recorded_at: string | null;
  state: "UNIQUE" | "AMBIGUOUS" | "UNMAPPED" | null;
  basis: string | null;
  selected_symbol_id: string | null;
  semantic_context_fingerprint: string | null;
  resolution_fingerprint: string | null;
  bundle_completeness: "BUNDLE_COMPLETE" | "BUNDLE_PARTIAL" | null;
  provider_id: string | null;
  model: string | null;
  provider_failure_code: string | null;
  provider_failure_status_code: number | null;
  presented_symbol_ids: string[];
  candidates: RecordedSemanticCandidate[];
  human_basis: string | null;
  human_acted_at: string | null;
}

export interface SemanticSelectionOption {
  kind: "VALID" | "PARTIAL_SUGGESTION" | "PRESENTED";
  symbol_id: string;
  qualified_name: string;
  symbol_kind: string;
  source_location: SourceLocation;
  rationale: string | null;
  provider_confidence: number | null;
}

export interface SemanticOperation {
  schema_version: 1;
  artifact: JsonRecord & {
    resolution?: { state: string; basis: string; selected_symbol_id: string | null } | null;
    resolution_fingerprint?: string | null;
    context?: { bundle_completeness: string; presented_symbol_ids: string[] };
    provider_failure?: { code: string; status_code?: number | null } | null;
  };
  graph_fingerprint: string;
  selection_options: SemanticSelectionOption[];
}

export interface ProjectAnalysis {
  schema_version: 1;
  generated_at: string;
  project_id: string;
  project_source_fingerprint: string;
  source_index_fingerprint: string;
  source_completeness: string;
  indexed_file_count: number;
  indexed_symbol_count: number;
  source_diagnostics: Array<{ code: string; impact: string; count: number }>;
  graph_fingerprint: string;
  graph_completeness: "COMPLETE" | "PARTIAL";
  graph_nodes: Array<{ kind: string; count: number }>;
  graph_edges: Array<{ kind: string; count: number }>;
  graph_diagnostics: Array<{ code: string; impact: string; count: number }>;
  semantics: {
    state: string | null;
    basis: string | null;
    selected_symbol_id: string | null;
    resolution_fingerprint: string | null;
    selected_target_provenance: string[];
    matching_artifact_current: boolean;
  };
  policy: MerchantPolicy;
  applicability: ApplicabilityArtifact;
}

export interface SourceLocation {
  path: string;
  line_start: number;
  column_start: number;
  line_end: number;
  column_end: number;
}

export interface ProvenanceRecord {
  kind: string;
  reference: string;
  source_location: SourceLocation | null;
  supporting_fingerprint: string | null;
}

export interface GraphNodeRecord {
  node_id: string;
  kind: string;
  label: string;
  backing_symbol_id: string | null;
  details: JsonRecord | null;
  provenance: ProvenanceRecord[];
}

export interface GraphEdgeRecord {
  edge_id: string;
  source_node_id: string;
  target_node_id: string;
  kind: string;
  branch: JsonRecord | null;
  provenance: ProvenanceRecord[];
}

export interface GraphArtifact {
  schema_version: 2;
  project_id: string;
  graph_fingerprint: string;
  completeness: "COMPLETE" | "PARTIAL";
  diagnostics: Array<JsonRecord & { code: string; impact: string }>;
  nodes: GraphNodeRecord[];
  edges: GraphEdgeRecord[];
}

export interface MerchantPolicy {
  fulfilment: JsonRecord & {
    evidence_status: string;
    suggested_policy: string | null;
    confirmed_policy: string | null;
    evidence_current: boolean | null;
    implementation_mismatch: boolean;
  };
  late_authorisation: JsonRecord & {
    confirmed_policy: string | null;
    evidence_current: boolean | null;
  };
}

export interface AssertionApplicability {
  assertion_id: string;
  key: string;
  role: "CORE" | "OPTIONAL";
  state: ApplicabilityState;
  reasons: Array<{ code: string; evidence: Array<{ kind: string; reference: string }> }>;
}

export interface ApplicabilityScenario {
  scenario_id: string;
  state: ApplicabilityState;
  instances: Array<{
    instance_id: string;
    state: ApplicabilityState;
    assertions: AssertionApplicability[];
  }>;
}

export interface ApplicabilityArtifact extends JsonRecord {
  policy: MerchantPolicy;
  scenarios: ApplicabilityScenario[];
}

export interface RuntimeCapability extends JsonRecord {
  mode: "managed" | "byo" | "static";
  ownership: string;
  lifecycle: string;
  ingresses: unknown[];
  customer_values: unknown[];
  mutations: unknown[];
  acknowledgements: unknown[];
  diagnostics: Array<{ code: string; stage: string; reference: string | null }>;
}

export interface EvidenceDistribution {
  no_tier: number;
  e0_discovered: number;
  e1_resolved: number;
  e2_static_verified: number;
  e3_dynamic_verified: number;
  e4_razorpay_grounded: number;
}

export interface RunSummary {
  verified_pass: number;
  verified_fail: number;
  static_warning: number;
  needs_input: number;
  unverified: number;
  not_applicable: number;
  dynamic_coverage_numerator: number;
  dynamic_coverage_denominator: number;
  evidence_tiers: EvidenceDistribution;
}

export interface RunListItem {
  run_id: string;
  status: "COMPLETED";
  created_at: string;
  completed_at: string;
  run_fingerprint: string;
  summary: RunSummary;
  finding_count: number;
}

export interface RunList { schema_version: 1; runs: RunListItem[] }

export interface Finding {
  occurrence_id: string;
  finding_key: string;
  check_id: string;
  check_key: string;
  kind: "VERIFIED_FAILURE" | "STATIC_WARNING" | "RESOLUTION_REQUIRED" | "VERIFICATION_COVERAGE";
  critical: boolean;
}

export interface RunCheck {
  check_id: string;
  check_key: string;
  scenario_id: string;
  scenario_instance_id: string;
  assertion_id: string;
  assertion_key: string;
  invariant_id: string;
  invariant_version: number;
  expected_invariant: string;
  applicability: JsonRecord & { state: ApplicabilityState; role: string; reasons: string[] };
  targets: JsonRecord;
  policy_authority: JsonRecord;
  razorpay_rule_ids: string[];
  source_references: Array<{ symbol_id: string; source_location: SourceLocation }>;
  graph_node_ids: string[];
  graph_edge_ids: string[];
  result: ResultState;
  evidence_tier: EvidenceTier | null;
  reason: string;
}

export interface RunReport {
  schema_version: 1 | 2 | 3;
  run_id: string;
  status: "COMPLETED";
  created_at: string;
  completed_at: string;
  run_fingerprint: string;
  summary: RunSummary;
  checks: RunCheck[];
  findings: Finding[];
}

export interface RazorpayRule {
  rule_id: string;
  fact: string;
  source_url: string;
  verified_on: string;
}

export interface FullRun extends RunReport {
  authority: JsonRecord & {
    razorpay_rules?: { referenced_rules: RazorpayRule[] };
    razorpay_grounding?: JsonRecord | null;
  };
  checks: Array<RunCheck & { runtime_evidence?: JsonRecord; scenario_evidence?: JsonRecord; relevant_authority?: JsonRecord | null; grounding?: JsonRecord | null }>;
}

export type AssistanceMode = "CURRENT_SOURCE_REMEDIATION" | "HISTORICAL_EXPLANATION_ONLY";
export type ProposalState = "PROPOSED" | "NO_SAFE_PROPOSAL" | "BLOCKED_CURRENT_SOURCE_AUTHORITY";

export interface RemediationAssistance {
  run_id: string;
  occurrence_id: string;
  check_id: string;
  check_key: string;
  invariant_id: string;
  invariant_version: number;
  mode: AssistanceMode;
  mode_label: string;
  historical_relevant_authority_fingerprint: string | null;
  current_relevant_authority_fingerprint: string | null;
  drift: Array<{
    dimension: string;
    historical_fingerprint: string | null;
    current_fingerprint: string | null;
    blocking: boolean;
  }>;
  causal_summary: string;
  grounded_claims: Array<{ text: string; references: string[] }>;
  proposal_state: ProposalState;
  remediation_rationale: string | null;
  patch: null | {
    verification_state: "AI_GENERATED_NOT_VERIFIED";
    diff: string;
    edits: Array<{ region_reference: string; path: string; kind: string }>;
  };
  limitations: string[];
  provider_id: string | null;
  model: string | null;
}

export type ComparisonOutcome =
  | "PROVEN_RESOLVED"
  | "STILL_VERIFIED_FAIL"
  | "NOT_PROVEN"
  | "NOT_APPLICABLE"
  | "NOT_DIRECTLY_COMPARABLE";

export interface FindingComparison {
  historical_run_id: string;
  current_run_id: string;
  check_key: string;
  outcome: ComparisonOutcome;
  current_check_id: string | null;
  changed_dimension: string | null;
}

export interface ReverificationResult {
  run: FullRun;
  comparison: FindingComparison;
}

export type RuntimeConfigRequest =
  | { mode: "static" }
  | {
      mode: "managed";
      working_directory: string;
      env_from_host: Record<string, string>;
      startup_timeout_seconds: number;
      request_timeout_seconds: number;
      shutdown_timeout_seconds: number;
    }
  | {
      mode: "byo";
      working_directory: string;
      env_from_host: Record<string, string>;
      startup_timeout_seconds: number;
      request_timeout_seconds: number;
      shutdown_timeout_seconds: number;
      target:
        | { kind: "local"; base_url: string }
        | {
            kind: "declared_test";
            base_url: string;
            declaration: "NON_PRODUCTION_TEST_ENVIRONMENT";
          };
      readiness: { path: string; accepted_statuses: number[] };
    };
