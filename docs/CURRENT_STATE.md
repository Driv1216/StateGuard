# StateGuard — Current State

**Last meaningful update:** 2026-09-02

**Purpose of this file:** Current implementation reality and near-term execution state. Keep concise. Update after meaningful capability/architecture/verification changes — not after every small edit.

---

## 1. Current objective

**Buildathon product complete; live walkthrough and genuine Razorpay Test Mode E4 proof complete.**

Project Discovery, the Python/FastAPI Source Index, the Step 2 structural Payment Safety Graph,
Step 3 provider-agnostic customer-value semantic resolution, Step 4 merchant policy/scenario
applicability, Step 5 exact runtime capability/instrumentation, Step 6 managed execution, Step 7
durable evidence/finding orchestration, the Step 8 stable CLI/local control API, Step 10 bounded
remediation/re-verification, Step 11 deterministic CI gate, and Step 12 demo hardening / independent
verification are complete.

The bounded stretch path can now fetch one developer-supplied captured Razorpay Test Mode Payment
and its linked paid Order, sanitize the resource pair, ground only the SG-01 synthetic payment
profile, and promote only an already verified SG-01 check from E3 to E4. Acquisition is fetch-only,
credentials and resource IDs remain ephemeral, Live/unknown keys fail closed before network access,
and every unavailable-provider path retains ordinary E3 verification and unchanged CI truth. E4 is
explicitly resource-profile grounding, not webhook-delivery, signature, retry, or duplicate evidence.

The ticketing merchant walkthrough has now exercised the real production path end to end. A one-attempt
Gemini `gemini-3.7-flash` semantic call succeeded through the configured provider adapter
(3,067 input tokens, 384 output tokens, approximately 6.15 seconds, no provider failure). Because the
semantic bundle was `BUNDLE_PARTIAL`, its bounded suggestions—including
`app.domain.mint_admission_pass`, `app.domain.bind_attendee_roster_row`, and related storage
functions—remained non-authoritative; the developer explicitly confirmed
`app.domain.mint_admission_pass`, producing `UNIQUE` / `HUMAN_CONFIRMED` authority. This was a live
product-path smoke, not a benchmark or a change to the frozen semantic spike.

Against the intentionally vulnerable merchant, the canonical run proved SG-01 `VERIFIED PASS` at E3,
SG-02 and SG-03 `VERIFIED FAIL` at E3, and two actionable findings. SG-02 recorded one exact target entry
and normal return for each of the initial and duplicate deliveries; other protected checks passed and
optional/non-applicable assertions remained honestly `NOT APPLICABLE`. A real production Gemini
remediation call then rebuilt current finding authority without blocking drift, produced a grounded
explanation and bounded diff that moved event claiming before merchant mutation and customer-value
execution, retained
`AI-GENERATED — NOT VERIFIED`, and modified no merchant file. After the developer explicitly applied the
corrected source, exact-key deterministic re-verification proved SG-02
`VERIFIED FAIL → VERIFIED PASS` / `PROVEN_RESOLVED`; SG-03 also passed. The corrected run contained
9 verified passes, no verified failures or unverified checks, zero findings, and honest
`NOT APPLICABLE` assertions. The live CI run then returned `REQUIRED_CHECKS_PASSED` with exit 0.

A genuine Razorpay Test Mode Payment created through Standard Checkout and its linked paid Order were
successfully fetched, validated, and sanitized by the fetch-only grounding adapter. The Payment
reported entity `payment`, status `captured`, `captured == true`, amount 100, and currency INR; the
linked Order reported entity `order`, status `paid`, amount 100, amount paid 100, amount due 0, and
currency INR. The E4-enabled canonical run produced 9 verified passes, no failures or unverified
checks, 9/9 dynamic coverage, and zero findings. Only SG-01 was promoted to
`E4 RAZORPAY GROUNDED` and displayed
`TEST MODE RESOURCE PROFILE GROUNDED`; StateGuard still executed SG-01 locally and retained the explicit
disclaimer that this was resource-profile grounding, not webhook-delivery evidence. SG-02 through SG-08
remained E3. No credential, resource ID, signature, or customer/payment-method data was persisted.

Managed runtime verification was optimized to ~4.2 seconds per canonical run. Independent repetition
testing confirmed 5/5 vulnerable and 5/5 corrected cycles with 100% deterministic repeatability and zero
resource leaks. The packaged distribution was independently verified via clean-room wheel smoke testing.

The live ticketing walkthrough regression is fixed: schema-v3 findings retain the same
relevance-scoped Step 10 current-authority rebuilding as schema v2, while schema v1 retains its
conservative whole-authority fallback. Dashboard result/evidence contracts now use the canonical
space-separated API values, so a backend-critical SG-02 `VERIFIED FAIL` at E3 remains eligible for
bounded assistance and receives critical presentation. Non-`VERIFIED FAIL` findings remain
ineligible; assistance remains non-authoritative and preview-only. The dashboard also now distinguishes
a successful partial-bundle provider response from an actual provider failure.

A dedicated concurrency feasibility pass concluded **NO-GO for Buildathon implementation**. The current
managed runtime cannot product-generally prove that duplicate requests overlap at the race-sensitive
event-identity decision boundary; simultaneous in-flight HTTP/ASGI requests are insufficient authority.
A defensible implementation needs either an explicit merchant-visible synchronization contract or a
substantial branch-level/runtime concurrency redesign. No SG-09, sleep-based race widening,
scheduler-luck PASS, hidden demo hook, concurrent Razorpay claim, or Buildathon schema/runtime redesign
will be added. Concurrency remains the highest-priority post-Buildathon runtime extension.

---

## 2. Current project status

### Product selection
StateGuard is the selected Razorpay AI Buildathon project.

### Product architecture
Accepted for Buildathon implementation.

The accepted core is:
- local-first FastAPI/Razorpay reliability auditor,
- Payment Safety Graph,
- provider-agnostic AI customer-value mapping,
- human ambiguity resolution,
- merchant payment policy,
- static + dynamic verification,
- 7 core Failure Lab scenarios + 1 advanced policy scenario,
- deterministic invariants/evidence,
- AI explanation/patch preview,
- deterministic re-verification,
- CLI + local dashboard + CI gate,
- optional Razorpay Test Mode grounding.

### Production implementation
**Batch 0 foundation, Steps 1–12, and bounded SG-01 Test Mode E4 grounding complete.**

Implemented:
- `src/stateguard` production package and isolated wheel/sdist packaging,
- hardened `stateguard.yaml` v2 validation with cross-platform path safety, credential-safe
  base URLs, and immutable analysis collections,
- stable source/symbol and graph node/edge identity conventions with backing-field validation,
- bounded, recognized payment-literal evidence without arbitrary raw source-string persistence,
- canonical project-source and Source Index fingerprints with artifact-level consistency checks,
- versioned Project Discovery, Source Index, Payment Safety Graph, and Semantic Resolution contracts,
- customer-value graph nodes requiring fingerprinted AI-inferred or human-confirmed provenance,
- domain-free structured-generation model-provider protocol,
- exact semantic candidate validation with explicit rejected/hallucinated references,
- relevance-scoped semantic-context fingerprinting for confirmation staleness,
- deterministic include/exclude-aware Python discovery with mandatory environment exclusions,
  non-followed symlinks, PEP 263 decoding, raw-byte fingerprints, and honest partial diagnostics,
- Python 3.11 AST indexing for modules, classes, functions/methods, safe signatures, imports,
  aliases, calls, bounded payment references, and source locations without executing merchant code,
- bounded local import/name/call resolution that retains textual uncertainty for dynamic or
  ambiguous Python behavior,
- stable FastAPI/APIRouter instance identities, configured/automatic app-target recovery, route
  extraction, and imported/nested/repeated router-composition facts without computing graph meaning,
- stale-source snapshot validation that stops downstream graph analysis when indexed bytes change,
- deterministic schema-v2 Payment Safety Graph construction with selected-app route reachability,
  bounded control/origin analysis, static provenance, partial-coverage diagnostics, and validated
  graph fingerprints,
- conservative Razorpay webhook/Checkout ingress, trust, server-order binding, event-identity,
  payment-state, merchant-mutation, and acknowledgement recognition,
- exception-aware `try`/handler/`else`/`finally` dominance, caller-effective helper validation,
  SDK binding/rebinding analysis, and client-independent server-order-origin classification,
- confidentiality-safe merchant-state carrier identity persisted in mutation details, provenance,
  node identity, and graph fingerprint inputs,
- deterministic semantic-neighborhood construction from selected payment ingress through exact
  resolved project-local calls, with route owners as supporting evidence and imported siblings
  excluded unless called,
- separate full-relevance and bounded-provider fingerprints, whole-excerpt tactical limits,
  explicit `BUNDLE_COMPLETE`/`BUNDLE_PARTIAL` omissions, and relevance-scoped human staleness,
- provider-independent structured semantic mapping with exact catalog validation, eight-candidate
  schema bounds, output byte/token ceilings, and partial-bundle suggestions that cannot create
  automatic resolution,
- exact Gemini `generate_content` and strict OpenAI-compatible Chat Completions adapters behind the
  domain-free provider protocol, with one application attempt, no substitution fallback, normalized
  failures, and no temperature override,
- minimal human semantic authority in YAML plus restricted atomic `.stateguard/semantics.json`
  audit persistence without merchant source, prompts, keys, or raw provider errors,
- deterministic customer-value graph projection: a stable semantic node always, and a static
  `CALLS` edge only when the Source Index proves an exact payment-ingress call path,
- explicit fulfillment eligibility requiring semantic `UNIQUE`, graph connectivity, and future
  runtime capability,
- stable `semantics resolve` and `semantics confirm --symbol` CLI operations alongside config
  validation,
- explicit `CAPTURE_REQUIRED`/`AUTHORIZED_ALLOWED` and compositional
  `FULFIL_LATER`/`DO_NOT_FULFIL` merchant policy contracts with guarded YAML persistence,
- deterministic, non-authoritative implementation evidence for fulfilment-policy suggestions,
  relevance-scoped per-policy rule/control/state/diagnostic fingerprints that exclude unrelated
  source-index provenance, and visible evidence drift without silently replacing merchant
  declarations,
- exact normal-control identities bound to ingress node, route registration, customer-value
  target, connectivity edge, ordered canonical call-path provenance, and semantic resolution, with
  artifact validation preventing cross-ingress/route/target dependency substitution,
- control-effective customer-value `BRANCHES_TO` and `ACKNOWLEDGES_AFTER` projection only for
  direct synchronous or directly awaited async execution, with bounded diagnostics for unproven
  execution and no customer-value `GUARDS` expansion,
- assertion-first applicability for SG-01 through SG-08, fixed exact-control dependencies,
  deterministic core-assertion roll-up, route/control-scoped optional state-regression and
  late-authorisation capability evidence, conservative SG-03 ordering, and internal
  `INDETERMINATE` analyzer state,
- schema-v2 restricted atomic `.stateguard/applicability.json` persistence plus stable
  `applicability analyze` and explicit `policy confirm` CLI wrappers,
- exact ingress/customer-value/mutation/acknowledgement runtime bindings composed only from current
  graph, applicability, source, route, symbol, and `NormalControlId` authority, including exact
  SG-05/SG-06 mutation-node evidence without requiring a normal control,
- empirically gated CPython 3.11 opcode tracing with exact compiled code descriptors, async
  suspension/terminal classification, FastAPI async/threadpool correlation, value-free assignment
  instruction lifecycle facts, and fail-closed tracer/channel behavior,
- exact FastAPI route reconciliation and ASGI boundary wrapping that consumes StateGuard
  correlation before merchant middleware and records sequence-ordered request/response facts,
- exact post-import customer-value/mutation code-object reconciliation before managed capability
  can be complete, with replaced/missing live targets degraded without fuzzy recovery,
- fail-closed uncorrelated exact-target detection, runtime route-order shadowing, unexpected worker
  termination containment, and typed request handles exposing exact request/ingress identity,
- independently graded per-ingress and per-target capability contracts with historical-input and
  sealed-transcript cross-identity validation,
- managed loopback child lifecycle with sanitized environment, fixed argv, graceful/forced process
  cleanup, source/config revalidation, private observation transport, and no external-state-reset
  claim,
- optional `managed-fastapi` dependency boundary with tested-version detection and no merchant
  dependency installation, upgrade, downgrade, or lockfile mutation,
- externally owned and explicitly launched BYO modes with client-side/partial observations only,
  plus static-only degradation,
- Buildathon-safe target policy: loopback by default, exact non-production-test declaration for
  non-local targets, per-request policy validation, redirect refusal, and no production target
  class,
- restricted atomic `.stateguard/runtime.json` capability-only persistence, in-memory sealed session
  transcripts for Step 6, and stable `runtime assess` CLI support.
- schema-v3 immutable Failure Lab result contracts (with schema-v2 read compatibility) with random
  scenario-execution identity,
  compositional applicability/runtime authority, one safe event-level input reference, ordered
  per-request observations, the generic E0–E4 vocabulary, scenario cardinality rules, and
  result-level fingerprint validation,
- SG-01 applicability restricted to current confirmed `CAPTURE_REQUIRED` policy plus exact
  route/control-scoped captured-state evidence, without requiring one literal graph-edge shape;
  Checkout, authorized-only, stale, contradictory, and coverage-reduced cases fail closed,
- managed-only SG-01 execution through the existing Step 5 opener/session contract, preserving
  source/config freshness, live-target reconciliation, exact route attachment, request correlation,
  transcript validation, and one close in the executor's `finally` path,
- a pinned, redacted Razorpay `payment.captured` sample-shaped request with canonical raw bytes and
  real HMAC-SHA256 verification through the existing `env_from_host` secret boundary, without a
  schema-v2 configuration change or secret/signature persistence,
- deterministic SG-01 truth mapping: one exact entry plus normal terminal/request lifecycle is
  `VERIFIED PASS`/E3; multiple exact entries with trustworthy evidence are `VERIFIED FAIL`/E3;
  zero entries under offline-synthetic protocol authority are `UNVERIFIED` with
  `NORMAL_INPUT_PRECONDITION_UNPROVEN`,
- fetch-only Razorpay Test Mode grounding activated only by CLI environment-variable names, using a
  fixed API origin, strict timeouts/response bounds, redirect refusal, Test-key prefix validation,
  and pre-network rejection of Live or unknown credential modes,
- strict captured-Payment/linked-paid-Order eligibility and consistency checks for entity, linkage,
  full amount/currency payment, and no current refund, without creating, capturing, refunding, or
  otherwise mutating a Razorpay resource,
- schema-v1 sanitized grounding evidence containing only mode/status/reason, run/currentness
  authority, endpoint kinds, resource/key fingerprints, consistency booleans, and composite
  fingerprints; no keys, raw IDs, raw responses/errors, merchant/customer/payment-method data, or
  signatures are persisted,
- schema-v3 verification runs with schema-v1/v2 read compatibility and an SG-01-only E4 promotion
  gate that requires exact run, acquisition interval, grounding, projection, input, and original E3
  authority; `ScenarioExecutionResult` remains E3 and deterministic PASS/FAIL authority is unchanged,
- dashboard schema-v3 parsing and explicit `TEST MODE RESOURCE PROFILE GROUNDED` presentation that
  disclaims webhook delivery/provider execution, with no dashboard credential or activation controls,
- SG-02 applicability requiring a current confirmed policy plus an exact webhook `POST` control
  whose captured-state branch reaches the selected customer-value target; authorized-only,
  same-route unrelated captured state, stale, and coverage-reduced authority fail closed,
- managed SG-02 execution using one fresh session, one prepared signed captured event, two
  sequential deliveries with distinct `RuntimeRequestId`s, one sealed transcript, exact ordered
  request/control/binding validation, and an independent first-delivery positive control,
- deterministic SG-02 truth mapping: a normal first delivery plus zero duplicate target entries is
  `VERIFIED PASS`/E3; a proven repeated exact target entry is `VERIFIED FAIL`/E3; zero/incomplete
  positive control, request failure, transcript diagnostics, or substituted authority is
  `UNVERIFIED`; a completed duplicate non-2xx remains outside the SG-02 at-most-once invariant,
- SG-05 applicability split by assertion: exact graph-backed mutation targets remain independently
  applicable without a normal control, while customer-value verification requires an exact captured
  webhook control; neither assertion depends on merchant fulfilment policy or a detected trust gate,
- deterministic SG-05 input preparation from the pinned captured-payment fixture, preserving the
  exact raw body and all non-signature headers while changing one hexadecimal signature character;
  the rejected request runs before its valid HMAC control in one fresh managed session,
- exact per-assertion SG-05 truth mapping: rejected-request mutation-instruction completion or exact
  customer-target entry is `VERIFIED FAIL`/E3; absence is `VERIFIED PASS`/E3 only when the valid
  control normally exercises every assertion-bound mutation target or satisfies the existing SG-01
  customer lifecycle; incomplete correlation, lifecycle, capability, coverage, or transcript
  authority remains `UNVERIFIED`,
- in-memory-only Step 6 execution results; no run, report, finding, raw body, response body,
  signature, exception, environment value, or merchant-value artifact persistence.
- a shared bounded managed-sequence kernel for applicability revalidation, one session open,
  ordered request dispatch, close-once transcript sealing, exact route/control correlation, and
  fail-closed result construction, without a generic scenario DSL or registry,
- backward-compatible schema-v3 safe input references for one captured webhook, an ordered
  captured/authorized webhook sequence, and an ordered tampered/valid Checkout sequence; all store
  only safe fixture/role/transport/event identifiers and fingerprints,
- provenance-backed Checkout request bindings for exact `Request.json()`, `Request.form()`, FastAPI
  query/scalar, `Form`, and `Body` shapes, with mixed/dynamic parsing, missing fields, unresolved
  models, uncontrolled required parameters, and static/live route mismatches rejected,
- structured managed query/body dispatch plus in-memory host authority through reserved
  `STATEGUARD_TEST_RAZORPAY_KEY_SECRET` and `STATEGUARD_TEST_SERVER_ORDER_ID` child names in the
  existing `runtime.env_from_host` boundary, without a config-schema change,
- bounded exact assigned payment-state metadata (`captured` or `authorized`) on merchant mutation
  graph nodes, with unknown values excluded from SG-04 regression authority,
- SG-04 applicability requiring the exact current captured control used by SG-02 under either
  confirmed fulfilment policy, plus an independent optional exact captured/authorized assignment
  pair on one merchant-state carrier,
- managed SG-04 delivery of captured then stale authorized events sharing one synthetic
  payment/order identity but using distinct bodies, signatures, event IDs, request IDs, and one
  sealed transcript; customer duplication and exact state regression are independently graded at
  E3 and all incomplete/cross-request authority remains `UNVERIFIED`,
- policy-independent SG-06 applicability restricted to an executable exact Checkout request
  binding and exact trust-guarded or recognized payment-state mutation targets, with customer-value
  authority retained per assertion,
- managed SG-06 tampered browser-order input followed by a valid server-order control, using
  HMAC-SHA256 over `order_id + "|" + payment_id`; a tampered protected effect is `VERIFIED FAIL`/E3,
  while absence becomes `VERIFIED PASS`/E3 only when the valid request exercises every bound target,
- SG-07 applicability requiring current policy, one exact captured webhook control, and an exact
  Checkout normal control linked to the same customer-value node; an unrelated callback route is
  insufficient,
- managed SG-07 execution of exactly one legitimate captured webhook and no manufactured callback;
  one normal exact target entry is `VERIFIED PASS`/E3, multiple entries are `VERIFIED FAIL`/E3, and
  zero entries remain `UNVERIFIED` rather than claiming a callback dependency failure,
- call-site source location included in semantic-context payment-call evidence, preserving distinct
  deterministic provenance when the same caller invokes the same resolved target at multiple exact
  source locations.
- SG-03 applicability requiring one current captured control and one exact successful
  `ACKNOWLEDGES_AFTER` boundary for the selected customer-value target, with ambiguous or foreign
  acknowledgement authority rejected,
- request-scoped managed SG-03 injection that consumes a private option before merchant middleware,
  proves the merchant-produced 2xx and exact customer processing order, records an exact
  `ACKNOWLEDGEMENT_FAILURE_INJECTED` event, and rewrites only that effective response to `503`,
- SG-03 modeled retry delivery reusing the identical body, signature, and event ID under a distinct
  request ID, with deterministic initial-versus-retry failure attribution and no claim that
  Razorpay performed the retry,
- SG-08 applicability split between capture-policy invariants and late-specific business-context
  assertions, with current fingerprints required for both merchant policies and
  `MERCHANT_LATE_CONTEXT_UNPROVEN` retained as explicit authority,
- SG-08 signed authorized/captured modeled sequences with redacted policy, fixture, role, event,
  path, and context fingerprints, explicitly excluding merchant-local pending/cancelled/expired or
  service-availability claims,
- deterministic SG-08 E3 outcomes only where `CAPTURE_REQUIRED` independently supplies authority:
  authorization-time execution fails the pre-capture invariant, and a clean authorization plus one
  normal captured execution can pass the modeled capture sequence,
- intentionally `UNVERIFIED` SG-08 outcomes for both `AUTHORIZED_ALLOWED` rows and zero execution
  under `CAPTURE_REQUIRED + DO_NOT_FULFIL`; no dispatch is manufactured for the authorized-allowed
  rows and no generic merchant-state seeding framework was added,
- schema-v1 immutable verification-run artifacts with distinct random run/check/finding occurrence
  identities, deterministic cross-run `VerificationCheckKey`, and `FindingKey` only for actionable
  finding projections,
- a versioned SG-01 through SG-08 assertion-definition catalog whose invariant version, stable
  target dimensions, and only materially relevant policy values control logical check identity,
- exact scenario-instance/assertion correlation between applicability and Step 6 result authority;
  missing, duplicate, substituted, or foreign authority aborts construction instead of reordering,
- structured allowlisted evidence and minimal immutable source/semantic/policy/graph/runtime/rule
  authority snapshots, excluding raw diagnostics, exception text, host paths, bodies, signatures,
  secrets, merchant values, source content, prompts, and provider output,
- deterministic finding derivation and factual summaries with recomputed result/tier counts and E3/E4
  dynamic-coverage numerator over every non-`NOT APPLICABLE` check,
- restricted atomic `.stateguard/runs/<VerificationRunId>/run.json` publication with staged reload,
  canonical whole-artifact fingerprinting, file/directory fsync where meaningful, no overwrite,
  symlink/path defenses, strict corrupt-final reporting, deterministic listing, and latest-run load,
- `create_verification_run(...)` orchestration in canonical SG-01 through SG-08 order, preserving
  per-instance executor/session isolation, materializing every no-dispatch assertion as a check, and
  aborting without a completed artifact on integrity, correlation, or authority drift,
- safe current-authority re-verification references that cannot directly replay old raw requests;
  old completed runs remain independently interpretable after current authority artifacts change,
- one canonical project-bound `StateGuardControl` facade over existing Step 1–7 use cases, with
  bounded frozen control projections, structural sanitized errors, project-relative configuration
  binding, and genuinely non-persisting general analysis,
- stable human and typed JSON CLI surfaces for analysis, semantics, merchant policy,
  applicability, runtime assessment, verification, and immutable run list/latest/show/report
  access, retaining hidden unambiguous `--repository` compatibility and operation-success exit
  semantics for ordinary verification,
- a versioned confidentiality-safe CI gate contract and pure deterministic evaluator over completed
  `VerificationRun` checks, with role-aware coverage, optional proven-failure authority, exact
  logical blocker identities, stable human/JSON output, completed-gate exits `0`/`1`/`2`, and a
  CI-scoped exit `3` for usage or operational failure without changing other command semantics,
- guarded whole-section AI/runtime setup operations that accept only existing typed contracts,
  preserve unrelated YAML/comments, retain optimistic concurrency and atomic validation, store
  only provider-key environment-variable names rather than values, and do not imply semantic or
  runtime capability,
- a synchronous single-project standard-library `/api/v1` control adapter whose endpoints call
  only `StateGuardControl`, including bounded project/analysis/graph/setup/report responses and
  full validated Step 7 runs only on the explicit run endpoint,
- loopback-only literal `127.0.0.1`/`::1` serving, exact Host/Origin/CORS/framing/content/path
  controls, a 64-KiB request limit, pre-parser input timeouts, suppressed `100 Continue`, safe JSON
  parser errors/security headers, no default Python HTTP logging/version leakage, and no unsafe
  shutdown endpoint,
- stable `stateguard serve [PROJECT] [--config PATH] [--host 127.0.0.1|::1] [--port PORT]` with
  startup validation, safe output, cooperative SIGINT/SIGTERM shutdown, and no framework server,
  worker, reload, daemon, TLS, or non-loopback override.
- a packaged React 19 + TypeScript 5.9 + Vite 7 dashboard on the same loopback origin as
  `/api/v1`, with React Router 7 and exactly five eagerly imported routes: Overview, Safety Graph,
  Failure Lab, Findings, and Project Setup,
- one initial JavaScript bundle and stylesheet containing all five routes, including React Flow 12
  and Dagre 3; route navigation requests no additional JavaScript or CSS assets,
- persistence-only `StateGuardControl.semantic_snapshot()` and `GET /api/v1/semantics`, which read
  only safe recorded configuration/artifact fields, report `NOT_CHECKED` source currentness, and
  never discover source, construct a graph, call a provider, or write state,
- response-only enriched semantic selection options after explicit current resolution, without
  expanding semantic persistence with qualified names or source locations,
- exact packaged static routing for the five dashboard paths and flat hashed assets through
  `importlib.resources`, explicit MIME/cache policies, strict same-origin script/style CSP, API
  precedence, and no CORS relaxation or arbitrary path-to-filesystem translation,
- an accessible design system with visible focus, native focus-managed dialogs, live
  announcements, error summaries, evidence/result/applicability separation, text graph index, and
  responsive no-overflow layouts at 1440, 1280, and 1024 pixels,
- backend-authoritative Safety Graph rendering with React Flow and Dagre positioning only;
  backend-derived Findings joined to exact checks and bounded full evidence; fixed SG-01–SG-08
  Failure Lab presentation; and bounded Project Setup forms with hidden BYO launch protection,
- an honest global synchronous-verification lock: loaded routes and state remain navigable while
  the one server thread verifies, every server action is disabled, no route assets or lazy data are
  requested, and no polling, progress simulation, cancellation, SSE, WebSockets, jobs, or threading
  were added,
- a first-class ticketing merchant demo (`examples/ticketing_merchant`) with authentic dual-candidate
  semantic ambiguity (`mint_admission_pass` vs `bind_attendee_roster_row`), direct HMAC webhook verification,
  Checkout server-order binding, and SQLite event claiming,
- vulnerable (`templates/main.vulnerable.py`) and corrected (`templates/main.fixed.py`) source templates
  alongside a deterministic demo reset utility (`reset_demo.py`) with strict local containment and no
  secret reading or leakage,
- product-general SG-01 captured-webhook scoping correction and structural semantic `CALLS` edge stability
  preserving freshness and provenance across confirmation,
- managed-runtime exact-tracing optimization reducing canonical verification duration from ~61 seconds to ~4.2 seconds,
- bounded dashboard polish: safe request evidence table (role, sequence/ordinal, HTTP status, entered/returned counts),
  `Full safe structured evidence` expander, persistent `AI-GENERATED — NOT VERIFIED` warning banner with editor-apply
  instructions, and clear `VERIFIED FAIL → VERIFIED PASS` (`PROVEN_RESOLVED`) re-verification transition presentation.

Not yet implemented:
- bounded merchant-normal input/state-reset authority for proving zero-entry dependency failures,
  generic merchant late-state seeding, actual Razorpay webhook/retry/duplicate grounding,
  timing/timeout scenarios,
  targeted/change-impact verification, automatic patch application, autonomous remediation, or
  concurrent scenario execution. A proof-quality concurrent SG-02 assertion is explicitly deferred
  after the Buildathon feasibility pass found no bounded product-general overlap mechanism in the
  current runtime.

Final Step 8 closure verification passed all 294 production tests, including SG-01 through SG-08,
Step 7 evidence/storage authority, stable CLI/JSON/configuration surfaces, real CLI/HTTP run-history
parity, deterministic `VERIFIED FAIL` transport success, local HTTP security/lifecycle, and optional
managed-runtime compatibility. Strict mypy passed across all 86 production source files. Ruff lint
and format-check passed across 163 `src`/`tests` files. `uv build` produced a 90-file wheel and
91-file sdist; archive inspection found the intended production control/API modules and runtime
documentation with no tests, fixture repositories, frozen-spike artifacts, run artifacts, local
configuration, caches, host paths, or secret material. An isolated installation from the wheel
passed CLI/help, control-API import, missing-managed-dependency behavior, ephemeral loopback
health/project requests, and clean shutdown. The frozen semantic spike was not run or modified.

Accepted Step 8 limitations remain explicit: long operations block the single-threaded API; there
is no progress stream, cancellation, TLS, or authentication against another hostile same-user local
process; full graph/run responses serialize in memory; at Step 8, CI result-sensitive exit semantics
were still deferred; they were completed in Step 11.

Step 9 focused closure completed without the historical 294-test suite. Frontend typecheck passed;
4 focused Vitest tests passed; one production Vite build produced one 503,947-byte eager JavaScript
bundle and one 35,609-byte stylesheet; browser inspection exercised all five surfaces at 1440,
1280, and 1024 pixels with no page overflow or console/CSP warnings; Analyze → Resolve → Confirm,
graph loading, applicability, a synchronous verification, backend findings, evidence detail,
dialogs, setup forms, and verification-pending state were exercised. The combined focused Python
closure passed 35 tests and had one managed-runtime request exceed its test timeout under combined
load; that exact test passed alone in 114.71 seconds. Ruff and focused strict mypy passed. One
wheel/sdist build included frontend source in the sdist and packaged built assets in both
distributions. A fresh installed-wheel server returned dashboard routes, both hashed assets,
passive `NOT_CHECKED` semantics, and run history on one loopback origin. The frozen spike and Steps
1–8 authority were not changed.

The existing spike is an evaluation harness/proof artifact, not the production product.

### Working-agent plan
- **Codex:** core/high-risk implementation and consequential architecture.
- **Antigravity (currently Gemini 3.7 Flash):** bounded/lower-risk implementation such as UI presentation and mechanical work behind stable contracts.

The split is operational, not a product dependency. Agent/model assignments may change without changing StateGuard architecture.

---

## 3. Frozen semantic spike

### Status
Complete and immutable.

### Contract hash
`3454f599945434d7dfbe3cf0eb42ad504bb007f63305453095ce38d07c73e62a`

### Official outcome
`NO_GO`

### Frozen AI configuration
- provider: Google Gemini
- model: `gemini-3.6-flash`
- temperature: 0
- structured output
- no model fallback/substitution

### Key result
Static baseline:
- unique mapping coverage: 3/6 = 50%
- defects detected: 6/12 = 50%

Gemini frozen run:
- unique mapping coverage: 5/6 = 83.33%
- defects detected: 10/12 = 83.33%
- +4 additional defects / +33.33 percentage points
- false critical findings: 0
- hallucinated symbols: 0

Failed frozen gates:
- semantic precision 85.71% < required 90%,
- correct normal-capture controls 5/6 rather than 6/6 because ticketing remained ambiguous.

Ticketing ambiguity:
- correct candidate: `app.domain.mint_admission_pass`
- extra plausible candidate: `app.domain.bind_attendee_roster_row`

This observed failure is the reason production StateGuard includes human semantic confirmation.

### Known local frozen artifact location
`spike-test/artifacts/evaluation/results.json`

Do not rerun or tune the original frozen experiment.

---

## 4. Decisions already settled

These should not be reopened casually during implementation.

### Scope
- Python/FastAPI first.
- Razorpay Payment Gateway / Standard Checkout + payment webhooks.
- Local-first.
- No real-money chaos.
- No remote arbitrary-repo execution in the Buildathon core.
- No cloud database/auth requirement.

### AI architecture
- Provider agnostic.
- Gemini is the frozen experiment provider, not the product dependency.
- Buildathon target: Gemini adapter + OpenAI-compatible adapter.
- Secrets remain environment-based and are never persisted in project config/artifacts.
- AI never owns PASS/FAIL.

### Payment semantics
- Primary AI semantic concept: customer-value action.
- Resolution states: UNIQUE / AMBIGUOUS / UNMAPPED.
- Human confirmation resolves consequential ambiguity.
- Merchant payment policy is explicit/confirmed when it changes applicable invariants.

### Verification
Core Failure Lab:
- SG-01 Normal Capture
- SG-02 Duplicate Webhook
- SG-03 Retry After Slow/Failed Acknowledgement
- SG-04 Out-of-Order Events
- SG-05 Forged Webhook
- SG-06 Tampered Checkout Callback
- SG-07 Lost Browser Callback

Advanced:
- SG-08 Late Authorisation

### Results/evidence
Evidence tiers:
- E0 DISCOVERED
- E1 RESOLVED
- E2 STATIC VERIFIED
- E3 DYNAMIC VERIFIED
- E4 RAZORPAY GROUNDED

Result states:
- VERIFIED PASS
- VERIFIED FAIL
- STATIC WARNING
- NEEDS INPUT
- UNVERIFIED
- NOT APPLICABLE

Only VERIFIED FAIL is a critical/red proven failure.

### Product surfaces
- CLI
- Local dashboard
- CI gate

Dashboard primary surfaces:
- Overview
- Safety Graph
- Failure Lab
- Findings
- Project Setup

---

## 5. Recommended implementation sequence

This is an execution order, not a set of permanent milestone documents.

### Step 0 — Repository/bootstrap contracts
Create the production repo/package skeleton, configuration conventions, core typed schemas/contracts, artifact layout, test conventions, and model-provider interface.

Do not copy the spike wholesale into production. Reuse proven ideas deliberately.

### Step 1 — Project discovery + source index
Implement:
- Python/FastAPI project discovery,
- route/function/import indexing,
- Razorpay/payment literal/reference detection,
- source locations,
- call relationships needed by the graph.

Validate against several deliberately different demo merchant apps.

### Step 2 — Payment Safety Graph foundation
Implement the canonical node/provenance model and enough graph construction for:
- webhook ingress,
- Checkout callback ingress,
- trust gates,
- event identity guards,
- payment-state gates,
- merchant state mutations,
- acknowledgement boundaries.

Keep customer-value action unresolved at this stage.

### Step 3 — Provider-agnostic semantic resolution
Implement:
- bounded source bundle generation,
- model-provider contract,
- Gemini adapter,
- OpenAI-compatible adapter,
- structured semantic mapping,
- provider/model capability validation,
- UNIQUE / AMBIGUOUS / UNMAPPED resolution,
- manual/human confirmation path,
- semantic persistence/invalidation.

### Step 4 — Merchant policy + applicability
Implement:
- `CAPTURE_REQUIRED`,
- `AUTHORIZED_ALLOWED`,
- late-authorisation policy field,
- inference evidence,
- human confirmation,
- scenario applicability/dependency graph.

### Step 5 — Runtime capability + deterministic instrumentation
Implement:
- managed local test/demo runtime,
- fresh-process isolation where required,
- bring-your-own test runtime contract,
- static-only fallback,
- instrumentation/evidence capture.

Do not add cloud arbitrary-code execution.

### Step 6 — Failure Lab core
Complete for managed SG-01 through SG-08 execution with conservative static/no-runtime outcomes.

### Step 7 — Evidence/findings engine
Complete. Produces immutable structured verification runs, deterministic cross-run check identity,
mechanically derived findings, factual summaries, minimal authority snapshots, and safe
current-authority re-verification references. Old artifacts are explanatory records, not raw replay
instructions.

### Step 8 — CLI + local control API
Complete. Exposes the same control/core authority through the stable CLI, typed JSON, bounded setup
configuration, immutable run/history/report access, and the hardened local `/api/v1` server.

### Step 9 — Dashboard
Complete. The five accepted surfaces render real core data:
- Overview
- Safety Graph
- Failure Lab
- Findings
- Project Setup

Production behavior fabricates no scores, graph facts, findings, scenario progress, or result truth.

### Step 10 — AI explanation + remediation + re-verify
Complete for exact critical `VERIFIED FAIL` findings. New schema-v2 runs persist confidentiality-safe
finding-relevant authority fingerprints while schema-v1 runs remain readable and immutable.
Unrelated project/index/graph drift is diagnostic for v2 findings rather than an automatic blocker;
missing or changed relevant authority fails patching closed. Legacy v1 runs use whole-authority
equality only as a conservative fallback.

Provider assistance explicitly separates current-source remediation from historical-run-only
explanation. Model output is structured and reference-allowlisted; merchant source is untrusted
prompt data. Patch previews accept only replacement content for StateGuard-created Python regions,
are rebuilt and syntax-checked in memory, carry `AI_GENERATED_NOT_VERIFIED`, and never write files.
Canonical re-verification currently runs the full suite behind a replaceable seam and correlates
only the exact `VerificationCheckKey`; no fuzzy or AI comparison exists.

### Step 11 — CI gate
Complete. `stateguard verify --ci` invokes the same canonical verifier once and evaluates only its
validated immutable result. `0` means applicable core verification passed, `1` means any core or
optional check produced `VERIFIED FAIL`, and `2` means required verification was not proven.
Malformed CI commands and tool failures use the separate exit `3`; completed gate JSON remains on
stdout for result-sensitive non-zero exits while safe errors remain on stderr. No gate artifact,
dashboard/API route, workflow generator, AI authority, or second verifier was added.

### Step 12 — Demo hardening
Complete. `examples/ticketing_merchant` demonstrates:
- non-obvious semantic resolution and authentic ambiguity (`mint_admission_pass` vs `bind_attendee_roster_row`),
- human semantic confirmation and policy confirmation,
- deterministic failure (SG-02 duplicate delivery and SG-03 acknowledgement retry fail at E3 under vulnerable code),
- bounded AI explanation and patch preview with `AI_GENERATED_NOT_VERIFIED`,
- exact deterministic re-verification (`VERIFIED FAIL → VERIFIED PASS` / `PROVEN_RESOLVED`),
- deterministic CI gate evaluation (`0` / `REQUIRED_CHECKS_PASSED`),
- managed-runtime exact-tracing optimization (~4.2s verification duration),
- bounded reset utility (`reset_demo.py`) with strict local containment.

### Step 13 — Stretch only if core is strong
Bounded Razorpay Test Mode grounding is complete and live-proven. Concurrency/race testing remains the
first post-Buildathon runtime stretch, but its current implementation decision is NO-GO for the
submission window because deterministic race-window overlap requires a new explicit checkpoint
contract or a substantially larger runtime-instrumentation design.

---

## 6. Immediate next work

1. Freeze Buildathon feature development; concurrency is NO-GO for the submission window and remains
   the first post-Buildathon runtime stretch.
2. Run one final coherent release/packaging gate after the live-walkthrough fixes and documentation
   update.
3. Finalize the five-minute demo narrative around the already live-proven workflow.
4. Preserve deterministic authority, exact-key re-verification, E4's resource-profile-only meaning,
   the five-route product surface, and the existing deferred scope boundaries.

---

## 7. Current known engineering risks

### Arbitrary runtime complexity
Real FastAPI repositories may require databases, Redis, queues, migrations, or external services.

Mitigation:
- explicit runtime capability levels,
- merchant-supplied test environment,
- static fallback,
- do not provision arbitrary infra.

### Payment Safety Graph false structure
A graph can look impressive while encoding incorrect control/data flow.

Mitigation:
- deterministic provenance,
- source locations,
- narrow graph vocabulary,
- tests against adversarial demo repositories,
- runtime observations where possible.

### AI provider/model variability
A provider-agnostic architecture does not imply every model will map semantics equally well.

Mitigation:
- capability contract,
- structured output validation,
- human resolution,
- future separate model-portability evaluation.

### Semantic staleness
A confirmed customer-value symbol/path may change after source edits.

Mitigation:
- retain project/source-index fingerprints for audit,
- invalidate confirmation using the relevance-scoped semantic-context fingerprint,
- require re-review when selected/candidate source, relevant payment calls, or graph neighborhood changes.

### SG-03 realism
Slow-ack/retry testing is more complex than replaying a duplicate event.

Mitigation:
- define the exact local failure model,
- prove the harness behavior independently,
- do not claim a Razorpay retry was literally observed unless using connected/grounded evidence.

### Merchant policy ambiguity
Authorization/capture/late-authorisation semantics differ by business.

Mitigation:
- policy inference is not final authority,
- require confirmation when invariants depend on it.

### Static-vs-runtime overclaiming
A source pattern can suggest a problem without proving behavior.

Mitigation:
- evidence tiers,
- user-facing result taxonomy,
- red only for VERIFIED FAIL.

### Runtime observation strength
Python body/assignment completion does not prove external durability or customer-value delivery;
BYO cannot provide managed in-process evidence without a future explicit agent contract.

Mitigation:
- fact names state only the observed Python lifecycle,
- independently graded target capability,
- incomplete transcript rejection,
- Step 6 must retain these meanings rather than promote them into stronger evidence.

---

## 8. Current verification state

### Frozen spike
- pre-evaluation compliance: complete,
- focused offline tests before run: 30/30 passed,
- first approved evaluation completed once,
- overall frozen result: NO_GO,
- evaluation artifacts preserved.

### Production StateGuard
- live production semantic proof: one Gemini `gemini-3.7-flash` attempt succeeded with no provider
  failure (3,067 input tokens, 384 output tokens, approximately 6.15 seconds). The
  `BUNDLE_PARTIAL` result correctly remained a bounded suggestion set until explicit human
  confirmation established `app.domain.mint_admission_pass` as `UNIQUE` / `HUMAN_CONFIRMED`;
  this was a product-path smoke, not a benchmark,
- live vulnerable ticketing proof: SG-01 passed at E3; SG-02 and SG-03 failed at E3; SG-02 showed
  one entry and normal return for both the initial and duplicate deliveries to the exact confirmed
  target; two actionable findings were produced,
- live remediation/re-verification proof: one production Gemini remediation call rebuilt current
  finding authority without blocking drift and returned a grounded explanation plus bounded
  `AI-GENERATED — NOT VERIFIED` diff without modifying merchant source. After explicit developer
  application, exact `VerificationCheckKey` correlation proved SG-02
  `VERIFIED FAIL → VERIFIED PASS` / `PROVEN_RESOLVED`; SG-03 also passed. The corrected run had
  9 verified passes, 0 failures, 0 unverified checks, and 0 findings; live CI returned
  `REQUIRED_CHECKS_PASSED` with exit 0,
- genuine Razorpay Test Mode E4 proof: the fetch-only adapter validated and sanitized one Payment
  reporting amount 100/currency INR and its linked fully paid Order reporting amount 100, amount
  paid 100, amount due 0, and currency INR. Canonical
  verification completed with 9 verified passes, 0 failures, 0 unverified checks, 9/9 dynamic
  coverage, and 0 findings. Only SG-01 was promoted to E4 resource-profile grounding; SG-02 through
  SG-08 remained E3. One earlier run without the required demo webhook secret failed closed with
  SG-01 `UNVERIFIED` and no E4 promotion before the environment was restored,
- concurrency feasibility decision: NO-GO for Buildathon implementation. Concurrent request launch
  alone cannot prove overlap at the event-identity decision boundary; a defensible explicit
  checkpoint design was estimated at roughly 5–8 focused engineering days and a source-free async
  branch/opcode design would require a substantially larger runtime redesign. The capability remains
  first in the post-Buildathon runtime roadmap,
- ticketing remediation regression gate: 23 focused remediation tests passed; 1 focused control-API
  route test passed; the coherent remediation/evidence/control gate passed 35 tests; all 18 frontend
  tests and TypeScript typecheck passed; Ruff lint/format and strict mypy across 101 production
  source files passed; the production dashboard build completed with the existing >500 kB
  chunk-size advisory. The earlier partial-bundle presentation correction also passed TypeScript,
  11 frontend tests, and a production Vite build,
- historical bounded Razorpay Test Mode E4 implementation gate: 365 passed, with 1 explicitly
  unconfigured credential-gated fetch-only smoke skipped at that time; this includes adapter safety/error mapping,
  confidentiality, schema-v1/v2 run compatibility, SG-01 E3 degradation, E4 pass/fail promotion,
  exact-key continuity, unchanged CI exit semantics, and dashboard v3 parsing. The credential-gated
  smoke was subsequently completed successfully as recorded above,
- bounded E4 strict mypy: 101 production source files passed with 0 issues; Ruff lint and format
  check: 187 `src`/`tests` files passed with 0 errors,
- bounded E4 frontend verification: 6 Vitest tests passed across 3 files, TypeScript typecheck passed,
  and the production Vite build completed with the existing >500 kB chunk-size advisory,
- bounded E4 packaging: wheel (108 entries) and sdist (135 entries) built successfully; both include
  the three grounding modules and package inspection found no frozen-spike, cache, or `.stateguard`
  runtime artifacts,
- Step 12 full Python regression suite: 339 passed in 62.81s,
- Step 12 frontend typecheck: passed with 0 errors (`tsc -b`),
- Step 12 frontend Vitest test suite: 5 passed across 3 test files,
- Step 12 production Vite build: 1 eager JS bundle (510.88 kB) and 1 CSS stylesheet (38.13 kB) in `src/stateguard/dashboard/static/`,
- Step 12 Ruff lint and format check across all 182 files in `src`/`tests`: passed with 0 errors,
- Step 12 strict mypy across all 98 production source files: passed with 0 issues,
- Step 12 managed-runtime repetition gate:
  - 5 vulnerable canonical cycles: min 4.17s, median 4.33s, max 4.46s (7 passes, SG-02 VERIFIED FAIL at E3, SG-03 VERIFIED FAIL at E3, 0 unverified),
  - 5 corrected canonical cycles: min 4.14s, median 4.20s, max 4.49s (9 VERIFIED PASS at E3, 0 failures, 0 unverified),
  - 10/10 runs passed with 100% clean process termination and zero leftover scratch directories or bound ports,
- historical Step 12 provider reliability note: the provider call was not run in the independent
  Antigravity environment because `GEMINI_API_KEY` was unavailable there; this is superseded by the
  successful live production semantic and remediation calls recorded above,
- Step 12 wheel and sdist packaging: `dist/stateguard-0.1.0-py3-none-any.whl` (105 entries) and `dist/stateguard-0.1.0.tar.gz` (132 entries) with verified packaged dashboard assets and zero forbidden state/caches/secrets,
- Step 12 clean-room installed-wheel smoke test: fresh isolated virtualenv verified CLI help, `analyze`, `serve` (all 5 routes returning 200 with CSP, static assets, control API, clean shutdown), `verify` (9 passes), and `verify --ci` (exit code 0, `REQUIRED_CHECKS_PASSED`),
- Step 11 focused CI/CLI/architecture/control gate: 38 passed,
- Step 10 full Python regression suite: 313 passed,
- Step 9 browser demo: five surfaces passed at 1440/1280/1024 with no overflow or console/CSP
  warnings; explicit semantic, graph, applicability, synchronous run, findings, and evidence flows
  exercised,
- frozen spike evaluator/tests were not run or modified.

---

## 9. Context maintenance rules

Update this file only when one or more of these changes:
- a meaningful capability becomes complete,
- the active implementation objective changes,
- an architecture blocker changes the execution plan,
- an important open risk is resolved/discovered,
- verification status materially changes,
- a durable product decision is accepted and reflected in `STATEGUARD_CONTEXT.md`.

Do not update this file for:
- CSS tweaks,
- tiny refactors,
- individual test additions,
- one-off debugging steps,
- minor package changes that do not affect product state.

Do not create new milestone/status/handoff files unless there is a real need that this file cannot serve.
