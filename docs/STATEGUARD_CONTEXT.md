# StateGuard — Durable Product Context

**Status:** Accepted Buildathon product architecture  
**Context date:** 2026-08-23  
**Purpose of this file:** Durable product truth. Read this before consequential architecture or implementation work. Update only when a lasting product decision changes.

---

## 1. Product identity

### 1.1 One-line definition

**StateGuard is a local-first reliability auditor for Razorpay integrations that reconstructs the payment safety path through a merchant codebase, identifies the merchant-specific action that actually delivers customer value, and adversarially verifies whether that path remains correct when the payment lifecycle stops following the happy path.**

### 1.2 Core pitch

> AI can help developers build a payment integration quickly. StateGuard tries to prove the finished integration will not lose money or deliver customer value incorrectly when duplicate, forged, delayed, retried, missing, or out-of-order payment events occur.

StateGuard is not primarily an integration generator. Razorpay already has Agentic Integration and a developer CLI that help developers integrate and automate payment workflows. StateGuard is positioned as the **verification layer after integration**.

### 1.3 Primary user

A developer or engineering team integrating Razorpay into a backend application.

### 1.4 Buildathon framing

StateGuard is being built for the Razorpay AI Buildathon, Open Track.

The product should perform well against the judging mindset visible in the Buildathon material:
- problem taste,
- build quality,
- AI judgment — including where AI is and is not used,
- failure recovery.

The final product must be understandable and compelling in a roughly five-minute demo. It should feel like a serious developer tool rather than an experimental script with a UI.

### 1.5 Product ambition rule

StateGuard must not become small merely because the team is afraid of overclaiming.

The rule is:

**Build large where claims can be proved; stay conservative only where truth authority requires it.**

When a valuable feature is uncertain, the preferred response is to design a proof, evidence tier, runtime precondition, policy confirmation, or safe fallback — not automatically delete the feature.

---

## 2. Current Buildathon product scope

### 2.1 Fully targeted scope

- Python repositories.
- FastAPI as the first fully supported backend framework.
- Razorpay Payment Gateway integration surfaces relevant to Standard Checkout and payment webhooks.
- Local-first source analysis and verification.
- Static analysis plus dynamic local chaos verification where runtime prerequisites are available.
- One bounded AI semantic problem: identifying the merchant-specific **customer-value action**.
- Human resolution when semantics or merchant policy are consequentially ambiguous.
- A fixed Razorpay-specific Failure Lab.
- Deterministic evidence and invariant evaluation.
- CLI, local dashboard, and CI/release-gate surfaces.
- AI-assisted explanation and patch proposal after a failure has already been proven.
- Optional Razorpay Test Mode grounding.

### 2.2 Explicit non-goals for the Buildathon core

StateGuard is not:
- a generic security scanner,
- a generic AI code reviewer,
- a generic test generator,
- an integration-writing agent,
- a production observability platform,
- a cloud service that executes arbitrary merchant code,
- a system that automatically rewrites payment code,
- a complete audit of every Razorpay product/lifecycle,
- a claim that an integration is globally “secure”.

The core Buildathon product does not require:
- real-money execution,
- production Razorpay credentials,
- SaaS user accounts,
- a cloud database,
- arbitrary infrastructure provisioning,
- multi-agent orchestration,
- multiple programming-language/framework adapters.

---

## 3. Product positioning relative to current Razorpay products

Razorpay's current Agentic Platform includes Agentic Integration, which auto-detects how an application is built and helps developers integrate payments quickly. StateGuard should complement this rather than imitate it.

Accepted positioning:

> **Integration tools help build the payment path. StateGuard reconstructs and adversarially verifies the path after it exists.**

Razorpay also has a CLI intended for terminal workflows, Test/Live operations, CI/CD, and AI-agent use. StateGuard may optionally compose with the Razorpay CLI/Test Mode for grounding, but StateGuard must remain useful without network access or connected Razorpay credentials.

Official current references used when this architecture was accepted:
- Agentic Platform: https://razorpay.com/blog/razorpay-agentic-platform/
- Razorpay CLI: https://razorpay.com/docs/cli/install-cli/
- CLI product page: https://razorpay.com/cli/

---

## 4. Product architecture

Canonical flow:

```text
Merchant repository
        ↓
Project discovery
        ↓
Source index
        ↓
Payment Safety Graph
        ↓
Static analysis + bounded AI semantics
        ↓
Semantic Resolution Gate
        ↓
Merchant payment policy inference/confirmation
        ↓
Scenario Applicability Engine
        ↓
Runtime Capability Resolver
        ↓
Failure Lab
        ↓
Deterministic Invariant Engine
        ↓
Evidence Engine
        ↓
Explanation / remediation
        ↓
Re-verify
```

The same core is exposed through:

```text
CLI  ←──────── StateGuard Core ────────→ Local Dashboard
                         │
                         ↓
                       CI Gate
```

---

## 5. Local-first execution model

StateGuard must not pretend it can safely execute every arbitrary FastAPI repository.

It supports explicit capability levels.

### 5.1 Mode A — Managed Local Runtime

The strongest Buildathon-supported path.

StateGuard:
- discovers the FastAPI application target,
- launches the merchant application or test harness locally as a child process,
- injects applicable scenarios,
- instruments relevant paths,
- captures deterministic observations,
- isolates scenarios using fresh processes/state where required.

This mode is intended for locally runnable test/demo repositories and compatible merchant test environments.

### 5.2 Mode B — Bring Your Own Test Environment

For repositories that need their own services/configuration, the developer supplies the runtime contract, for example:
- application command,
- test environment variables,
- test database/Redis already running,
- base URL or app target.

StateGuard verifies the environment; it does not provision the merchant's infrastructure.

### 5.3 Mode C — Static-only

If dynamic execution prerequisites are unavailable:
- source/graph analysis continues,
- semantic resolution may continue,
- static warnings/evidence may be shown,
- scenarios requiring runtime proof become `UNVERIFIED`,
- StateGuard must not claim `VERIFIED PASS` or `VERIFIED FAIL` for behavior it did not execute/prove.

### 5.4 Runtime safety boundary

Buildathon StateGuard does not:
- upload arbitrary repositories to a StateGuard server for execution,
- execute merchant code in production,
- auto-install/provision arbitrary databases, queues, or cloud dependencies as a core promise.

---

## 6. Payment Safety Graph

The Payment Safety Graph is not decorative UI. It is StateGuard's internal representation for:
- understanding payment trust/business paths,
- narrowing source for semantic analysis,
- deciding scenario applicability,
- selecting instrumentation points,
- explaining evidence to the developer.

### 6.1 Canonical node classes

#### Payment Ingress
Where payment information enters merchant-controlled code.

Buildathon examples:
- `WEBHOOK`
- `CHECKOUT_CALLBACK`

#### Trust Gate
Code that establishes whether incoming payment information is authentic/trusted.

Examples:
- webhook signature verification,
- Checkout/payment signature verification,
- server-side order identity binding.

#### Event Identity Guard
Code used to recognize duplicate/replayed webhook events.

Example:
- `x-razorpay-event-id` lookup/claim/dedupe.

#### Payment-State Gate
Branches or state transitions tied to payment lifecycle states/events.

Examples:
- `payment.authorized`
- `payment.captured`
- `payment.failed`

#### Merchant State Mutation
Payment-related mutation in the merchant application.

Examples:
- marking an order paid,
- storing captured state,
- recording a processed event.

#### Customer Value Action
The action that grants/provides/issues/activates/allocates/ships/unlocks/delivers the product, service, entitlement, admission, or other value the customer paid for.

This is the primary AI-owned semantic concept.

#### Acknowledgement Boundary
The response/acknowledgement point of a webhook request relative to trusted processing and customer-value execution.

This allows StateGuard to reason about retry risk when processing occurs before a successful acknowledgement.

### 6.2 Initial edge vocabulary

Keep the graph small and useful. Initial relationships may include:
- `CALLS`
- `GUARDS`
- `BRANCHES_TO`
- `MUTATES`
- `TRIGGERS`
- `ACKNOWLEDGES_AFTER`

Add new edge types only when they unlock a real analysis/verification need.

### 6.3 Graph provenance

Every important graph fact must carry provenance. Canonical provenance values:

- `STATIC`
- `AI_INFERRED`
- `HUMAN_CONFIRMED`
- `RUNTIME_OBSERVED`

Provenance must not be flattened. An AI-inferred node is not equivalent to runtime-observed behavior.

### 6.4 Graph principles

- Static facts should be extracted deterministically when feasible.
- AI should not be asked to classify structural facts that the analyzer can reliably derive.
- AI confidence is not correctness authority.
- Runtime observations may strengthen/confirm graph facts but do not erase their origin.
- The UI graph should expose enough provenance/source location to let a developer inspect why a node/edge exists.

---

## 7. AI semantic layer — provider agnostic by design

### 7.1 Product requirement

StateGuard must not depend on Gemini as a product.

Gemini was the model used in the frozen semantic spike. Production architecture must use a provider abstraction so the semantic engine can operate with any **supported model/provider that satisfies StateGuard's capability contract**.

Accepted architecture:

```text
Semantic Mapper
      ↓
Model Provider Contract
      ├── Gemini Provider
      ├── OpenAI-Compatible Provider
      └── future provider adapters
```

A native provider adapter can be added when it provides meaningful capability/quality benefits.

### 7.2 Buildathon implementation target

At minimum:
- a Gemini provider adapter,
- an OpenAI-compatible provider adapter.

The OpenAI-compatible adapter may enable providers/gateways that expose a compatible API, subject to model capability checks.

Do not claim literally every model works. StateGuard should say:

> **StateGuard is model-provider agnostic and supports models that satisfy the Semantic Mapper capability contract.**

### 7.3 Minimum semantic-model capabilities

A configured model must provide enough of the following for StateGuard's mapper:
- code/text input,
- sufficient context window for the narrowed source bundle,
- reliable structured output/schema compliance,
- stable single-response generation appropriate for evaluation,
- no required browsing/tool access for the core mapping task.

Provider/model compatibility should fail explicitly rather than silently degrade the schema.

### 7.4 Secrets/configuration

Provider secrets:
- come from environment variables or an equally explicit secure runtime configuration,
- are never committed to the repo,
- are never written to `stateguard.yaml`,
- are never printed in logs/artifacts,
- are not required by deterministic verification once semantics are resolved.

Configuration should store the **environment variable name**, not the secret value.

Conceptual example:

```yaml
ai:
  provider: openai_compatible
  model: <model-name>
  api_key_env: OPENROUTER_API_KEY
  base_url: <provider-base-url>
```

### 7.5 Model optionality rationale

Provider independence is not only a portability preference. It matches the broader engineering reality that model quality, latency, cost, and capability change quickly and should be evaluated per task rather than treated as a permanent single-vendor choice.

Razorpay engineering has publicly described moving from a single frontier model toward a fleet of models selected through use-case-specific evaluation, emphasizing model optionality as an asset.

Current reference:
https://razorpay.com/blog/?p=27428

This does **not** make Razorpay's internal model strategy part of StateGuard's runtime contract; it supports the decision to keep the product architecture model-independent.

### 7.6 AI responsibility

AI may:
- identify merchant-specific customer-value actions from structurally narrowed code,
- explain an already-proven failure,
- propose a remediation/patch preview.

AI does not own:
- Razorpay protocol truth,
- scenario applicability truth when statically/deterministically derivable,
- runtime observations,
- invariant evaluation,
- PASS/FAIL,
- automatic patch application.

---

## 8. Semantic Resolution Gate

StateGuard uses three primary resolution states for the customer-value action.

### 8.1 `UNIQUE`

Exactly one defensible valid customer-value target is resolved.

Dynamic fulfilment-specific verification may proceed.

### 8.2 `AMBIGUOUS`

More than one plausible valid target remains.

StateGuard must not guess. The UI presents candidates/evidence and asks the developer which action actually provides the purchased value.

Until resolved:
- status is `NEEDS INPUT`,
- fulfilment-specific scenarios do not claim PASS/FAIL.

After confirmation, provenance includes `HUMAN_CONFIRMED`.

### 8.3 `UNMAPPED`

No defensible target is established.

StateGuard may:
- ask the developer to select the action manually from relevant symbols,
- continue non-fulfilment analysis where safe,
- leave dependent scenarios unresolved.

### 8.4 Model/provider failure

If the configured model is unavailable or incompatible:
- static analysis survives,
- the developer can manually resolve customer value,
- StateGuard does not become unusable.

### 8.5 Uncertainty principle

**Uncertainty reduces verification coverage; it must not reduce truth quality.**

---

## 9. Merchant payment policy

Payment correctness is not one universal merchant policy.

StateGuard should infer a likely policy from code/graph evidence, then ask for confirmation where the assumption affects invariants.

### 9.1 Buildathon policy vocabulary

Initial fulfilment policies:
- `CAPTURE_REQUIRED`
- `AUTHORIZED_ALLOWED`

`CAPTURE_REQUIRED` means customer value is not permitted before captured state.

`AUTHORIZED_ALLOWED` means the merchant intentionally permits customer value at authorization under its business policy.

Do not treat `AUTHORIZED_ALLOWED` as universally safe; it is a declared merchant policy that changes which invariant is applicable.

### 9.2 Late-authorisation policy

Razorpay's current docs explicitly describe late authorisation handling as dependent on merchant/business ability to provide the service.

StateGuard should model an explicit late-authorisation choice rather than hard-code one universal outcome, for example:
- fulfil later if service can still be provided,
- do not fulfil / allow the payment handling/refund path appropriate to the merchant.

Current reference:
https://razorpay.com/docs/payments/payments/late-authorisation/handle/?preferred-country=IN

---

## 10. Razorpay Rule Catalog

StateGuard should maintain a small, versioned, curated rule catalog derived from authoritative Razorpay sources.

Do not use an LLM's memory as protocol truth.

The Buildathon rules that currently matter include:

### Webhook signature
Razorpay webhooks are signed and signature validation must use the raw request body.

Source:
https://razorpay.com/docs/webhooks/validate-test/

### Duplicate delivery / idempotency
The same webhook event may be delivered multiple times. Razorpay documents `x-razorpay-event-id` as a unique event identifier useful for duplicate detection.

Source:
https://razorpay.com/docs/webhooks/validate-test/

### Out-of-order delivery
Webhook delivery order is not guaranteed; a merchant should not assume `payment.authorized` and `payment.captured` will always be delivered in occurrence order.

Source:
https://razorpay.com/docs/webhooks/validate-test/

### Retry after unsuccessful acknowledgement
Razorpay webhook best-practice documentation describes retries when the merchant endpoint does not return a successful response and specifically notes timeout/retry behavior when processing is accepted but acknowledgement is not returned quickly enough.

Source:
https://razorpay.com/docs/webhooks/best-practices/

### Checkout/payment signature verification
Razorpay Standard Checkout requires server-side signature verification. The verification should use the merchant's server-side `order_id`, not blindly trust the order ID returned through the browser.

Source:
https://razorpay.com/docs/payments/payment-gateway/web-integration/standard/integration-steps/?preferred-country=IN

### Test Mode webhook grounding
Razorpay states Test Mode webhook payload structure remains the same as Live Mode, allowing stage testing to provide realistic payload grounding.

Source:
https://razorpay.com/docs/webhooks/validate-test/

### Freshness rule
These are current as of 2026-08-23. Current Razorpay behavior must be rechecked against official docs when a future product decision, invariant, or user-facing claim depends on it.

---

## 11. Failure Lab

The Buildathon design is **7 core scenarios + 1 advanced policy scenario**.

Scenarios should run only when their graph/runtime prerequisites are applicable. `NOT APPLICABLE` is not a PASS.

### SG-01 — Normal Capture

Purpose:
Establish a positive control before adversarial fulfilment tests.

Core assertion for a `CAPTURE_REQUIRED` flow:
- a normal captured payment reaches the resolved customer-value action exactly once.

If the normal control fails, dependent fulfilment scenarios may be blocked because “nothing happened” must not be mistaken for safety.

### SG-02 — Duplicate Webhook

Input:
- the same captured webhook event/event ID is delivered twice.

Core assertion:
- irreversible customer value occurs no more than once.

This is a core demo scenario and is directly motivated by Razorpay's documented duplicate-delivery behavior.

### SG-03 — Retry After Slow/Failed Acknowledgement

Purpose:
Test an architecture that performs consequential/slow work before acknowledgement and can therefore receive a retry of an event it already began processing.

The harness may inject/delay the relevant path and deliver the same event again under a modeled retry condition.

Core assertion:
- retry behavior must not duplicate customer value.

Additional graph evidence may show whether irreversible work is positioned before the acknowledgement boundary.

This is distinct from SG-02: SG-02 injects a duplicate; SG-03 tests a merchant execution/acknowledgement pattern that can create duplicate-delivery risk.

### SG-04 — Out-of-Order Events

Representative sequence:
- `payment.captured`
- then a late/stale `payment.authorized`

Core assertion:
- customer value must not duplicate.

Optional assertion:
- a specific merchant payment state must not regress **only when StateGuard has sufficient graph evidence to identify that state/mutation**.

Do not invent a generic state-regression field.

### SG-05 — Forged Webhook

Input:
- payment-like webhook payload,
- invalid webhook signature.

Core assertions:
- no trusted payment mutation attributable to the forged input,
- no customer-value action.

### SG-06 — Tampered Checkout Callback

Input:
- plausible Checkout success values with a mismatched/attacker-controlled order identity and invalid/mismatched signature.

Core assertions:
- the callback is not treated as a trusted successful payment,
- no trusted paid-state/customer-value effect occurs.

This tests the browser trust boundary separately from the webhook trust boundary.

### SG-07 — Lost Browser Callback

Representative condition:
- browser success/callback path is absent/lost,
- server receives the legitimate captured webhook path.

Core question:
- can the server-side integration still reach the intended correct payment/business outcome without relying on the browser callback?

Exact assertions should be derived from the graph/policy and should not overclaim merchant-specific state that was never resolved.

### SG-08 — Late Authorisation (Advanced)

Policy-aware scenario.

StateGuard tests the behavior against the developer-confirmed late-authorisation policy.

This is architecturally included but is lower priority than a strong SG-01 through SG-07 implementation.

---

## 12. Scenario applicability and dependency model

StateGuard must not blindly run every scenario.

Examples:
- no webhook ingress → webhook scenarios may be `NOT APPLICABLE`,
- no Checkout callback → SG-06 may be `NOT APPLICABLE`,
- no resolved customer-value action → fulfilment-specific assertions are `NEEDS INPUT`/`UNVERIFIED`,
- failed normal control may block dependent fulfilment assertions,
- missing runtime may reduce dynamic checks to static evidence.

The Payment Safety Graph should drive applicability.

A scenario may contain multiple assertions, and an optional assertion may be omitted when its prerequisite evidence is not strong enough.

---

## 13. Evidence model

### 13.1 Evidence tiers

- `E0 DISCOVERED` — structural/source fact found.
- `E1 RESOLVED` — semantic meaning/policy established through AI and/or human resolution.
- `E2 STATIC VERIFIED` — code structure supports a specific assertion strongly enough for a static verification claim.
- `E3 DYNAMIC VERIFIED` — StateGuard executed the scenario and observed deterministic behavior.
- `E4 RAZORPAY GROUNDED` — optional Razorpay Test Mode/API evidence additionally grounds the run/input.

Higher tiers do not erase the provenance of lower-level facts.

### 13.2 User-facing result taxonomy

- `VERIFIED PASS`
- `VERIFIED FAIL`
- `STATIC WARNING`
- `NEEDS INPUT`
- `UNVERIFIED`
- `NOT APPLICABLE`

### 13.3 Critical display rule

**Only `VERIFIED FAIL` receives critical/red failure treatment.**

A static suspicion must not be presented as a proven runtime failure.

### 13.4 No fake risk score

Do not produce an unexplained global safety score such as `87/100`.

Prefer factual summaries:
- verified passes,
- verified failures,
- unresolved checks,
- static warnings,
- dynamic coverage,
- semantic-resolution state,
- evidence tier.

---

## 14. Deterministic truth authority

The LLM must never own the final safety verdict.

Canonical authority split:

| Problem | Authority |
|---|---|
| Parse/index Python | Deterministic |
| Discover FastAPI/Razorpay structures | Deterministic where feasible |
| Build structural Payment Safety Graph | Deterministic |
| Understand merchant-specific customer value | AI + possible human confirmation |
| Merchant policy when consequential | Infer + human confirm |
| Scenario applicability | Deterministic/graph-driven |
| Generate fixed scenario event sequence | Deterministic |
| Instrument/execute | Deterministic |
| Count/observe effects | Deterministic |
| Evaluate invariant | Deterministic |
| PASS/FAIL | Deterministic only |
| Explain a proven failure | AI may assist |
| Propose remediation/patch | AI may assist |
| Apply payment-code patch automatically | Not Buildathon core |

Core principle:

> **AI proposes meaning or remediation; StateGuard proves behavior.**

---

## 15. Evidence-backed finding shape

Every important finding should be able to expose:

- finding/scenario ID,
- merchant policy used,
- Razorpay rule/rationale,
- input event/request sequence,
- semantic mapping and its provenance,
- graph path,
- source locations,
- runtime capability/evidence tier,
- deterministic execution trace,
- expected invariant,
- observed value/behavior,
- result,
- explanation,
- remediation guidance,
- patch verification state when applicable.

If StateGuard cannot show evidence supporting a critical claim, it should not display that claim as a verified failure.

---

## 16. Remediation and re-verification

### 16.1 Explanation

After deterministic evidence has proven a failure, AI may explain the likely source-level cause using:
- the proven trace,
- relevant source slice,
- graph path,
- invariant result.

The explanation does not create or remove the finding.

### 16.2 Patch proposal

StateGuard may generate a patch preview for a verified failure.

The UI must clearly label it:
- AI-generated,
- not yet verified.

### 16.3 Buildathon patch boundary

Automatic/silent payment-code rewriting is not core.

The developer may copy/apply a proposed patch explicitly. If local apply is later added as a stretch feature, it must require explicit approval.

### 16.4 Re-verification

A patch does not make a finding green.

Only a deterministic re-run of the relevant scenario can change:
- `VERIFIED FAIL`
to
- `VERIFIED PASS`.

This is an important demo moment.

---

## 17. Product surfaces

### 17.1 CLI

Target commands/concepts:

```text
stateguard analyze .
stateguard verify .
stateguard verify --ci
stateguard report
stateguard configure ai
```

Exact command names may evolve, but the CLI must support:
- project discovery/analysis,
- verification,
- CI-readable execution,
- provider/runtime configuration.

### 17.2 Local dashboard

Keep primary navigation small.

Accepted primary surfaces:
1. **Overview**
   - project/integration status,
   - semantic resolution,
   - runtime capability,
   - latest verification summary.

2. **Safety Graph**
   - payment ingress/trust/business path,
   - provenance,
   - source links,
   - unresolved semantics.

3. **Failure Lab**
   - scenario applicability,
   - run controls/progress,
   - status/evidence tier.

4. **Findings**
   - trace,
   - invariant,
   - source,
   - explanation,
   - remediation,
   - re-verification.

5. **Project Setup**
   - `stateguard.yaml`,
   - runtime contract,
   - model provider,
   - merchant policy,
   - CI export/setup.

Do not create admin/account/dashboard surfaces that do not improve the developer verification workflow.

### 17.3 CI

Target semantics:

```text
0 = required verification passed
1 = one or more verified failures
2 = required checks unresolved/unverified
```

The exact implementation may evolve, but unresolved required checks must not silently exit as success.

A GitHub Actions snippet/generator is a natural stretch after the CLI gate is stable.

---

## 18. Local persistence

A traditional cloud database is not required for the Buildathon core.

Preferred local project state:

```text
stateguard.yaml

.stateguard/
  project.json
  semantics.json
  runs/
  reports/
```

Goals:
- inspectable,
- portable,
- CI-readable,
- no SaaS dependency.

`stateguard.yaml` should store durable project configuration such as:
- framework/app target,
- detected ingress routes where appropriate,
- confirmed semantic mapping,
- merchant policy,
- runtime configuration,
- model provider metadata excluding secrets.

Confirmed semantics should be invalidated/reviewed when relevant source changes make them stale.

---

## 19. Optional Razorpay Test Mode grounding

Connected Test Mode is valuable but must not be a prerequisite for core StateGuard.

Offline/local verification should use a pinned Razorpay-compatible rule/event fixture layer.

Optional connected mode may:
- use Razorpay Test Mode resources,
- use Razorpay CLI/API where appropriate,
- ground event/resource metadata,
- raise evidence to `E4 RAZORPAY GROUNDED`.

Current Razorpay docs state Test Mode webhook payload structure remains the same as Live Mode.

StateGuard should not recreate the entire Razorpay CLI.

---

## 20. Failure recovery behavior

StateGuard should fail safely and visibly.

| Failure/uncertainty | Required behavior |
|---|---|
| Razorpay integration not automatically detected | Show evidence found and allow bounded manual ingress selection |
| Model provider unavailable | Continue static analysis; allow manual customer-value selection |
| Multiple semantic candidates | `NEEDS INPUT`; developer resolves |
| No semantic candidate | Manual resolution or dependent checks remain unresolved |
| Merchant runtime fails to start | Static mode; dynamic checks `UNVERIFIED` |
| Missing DB/Redis/env | Name prerequisite; allow merchant-provided test environment |
| Normal fulfilment control fails | Block dependent fulfilment assertions rather than count “nothing happened” as safe |
| Scenario not structurally applicable | `NOT APPLICABLE` |
| Harness/scenario crashes | `UNVERIFIED`, not PASS/FAIL |
| Test Mode unavailable | Core local/offline verification remains usable |
| AI explanation/patch fails | Existing verified finding remains unchanged |
| AI patch generated | Remains unverified until deterministic rerun |
| Razorpay rule cannot be refreshed online | Use pinned catalog/version; do not invent a new rule |

Failure recovery is a product feature, not an error-message afterthought.

---

## 21. Five-minute demo target

The product should be built toward this narrative, not toward showing every feature.

### 0:00–0:30 — Problem
AI can build payment integrations quickly; a happy-path checkout does not prove reliability under duplicate, forged, delayed, retried, missing, or out-of-order events.

### 0:30–1:00 — Analyze repository
Run StateGuard on a FastAPI Razorpay demo/merchant integration.
Show detected ingress/trust paths and the Payment Safety Graph.

### 1:00–1:35 — AI earns its place
Show a genuinely non-obvious customer-value mapping. Prefer the ticketing-style ambiguity:
- `mint_admission_pass`
- `bind_attendee_roster_row`

StateGuard refuses to guess; developer confirms.

Explain that this failure-recovery path came from the frozen experiment.

### 1:35–2:30 — Failure Lab
Run the applicable scenario suite and show clear PASS/FAIL/unresolved progress.

### 2:30–3:25 — Deep dive one verified failure
Best candidate: duplicate webhook.
Show:
- same event delivered twice,
- customer-value function invoked twice,
- deterministic invariant violated,
- source/graph evidence.

### 3:25–4:10 — Remediation
Generate an AI patch preview.
Clearly show `AI-GENERATED — NOT VERIFIED`.
Apply/use the prepared fix and re-run the same scenario.
Show `FAIL → PASS`.

### 4:10–4:35 — CI gate
Show the same verification core running non-interactively with meaningful exit semantics.

### 4:35–5:00 — Experimental evidence
Show the frozen semantic evaluation honestly:
- static unique mapping coverage: 50%,
- Gemini unique mapping coverage: 83.33%,
- static defects detected: 6/12,
- Gemini defects detected: 10/12,
- lift: +4 defects / +33.33 percentage points,
- zero false critical findings,
- frozen overall outcome: `NO_GO`.

Explain that one ambiguous ticketing mapping failed the predeclared precision/normal-control gates and was preserved rather than tuned away.

---

## 22. Frozen semantic spike — immutable evidence

### 22.1 Status

The frozen evaluation is complete.

**Official outcome: `NO_GO`.**

Contract SHA-256:

```text
3454f599945434d7dfbe3cf0eb42ad504bb007f63305453095ce38d07c73e62a
```

The frozen result must never be rewritten as a GO.

### 22.2 Frozen benchmark shape

- 6 FastAPI app families.
- 3 fixtures per family.
- 18 fixtures total.
- 6 correct integrations.
- 12 seeded defects.
- One semantic role: `IRREVERSIBLE_FULFILMENT`.
- Static baseline versus Gemini model used for the approved frozen run.
- Deterministic scenario/invariant engine owned PASS/FAIL.

Families:
- ecommerce → `app.domain.ship_order`
- saas → `app.domain.grant_subscription_access`
- course → `app.domain.unlock_course`
- ticketing → `app.domain.mint_admission_pass`
- workspace → `app.domain.materialize_workspace_entitlement`
- licensing → `app.domain.allocate_license_seat`

### 22.3 Frozen model/run configuration

The approved frozen AI run used:
- provider: Google Gemini,
- model: `gemini-3.6-flash`,
- temperature: `0`,
- candidate count: `1`,
- max output tokens: `4096`,
- structured JSON output,
- no tools/search/code execution/embeddings,
- no model fallback/substitution.

Transport behavior:
- six family requests,
- one attempt per family,
- zero transport retries,
- zero fallbacks/substitutions.

The model name/configuration belongs to the **frozen experiment record**, not the production provider contract.

### 22.4 Frozen result summary

Static baseline:
- semantic precision: 40.00%
- semantic recall: 100%
- unique mapping coverage: 3/6 = 50%
- ambiguous families: 3
- seeded defects detected: 6/12 = 50%
- false critical findings: 0

Gemini frozen run:
- semantic precision: 85.71%
- semantic recall: 100%
- semantic F1: 92.31%
- non-obvious recall: 3/3 = 100%
- unique mapping coverage: 5/6 = 83.33%
- ambiguous families: 1
- seeded defects detected: 10/12 = 83.33%
- evidence-trace completeness: 100%
- false critical findings: 0
- hallucinated symbols: 0

Material defect-recall lift:
- +4 additional seeded defects,
- +33.33 percentage points.

### 22.5 Why the frozen result was `NO_GO`

Two predeclared gates failed:
1. AI critical-role precision required at least 90%; observed precision was 85.71%.
2. All six AI-backed correct normal-capture controls had to pass; only 5/6 counted because ticketing remained ambiguous and was not executed.

Ticketing:
- Gemini correctly included `app.domain.mint_admission_pass`,
- but also included `app.domain.bind_attendee_roster_row`,
- therefore resolution was `AMBIGUOUS`,
- StateGuard's frozen safety rule skipped fulfilment-specific execution for that family.

This is the empirical reason the production product includes human semantic resolution.

### 22.6 Frozen pass-condition record

The ten predeclared gates were:

1. AI role recall at least 5/6 — **PASS**
2. AI non-obvious recall at least 2/3 — **PASS**
3. AI critical-role precision at least 90% — **FAIL**
4. AI hallucinated symbol count = 0 — **PASS**
5. AI defect recall at least 10/12 — **PASS**
6. Material AI lift: at least +25 percentage points or +3 additional defects — **PASS**
7. False critical findings = 0 — **PASS**
8. All six AI-backed correct normal-capture cases pass — **FAIL**
9. All defect findings have complete deterministic traces — **PASS**
10. Invariant engine has exclusive PASS/FAIL authority — **PASS**

Overall `NO_GO` was therefore 8/10 gates passed with two linked failures caused by the ticketing ambiguity. The gates remain frozen historical evidence; production architecture may learn from them but must not retroactively change them.

### 22.7 Integrity rules

Do not:
- rerun the frozen experiment to seek a better result,
- alter its benchmark/prompt/model/settings/gates and call the result the original run,
- hide the failed gates,
- treat the Gemini metrics as evidence that every provider/model will perform equally.

A future model-portability benchmark must be a **new, separately labelled evaluation**.

Frozen artifact location currently known from the experiment:
`spike-test/artifacts/evaluation/results.json`

---

## 23. Model portability — future evaluation direction

Because the product is provider agnostic, a later experiment may compare multiple models/providers on the same semantic task.

Possible metrics:
- semantic precision/recall/F1,
- unique mapping coverage,
- ambiguity rate,
- hallucination count,
- latency,
- cost,
- schema failure rate.

This would be new evidence, not a rewrite of the original Gemini spike.

---

## 24. Deliberately deferred / expansion register

“Not now” means **deferred**, not forgotten.

### 24.1 Deliberate Buildathon exclusions

#### Multi-framework support
Examples:
- Node/Express,
- Django,
- Spring,
- Laravel/PHP,
- Go frameworks.

Why deferred:
The first version needs deep, trustworthy FastAPI source/runtime adapters. Premature framework breadth would multiply parser, route, instrumentation, and runtime complexity.

Future requirement:
Framework adapter interfaces around source indexing, route discovery, graph construction, and runtime instrumentation.

#### Remote arbitrary-repository execution
Why deferred:
Introduces untrusted-code sandboxing, secret isolation, network policies, dependency installation, quotas, and cloud orchestration.

Future requirement:
Ephemeral hardened execution environments/containers and explicit tenant/security boundaries.

#### Automatic merchant infrastructure provisioning
Why deferred:
StateGuard is a verifier, not a general dev-environment platform.

Future requirement:
A safe dependency/runtime graph and bounded service orchestration.

#### Production/live payment chaos execution
Why deferred:
Unnecessary real-money/customer risk for the Buildathon thesis.

Future requirement:
Much stronger authorization, safety policy, operational controls, compliance review, and blast-radius guarantees.

#### Automatic/silent patch application
Why deferred:
Payment code should not be rewritten without explicit developer control.

Future requirement:
Explicit approval, backup/rollback, source-control integration, and mandatory re-verification.

#### Generic multi-agent architecture
Why deferred:
No proven need. It would add context/coordination nondeterminism without strengthening the thesis.

Future requirement:
Only introduce distinct agents if a later capability empirically needs independent roles.

#### Full generic security scanner
Why deferred:
Dilutes the payment-reliability differentiator and creates a much larger claim surface.

Future requirement:
A separately scoped security module with its own evidence/rules.

#### SaaS auth/accounts/team administration
Why deferred:
Adds little to the five-minute developer-tool thesis.

Future requirement:
Needed only for cloud/team collaboration, centralized policy, and hosted history.

#### Cloud/Postgres run history
Why deferred:
Local artifacts are sufficient and desirable for a developer tool.

Future requirement:
Hosted/team product with persistence, auth, tenancy, retention, and privacy policies.

#### RAG over Razorpay docs
Why deferred:
The Buildathon rule corpus is small enough for a curated, versioned authoritative catalog. RAG would add retrieval uncertainty without clear value.

Future requirement:
Consider only when the product covers enough Razorpay products/rules that manual curation becomes a real bottleneck.

#### GitHub App/OAuth
Why deferred:
CLI CI gating demonstrates the workflow without spending time on OAuth/install plumbing.

Future requirement:
PR status checks, annotations, repository installations, organization policy.

#### Fully automatic semantic re-resolution
Why deferred:
A previously confirmed customer-value mapping should not silently change because a model changed its mind.

Future requirement:
Source-diff invalidation, review workflow, and versioned semantic decisions.

---

## 25. Stretch features after core Buildathon quality is high

These are candidates if the core implementation finishes early.

### 25.1 Concurrency / race-condition testing
High priority.

Run the same event concurrently in multiple workers to detect:
- check-then-act races,
- non-atomic idempotency,
- double fulfilment under parallel delivery.

Why valuable:
Sequential duplicate handling can pass while concurrent delivery still fails.

### 25.2 Connected Razorpay Test Mode grounding
Use Test Mode/API/CLI resources to provide E4 evidence.

Do not make the core suite depend on network access.

### 25.3 GitHub Actions generator
Generate a workflow file or precise CI snippet once `stateguard verify --ci` is stable.

### 25.4 Run comparison
Show:
- new failures,
- resolved failures,
- changed evidence/coverage.

### 25.5 Payment Safety Graph/source diff
Detect changes to payment-sensitive paths and invalidate affected semantic confirmations/checks.

### 25.6 Explicit local patch application
Allow a developer to approve and apply an AI-generated patch locally, followed immediately by deterministic re-verification.

---

## 26. Larger post-Buildathon ambitions

### 26.1 Multi-value fulfilment graphs
Real payments may deliver several coordinated pieces of value.

Future model:
- `CustomerValueSet`,
- all-or-none expectations,
- exactly-once per effect,
- compensation behavior.

### 26.2 Property-based payment state testing
Generate many valid/adversarial event sequences from a formal payment-state model rather than only the curated Failure Lab.

Use deterministic/model-based testing, not LLM randomness, for the state-space engine.

### 26.3 Stateful fuzzing
Vary:
- event order,
- duplicate count,
- timing,
- timeout conditions,
- callback loss,
- constrained payload fields.

Preserve protocol validity where required.

### 26.4 Refund reliability
Extend the graph/invariants to:
- refund initiation,
- refund processing,
- amount constraints,
- duplicate refund actions,
- merchant state/value compensation.

### 26.5 Subscription reliability
Potential future lifecycle:
- renewal,
- failed charge,
- retry,
- pause,
- cancel,
- resume,
- entitlement grant/revoke.

This is intentionally separate from the one-time-payment Buildathon core.

### 26.6 Payment–order consistency
Model consistency across:
- Razorpay order,
- Razorpay payment,
- merchant order,
- customer entitlement,
- amount/currency/identity.

### 26.7 AI-assisted graph completion
When dynamic code defeats static analysis, AI may propose graph nodes/edges, but proposed facts remain lower-evidence until human-confirmed or runtime-observed.

### 26.8 Continuous Razorpay rule synchronization
Monitor current official Razorpay documentation for changes, then require human review before updating the versioned rule pack.

### 26.9 GitHub-native review
Future GitHub App:
- detect payment-sensitive PR changes,
- determine affected scenarios,
- run StateGuard,
- annotate verified regressions.

### 26.10 Change-impact verification
Use Git/graph diffing to run only affected Failure Lab scenarios in PRs.

### 26.11 Historical incident replay
Turn a merchant's real sanitized problematic event sequence into a permanent regression scenario.

### 26.12 Production observability bridge
Use sanitized production event traces to reproduce incidents safely in a test environment. Do not inject chaos into production.

### 26.13 Cloud/team platform
Potential future capabilities:
- organizations,
- repositories,
- centralized run history,
- team payment policies,
- compliance/release evidence,
- deployment gates.

### 26.14 Formal/state-machine verification
Longer-term graph properties may include:
- trusted input required before customer value,
- no duplicate customer value per payment,
- monotonic payment state where modeled,
- amount/refund consistency,
- terminal-state reachability/liveness.

---

## 27. Expansion priority order

If the Buildathon core is completed early, preferred expansion order is:

1. concurrency/race-condition testing,
2. connected Razorpay Test Mode grounding,
3. GitHub Actions generation,
4. run comparison + graph/source diffing,
5. multi-value fulfilment,
6. property-based event-sequence testing,
7. Node/Express support,
8. refund lifecycle,
9. GitHub App / PR integration,
10. cloud/team platform.

This order may change only when implementation evidence or deadline constraints justify it.

---

## 28. Permanent product principles

1. **AI where semantics are needed; deterministic code where truth is needed.**
2. **Human confirmation where consequential semantics remain ambiguous.**
3. **Uncertainty reduces coverage, never truth quality.**
4. **Only runtime/deterministic evidence can create a verified failure.**
5. **Do not confuse a static warning with proof.**
6. **Do not hide or retune failed experiments.**
7. **Do not make Gemini a product dependency.**
8. **Do not invent a universal merchant policy.**
9. **Use current authoritative Razorpay rules, not model memory, for protocol truth.**
10. **Be ambitious by proving more, not by claiming more.**
11. **The Payment Safety Graph must power verification; it is not decorative.**
12. **A generated fix remains unverified until the same deterministic failure is re-run.**
13. **The product should degrade gracefully when AI, runtime, or Test Mode is unavailable.**
14. **Prefer one coherent payment-reliability platform over unrelated feature accumulation.**
15. **Build toward an inspectable five-minute demonstration of real engineering judgment.**
