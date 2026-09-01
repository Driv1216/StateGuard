# AGENTS.md — StateGuard Coding-Agent Operating Rules

This file defines how coding agents should work in the StateGuard repository. It is intentionally shorter than the product context.

## 1. Read before consequential work

For architecture, payment logic, semantic mapping, runtime verification, invariants, security-sensitive code, or broad refactors, read:

1. `docs/STATEGUARD_CONTEXT.md`
2. `docs/CURRENT_STATE.md`

Do not infer product truth from this file alone.

---

## 2. Source-of-truth precedence

When sources conflict, use this order:

1. Frozen experiment artifacts/contracts for claims about the frozen spike.
2. Current official Razorpay documentation for Razorpay behavior.
3. `docs/STATEGUARD_CONTEXT.md` for accepted durable product architecture/boundaries.
4. `docs/CURRENT_STATE.md` for current implementation status.
5. The explicitly approved task/plan.
6. Existing implementation details.
7. Agent inference.

Surface conflicts instead of silently choosing whichever source is convenient.

---

## 3. Non-negotiable product boundaries

Do not silently change any of the following:

- PASS/FAIL is deterministic-only.
- AI confidence never becomes safety authority.
- Customer-value semantics may be AI-inferred but ambiguity requires human resolution.
- StateGuard is provider agnostic; Gemini-specific SDK/config must stay behind a provider adapter.
- Provider secrets must not be committed, logged, printed, or persisted in `stateguard.yaml`/artifacts.
- Static evidence must not be represented as runtime proof.
- Only `VERIFIED FAIL` is a critical/red proven failure.
- `NOT APPLICABLE`, `NEEDS INPUT`, and `UNVERIFIED` must not be converted into PASS to improve metrics/demo appearance.
- Merchant payment policy must not be assumed universally.
- The Payment Safety Graph must carry provenance/source evidence.
- AI-generated remediation remains unverified until deterministic re-verification.
- The frozen semantic spike remains `NO_GO` and must not be rerun/tuned as if the original result can change.
- No real-money chaos execution in the Buildathon core.
- No remote arbitrary-repository execution/cloud sandbox unless explicitly approved as a new scope decision.

If implementation evidence shows one of these boundaries is wrong, stop and report the conflict with alternatives. Do not rewrite product truth silently.

---

## 4. Current agent responsibility split

### Codex — core/high-risk owner

Prefer Codex for:
- production architecture,
- typed contracts/schemas,
- Payment Safety Graph model/construction,
- Python/FastAPI source analysis,
- Razorpay trust/payment-state analysis,
- model-provider abstraction,
- Gemini/OpenAI-compatible adapters,
- semantic resolution logic,
- merchant policy/applicability engine,
- runtime harness/instrumentation,
- deterministic invariants,
- evidence/result semantics,
- security/secrets boundaries,
- CI exit semantics,
- consequential refactors,
- test strategy for core logic.

### Antigravity (currently Gemini 3.7 Flash) — bounded/lower-risk owner

Antigravity may handle well-specified work where core product truth is not at stake, for example:
- React presentation components,
- graph visualization/rendering after graph contracts are fixed,
- layout/styling/responsiveness,
- animations,
- loading/empty/error visual states,
- straightforward form wiring to already-defined APIs,
- reusable presentational components,
- non-critical frontend utilities,
- mechanical/repetitive changes within an approved boundary.

Antigravity must not independently redefine:
- Razorpay rules,
- invariant semantics,
- payment policy,
- result/evidence authority,
- model-provider contracts,
- runtime safety behavior,
- customer-value meaning,
- persistence of secrets,
- the frozen experiment.

If a UI task requires changing a core contract, return the requirement to Codex/architecture review instead of making the change implicitly.

### Coordination rule

Avoid having Codex and Antigravity edit the same core files concurrently.

Prefer explicit ownership by task/subsystem and integrate at stable contracts.

---

## 5. Planning and explanation

For consequential work:
1. inspect relevant code/context first,
2. state a concise implementation plan,
3. identify product contracts/invariants that must remain unchanged,
4. implement in bounded batches,
5. explain what changed and why at the end.

Do not create a huge planning ceremony for trivial isolated changes.

Do not make architecture decisions solely because they are easiest to code.

---

## 6. Proportional verification

Testing matters, but repeated full-suite execution after every micro-edit wastes time and tokens.

Use proportional verification:

### Small isolated edit
Run the smallest focused check that can catch the likely regression.

### Meaningful subsystem batch
Run subsystem tests/type/lint checks that cover the changed behavior.

### Completed implementation batch
Run the relevant broader suite and static checks once the batch is coherent.

### Release/demo gate
Run the complete agreed verification set.

Do not:
- rerun the entire suite after every minor edit,
- duplicate the same expensive verification with no new risk,
- skip focused tests for high-risk payment/invariant logic.

Core payment/invariant behavior needs stronger proof than styling work.

---

## 7. Test design principles

For safety-critical code:
- prefer deterministic tests,
- test negative/failure paths,
- verify `UNVERIFIED`/`NOT APPLICABLE` behavior,
- test ambiguity rather than only happy UNIQUE mappings,
- test provider/schema failure,
- test no-result/no-runtime behavior,
- test that AI output cannot directly create PASS/FAIL,
- test trace completeness for VERIFIED FAIL,
- test that stale semantic mappings are invalidated when relevant source changes.

Do not fabricate successful runtime evidence in tests that are intended to prove production behavior.

Mocks are acceptable for unit boundaries but must not be presented as external-provider/runtime proof.

---

## 8. Razorpay rule discipline

When adding/changing a rule or invariant that depends on Razorpay behavior:
- verify the current official Razorpay documentation,
- record/reference the authoritative rule source in the appropriate rule catalog,
- distinguish a Razorpay fact from a StateGuard/merchant policy assumption.

Do not use LLM memory as payment-protocol authority.

If official documentation is unavailable or ambiguous, mark the assumption and request review.

---

## 9. Model-provider discipline

The semantic engine must depend on a StateGuard-owned provider interface, not directly on a vendor SDK.

Provider-specific code belongs inside adapters.

Expected concerns handled at the adapter/gateway boundary:
- authentication,
- endpoint/base URL,
- model name,
- structured output/schema,
- normalized transport errors,
- retry policy,
- metadata such as latency/usage where available.

The semantic domain should receive normalized request/response objects.

Do not:
- hard-code `GEMINI_API_KEY` throughout product code,
- store raw keys in project files,
- silently fall back to a different model/provider when correctness/evaluation depends on the configured model,
- fuzzy-correct hallucinated source symbols into valid ones without making that an explicit product decision.

---

## 10. Runtime and untrusted-code boundary

Buildathon StateGuard is local-first.

Do not add a remote arbitrary-code execution service as an implementation shortcut.

For local verification:
- isolate scenarios where required,
- avoid leaking host secrets into the merchant process,
- make runtime prerequisites explicit,
- treat harness crashes as `UNVERIFIED`,
- preserve enough raw evidence to diagnose the run,
- do not let a failed harness become a PASS.

---

## 11. UI data integrity

The dashboard must render real StateGuard state/contracts.

Do not invent:
- scores,
- findings,
- source locations,
- AI confidences,
- runtime traces,
- scenario results.

Demo fixtures/examples are acceptable only when clearly part of the demo merchant repository/test data and processed through the real product path.

No fabricated production values.

---

## 12. Context maintenance

Persistent context is intentionally small.

### `docs/STATEGUARD_CONTEXT.md`
Update only when a durable product truth changes and that change is explicitly accepted.

### `docs/CURRENT_STATE.md`
At the end of a meaningful completed work batch, update only if:
- a capability materially changed status,
- the active objective changed,
- an important risk/blocker changed,
- verification status materially changed.

Do not update it for every small edit.

### New context files
Do not create:
- milestone files,
- invariant files,
- handoff files,
- phase files,
- status files,
- agent-memory files

unless the user explicitly approves a concrete need that the existing files cannot handle.

Technical specs that are part of the actual product/codebase (for example an API schema generated from code) are not automatically “context files”; use judgment.

---

## 13. Documentation/code drift

Implementation truth can reveal that the accepted design needs revision.

When this happens:
1. do not silently mutate the durable context,
2. show the observed evidence,
3. explain the conflict,
4. propose the smallest coherent decision,
5. update durable context only after acceptance.

Conversely, do not preserve a stale implementation merely because changing it is inconvenient when it clearly violates the accepted product contract.

---

## 14. Scope discipline

Before adding a new capability, ask:
- Does it strengthen the payment-reliability thesis?
- Can it be demonstrated/proved?
- Is it core, stretch, or deferred?
- Does it create a new truth/security/runtime surface?
- Is there already a deferred entry for it?

Prefer depth around:
- Safety Graph,
- semantic resolution,
- Failure Lab,
- evidence,
- remediation/re-verification,
- CLI/dashboard/CI.

Avoid unrelated feature accumulation.

---

## 15. Completion reporting

At the end of a consequential task, report compactly:
- what changed,
- why it changed,
- key files/contracts touched,
- focused verification run and result,
- any broader verification run and result,
- unresolved risks/assumptions,
- whether `CURRENT_STATE.md` was updated and why.

Do not hide warnings/failures or describe an unrun check as passing.
