---
name: proportional-verification
description: Use risk-proportional testing and verification during implementation or modification work. Activate when making changes that may need validation. Do not activate for planning-only work, architecture discussion, repository exploration, research, explanation, or read-only review unless verification itself is the task.
---

# Proportional Verification

## Purpose

Maintain strong engineering confidence without wasting time, tokens, or compute on repetitive or low-value verification.

This skill controls **when and how much verification to run during implementation**.

It must not reduce:
- planning depth,
- reasoning quality,
- implementation completeness,
- architectural exploration,
- edge-case analysis,
- or correctness standards.

The default pattern is:

> **Reason fully → implement coherently → verify narrowly when justified → complete the scope → verify comprehensively at closure.**

---

## 1. Verification must be proportional to risk

Do not treat every edit as requiring the same level of validation.

Choose verification effort according to factors such as:
- behavioral risk,
- blast radius,
- uncertainty,
- coupling,
- reversibility,
- security or data sensitivity,
- and the cost of discovering an error later.

A small, obvious, low-risk change may require no intermediate verification.

A foundational or high-risk change may justify an early targeted check before further work depends on it.

---

## 2. Do not fragment implementation unnecessarily

Do not automatically stop after every edit, file change, or minor implementation step to run broad tests, builds, lint, type checks, integration checks, or other expensive validation.

Complete logically related work as a coherent unit before broader verification unless an unresolved high-risk assumption makes continuing likely to cause substantial rework.

A coherent unit is determined by the task and dependency structure, not by a fixed number of files, edits, or steps.

Avoid an automatic:

> **edit → broad verification → edit → broad verification → edit → broad verification**

cycle.

---

## 3. Use the smallest useful intermediate check

Before running an intermediate verification command, ask:

> **What specific uncertainty will this check resolve right now, and would waiting until the current coherent unit or final closure materially increase risk or rework?**

If there is no strong answer, keep implementing.

When an intermediate check is justified, prefer the smallest high-signal check capable of answering the immediate question.

Possible forms include:
- a focused test,
- a narrow static check,
- a targeted reference check,
- a small affected test group,
- or another project-appropriate validation step.

Do not escalate to a broad suite merely because a narrower check exists and is sufficient.

---

## 4. Preserve full planning and reasoning quality

This skill is **not** permission to:
- think less,
- inspect less,
- skip edge cases,
- choose weaker architecture,
- avoid useful investigation,
- simplify the requested scope,
- suppress alternatives,
- or rush implementation to save tokens.

Planning should remain as rigorous as the task requires.

Only the **frequency and scope of execution-time verification** should be optimized.

---

## 5. Verify comprehensively at closure

Once the approved implementation scope is complete, perform the comprehensive verification appropriate to the changes and the repository.

Determine the final verification set from:
- the actual blast radius of the completed work,
- explicit user requirements,
- repository requirements,
- and project-specific risk.

Do not blindly run every available validation command if some are unrelated to the completed changes.

At closure, confidence should be strong enough to support the final implementation claim.

---

## 6. Handle failures efficiently

If broader or final verification finds a defect:

1. Diagnose the specific failure.
2. Repair the defect.
3. Run the smallest directly affected check first.
4. Expand verification only as needed to establish that the repair is stable.
5. Return to the appropriate broader closure verification afterward.

Avoid:

> **full suite → one failure → tiny fix → full suite → tiny fix → full suite**

Prefer:

> **broad check → failure → targeted repair → focused check → broader closure check when stable**

Do not repeatedly rerun an unchanged expensive suite unless intervening changes could reasonably invalidate its previous result.

---

## 7. Reuse valid verification evidence

Previously established verification remains useful until a later change could reasonably invalidate it.

Do not repeat expensive checks solely because:
- another file was saved,
- an unrelated edit occurred,
- implementation continued in an unaffected area,
- or additional verification would merely duplicate already-established evidence.

Every non-trivial verification command should answer a concrete question or satisfy a required gate.

---

## 8. Increase verification when risk demands it

Efficiency never outranks correctness, safety, or explicit requirements.

Use stronger intermediate verification when the consequences of a mistaken assumption are significant, especially when changes affect foundational, shared, destructive, security-sensitive, concurrent, persistent, externally consumed, or difficult-to-reverse behavior.

Even then, begin with the smallest high-signal check that resolves the immediate uncertainty before escalating.

---

## 9. Respect user and repository requirements

Explicit user instructions and mandatory repository rules take precedence over this default workflow.

If the user or repository requires:
- no tests,
- specific tests,
- targeted verification only,
- exhaustive verification,
- a mandatory closure sequence,
- or another validation boundary,

follow it unless it conflicts with a higher-priority safety requirement.

Use this skill to eliminate unnecessary repetition around required checks, not to silently remove required gates.

---

## 10. Avoid verification theater

Do not confuse more commands with more confidence.

Avoid:
- testing reflexively after every minor change,
- rerunning broad suites without a concrete reason,
- repeating checks whose relevant inputs have not changed,
- performing unrelated validation for appearance of rigor,
- restarting or rebuilding systems merely to re-prove unchanged behavior,
- or spending more effort validating a trivial edit than the edit reasonably warrants.

Verification should be intentional, evidence-producing, and proportional.

---

## Default operating principle

> **Reason deeply. Implement completely. Test proportionally. Verify comprehensively at closure.**

Correctness remains mandatory.

Redundant verification does not.
