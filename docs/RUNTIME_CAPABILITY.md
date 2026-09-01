# Step 5 Runtime Capability and Managed Step 6 Observation Contract

Step 5 assesses whether current Payment Safety Graph identities can be addressed at runtime. It
opens value-free observation streams used by Step 6. Step 5 itself does not drive Failure Lab
scenarios, persist scenario evidence, or produce PASS/FAIL; the current Step 6 executor consumes
those streams in memory and applies deterministic scenario reducers.

## Identity authority

`NormalControlId` remains only the exact ingress/path/customer-value fulfilment control. It is not a
generic runtime identifier.

- An ingress observation binds the existing ingress graph node, route registration, selected app
  instance, ingress symbol, HTTP method, and effective path.
- A customer-value observation additionally requires the existing `NormalControlId`, exact
  customer-value graph node and symbol, connectivity edge, call path, and semantic fingerprint.
- A mutation observation binds the existing mutation graph node, backing symbol, structural
  anchor, mutation kind, and merchant-state carrier.
- An acknowledgement observation binds the existing acknowledgement graph node, backing symbol,
  structural anchor, exit kind, and static outcome.

Mutation and acknowledgement targets can therefore be assessed without a customer-value semantic
resolution. Exact full-binding reconciliation is mandatory. Missing, ambiguous, stale,
cross-route, decorated-beyond-reconciliation, or bytecode-mismatched targets degrade capability;
StateGuard never selects a nearby target.

Managed readiness also resolves every customer-value and mutation symbol through its exact imported
module and qualified-name chain. `COMPLETE` requires one live code object matching the compiled
descriptor; a missing, replaced, multiply resolved, or mismatched live target is unavailable.

## Customer-value lifecycle facts

These events deliberately avoid the phrase "customer value occurred":

- `CUSTOMER_VALUE_ENTERED` proves that the exact target body reached its initial CPython `RESUME`
  under the correlated request and normal control. It does not prove completion, a return, value
  delivery, state commit, or an external side effect.
- `CUSTOMER_VALUE_RETURNED_NORMALLY` proves that the same invocation reached a genuine terminal
  Python return rather than an async suspension or generator yield. It does not inspect or prove
  the return value, value delivery, transaction commit, or an external side effect.
- `CUSTOMER_VALUE_EXCEPTION_ESCAPED` proves that an exception propagated out of the exact body. It
  stores no exception object, type, or message. It does not prove that no side effect happened
  before the exception.

Caught internal exceptions do not create an exceptional-exit event. Async suspension/resumption
does not create duplicate entry or completion events. Generators, async generators, opaque
decorators, native extensions, and other shapes without reliable terminal classification expose
`ENTRY_ONLY` or `UNAVAILABLE` rather than a stronger claim.

## Python assignment lifecycle facts

`PYTHON_ASSIGNMENT_INSTRUCTION_COMPLETION` is the capability name. Its observations are:

- `MERCHANT_ASSIGNMENT_INSTRUCTION_REACHED`
- `MERCHANT_ASSIGNMENT_INSTRUCTION_COMPLETED_NORMALLY`
- `MERCHANT_ASSIGNMENT_INSTRUCTION_RAISED`

They describe only the exact statically recognized `STORE_SUBSCR` or `STORE_ATTR` instruction.
Normal instruction completion does not prove database durability, a committed transaction, queue
publication, external-service success, permanence after rollback/reversion, or customer-value
delivery. A source location that does not resolve to one unique assignment instruction is
unavailable.

## Runtime modes and dependency boundary

Managed mode imports and serves the exact FastAPI app in one StateGuard-owned local child process.
It uses a sanitized environment, fixed argv with `shell=False`, one worker, reload disabled, a
fresh loopback port, bounded lifecycle timeouts, a private process group, and graceful then forced
cleanup. It provides fresh process and observation state, but never claims that merchant-owned
databases, Redis, queues, or other business state were reset.

FastAPI and Uvicorn are not mandatory StateGuard dependencies. Managed support is installed
explicitly with the `managed-fastapi` extra in an isolated compatible environment:

```console
uv sync --extra managed-fastapi
```

The current empirical matrix is CPython 3.11, FastAPI 0.141.x, Starlette 1.6.x, and Uvicorn 0.52.x.
StateGuard detects missing or untested versions as capability degradation. It never installs,
upgrades, downgrades, or edits merchant dependencies or lockfiles.

BYO mode can contact an already-running service or launch an explicit argv list. Launch ownership
does not imply in-process tracing: BYO customer-value and mutation capability remains unavailable,
and HTTP observations are client-side/partial. Static mode imports and contacts nothing.

## Buildathon-safe targets

Managed mode always binds loopback. BYO defaults to a `local` target and accepts only `localhost`,
loopback IPv4, or loopback IPv6. A non-loopback HTTP(S) target requires `kind: declared_test` and
the exact persisted declaration `NON_PRODUCTION_TEST_ENVIRONMENT`. That declaration makes a target
eligible for test driving; it is not proof that the environment is isolated.

Base URLs with credentials, query strings, or fragments are rejected. Readiness and each request
revalidate the target. Redirects are never followed, and readiness redirects are rejected. There
is no production target class or override. Step 5 implements no live-money or production chaos.

## Capability lifetime versus observations

`.stateguard/runtime.json` is an atomic, permission-restricted historical capability assessment.
It records source/index/graph/applicability/runtime-config fingerprints, compatibility, exact
attachment capability, ownership/isolation claims, and bounded diagnostics. It contains no request
events or transcript.

An active session exposes a bounded in-memory observation stream. Closing the session seals an
in-memory transcript with exact session/request/target identities, contiguous monotonic sequence,
completeness, diagnostics, event count validation across the worker channel, and a transcript
fingerprint. Source and normalized configuration are revalidated before import, after attachment,
and at close. Overflow, truncation, tracer failure, channel failure, drift, or cleanup failure makes
the transcript incomplete. The transcript validator rejects incomplete, stale-capability,
cross-ingress, cross-control, cross-mutation, and cross-acknowledgement observations.
Execution of an exact instrumented target without a matching active request/control context is
never assigned to another request and makes the transcript incomplete.

Step 5 does not persist the transcript. `runtime assess` discards readiness/smoke observations after
printing the capability summary. The application-level `open_runtime_session` API instead returns
the freshly assessed `READY` capability and active session together without writing `runtime.json`.
Its generic `request()` operation returns a typed handle containing the generated request ID, exact
ingress binding, and HTTP response so the caller never predicts request ordinals. Managed dispatch
supports exact headers plus bounded raw body or query parameters. SG-06 uses that extension only
after an exact Checkout binding has been reconciled against the live FastAPI route.

Step 6 currently owns ordered scenario/request mapping, one close-once sealed transcript, and
immutable in-memory result construction. No scenario result or transcript persistence exists yet.
Safe input references contain only fixture/role/transport identifiers, event IDs where relevant,
and request/body/context fingerprints; they never contain request bodies, Checkout values,
signatures, response bodies, secrets, or environment values.

## Managed Step 6 input authority

SG-03 uses a managed-only, request-scoped acknowledgement option. The driver supplies
`FORCE_NON_2XX_AFTER_SUCCESS` together with the exact selected acknowledgement graph node through
a private header. The outer correlation wrapper consumes that header before merchant middleware,
binds it to the current request context, and resets the context automatically. It cannot leak into
a later request. At the exact ASGI response-start boundary, StateGuard applies the option only when
the merchant produced the selected successful 2xx acknowledgement. It records the exact
acknowledgement node, merchant-produced status, effective status, and transcript sequence, then
rewrites the effective response status to fixed `503`. A missing, ambiguous, non-2xx, or foreign
acknowledgement cannot produce this evidence.

The first SG-03 delivery must also prove exact customer-target entry and normal terminal return
before the injection sequence. StateGuard then dispatches the identical signed body, signature,
and event ID again under a distinct `RuntimeRequestId`, with no injection. This is a
StateGuard-modeled retry-eligible acknowledgement failure and a StateGuard-modeled second
delivery. It is not evidence that Razorpay performed a retry. Two ordinary deliveries without the
exact injection remain SG-02-like evidence and cannot produce an SG-03 verdict.

SG-04 delivers one pinned `payment.captured` webhook followed by one pinned stale
`payment.authorized` webhook in the same fresh session. The requests share a synthetic payment and
order identity, but use distinct event IDs, fixture-appropriate bodies, and independently computed
signatures.

SG-06 accepts only a provenance-backed exact Checkout request binding. Supported shapes are a JSON
object read by `Request.json()`, URL-encoded form data read by `Request.form()`, and exact FastAPI
query/scalar, `Form`, or `Body` fields. Mixed or dynamic parsing, missing/duplicate fields,
unresolved body models, uncontrolled required parameters, and static/live route mismatches degrade
capability. The host may supply test authority through the reserved child names
`STATEGUARD_TEST_RAZORPAY_KEY_SECRET` and `STATEGUARD_TEST_SERVER_ORDER_ID` in existing
`runtime.env_from_host`; the merchant runtime's own environment names must be mapped independently.
The values remain in memory and redacted, with no configuration-schema change.

SG-07 dispatches exactly one legitimate captured webhook and no callback request. Any foreign or
callback request evidence, incomplete lifecycle, cross-control observation, or transcript defect
makes the result `UNVERIFIED`.

SG-08 uses a signed `payment.authorized` fixture, and for
`CAPTURE_REQUIRED + FULFIL_LATER` a later signed `payment.captured` fixture for the same synthetic
payment/order identity. The event IDs, signatures, bodies, and request IDs remain distinct. The
safe input reference labels this only as a StateGuard-modeled late-event sequence and explicitly
records that merchant late business context was not observed. It does not claim that an order was
pending, cancelled, expired, beyond a deadline, or still serviceable.

The capture policy supplies independent authority for two bounded SG-08 invariants. Under
`CAPTURE_REQUIRED`, any exact authorization-time customer-target entry is a verified pre-capture
failure. For `FULFIL_LATER`, zero authorization entries plus one normal captured-control entry can
verify the modeled capture sequence. Under `CAPTURE_REQUIRED + DO_NOT_FULFIL`, zero authorization
entries remain `UNVERIFIED` because absence does not prove merchant late-state handling. Both
`AUTHORIZED_ALLOWED` combinations remain `UNVERIFIED` with
`MERCHANT_LATE_CONTEXT_UNPROVEN` and do not dispatch: an ordinary authorized-path outcome cannot
prove a late-specific merchant policy. No generic merchant-state seeding or late-state mutation
assertion exists.

Events never contain merchant arguments, locals, return values, exception objects/messages,
carrier values, request/response bodies or headers, environment values, or credentials.

## Instrumentation proof gate

The CPython 3.11 trace mechanism is gated by focused tests for sync and async lifecycle, un-awaited
coroutines, suspension/resumption, FastAPI async and threadpool sync endpoints, exact decorated and
aliased targets, methods, concurrent correlation, assignment success/failure, behavior
preservation, tracer containment, exact mismatch, and value absence. Material failure of coroutine
terminal classification, threadpool correlation, instruction completion, or behavior preservation
requires revisiting the mechanism rather than weakening event meaning.
