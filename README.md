# StateGuard

StateGuard is a local-first reliability auditor for Razorpay integrations. The
production package is intentionally separate from the frozen semantic experiment
under `spike-test/`.

The pipeline implements the local static, semantic, policy, applicability, runtime-capability,
Failure Lab, and deterministic verification path:

```text
Project Discovery -> Source Index -> Payment Safety Graph -> Semantic Resolution
                  -> Merchant Policy -> Scenario Applicability -> Runtime Capability
                  -> Failure Lab (SG-01..SG-08) -> Deterministic Invariant Engine
                  -> Structured Evidence & Findings -> CLI / Local Dashboard / CI Gate
```

StateGuard discovers and indexes Python/FastAPI source, constructs the structural Payment Safety Graph,
builds a bounded payment-path semantic neighborhood, and resolves the merchant's customer-value
callable through Gemini, an OpenAI-compatible endpoint, or human confirmation. It deterministically
evaluates policy evidence, scenario applicability for SG-01 through SG-08, assesses runtime capability,
and executes adversarial managed-runtime failure scenarios. All invariant checks evaluate deterministically
into E0–E4 evidence tiers, and findings are joined to exact checks. Proven failures provide bounded AI
explanation, patch previews with persistent unverified warnings, exact re-verification, and a zero-leak
CI gate (`stateguard verify --ci`).

A canonical demo is provided in `examples/ticketing_merchant`.

## Development

StateGuard currently supports Python 3.11 and uses `uv` for locking and local
development.

```console
uv sync --extra managed-fastapi
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
uv build
```

The CLI exposes stable human-readable and typed JSON control surfaces for analysis,
configuration, semantic resolution, applicability, runtime assessment, verification,
and immutable run history. Project paths may be supplied positionally; the hidden
`--repository` alias remains available for compatibility.

```console
uv run stateguard --version
uv run stateguard config validate /path/to/stateguard.yaml
uv run stateguard analyze /path/to/repo --json
uv run stateguard semantics resolve /path/to/repo
uv run stateguard applicability analyze /path/to/repo
uv run stateguard runtime assess /path/to/repo
uv run stateguard verify /path/to/repo
uv run stateguard runs latest /path/to/repo
```

An existing captured Razorpay Test Mode Payment can optionally strengthen one successfully
verified SG-01 check to `E4 RAZORPAY GROUNDED`. Supply only environment-variable names on the
command line; StateGuard rejects Live/unknown key modes before network access, fetches the Payment
and linked Order without mutating either resource, and persists only sanitized fingerprints:

```console
uv run stateguard verify /path/to/repo \
  --razorpay-test-payment-id-env RAZORPAY_PAYMENT_ID \
  --razorpay-test-key-id-env RAZORPAY_KEY_ID \
  --razorpay-test-key-secret-env RAZORPAY_KEY_SECRET
```

The Payment must already have been completed through Test Mode Checkout and be captured, linked to
a fully paid Order, and currently unrefunded. This is **Test Mode resource-profile grounding**, not
evidence of webhook delivery, signature, retry, duplication, or provider execution. Missing or
unavailable provider evidence leaves the ordinary deterministic E3 run and CI truth unchanged.

For a non-interactive release gate, use `verify --ci`. It creates the same canonical
immutable verification run as ordinary `verify`, then applies a deterministic projection
over its completed checks:

```console
uv run stateguard verify /path/to/repo --ci
uv run stateguard verify /path/to/repo --ci --json
```

CI exit statuses are:

- `0`: applicable required (`CORE`) verification passed;
- `1`: at least one `CORE` or `OPTIONAL` check produced a deterministic `VERIFIED FAIL`;
- `2`: required verification was not proven, including zero applicable core checks;
- `3`: the CI command or StateGuard operation failed before a valid gate result existed.

Unresolved optional assertions do not reduce required coverage, but a deterministically
proven optional failure still blocks release. `NOT APPLICABLE` is never relabeled as PASS.
Completed gate JSON is written to stdout even for exits `1` and `2`; safe parser and
operational error JSON is written to stderr for exit `3`. Plain `verify` intentionally
retains operation-success exit behavior.

## Configuration

Provider credentials are referenced by environment-variable name. Secret values
must never be stored in `stateguard.yaml`.

```yaml
schema_version: 2
project:
  id: sgproj_0123456789abcdef0123456789abcdef
  source_root: .
  framework: fastapi
  app_target: app.main:app
analysis:
  include:
    - "**/*.py"
  exclude:
    - ".venv/**"
    - ".git/**"
    - ".stateguard/**"
ai:
  provider: openai-compatible
  model: example-model
  api_key_env: EXAMPLE_API_KEY
  base_url: https://provider.example/v1
policy:
  fulfilment:
    value: CAPTURE_REQUIRED
    evidence_fingerprint: sha256:<64 lowercase hex characters>
  late_authorisation:
    value: FULFIL_LATER
    evidence_fingerprint: sha256:<64 lowercase hex characters>
runtime:
  mode: managed
  env_from_host:
    STATEGUARD_TEST_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET
    MERCHANT_WEBHOOK_SECRET: SG_TEST_WEBHOOK_SECRET
```

Use `provider: gemini` without `base_url` for Google Gemini. Environment-variable
names follow portable shell identifier syntax and may be lowercase, mixed case, or
uppercase.

For managed SG-01 execution, `STATEGUARD_TEST_WEBHOOK_SECRET` is a reserved child
mapping: its configured host variable supplies the parent request signer. Map the same
host variable to the environment-variable name used by the merchant application, such
as `MERCHANT_WEBHOOK_SECRET` above. Only names are retained in configuration and
authority fingerprints; secret values and signatures are excluded from artifacts and
diagnostics. Missing mappings or empty host values fail closed as `UNVERIFIED`.

When AI mapping is enabled, the bounded candidate/supporting source excerpts are sent
to the configured external provider. StateGuard uses Gemini's one-shot
`generate_content` API and explicitly sends `store: false` for this request. That
request setting is not a broader claim about provider infrastructure or retention
under the provider's terms.

The non-secret semantic audit is written to `.stateguard/semantics.json` with
restrictive permissions. Full merchant source, mapper instructions, raw provider
errors, prompts, and API keys are not persisted there. A human resolution stores only
the exact symbol ID, relevance-scoped semantic fingerprint, and human basis in
`stateguard.yaml`.

Step 4 writes `.stateguard/applicability.json` with restrictive permissions. Policy
suggestions describe observed implementation evidence only: they never edit the
configuration or become merchant intent automatically. Policy confirmation requires
an explicit value. `INDETERMINATE` in this artifact is an internal analyzer state;
it is not an additional verification result and will normally become `UNVERIFIED`
after runtime/result contracts are introduced.

Step 5 writes only historical capability information to `.stateguard/runtime.json`; request
observations remain in a bounded session stream and are discarded by `runtime assess`. FastAPI and
Uvicorn are optional managed-runtime dependencies and are never installed into or reconciled by
mutating a merchant project. BYO targets default to loopback; a non-loopback target requires the
exact `NON_PRODUCTION_TEST_ENVIRONMENT` declaration, redirects are refused, and there is no
production/live-chaos target class. See [the runtime capability contract](docs/RUNTIME_CAPABILITY.md)
for lifecycle fact meanings, tested compatibility, safety boundaries, and configuration modes.

The Failure Lab executes managed mode and generates immutable verification runs (`.stateguard/runs/<run_id>/run.json`)
containing structured allowlisted evidence. Invariant outcomes for SG-01 through SG-08 are evaluated deterministically
into E0–E4 evidence tiers. Proven failures (`VERIFIED FAIL`) provide grounded explanation and unverified patch
previews without modifying merchant code, and support exact-key re-verification.
