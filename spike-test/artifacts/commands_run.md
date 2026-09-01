# StateGuard Implementation Command Log

All commands ran from `/Users/drivyaanshyadav/Desktop/Razorpay/spike-test` unless noted. Source-file content was created or changed with `apply_patch`; mechanical fixture copying and symbol renaming used the commands shown below.

## Inspection

```sh
sed -n '1,320p' '/Users/drivyaanshyadav/Downloads/PLAN (2).md'
find . -maxdepth 3 -type f | sort | sed -n '1,260p'
git -C . status --short 2>/dev/null || true
sed -n '321,760p' '/Users/drivyaanshyadav/Downloads/PLAN (2).md'
find . -maxdepth 2 -type d -print | sort
ls -la
```

```sh
python3 - <<'PY'
mods=['fastapi','httpx','pydantic','pytest','google.genai']
for name in mods:
    try:
        mod=__import__(name)
        print(name, getattr(mod,'__version__','installed'))
    except Exception as exc:
        print(name, 'MISSING', type(exc).__name__)
PY
command -v shasum
command -v uv
```

## Directory and Fixture Construction

```sh
mkdir -p state_guard_spike/mappers state_guard_spike/runtime state_guard_spike/evaluation benchmarks/{ecommerce,saas,course,ticketing,workspace,licensing}/{family_source/app,variants/fixture_01/app,variants/fixture_02/app,variants/fixture_03/app} evaluation_only tests/calibration_fixtures/{document_export,device_enrollment} artifacts
mkdir -p tests/calibration_fixtures/document_export/app tests/calibration_fixtures/device_enrollment/app
```

```sh
for family in ecommerce saas course ticketing workspace licensing; do for fixture in fixture_01 fixture_02 fixture_03; do cp benchmarks/$family/family_source/app/*.py benchmarks/$family/variants/$fixture/app/; done; done
```

```sh
perl -pi -e 's/update_customer_profile/persist_customer_profile/g; s/update_learner_profile/persist_learner_profile/g; s/snapshot_plan_catalog/persist_plan_catalog/g; s/attach_cohort_row/persist_cohort_row/g' benchmarks/*/family_source/app/*.py benchmarks/*/variants/*/app/*.py
```

## Hash Computation

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib, json
root=Path('.')
def tree_hash(p):
 d={x.relative_to(p).as_posix():hashlib.sha256(x.read_bytes()).hexdigest() for x in sorted(p.rglob('*.py'))}
 return hashlib.sha256(json.dumps(d,sort_keys=True,separators=(',',':')).encode()).hexdigest()
for fam in ['ecommerce','saas','course','ticketing','workspace','licensing']:
 print(fam, 'family', tree_hash(root/'benchmarks'/fam/'family_source'))
 for fixture in ['fixture_01','fixture_02','fixture_03']:
  print(fam, fixture, tree_hash(root/'benchmarks'/fam/'variants'/fixture))
for f in ['evaluation_only/role_ground_truth.json','evaluation_only/mutation_ground_truth.json']:
 print(f, hashlib.sha256(Path(f).read_bytes()).hexdigest())
PY
```

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib,json
for p in sorted(Path('tests/calibration_fixtures').iterdir()):
 d={x.relative_to(p).as_posix():hashlib.sha256(x.read_bytes()).hexdigest() for x in sorted(p.rglob('*.py'))}
 print(p.name,hashlib.sha256(json.dumps(d,sort_keys=True,separators=(',',':')).encode()).hexdigest())
for f in ['state_guard_spike/mappers/prompt.py','state_guard_spike/schemas.py','state_guard_spike/mappers/baseline.py']:
 print(f,hashlib.sha256(Path(f).read_bytes()).hexdigest())
PY
```

After the approved mechanical distractor renames, fixture hashes were recomputed with:

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib,json
root=Path('.')
def tree_hash(p):
 d={x.relative_to(p).as_posix():hashlib.sha256(x.read_bytes()).hexdigest() for x in sorted(p.rglob('*.py'))}
 return hashlib.sha256(json.dumps(d,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
for fam in ['ecommerce','saas','course','ticketing','workspace','licensing']:
 print(fam, tree_hash(root/'benchmarks'/fam/'family_source'),*[tree_hash(root/'benchmarks'/fam/'variants'/f) for f in ['fixture_01','fixture_02','fixture_03']])
for f in ['state_guard_spike/mappers/baseline.py','state_guard_spike/mappers/prompt.py','state_guard_spike/schemas.py']:
 print(f,hashlib.sha256(Path(f).read_bytes()).hexdigest())
PY
```

The contract seal was calculated twice as the contract was finalized, using the exact command:

```sh
python3 - <<'PY'
import hashlib,json
from pathlib import Path
v=json.loads(Path('experiment_contract.json').read_text())
print(hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest())
PY
```

## Dependency Lock and Installation

```sh
uv lock
```

Failed because the sandbox could not write the default uv cache.

```sh
UV_CACHE_DIR=/tmp/state_guard_uv_cache uv lock
```

Failed because sandbox DNS could not reach PyPI.

```sh
UV_CACHE_DIR=/tmp/state_guard_uv_cache uv lock
```

Re-run with approved network access; succeeded and created `uv.lock`.

```sh
UV_CACHE_DIR=/tmp/state_guard_uv_cache uv sync --all-groups
```

First sandboxed run created `.venv` but failed to download packages because DNS was blocked.

```sh
UV_CACHE_DIR=/tmp/state_guard_uv_cache uv sync --all-groups
```

Re-run with approved network access; installed the locked dependencies.

## Offline Validation and Tests

```sh
UV_CACHE_DIR=/tmp/state_guard_uv_cache uv run python -m compileall -q state_guard_spike benchmarks tests
UV_CACHE_DIR=/tmp/state_guard_uv_cache uv run python -m state_guard_spike.cli validate-contract
```

```sh
UV_CACHE_DIR=/tmp/state_guard_uv_cache uv run pytest -q
```

The first pytest invocation failed during collection because the project root was not on pytest's import path. `pythonpath = ["."]` was added to `pyproject.toml`; the repeated command passed 30 tests.

```sh
UV_CACHE_DIR=/tmp/state_guard_uv_cache uv run python -m state_guard_spike.cli pre-evaluation-audit
```

Generated `artifacts/pre_evaluation_compliance.md` and `artifacts/structural_validation.json`; 16 compliance checks passed.

```sh
UV_CACHE_DIR=/tmp/state_guard_uv_cache uv run python - <<'PY'
from google.genai import types
import inspect
print('HttpRetryOptions', inspect.signature(types.HttpRetryOptions))
print('HttpOptions', inspect.signature(types.HttpOptions))
print('GenerateContentConfig fields', sorted(types.GenerateContentConfig.model_fields))
PY
```

This was local API-shape inspection only. No client was constructed and no model request was made.

Final read-only verification repeated:

```sh
UV_CACHE_DIR=/tmp/state_guard_uv_cache uv run pytest -q
UV_CACHE_DIR=/tmp/state_guard_uv_cache uv run python -m state_guard_spike.cli validate-contract
test ! -e artifacts/evaluation_approval.json
test ! -e artifacts/evaluation
```

Artifact and stop-boundary inspection used:

```sh
sed -n '1,260p' artifacts/pre_evaluation_compliance.md
sed -n '1,320p' artifacts/structural_validation.json
find . -maxdepth 3 -type f -not -path './.venv/*' -not -path './spike/*' | sort
test ! -e artifacts/evaluation_approval.json
test ! -e artifacts/evaluation
rg -n "GEMINI_API_KEY|genai\.Client|models\.generate_content" artifacts benchmarks evaluation_only tests state_guard_spike -g '!state_guard_spike/mappers/gemini.py' || true
```

The final created-file and truth-boundary inspection used:

```sh
find benchmarks evaluation_only state_guard_spike tests artifacts -type f -not -path '*/__pycache__/*' | sort
find . -maxdepth 1 -type f | sort
test ! -e artifacts/evaluation_approval.json
test ! -e artifacts/evaluation
rg -n "models\.generate_content\(|genai\.Client\(" state_guard_spike | sed -n '1,80p'
rg -n "evaluation_only|role_ground_truth|mutation_ground_truth|_business_value_present" state_guard_spike/mappers state_guard_spike/source_index.py || true
```

The final baseline-resolution inspection used:

```sh
UV_CACHE_DIR=/tmp/state_guard_uv_cache uv run python - <<'PY'
from pathlib import Path
from state_guard_spike.source_index import build_source_bundle
from state_guard_spike.mappers.baseline import map_roles
from state_guard_spike.runtime.traces import resolve_mapping
for family in ('ecommerce','saas','course','ticketing','workspace','licensing'):
    bundle=build_source_bundle(family,Path('benchmarks')/family/'family_source')
    mapping=map_roles(bundle)
    resolution=resolve_mapping(mapping,bundle,'contract')
    print(family,resolution.resolution.value,resolution.valid_symbols)
PY
```

## Explicitly Not Run

```text
python -m state_guard_spike.cli evaluate
```

No Gemini request, approval-file creation, or frozen evaluation command was performed.
