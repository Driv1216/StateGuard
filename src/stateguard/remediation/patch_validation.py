"""Minimal allowlisted region replacement and deterministic patch rendering."""

from __future__ import annotations

import ast
import difflib
import io
import tokenize
from collections import defaultdict
from pathlib import Path

from stateguard.contracts.identity import sha256_digest
from stateguard.discovery.contracts import SourceIndexArtifact
from stateguard.model_providers.bounds import DEFAULT_STRUCTURED_GENERATION_BOUNDS

from .contracts import (
    EditableRegion,
    EditableRegionKind,
    PatchPreview,
    ProposalVerificationState,
    RawStructuredEdit,
    StructuredEditPreview,
)

_BOUNDS = DEFAULT_STRUCTURED_GENERATION_BOUNDS
_FORBIDDEN_PARTS = frozenset(
    {
        ".stateguard",
        ".env",
        ".git",
        "stateguard.yaml",
        "stateguard.yml",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "poetry.lock",
    }
)


class UnsafePatchError(ValueError):
    """A proposed edit could not be proven safe within Step 10's edit shapes."""


def _contains_literal_secret(source: str, start_line: int, end_line: int) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return True
    sensitive = ("secret", "password", "api_key", "apikey", "access_token")
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        if not (start_line <= node.lineno <= end_line):
            continue
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not isinstance(value, ast.Constant) or not isinstance(value.value, (str, bytes)):
            continue
        names = tuple(ast.unparse(target).casefold() for target in targets)
        if any(fragment in name for name in names for fragment in sensitive):
            return True
    return False


def _read_python(repository_root: Path, relative_path: str) -> tuple[Path, bytes, str, str]:
    if not relative_path.endswith(".py") or any(
        part.casefold() in _FORBIDDEN_PARTS for part in Path(relative_path).parts
    ):
        raise UnsafePatchError("editable target is not an allowlisted Python source file")
    root = repository_root.resolve(strict=True)
    candidate = root / relative_path
    if any(part.is_symlink() for part in (candidate, *candidate.parents) if part != root.parent):
        raise UnsafePatchError("editable target contains a symlink component")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        raw = resolved.read_bytes()
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        text = raw.decode(encoding)
    except (OSError, UnicodeError, SyntaxError, ValueError) as exc:
        raise UnsafePatchError("editable target is unavailable or has invalid encoding") from exc
    return resolved, raw, text, encoding


def build_symbol_regions(
    repository_root: Path,
    source_index: SourceIndexArtifact,
    symbol_ids: set[str],
) -> tuple[EditableRegion, ...]:
    """Create only full-symbol regions from exact current indexed Python facts."""

    indexed_files = {item.file_id: item for item in source_index.indexed_files}
    regions: list[EditableRegion] = []
    consumed = 0
    for symbol in sorted(
        (item for item in source_index.symbols if item.symbol_id in symbol_ids),
        key=lambda item: item.symbol_id,
    ):
        file_record = indexed_files.get(symbol.source_file_id)
        if file_record is None:
            raise UnsafePatchError("symbol source file is not indexed")
        _, raw, text, _ = _read_python(repository_root, file_record.path)
        if sha256_digest(raw) != file_record.content_fingerprint:
            raise UnsafePatchError("indexed source changed before region construction")
        lines = text.splitlines(keepends=True)
        start_line = symbol.source_location.line_start
        end_line = symbol.source_location.line_end
        if start_line < 1 or end_line < start_line or end_line > len(lines):
            raise UnsafePatchError("indexed symbol region is unavailable")
        start = sum(len(line) for line in lines[: start_line - 1])
        end = sum(len(line) for line in lines[:end_line])
        content = text[start:end]
        if _contains_literal_secret(text, start_line, end_line):
            raise UnsafePatchError("editable source may contain a literal secret")
        consumed += len(content.encode("utf-8"))
        if consumed > _BOUNDS.max_excerpt_material_bytes:
            raise UnsafePatchError("editable source exceeds structured-generation bounds")
        regions.append(
            EditableRegion(
                region_reference=f"region-{len(regions) + 1}",
                kind=EditableRegionKind.FULL_SYMBOL,
                path=file_record.path,
                start_offset=start,
                end_offset=end,
                file_fingerprint=file_record.content_fingerprint,
                region_fingerprint=sha256_digest(content),
                content=content,
            )
        )
        if len(regions) == _BOUNDS.max_structured_items:
            break
    return tuple(regions)


def validate_and_render_patch(
    repository_root: Path,
    regions: tuple[EditableRegion, ...],
    edits: tuple[RawStructuredEdit, ...],
) -> PatchPreview:
    """Re-read current files, replace exact regions in memory, validate, and diff."""

    by_reference = {item.region_reference: item for item in regions}
    if len(by_reference) != len(regions) or not edits:
        raise UnsafePatchError("patch requires unique known editable regions")
    if len(edits) > _BOUNDS.max_structured_items:
        raise UnsafePatchError("patch contains too many edits")
    selected: list[tuple[EditableRegion, RawStructuredEdit]] = []
    for edit in edits:
        region = by_reference.get(edit.region_reference)
        if region is None:
            raise UnsafePatchError("model referenced an unknown editable region")
        selected.append((region, edit))

    by_path: dict[str, list[tuple[EditableRegion, RawStructuredEdit]]] = defaultdict(list)
    for item in selected:
        by_path[item[0].path].append(item)
    diffs: list[str] = []
    previews: list[StructuredEditPreview] = []
    total_source_bytes = 0
    for path in sorted(by_path):
        _, raw, original, encoding = _read_python(repository_root, path)
        file_fingerprint = sha256_digest(raw)
        file_edits = sorted(by_path[path], key=lambda item: item[0].start_offset)
        prior_end = -1
        for region, edit in file_edits:
            if file_fingerprint != region.file_fingerprint:
                raise UnsafePatchError("editable file changed during provider request")
            if region.start_offset < prior_end:
                raise UnsafePatchError("editable regions overlap")
            if sha256_digest(original[region.start_offset : region.end_offset]) != (
                region.region_fingerprint
            ):
                raise UnsafePatchError("editable region changed during provider request")
            try:
                edit.replacement_content.encode(encoding)
            except UnicodeError as exc:
                raise UnsafePatchError("replacement cannot preserve source encoding") from exc
            prior_end = region.end_offset
        candidate = original
        for region, edit in reversed(file_edits):
            candidate = (
                candidate[: region.start_offset]
                + edit.replacement_content
                + candidate[region.end_offset :]
            )
            previews.append(
                StructuredEditPreview(
                    region_reference=region.region_reference,
                    path=region.path,
                    kind=region.kind,
                    original_region_fingerprint=region.region_fingerprint,
                    replacement_fingerprint=sha256_digest(edit.replacement_content),
                )
            )
        total_source_bytes += len(candidate.encode("utf-8"))
        if total_source_bytes > _BOUNDS.max_excerpt_material_bytes:
            raise UnsafePatchError("candidate source exceeds structured-generation bounds")
        try:
            ast.parse(candidate, filename=path, feature_version=(3, 11))
        except SyntaxError as exc:
            raise UnsafePatchError("candidate is not valid Python 3.11 syntax") from exc
        rendered = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                candidate.splitlines(keepends=True),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                lineterm="\n",
            )
        )
        if rendered:
            diffs.append(rendered)
    diff = "".join(diffs)
    if not diff:
        raise UnsafePatchError("proposal does not change current source")
    if len(diff.encode("utf-8")) > _BOUNDS.max_excerpt_material_bytes:
        raise UnsafePatchError("rendered diff exceeds structured-generation bounds")
    return PatchPreview(
        verification_state=ProposalVerificationState.AI_GENERATED_NOT_VERIFIED,
        diff=diff,
        edits=tuple(sorted(previews, key=lambda item: (item.path, item.region_reference))),
    )
