"""Literal, byte-exact search over a small explicit set of local text files."""

from __future__ import annotations

import json
import ntpath
import re
import unicodedata
from collections.abc import Sequence
from pathlib import Path
from typing import cast
from uuid import UUID

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization import NormalizationError
from sentinel.readers.local_search_types import (
    LocalFileMatch,
    LocalFilePreview,
    LocalFileSearch,
    LocalFileSearchFile,
    LocalSearchError,
    LocalSearchErrorCode,
)
from sentinel.readers.local_text import read_allowlisted_local_text, verify_local_text_span
from sentinel.readers.local_text_types import LocalTextError, LocalTextRead

MAX_SELECTED_FILES = 8
MAX_SELECTED_BYTES = 8 * 1_048_576
MAX_MATCHES = 32
MAX_QUERY_CHARACTERS = 128
MAX_QUERY_BYTES = 512
MAX_CONTEXT_CHARACTERS = 40
MAX_PREVIEW_BYTES = 256
MAX_RENDERED_OUTPUT_BYTES = 128 * 1024
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BIDI_CONTROLS = frozenset(
    {
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
    }
)
_LINE_BREAKS = frozenset("\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029")


def _fail(code: LocalSearchErrorCode) -> None:
    raise LocalSearchError(code) from None


def _validate_search_arguments(
    file_paths: object,
    query: object,
    show_snippets: object,
) -> tuple[tuple[str | Path, ...], bytes]:
    if type(show_snippets) is not bool:
        _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
    if type(file_paths) not in (tuple, list):
        _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
    selected = tuple(cast(Sequence[str | Path], file_paths))
    if not selected:
        _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
    if len(selected) > MAX_SELECTED_FILES:
        _fail(LocalSearchErrorCode.TOO_MANY_FILES)
    if any(not (type(path) is str or type(path) is type(Path())) for path in selected):
        _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
    if type(query) is not str:
        _fail(LocalSearchErrorCode.INVALID_QUERY)
    query_text = cast(str, query)
    if not 1 <= len(query_text) <= MAX_QUERY_CHARACTERS:
        _fail(LocalSearchErrorCode.INVALID_QUERY)
    try:
        query_bytes = query_text.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail(LocalSearchErrorCode.INVALID_QUERY)
    if (
        not query_bytes
        or len(query_bytes) > MAX_QUERY_BYTES
        or any(unicodedata.category(character) == "Cc" for character in query_text)
        or any(character in _LINE_BREAKS for character in query_text)
        or any(ord(character) in _BIDI_CONTROLS for character in query_text)
    ):
        _fail(LocalSearchErrorCode.INVALID_QUERY)
    if show_snippets and len(query_bytes) > MAX_PREVIEW_BYTES:
        _fail(LocalSearchErrorCode.PREVIEW_UNAVAILABLE)
    return selected, query_bytes


def _validate_source_value(source: LocalTextRead) -> bytes:
    if (
        type(source) is not LocalTextRead
        or source.trust is not TrustLabel.T4_EXTERNAL
        or source.sensitivity is not SensitivityLabel.PRIVATE
        or type(source.source_id) is not UUID
        or type(source.content_sha256) is not str
        or _HEX_SHA256.fullmatch(source.content_sha256) is None
        or type(source.byte_length) is not int
        or type(source._relative_identity) is not str
        or type(source.normalized_source.original_bytes) is not bytes
        or type(source.normalized_source.text) is not str
        or source.byte_length != len(source.normalized_source.original_bytes)
        or source.normalized_source.text.encode("utf-8", errors="strict")
        != source.normalized_source.original_bytes
    ):
        _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
    if not 0 <= source.byte_length <= 1_048_576:
        _fail(LocalSearchErrorCode.TOTAL_TOO_LARGE)
    return source.normalized_source.original_bytes


def _preview_char_range(text: str, start: int, end: int) -> tuple[int, int]:
    """Select same-line context, trimming far context to the fixed byte limit."""
    previous_boundaries = [text.rfind(separator, 0, start) for separator in _LINE_BREAKS]
    line_start = max(previous_boundaries) + 1
    next_boundaries = [
        position
        for position in (text.find(separator, end) for separator in _LINE_BREAKS)
        if position >= 0
    ]
    line_end = min(next_boundaries) if next_boundaries else len(text)

    preview_start = max(line_start, start - MAX_CONTEXT_CHARACTERS)
    preview_end = min(line_end, end + MAX_CONTEXT_CHARACTERS)
    left_context = start - preview_start
    right_context = preview_end - end
    while len(text[preview_start:preview_end].encode("utf-8", errors="strict")) > MAX_PREVIEW_BYTES:
        if left_context > right_context and left_context:
            preview_start += 1
            left_context -= 1
        elif right_context:
            preview_end -= 1
            right_context -= 1
        elif left_context:
            preview_start += 1
            left_context -= 1
        else:
            _fail(LocalSearchErrorCode.PREVIEW_UNAVAILABLE)
    return preview_start, preview_end


def _preview_for_match(
    source: LocalTextRead,
    raw_bytes: bytes,
    match_start_byte: int,
    match_end_byte: int,
) -> LocalFilePreview:
    text = source.normalized_source.text
    try:
        start_character = len(raw_bytes[:match_start_byte].decode("utf-8", errors="strict"))
        end_character = len(raw_bytes[:match_end_byte].decode("utf-8", errors="strict"))
        preview_start_character, preview_end_character = _preview_char_range(
            text, start_character, end_character
        )
        preview_start_byte = len(text[:preview_start_character].encode("utf-8", errors="strict"))
        preview_end_byte = len(text[:preview_end_character].encode("utf-8", errors="strict"))
        verified = verify_local_text_span(
            source,
            start_byte=preview_start_byte,
            end_byte=preview_end_byte,
        )
    except (UnicodeError, LocalTextError, NormalizationError):
        _fail(LocalSearchErrorCode.PREVIEW_UNAVAILABLE)
    return LocalFilePreview(
        start_byte=verified.bound_citation.span.start_byte,
        end_byte=verified.bound_citation.span.end_byte,
        span_id=verified.bound_citation.span.span_id,
        text_sha256=verified.bound_citation.span.text_sha256,
        cited_text=verified.cited_text,
    )


def _same_selected_source(before: LocalTextRead, after: LocalTextRead) -> bool:
    return (
        type(after) is LocalTextRead
        and ntpath.normcase(before._relative_identity) == ntpath.normcase(after._relative_identity)
        and before.source_id == after.source_id
        and before.content_sha256 == after.content_sha256
        and before.byte_length == after.byte_length
    )


def search_selected_local_text_files(
    *,
    allowed_root: str | Path,
    file_paths: Sequence[str | Path],
    query: str,
    show_snippets: bool = False,
) -> LocalFileSearch:
    """Search 1–8 explicitly selected local files for literal UTF-8 bytes.

    Matches may overlap. A final metadata/digest reread rejects detectable
    changes while the complete result is being assembled; this is not an
    atomic snapshot across multiple files.
    """
    selected, query_bytes = _validate_search_arguments(file_paths, query, show_snippets)
    sources: list[LocalTextRead] = []
    identities: set[str] = set()
    selected_bytes = 0
    for file_path in selected:
        source = read_allowlisted_local_text(allowed_root=allowed_root, file_path=file_path)
        raw_bytes = _validate_source_value(source)
        identity = ntpath.normcase(source._relative_identity)
        if identity in identities:
            _fail(LocalSearchErrorCode.DUPLICATE_FILE)
        identities.add(identity)
        selected_bytes += len(raw_bytes)
        if selected_bytes > MAX_SELECTED_BYTES:
            _fail(LocalSearchErrorCode.TOTAL_TOO_LARGE)
        sources.append(source)

    file_results: list[LocalFileSearchFile] = []
    total_matches = 0
    for ordinal, source in enumerate(sources, start=1):
        raw_bytes = source.normalized_source.original_bytes
        matches: list[LocalFileMatch] = []
        search_from = 0
        while True:
            start_byte = raw_bytes.find(query_bytes, search_from)
            if start_byte < 0:
                break
            end_byte = start_byte + len(query_bytes)
            total_matches += 1
            if total_matches > MAX_MATCHES:
                _fail(LocalSearchErrorCode.TOO_MANY_MATCHES)
            try:
                verified = verify_local_text_span(
                    source,
                    start_byte=start_byte,
                    end_byte=end_byte,
                    expected_text=query,
                )
            except (LocalTextError, NormalizationError):
                _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
            citation_span = verified.bound_citation.span
            preview = (
                _preview_for_match(source, raw_bytes, start_byte, end_byte)
                if show_snippets
                else None
            )
            matches.append(
                LocalFileMatch(
                    file_ordinal=ordinal,
                    source_id=source.source_id,
                    content_sha256=source.content_sha256,
                    start_byte=citation_span.start_byte,
                    end_byte=citation_span.end_byte,
                    span_id=citation_span.span_id,
                    text_sha256=citation_span.text_sha256,
                    preview=preview,
                )
            )
            search_from = start_byte + 1
        matches.sort(key=lambda item: (item.start_byte, item.end_byte, str(item.span_id)))
        file_results.append(
            LocalFileSearchFile(
                ordinal=ordinal,
                source_id=source.source_id,
                content_sha256=source.content_sha256,
                byte_length=source.byte_length,
                matches=tuple(matches),
            )
        )

    # Files are read independently by CR1-M. Recheck the bounded identity and
    # digest set before returning, without claiming an atomic multi-file view.
    for file_path, original in zip(selected, sources, strict=True):
        try:
            current = read_allowlisted_local_text(allowed_root=allowed_root, file_path=file_path)
        except (LocalTextError, OSError):
            _fail(LocalSearchErrorCode.SOURCE_CHANGED)
        if not _same_selected_source(original, current):
            _fail(LocalSearchErrorCode.SOURCE_CHANGED)

    return LocalFileSearch(
        schema_version="sentinel.local-file-search.v1",
        search_mode="literal_utf8_exact",
        synthetic_data=False,
        trust=TrustLabel.T4_EXTERNAL,
        sensitivity=SensitivityLabel.PRIVATE,
        selected_file_count=len(file_results),
        total_match_count=total_matches,
        snippets_included=show_snippets,
        files=tuple(file_results),
    )


def _validate_result(search: LocalFileSearch) -> None:
    if (
        type(search) is not LocalFileSearch
        or search.schema_version != "sentinel.local-file-search.v1"
        or search.search_mode != "literal_utf8_exact"
        or search.synthetic_data is not False
        or search.trust is not TrustLabel.T4_EXTERNAL
        or search.sensitivity is not SensitivityLabel.PRIVATE
        or type(search.files) is not tuple
        or not 1 <= len(search.files) <= MAX_SELECTED_FILES
        or search.selected_file_count != len(search.files)
        or type(search.total_match_count) is not int
        or not 0 <= search.total_match_count <= MAX_MATCHES
        or type(search.snippets_included) is not bool
    ):
        _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
    total = 0
    for expected_ordinal, item in enumerate(search.files, start=1):
        if (
            type(item) is not LocalFileSearchFile
            or item.ordinal != expected_ordinal
            or type(item.source_id) is not UUID
            or type(item.content_sha256) is not str
            or _HEX_SHA256.fullmatch(item.content_sha256) is None
            or type(item.byte_length) is not int
            or not 0 <= item.byte_length <= 1_048_576
            or type(item.matches) is not tuple
        ):
            _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
        previous: tuple[int, int, str] | None = None
        for match in item.matches:
            if (
                type(match) is not LocalFileMatch
                or match.file_ordinal != item.ordinal
                or match.source_id != item.source_id
                or match.content_sha256 != item.content_sha256
                or type(match.start_byte) is not int
                or type(match.end_byte) is not int
                or not 0 <= match.start_byte < match.end_byte <= item.byte_length
                or type(match.span_id) is not UUID
                or type(match.text_sha256) is not str
                or _HEX_SHA256.fullmatch(match.text_sha256) is None
            ):
                _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
            order = (match.start_byte, match.end_byte, str(match.span_id))
            if previous is not None and order < previous:
                _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
            previous = order
            if search.snippets_included:
                preview = match.preview
                if (
                    type(preview) is not LocalFilePreview
                    or not 0 <= preview.start_byte <= match.start_byte
                    or not match.end_byte <= preview.end_byte <= item.byte_length
                    or type(preview.span_id) is not UUID
                    or type(preview.text_sha256) is not str
                    or _HEX_SHA256.fullmatch(preview.text_sha256) is None
                    or type(preview.cited_text) is not str
                    or len(preview.cited_text.encode("utf-8", errors="strict")) > MAX_PREVIEW_BYTES
                ):
                    _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
            elif match.preview is not None:
                _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
            total += 1
    if total != search.total_match_count:
        _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)


def _check_output_size(output: str) -> str:
    if len(output.encode("utf-8", errors="strict")) > MAX_RENDERED_OUTPUT_BYTES:
        _fail(LocalSearchErrorCode.OUTPUT_TOO_LARGE)
    return output


def _escape_display_text(value: str) -> str:
    # Delayed import avoids a readers -> briefing -> ingestion -> readers cycle.
    from sentinel.briefing.formatters import escape_display_text

    return escape_display_text(value)


def format_text_local_file_search(search: LocalFileSearch) -> str:
    """Render bounded search metadata; snippets appear only when requested."""
    _validate_result(search)
    lines = [
        "Sentinel - Literal local text-file search",
        "Mode: exact, case-sensitive UTF-8 bytes; overlapping matches included",
        "Source labels: T4 EXTERNAL | PRIVATE",
        f"Files: {search.selected_file_count} | Verified matches: {search.total_match_count}",
        f"Snippets included: {'yes' if search.snippets_included else 'no'}",
    ]
    for item in search.files:
        lines.extend(
            [
                "",
                f"File {item.ordinal}: source {item.source_id}",
                f"  SHA-256: {item.content_sha256}",
                f"  Bytes: {item.byte_length} | Matches: {len(item.matches)}",
            ]
        )
        for match in item.matches:
            lines.append(
                f"  [bytes {match.start_byte}:{match.end_byte}) span {match.span_id} "
                f"sha256 {match.text_sha256}"
            )
            if match.preview is not None:
                preview = match.preview
                safe_text = _escape_display_text(preview.cited_text)
                lines.append(
                    f"    Preview [bytes {preview.start_byte}:{preview.end_byte}) "
                    f'span {preview.span_id} sha256 {preview.text_sha256}: "{safe_text}"'
                )
    return _check_output_size("\n".join(lines))


def format_json_local_file_search(search: LocalFileSearch) -> str:
    """Serialize a deterministic, path-free versioned search result."""
    _validate_result(search)
    files: list[dict[str, object]] = []
    for item in search.files:
        matches: list[dict[str, object]] = []
        for match in item.matches:
            record: dict[str, object] = {
                "file_ordinal": match.file_ordinal,
                "source_id": str(match.source_id),
                "content_sha256": match.content_sha256,
                "start_byte": match.start_byte,
                "end_byte": match.end_byte,
                "span_id": str(match.span_id),
                "text_sha256": match.text_sha256,
            }
            if match.preview is not None:
                preview = match.preview
                record["preview"] = {
                    "start_byte": preview.start_byte,
                    "end_byte": preview.end_byte,
                    "span_id": str(preview.span_id),
                    "text_sha256": preview.text_sha256,
                    "cited_text": _escape_display_text(preview.cited_text),
                }
            matches.append(record)
        files.append(
            {
                "ordinal": item.ordinal,
                "source_id": str(item.source_id),
                "content_sha256": item.content_sha256,
                "byte_length": item.byte_length,
                "match_count": len(item.matches),
                "matches": matches,
            }
        )
    document = {
        "schema_version": search.schema_version,
        "search_mode": search.search_mode,
        "synthetic_data": search.synthetic_data,
        "trust": search.trust.value,
        "sensitivity": search.sensitivity.value,
        "selected_file_count": search.selected_file_count,
        "total_match_count": search.total_match_count,
        "snippets_included": search.snippets_included,
        "files": files,
    }
    try:
        output = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        _fail(LocalSearchErrorCode.INVALID_FILE_SELECTION)
    return _check_output_size(output)


__all__ = [
    "format_json_local_file_search",
    "format_text_local_file_search",
    "search_selected_local_text_files",
]
