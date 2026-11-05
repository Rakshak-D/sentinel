"""Build and verify explicit metadata-only local-notes registries."""

from __future__ import annotations

import hashlib
import json
import ntpath
import re
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn, cast

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization import MAX_PLAIN_TEXT_BYTES
from sentinel.readers.local_text import read_allowlisted_local_text
from sentinel.readers.local_text_types import (
    LocalTextError,
    LocalTextErrorCode,
    LocalTextFormat,
    LocalTextRead,
)
from sentinel.readers.notes_registry_types import (
    LocalNotesEntryStatus,
    LocalNotesRegistry,
    LocalNotesRegistryEntry,
    LocalNotesRegistryError,
    LocalNotesRegistryErrorCode,
    LocalNotesVerification,
    LocalNotesVerificationEntry,
)

LOCAL_NOTES_REGISTRY_SCHEMA_VERSION = "sentinel.local-notes-registry.v1"
LOCAL_NOTES_VERIFICATION_SCHEMA_VERSION = "sentinel.local-notes-verification.v1"
MAX_SELECTED_FILES = 8
MAX_REGISTRY_BYTES = 16 * 1024
MAX_RENDERED_BYTES = 16 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CONIN$",
        "CONOUT$",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
        *(f"COM{digit}" for digit in "¹²³"),
        *(f"LPT{digit}" for digit in "¹²³"),
    }
)


def _fail(code: LocalNotesRegistryErrorCode) -> NoReturn:
    raise LocalNotesRegistryError(code) from None


def _valid_path_value(value: object) -> bool:
    return type(value) is str or type(value) is type(Path())


def _validate_selection(file_paths: object) -> tuple[str | Path, ...]:
    if type(file_paths) not in (tuple, list):
        _fail(LocalNotesRegistryErrorCode.INVALID_SELECTION)
    selected = tuple(cast(Sequence[str | Path], file_paths))
    if not selected:
        _fail(LocalNotesRegistryErrorCode.TOO_MANY_FILES)
    if len(selected) > MAX_SELECTED_FILES:
        _fail(LocalNotesRegistryErrorCode.TOO_MANY_FILES)
    if any(not _valid_path_value(path) for path in selected):
        _fail(LocalNotesRegistryErrorCode.INVALID_SELECTION)
    return selected


def _validate_relative_path(value: object) -> str:
    if type(value) is not str:
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    relative_path = value
    if not relative_path or len(relative_path) > 32760:
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    try:
        relative_path.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    if relative_path.startswith("/") or "\\" in relative_path or ":" in relative_path:
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    components = relative_path.split("/")
    for component in components:
        if (
            not component
            or component in {".", ".."}
            or component.endswith((".", " "))
            or any(ord(character) < 32 or ord(character) == 127 for character in component)
            or any(character in component for character in '<>"|?*')
        ):
            _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
        base = component.split(".", 1)[0].rstrip(" .").upper()
        if base in _WINDOWS_RESERVED_NAMES:
            _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    if Path(components[-1]).suffix.lower() not in {".txt", ".md"}:
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    return relative_path


def _metadata_from_source(source: LocalTextRead) -> LocalNotesRegistryEntry:
    if (
        type(source) is not LocalTextRead
        or type(source.normalized_source.original_bytes) is not bytes
        or type(source.byte_length) is not int
        or type(source.content_sha256) is not str
        or _SHA256.fullmatch(source.content_sha256) is None
        or type(source.source_format) is not LocalTextFormat
        or source.provider_id != "local.file"
        or source.trust is not TrustLabel.T4_EXTERNAL
        or source.sensitivity is not SensitivityLabel.PRIVATE
    ):
        _fail(LocalNotesRegistryErrorCode.FILE_INVALID)
    relative_path = _validate_relative_path(source._relative_identity)
    raw_bytes = source.normalized_source.original_bytes
    if (
        source.byte_length != len(raw_bytes)
        or not 0 <= source.byte_length <= MAX_PLAIN_TEXT_BYTES
        or hashlib.sha256(raw_bytes).hexdigest() != source.content_sha256
        or source.source_format.value != Path(relative_path).suffix.lower()
    ):
        _fail(LocalNotesRegistryErrorCode.FILE_INVALID)
    return LocalNotesRegistryEntry(
        relative_path=relative_path,
        byte_length=source.byte_length,
        content_sha256=source.content_sha256,
    )


def _read_source(*, allowed_root: str | Path, file_path: str | Path) -> LocalTextRead:
    try:
        return read_allowlisted_local_text(allowed_root=allowed_root, file_path=file_path)
    except LocalTextError as error:
        if error.code is LocalTextErrorCode.FILE_CHANGED:
            _fail(LocalNotesRegistryErrorCode.FILE_CHANGED)
        if error.code is LocalTextErrorCode.TOO_LARGE:
            _fail(LocalNotesRegistryErrorCode.TOO_LARGE)
        if error.code is LocalTextErrorCode.FILE_UNAVAILABLE:
            _fail(LocalNotesRegistryErrorCode.FILE_UNAVAILABLE)
        _fail(LocalNotesRegistryErrorCode.FILE_INVALID)
    except Exception:
        _fail(LocalNotesRegistryErrorCode.FILE_INVALID)


def _read_metadata(*, allowed_root: str | Path, file_path: str | Path) -> LocalNotesRegistryEntry:
    source = _read_source(allowed_root=allowed_root, file_path=file_path)
    return _metadata_from_source(source)


def _same_metadata(left: LocalNotesRegistryEntry, right: LocalNotesRegistryEntry) -> bool:
    return (
        left.relative_path == right.relative_path
        and left.byte_length == right.byte_length
        and left.content_sha256 == right.content_sha256
    )


def build_local_notes_registry(
    *,
    allowed_root: str | Path,
    file_paths: Sequence[str | Path],
) -> LocalNotesRegistry:
    """Build metadata for 1–8 explicit files and reject detectable changes."""
    selected = _validate_selection(file_paths)
    initial: list[LocalNotesRegistryEntry] = []
    identities: set[str] = set()
    for path in selected:
        entry = _read_metadata(allowed_root=allowed_root, file_path=path)
        identity_key = ntpath.normcase(entry.relative_path)
        if identity_key in identities:
            _fail(LocalNotesRegistryErrorCode.DUPLICATE_FILE)
        identities.add(identity_key)
        initial.append(entry)

    for path, before in zip(selected, initial, strict=True):
        after = _read_metadata(allowed_root=allowed_root, file_path=path)
        if not _same_metadata(before, after):
            _fail(LocalNotesRegistryErrorCode.FILE_CHANGED)

    registry = LocalNotesRegistry(
        schema_version=LOCAL_NOTES_REGISTRY_SCHEMA_VERSION,
        entries=tuple(initial),
    )
    format_json_local_notes_registry(registry)
    return registry


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _parse_registry(raw_bytes: bytes) -> LocalNotesRegistry:
    if len(raw_bytes) > MAX_REGISTRY_BYTES:
        _fail(LocalNotesRegistryErrorCode.TOO_LARGE)
    try:
        document = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    if (
        type(document) is not dict
        or set(document) != {"schema_version", "entries"}
        or type(document.get("schema_version")) is not str
        or document["schema_version"] != LOCAL_NOTES_REGISTRY_SCHEMA_VERSION
        or type(document.get("entries")) is not list
    ):
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    raw_entries = cast(list[object], document["entries"])
    if not 1 <= len(raw_entries) <= MAX_SELECTED_FILES:
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    entries: list[LocalNotesRegistryEntry] = []
    identities: set[str] = set()
    for raw_entry in raw_entries:
        if type(raw_entry) is not dict or set(raw_entry) != {
            "relative_path",
            "byte_length",
            "content_sha256",
        }:
            _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
        item = cast(dict[str, object], raw_entry)
        relative_path = _validate_relative_path(item["relative_path"])
        byte_length = item["byte_length"]
        digest = item["content_sha256"]
        if (
            type(byte_length) is not int
            or not 0 <= byte_length <= MAX_PLAIN_TEXT_BYTES
            or type(digest) is not str
            or _SHA256.fullmatch(digest) is None
        ):
            _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
        key = ntpath.normcase(relative_path)
        if key in identities:
            _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
        identities.add(key)
        entries.append(
            LocalNotesRegistryEntry(
                relative_path=relative_path,
                byte_length=byte_length,
                content_sha256=digest,
            )
        )
    registry = LocalNotesRegistry(
        schema_version=LOCAL_NOTES_REGISTRY_SCHEMA_VERSION,
        entries=tuple(entries),
    )
    _validate_registry(registry)
    return registry


def _validate_registry(registry: LocalNotesRegistry) -> None:
    if (
        type(registry) is not LocalNotesRegistry
        or registry.schema_version != LOCAL_NOTES_REGISTRY_SCHEMA_VERSION
        or type(registry.entries) is not tuple
        or not 1 <= len(registry.entries) <= MAX_SELECTED_FILES
    ):
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    identities: set[str] = set()
    for entry in registry.entries:
        if type(entry) is not LocalNotesRegistryEntry:
            _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
        relative_path = _validate_relative_path(entry.relative_path)
        if (
            type(entry.byte_length) is not int
            or not 0 <= entry.byte_length <= MAX_PLAIN_TEXT_BYTES
            or type(entry.content_sha256) is not str
            or _SHA256.fullmatch(entry.content_sha256) is None
        ):
            _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
        key = ntpath.normcase(relative_path)
        if key in identities:
            _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
        identities.add(key)


def format_json_local_notes_registry(registry: LocalNotesRegistry) -> str:
    """Serialize a compact, deterministic registry without absolute paths."""
    _validate_registry(registry)
    document = {
        "schema_version": registry.schema_version,
        "entries": [
            {
                "relative_path": entry.relative_path,
                "byte_length": entry.byte_length,
                "content_sha256": entry.content_sha256,
            }
            for entry in registry.entries
        ],
    }
    try:
        output = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    # The CLI appends one LF after the JSON record when writing stdout.
    if len(output.encode("utf-8", errors="strict")) + 1 > MAX_REGISTRY_BYTES:
        _fail(LocalNotesRegistryErrorCode.OUTPUT_TOO_LARGE)
    return output


def _target_for_relative_path(allowed_root: str | Path, relative_path: str) -> Path:
    return Path(allowed_root).joinpath(*relative_path.split("/"))


def _read_registry(
    *, allowed_root: str | Path, registry_path: str | Path
) -> tuple[LocalNotesRegistryEntry, LocalNotesRegistry]:
    try:
        source = _read_source(allowed_root=allowed_root, file_path=registry_path)
    except LocalNotesRegistryError as error:
        if error.code is LocalNotesRegistryErrorCode.FILE_INVALID:
            _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
        raise
    if source.source_format is not LocalTextFormat.TXT:
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    metadata = _metadata_from_source(source)
    if metadata.byte_length > MAX_REGISTRY_BYTES:
        _fail(LocalNotesRegistryErrorCode.TOO_LARGE)
    registry = _parse_registry(source.normalized_source.original_bytes)
    if any(
        ntpath.normcase(entry.relative_path) == ntpath.normcase(metadata.relative_path)
        for entry in registry.entries
    ):
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    return metadata, registry


def verify_local_notes_registry(
    *,
    allowed_root: str | Path,
    registry_path: str | Path,
) -> LocalNotesVerification:
    """Verify every registered note and reject detectable cross-read changes."""
    registry_before, registry = _read_registry(
        allowed_root=allowed_root,
        registry_path=registry_path,
    )
    observed: list[LocalNotesRegistryEntry] = []
    result_entries: list[LocalNotesVerificationEntry] = []
    for ordinal, expected in enumerate(registry.entries, start=1):
        current = _read_metadata(
            allowed_root=allowed_root,
            file_path=_target_for_relative_path(allowed_root, expected.relative_path),
        )
        observed.append(current)
        status = (
            LocalNotesEntryStatus.UNCHANGED
            if _same_metadata(expected, current)
            else LocalNotesEntryStatus.CHANGED
        )
        result_entries.append(LocalNotesVerificationEntry(ordinal=ordinal, status=status))

    registry_after, _ = _read_registry(
        allowed_root=allowed_root,
        registry_path=registry_path,
    )
    if not _same_metadata(registry_before, registry_after):
        _fail(LocalNotesRegistryErrorCode.FILE_CHANGED)
    for expected, before in zip(registry.entries, observed, strict=True):
        after = _read_metadata(
            allowed_root=allowed_root,
            file_path=_target_for_relative_path(allowed_root, expected.relative_path),
        )
        if not _same_metadata(before, after):
            _fail(LocalNotesRegistryErrorCode.FILE_CHANGED)

    unchanged_count = sum(
        entry.status is LocalNotesEntryStatus.UNCHANGED for entry in result_entries
    )
    changed_count = len(result_entries) - unchanged_count
    overall_status = (
        LocalNotesEntryStatus.CHANGED if changed_count else LocalNotesEntryStatus.UNCHANGED
    )
    result = LocalNotesVerification(
        schema_version=LOCAL_NOTES_VERIFICATION_SCHEMA_VERSION,
        registry_schema_version=registry.schema_version,
        entries=tuple(result_entries),
        registered_count=len(result_entries),
        unchanged_count=unchanged_count,
        changed_count=changed_count,
        overall_status=overall_status,
    )
    format_json_local_notes_verification(result)
    return result


def _validate_verification(verification: LocalNotesVerification) -> None:
    if (
        type(verification) is not LocalNotesVerification
        or verification.schema_version != LOCAL_NOTES_VERIFICATION_SCHEMA_VERSION
        or verification.registry_schema_version != LOCAL_NOTES_REGISTRY_SCHEMA_VERSION
        or type(verification.entries) is not tuple
        or not 1 <= len(verification.entries) <= MAX_SELECTED_FILES
        or verification.registered_count != len(verification.entries)
        or verification.trust is not TrustLabel.T4_EXTERNAL
        or verification.sensitivity is not SensitivityLabel.PRIVATE
        or verification.hashes_authenticate_authors is not False
    ):
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    for ordinal, entry in enumerate(verification.entries, start=1):
        if (
            type(entry) is not LocalNotesVerificationEntry
            or entry.ordinal != ordinal
            or type(entry.status) is not LocalNotesEntryStatus
        ):
            _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    unchanged = sum(
        entry.status is LocalNotesEntryStatus.UNCHANGED for entry in verification.entries
    )
    changed = len(verification.entries) - unchanged
    expected_status = LocalNotesEntryStatus.CHANGED if changed else LocalNotesEntryStatus.UNCHANGED
    if (
        verification.unchanged_count != unchanged
        or verification.changed_count != changed
        or verification.overall_status is not expected_status
    ):
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)


def format_text_local_notes_verification(verification: LocalNotesVerification) -> str:
    """Render status only; no registered path, digest, or note text is shown."""
    _validate_verification(verification)
    lines = [
        "Sentinel - Local notes registry verification",
        f"Overall status: {verification.overall_status.value}",
        (
            f"Registered: {verification.registered_count} | "
            f"Unchanged: {verification.unchanged_count} | Changed: {verification.changed_count}"
        ),
        f"Source labels: {verification.trust.name} / {verification.sensitivity.name}",
        "Hashes authenticate file authors: no",
    ]
    lines.extend(f"File {entry.ordinal}: {entry.status.value}" for entry in verification.entries)
    output = "\n".join(lines)
    if len(output.encode("utf-8", errors="strict")) > MAX_RENDERED_BYTES:
        _fail(LocalNotesRegistryErrorCode.OUTPUT_TOO_LARGE)
    return output


def format_json_local_notes_verification(verification: LocalNotesVerification) -> str:
    """Serialize deterministic ordinal/status output without file names."""
    _validate_verification(verification)
    document = {
        "schema_version": verification.schema_version,
        "registry_schema_version": verification.registry_schema_version,
        "registered_count": verification.registered_count,
        "unchanged_count": verification.unchanged_count,
        "changed_count": verification.changed_count,
        "overall_status": verification.overall_status.value,
        "entries": [
            {"ordinal": entry.ordinal, "status": entry.status.value}
            for entry in verification.entries
        ],
        "trust": verification.trust.name,
        "sensitivity": verification.sensitivity.name,
        "hashes_authenticate_authors": verification.hashes_authenticate_authors,
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
        _fail(LocalNotesRegistryErrorCode.INVALID_REGISTRY)
    if len(output.encode("utf-8", errors="strict")) > MAX_RENDERED_BYTES:
        _fail(LocalNotesRegistryErrorCode.OUTPUT_TOO_LARGE)
    return output


__all__ = [
    "LOCAL_NOTES_REGISTRY_SCHEMA_VERSION",
    "LOCAL_NOTES_VERIFICATION_SCHEMA_VERSION",
    "build_local_notes_registry",
    "format_json_local_notes_registry",
    "format_json_local_notes_verification",
    "format_text_local_notes_verification",
    "verify_local_notes_registry",
]
