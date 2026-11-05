from __future__ import annotations

import hashlib
import json

import pytest

from sentinel.readers.notes_registry import (
    LOCAL_NOTES_REGISTRY_SCHEMA_VERSION,
    build_local_notes_registry,
    format_json_local_notes_registry,
    format_json_local_notes_verification,
    verify_local_notes_registry,
)
from sentinel.readers.notes_registry_types import (
    LocalNotesEntryStatus,
    LocalNotesRegistryError,
    LocalNotesRegistryErrorCode,
)


def _build(root, *paths):
    return build_local_notes_registry(allowed_root=root, file_paths=paths)


def test_build_is_ordered_deterministic_and_contains_metadata_only(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    first = root / "one.txt"
    second = root / "two.md"
    first.write_bytes(b"first body canary")
    second.write_bytes("二番目 🧭\r\n".encode())

    registry = _build(root, first, second)
    output = format_json_local_notes_registry(registry)
    document = json.loads(output)

    assert registry.schema_version == LOCAL_NOTES_REGISTRY_SCHEMA_VERSION
    assert [entry.relative_path for entry in registry.entries] == ["one.txt", "two.md"]
    assert [entry.byte_length for entry in registry.entries] == [17, len("二番目 🧭\r\n".encode())]
    assert document["entries"][0]["content_sha256"] == hashlib.sha256(
        b"first body canary"
    ).hexdigest()
    assert "first body canary" not in output
    assert str(root) not in output
    assert "first body canary" not in repr(registry)
    assert str(first) not in repr(registry)
    assert format_json_local_notes_registry(_build(root, first, second)) == output


def test_registry_verifies_across_calls_and_detects_same_length_edit(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    first = root / "one.txt"
    second = root / "two.txt"
    first.write_bytes(b"same-size A")
    second.write_bytes("emoji 🧭\r\n".encode())
    registry_path = root / "baseline.txt"
    registry_path.write_bytes(
        (format_json_local_notes_registry(_build(root, first, second)) + "\n").encode()
    )

    unchanged = verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    assert unchanged.overall_status is LocalNotesEntryStatus.UNCHANGED
    assert [entry.status for entry in unchanged.entries] == [
        LocalNotesEntryStatus.UNCHANGED,
        LocalNotesEntryStatus.UNCHANGED,
    ]

    first.write_bytes(b"same-size B")
    changed = verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    assert changed.overall_status is LocalNotesEntryStatus.CHANGED
    assert changed.unchanged_count == 1
    assert changed.changed_count == 1
    output = format_json_local_notes_verification(changed)
    assert '"status":"CHANGED"' in output
    assert "same-size B" not in output
    assert str(root) not in output


@pytest.mark.parametrize(
    "contents",
    [
        b'{"schema_version":"sentinel.local-notes-registry.v1","schema_version":"x","entries":[]}',
        b'{"schema_version":"sentinel.local-notes-registry.v1","entries":[],"unexpected":true}',
        (
            b'{"schema_version":"sentinel.local-notes-registry.v1","entries":'
            b'[{"relative_path":"../outside.txt","byte_length":1,"content_sha256":"'
            + b"0" * 64
            + b'"}]}'
        ),
        (
            b'{"schema_version":"sentinel.local-notes-registry.v1","entries":'
            b'[{"relative_path":"C:\\\\outside.txt","byte_length":1,"content_sha256":"'
            + b"0" * 64
            + b'"}]}'
        ),
    ],
)
def test_malformed_or_unsafe_registry_fails_before_output(tmp_path, contents) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    registry_path = root / "baseline.txt"
    registry_path.write_bytes(contents)

    with pytest.raises(LocalNotesRegistryError) as error:
        verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    assert error.value.code is LocalNotesRegistryErrorCode.INVALID_REGISTRY


def test_case_alias_selection_and_ninth_selection_are_rejected(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    note = root / "note.txt"
    note.write_bytes(b"note")

    with pytest.raises(LocalNotesRegistryError) as duplicate:
        _build(root, note, type(note)(str(note).upper()))
    assert duplicate.value.code is LocalNotesRegistryErrorCode.DUPLICATE_FILE
    with pytest.raises(LocalNotesRegistryError) as too_many:
        _build(root, *(root / f"{index}.txt" for index in range(9)))
    assert too_many.value.code is LocalNotesRegistryErrorCode.TOO_MANY_FILES


def test_empty_selection_unsupported_format_and_missing_file_fail_closed(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    with pytest.raises(LocalNotesRegistryError) as empty:
        _build(root)
    assert empty.value.code is LocalNotesRegistryErrorCode.TOO_MANY_FILES

    unsupported = root / "note.csv"
    unsupported.write_bytes(b"body")
    with pytest.raises(LocalNotesRegistryError) as format_error:
        _build(root, unsupported)
    assert format_error.value.code is LocalNotesRegistryErrorCode.FILE_INVALID

    missing = root / "missing.txt"
    with pytest.raises(LocalNotesRegistryError) as unavailable:
        _build(root, missing)
    assert unavailable.value.code is LocalNotesRegistryErrorCode.FILE_UNAVAILABLE


def test_eight_notes_keep_argument_order_and_zero_matches_are_still_registered(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    paths = []
    for index in range(8):
        path = root / f"note-{index}.txt"
        path.write_text("same content" if index % 2 else "", encoding="utf-8")
        paths.append(path)

    registry = _build(root, *reversed(paths))

    assert [entry.relative_path for entry in registry.entries] == [
        path.name for path in reversed(paths)
    ]
    assert len(registry.entries) == 8


def test_verification_hides_relative_paths_and_note_content(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    note = root / "private-title-canary.txt"
    note.write_text("private body canary", encoding="utf-8")
    registry_path = root / "baseline.txt"
    registry_path.write_text(format_json_local_notes_registry(_build(root, note)), encoding="utf-8")

    verification = verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    output = format_json_local_notes_verification(verification)

    assert "private-title-canary.txt" not in output
    assert "private body canary" not in output
    assert str(root) not in output
    assert '"trust":"T4_EXTERNAL"' in output
    assert '"sensitivity":"PRIVATE"' in output
    assert '"hashes_authenticate_authors":false' in output


def test_registry_does_not_reference_itself(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    registry_path = root / "baseline.txt"
    entry = {"relative_path": "baseline.txt", "byte_length": 1, "content_sha256": "0" * 64}
    registry_path.write_text(
        json.dumps({"schema_version": LOCAL_NOTES_REGISTRY_SCHEMA_VERSION, "entries": [entry]}),
        encoding="utf-8",
    )
    with pytest.raises(LocalNotesRegistryError) as error:
        verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    assert error.value.code is LocalNotesRegistryErrorCode.INVALID_REGISTRY
