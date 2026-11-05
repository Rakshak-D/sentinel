from __future__ import annotations

import json

import pytest

from sentinel.readers.notes_registry import (
    LOCAL_NOTES_REGISTRY_SCHEMA_VERSION,
    format_json_local_notes_registry,
    verify_local_notes_registry,
)
from sentinel.readers.notes_registry_types import (
    LocalNotesRegistry,
    LocalNotesRegistryEntry,
    LocalNotesRegistryError,
    LocalNotesRegistryErrorCode,
)


def _write_manifest(path, entry):
    path.write_text(
        json.dumps({"schema_version": LOCAL_NOTES_REGISTRY_SCHEMA_VERSION, "entries": [entry]}),
        encoding="utf-8",
    )


def test_unknown_version_keys_bad_types_and_duplicate_json_keys_rejected(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    registry = root / "registry.txt"
    invalid_documents = [
        '{"schema_version":"v0","entries":[]}',
        '{"schema_version":"sentinel.local-notes-registry.v1","entries":[],"other":1}',
        '{"schema_version":"sentinel.local-notes-registry.v1","entries":[{"relative_path":"note.txt","byte_length":true,"content_sha256":"'
        + "0" * 64
        + '"}]}',
        '{"schema_version":"sentinel.local-notes-registry.v1","schema_version":"sentinel.local-notes-registry.v1","entries":[]}',
    ]
    for document in invalid_documents:
        registry.write_text(document, encoding="utf-8")
        with pytest.raises(LocalNotesRegistryError) as error:
            verify_local_notes_registry(allowed_root=root, registry_path=registry)
        assert error.value.code is LocalNotesRegistryErrorCode.INVALID_REGISTRY


def test_oversized_registry_and_invalid_extension_are_rejected(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    registry = root / "registry.txt"
    registry.write_bytes(b" " * (16 * 1024 + 1))
    with pytest.raises(LocalNotesRegistryError) as large:
        verify_local_notes_registry(allowed_root=root, registry_path=registry)
    assert large.value.code is LocalNotesRegistryErrorCode.TOO_LARGE

    markdown_registry = root / "registry.md"
    markdown_registry.write_text("{}", encoding="utf-8")
    with pytest.raises(LocalNotesRegistryError):
        verify_local_notes_registry(allowed_root=root, registry_path=markdown_registry)


def test_build_output_limit_accounts_for_the_cli_final_newline() -> None:
    entries = tuple(
        LocalNotesRegistryEntry(
            relative_path=(
                "/".join([f"segment-{index:03d}" * 16 for index in range(13)])
                + f"/note-{ordinal}.txt"
            ),
            byte_length=0,
            content_sha256="0" * 64,
        )
        for ordinal in range(8)
    )
    registry = LocalNotesRegistry(
        schema_version=LOCAL_NOTES_REGISTRY_SCHEMA_VERSION,
        entries=entries,
    )
    with pytest.raises(LocalNotesRegistryError) as error:
        format_json_local_notes_registry(registry)
    assert error.value.code is LocalNotesRegistryErrorCode.OUTPUT_TOO_LARGE
