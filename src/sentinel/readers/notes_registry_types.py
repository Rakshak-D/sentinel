"""Immutable records and bounded errors for local notes registries."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from sentinel.contracts.labels import SensitivityLabel, TrustLabel


class LocalNotesRegistryErrorCode(StrEnum):
    INVALID_SELECTION = "invalid_selection"
    TOO_MANY_FILES = "too_many_files"
    DUPLICATE_FILE = "duplicate_file"
    INVALID_REGISTRY = "invalid_registry"
    FILE_UNAVAILABLE = "file_unavailable"
    FILE_INVALID = "file_invalid"
    FILE_CHANGED = "file_changed"
    TOO_LARGE = "too_large"
    OUTPUT_TOO_LARGE = "output_too_large"


_ERROR_MESSAGES = {
    LocalNotesRegistryErrorCode.INVALID_SELECTION: "An explicit valid notes selection is required.",
    LocalNotesRegistryErrorCode.TOO_MANY_FILES: "Select between one and eight notes.",
    LocalNotesRegistryErrorCode.DUPLICATE_FILE: (
        "The selected notes contain a duplicate file identity."
    ),
    LocalNotesRegistryErrorCode.INVALID_REGISTRY: "The selected registry is invalid.",
    LocalNotesRegistryErrorCode.FILE_UNAVAILABLE: "A selected or registered note is unavailable.",
    LocalNotesRegistryErrorCode.FILE_INVALID: (
        "A selected note is not allowed or could not be verified."
    ),
    LocalNotesRegistryErrorCode.FILE_CHANGED: "A selected file changed during verification.",
    LocalNotesRegistryErrorCode.TOO_LARGE: "A selected file exceeds its permitted size.",
    LocalNotesRegistryErrorCode.OUTPUT_TOO_LARGE: "The registry output exceeds its permitted size.",
}


class LocalNotesRegistryError(RuntimeError):
    """A fixed-category error that never includes file paths or note text."""

    def __init__(self, code: LocalNotesRegistryErrorCode) -> None:
        if type(code) is not LocalNotesRegistryErrorCode:
            raise TypeError("notes registry error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class LocalNotesRegistryEntry:
    relative_path: str = field(repr=False)
    byte_length: int
    content_sha256: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class LocalNotesRegistry:
    schema_version: str
    entries: tuple[LocalNotesRegistryEntry, ...]


class LocalNotesEntryStatus(StrEnum):
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"


@dataclass(frozen=True, slots=True)
class LocalNotesVerificationEntry:
    ordinal: int
    status: LocalNotesEntryStatus


@dataclass(frozen=True, slots=True)
class LocalNotesVerification:
    schema_version: str
    registry_schema_version: str
    entries: tuple[LocalNotesVerificationEntry, ...]
    registered_count: int
    unchanged_count: int
    changed_count: int
    overall_status: LocalNotesEntryStatus
    trust: TrustLabel = TrustLabel.T4_EXTERNAL
    sensitivity: SensitivityLabel = SensitivityLabel.PRIVATE
    hashes_authenticate_authors: bool = False
