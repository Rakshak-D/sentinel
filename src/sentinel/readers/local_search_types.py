"""Immutable results and bounded errors for selected local-file search."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal
from uuid import UUID

from sentinel.contracts.labels import SensitivityLabel, TrustLabel


class LocalSearchErrorCode(StrEnum):
    INVALID_QUERY = "invalid_query"
    INVALID_FILE_SELECTION = "invalid_file_selection"
    TOO_MANY_FILES = "too_many_files"
    DUPLICATE_FILE = "duplicate_file"
    TOTAL_TOO_LARGE = "total_too_large"
    TOO_MANY_MATCHES = "too_many_matches"
    PREVIEW_UNAVAILABLE = "preview_unavailable"
    SOURCE_CHANGED = "source_changed"
    OUTPUT_TOO_LARGE = "output_too_large"


_ERROR_MESSAGES = {
    LocalSearchErrorCode.INVALID_QUERY: "The literal query is invalid or exceeds its limit.",
    LocalSearchErrorCode.INVALID_FILE_SELECTION: "The selected files or search result are invalid.",
    LocalSearchErrorCode.TOO_MANY_FILES: "Select between one and eight files.",
    LocalSearchErrorCode.DUPLICATE_FILE: "The same file was selected more than once.",
    LocalSearchErrorCode.TOTAL_TOO_LARGE: "Selected source bytes exceed the 8 MiB limit.",
    LocalSearchErrorCode.TOO_MANY_MATCHES: "More than 32 matches were found; narrow the query.",
    LocalSearchErrorCode.PREVIEW_UNAVAILABLE: "The requested query cannot fit a verified preview.",
    LocalSearchErrorCode.SOURCE_CHANGED: "A selected file changed during search verification.",
    LocalSearchErrorCode.OUTPUT_TOO_LARGE: "The formatted search result exceeds its output limit.",
}


class LocalSearchError(RuntimeError):
    def __init__(self, code: LocalSearchErrorCode) -> None:
        if type(code) is not LocalSearchErrorCode:
            raise TypeError("local search error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class LocalFilePreview:
    start_byte: int
    end_byte: int
    span_id: UUID
    text_sha256: str
    cited_text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class LocalFileMatch:
    file_ordinal: int
    source_id: UUID
    content_sha256: str
    start_byte: int
    end_byte: int
    span_id: UUID
    text_sha256: str
    preview: LocalFilePreview | None = None


@dataclass(frozen=True, slots=True)
class LocalFileSearchFile:
    ordinal: int
    source_id: UUID
    content_sha256: str
    byte_length: int
    matches: tuple[LocalFileMatch, ...]


@dataclass(frozen=True, slots=True)
class LocalFileSearch:
    schema_version: Literal["sentinel.local-file-search.v1"]
    search_mode: Literal["literal_utf8_exact"]
    synthetic_data: Literal[False]
    trust: TrustLabel
    sensitivity: SensitivityLabel
    selected_file_count: int
    total_match_count: int
    snippets_included: bool
    files: tuple[LocalFileSearchFile, ...]


__all__ = [
    "LocalFileMatch",
    "LocalFilePreview",
    "LocalFileSearch",
    "LocalFileSearchFile",
    "LocalSearchError",
    "LocalSearchErrorCode",
]
