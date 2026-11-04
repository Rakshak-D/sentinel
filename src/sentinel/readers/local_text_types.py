"""Typed result and bounded error types for the local text reader."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization.types import NormalizedPlainTextSource, SourceBoundCitation


class LocalTextFormat(StrEnum):
    TXT = ".txt"
    MARKDOWN = ".md"


class LocalTextErrorCode(StrEnum):
    INVALID_PATH = "invalid_path"
    PATH_NOT_ALLOWED = "path_not_allowed"
    FILE_UNAVAILABLE = "file_unavailable"
    UNSUPPORTED_FILESYSTEM = "unsupported_filesystem"
    UNSUPPORTED_FORMAT = "unsupported_format"
    NOT_REGULAR_FILE = "not_regular_file"
    TOO_LARGE = "too_large"
    INVALID_UTF8 = "invalid_utf8"
    FILE_CHANGED = "file_changed"
    INVALID_SOURCE = "invalid_source"
    INVALID_CITATION = "invalid_citation"


_ERROR_MESSAGES = {
    LocalTextErrorCode.INVALID_PATH: "An explicit absolute local path is required.",
    LocalTextErrorCode.PATH_NOT_ALLOWED: "The selected file is not allowed beneath this root.",
    LocalTextErrorCode.FILE_UNAVAILABLE: "The selected local file is unavailable.",
    LocalTextErrorCode.UNSUPPORTED_FILESYSTEM: (
        "Only supported local Windows filesystems are allowed."
    ),
    LocalTextErrorCode.UNSUPPORTED_FORMAT: (
        "Only .txt and .md UTF-8 plain text files are supported."
    ),
    LocalTextErrorCode.NOT_REGULAR_FILE: "The selected path must be a regular file.",
    LocalTextErrorCode.TOO_LARGE: "The selected file exceeds the 1 MiB source limit.",
    LocalTextErrorCode.INVALID_UTF8: "The selected file is not valid UTF-8 text.",
    LocalTextErrorCode.FILE_CHANGED: "The selected file changed while it was being read.",
    LocalTextErrorCode.INVALID_SOURCE: "The normalized local source failed validation.",
    LocalTextErrorCode.INVALID_CITATION: "The requested UTF-8 byte range is invalid.",
}


class LocalTextError(RuntimeError):
    def __init__(self, code: LocalTextErrorCode) -> None:
        if type(code) is not LocalTextErrorCode:
            raise TypeError("local text error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class LocalFileMetadata:
    byte_length: int
    source_format: LocalTextFormat
    modified_at_utc: datetime = field(repr=False)


@dataclass(frozen=True, slots=True)
class LocalTextRead:
    normalized_source: NormalizedPlainTextSource = field(repr=False)
    source_id: UUID
    provider_id: str
    byte_length: int
    content_sha256: str
    trust: TrustLabel
    sensitivity: SensitivityLabel
    source_format: LocalTextFormat
    file_metadata: LocalFileMetadata = field(repr=False)
    _relative_identity: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class LocalTextCitation:
    bound_citation: SourceBoundCitation
    cited_text: str = field(repr=False)


__all__ = [
    "LocalFileMetadata",
    "LocalTextCitation",
    "LocalTextError",
    "LocalTextErrorCode",
    "LocalTextFormat",
    "LocalTextRead",
]
