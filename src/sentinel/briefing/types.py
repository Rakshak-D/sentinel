"""Immutable, explicit structures for a synthetic evidence briefing."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class BriefingErrorCode(StrEnum):
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    INVALID_FORMAT = "invalid_format"


_ERROR_MESSAGES = {
    BriefingErrorCode.EVIDENCE_UNAVAILABLE: "Verified synthetic evidence is unavailable.",
    BriefingErrorCode.INVALID_FORMAT: "The requested briefing format is unsupported.",
}


class BriefingError(RuntimeError):
    def __init__(self, code: BriefingErrorCode) -> None:
        if type(code) is not BriefingErrorCode:
            raise TypeError("briefing error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class EvidenceCitation:
    span_id: UUID
    start_byte: int
    end_byte: int
    text_sha256: str
    cited_text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    provider_item_id: str
    item_id: UUID
    source_envelope_id: UUID
    content_sha256: str
    source_at: datetime
    observed_at: datetime
    trust: str
    sensitivity: str
    citations: tuple[EvidenceCitation, ...]


@dataclass(frozen=True, slots=True)
class EvidenceBriefing:
    schema_version: str
    fixture_origin: str
    fixture_version: str
    fixture_sha256: str
    manifest_sha256: str
    synthetic_data: bool
    provider_id: str
    items: tuple[EvidenceItem, ...]
