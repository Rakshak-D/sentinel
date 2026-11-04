"""Read-only synthetic evidence presentation APIs."""

from sentinel.briefing.evidence import build_github_fixture_brief
from sentinel.briefing.formatters import format_json_brief, format_text_brief
from sentinel.briefing.types import (
    BriefingError,
    BriefingErrorCode,
    EvidenceBriefing,
    EvidenceCitation,
    EvidenceItem,
)

__all__ = [
    "BriefingError",
    "BriefingErrorCode",
    "EvidenceBriefing",
    "EvidenceCitation",
    "EvidenceItem",
    "build_github_fixture_brief",
    "format_json_brief",
    "format_text_brief",
]
