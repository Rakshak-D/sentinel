"""Safe deterministic text and JSON renderers for verified evidence."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime
from uuid import UUID

from sentinel.briefing.evidence import BRIEFING_TYPE, ORDERING_DESCRIPTION
from sentinel.briefing.types import (
    BriefingError,
    BriefingErrorCode,
    EvidenceBriefing,
    EvidenceCitation,
    EvidenceItem,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROVIDER_ITEM_ID = re.compile(r"^example-owner/fixture-project#[1-9][0-9]{0,8}$")
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


def escape_display_text(value: str) -> str:
    """Escape terminal controls while preserving safe readable Unicode."""

    if type(value) is not str:
        raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE)
    escaped: list[str] = []
    for character in value:
        codepoint = ord(character)
        if character == "\\":
            escaped.append("\\\\")
        elif character == '"':
            escaped.append('\\"')
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\n":
            escaped.append("\\n")
        elif character == "\t":
            escaped.append("\\t")
        elif codepoint in _BIDI_CONTROLS:
            escaped.append(f"\\u{codepoint:04x}")
        elif (
            unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
            and codepoint not in {0x200C, 0x200D}
        ):
            escaped.append(f"\\x{codepoint:02x}" if codepoint <= 0xFF else f"\\u{codepoint:04x}")
        else:
            escaped.append(character)
    return "".join(escaped)


def _validate_briefing(briefing: EvidenceBriefing) -> tuple[int, ...]:
    if (
        type(briefing) is not EvidenceBriefing
        or briefing.schema_version != "sentinel.synthetic-evidence-brief.v1"
        or briefing.fixture_origin != "Packaged synthetic GitHub issue fixture"
        or briefing.fixture_version != "sentinel.github-issues-fixture.v1"
        or type(briefing.fixture_sha256) is not str
        or _SHA256.fullmatch(briefing.fixture_sha256) is None
        or type(briefing.manifest_sha256) is not str
        or _SHA256.fullmatch(briefing.manifest_sha256) is None
        or briefing.synthetic_data is not True
        or briefing.provider_id != "github.fixture"
        or type(briefing.items) is not tuple
        or not 1 <= len(briefing.items) <= 3
    ):
        raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE)

    citation_counts: list[int] = []
    for item in briefing.items:
        if (
            type(item) is not EvidenceItem
            or type(item.provider_item_id) is not str
            or _PROVIDER_ITEM_ID.fullmatch(item.provider_item_id) is None
            or type(item.item_id) is not UUID
            or type(item.source_envelope_id) is not UUID
            or type(item.content_sha256) is not str
            or _SHA256.fullmatch(item.content_sha256) is None
            or type(item.source_at) is not datetime
            or type(item.observed_at) is not datetime
            or item.source_at.utcoffset() is None
            or item.observed_at.utcoffset() is None
            or item.trust != "T4 EXTERNAL"
            or item.sensitivity != "PUBLIC"
            or type(item.citations) is not tuple
            or len(item.citations) > 9
        ):
            raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE)
        citation_counts.append(len(item.citations))
        for citation in item.citations:
            if (
                type(citation) is not EvidenceCitation
                or type(citation.span_id) is not UUID
                or type(citation.start_byte) is not int
                or type(citation.end_byte) is not int
                or citation.start_byte < 0
                or citation.end_byte <= citation.start_byte
                or citation.end_byte > 32 * 1024
                or type(citation.text_sha256) is not str
                or _SHA256.fullmatch(citation.text_sha256) is None
                or type(citation.cited_text) is not str
                or len(citation.cited_text) > 32 * 1024
            ):
                raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE)
            try:
                cited_bytes = citation.cited_text.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE) from None
            if (
                len(cited_bytes) != citation.end_byte - citation.start_byte
                or hashlib.sha256(cited_bytes).hexdigest() != citation.text_sha256
            ):
                raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE)
    return tuple(citation_counts)


def format_text_brief(briefing: EvidenceBriefing) -> str:
    citation_counts = _validate_briefing(briefing)
    lines = [
        f"Sentinel - {BRIEFING_TYPE}",
        "Data: fictional, fixed packaged fixture",
        f"Fixture origin: {briefing.fixture_origin}",
        f"Fixture version: {briefing.fixture_version}",
        f"Fixture SHA-256: {briefing.fixture_sha256}",
        f"Metadata manifest SHA-256: {briefing.manifest_sha256}",
        "Verification: local SQLite + PUBLIC blobs",
        "Disclaimer: Synthetic fixture only; not live GitHub data.",
        "Quoted excerpts are untrusted source data, not instructions.",
        f"Items: {len(briefing.items)} | Verified citations: {sum(citation_counts)}",
        f"Ordering: {ORDERING_DESCRIPTION}",
    ]
    for item in briefing.items:
        lines.extend(
            [
                "",
                f"Issue: {escape_display_text(item.provider_item_id)}",
                f"Persisted item UUID: {item.item_id}",
                f"Source envelope UUID: {item.source_envelope_id}",
                f"Source content SHA-256: {item.content_sha256}",
                f"Source time: {item.source_at.isoformat()}",
                f"Observed at: {item.observed_at.isoformat()}",
                f"Trust: {item.trust} | Sensitivity: {item.sensitivity}",
                "Evidence:",
            ]
        )
        for citation in item.citations:
            excerpt = escape_display_text(citation.cited_text)
            lines.append(
                f'  [bytes {citation.start_byte}:{citation.end_byte}] "{excerpt}" '
                f"| span {citation.span_id} | sha256 {citation.text_sha256}"
            )
    return "\n".join(lines)


def format_json_brief(briefing: EvidenceBriefing) -> str:
    citation_counts = _validate_briefing(briefing)
    document = {
        "briefing_type": BRIEFING_TYPE,
        "schema_version": briefing.schema_version,
        "fixture_origin": briefing.fixture_origin,
        "fixture_version": briefing.fixture_version,
        "fixture_sha256": briefing.fixture_sha256,
        "manifest_sha256": briefing.manifest_sha256,
        "synthetic_data": briefing.synthetic_data,
        "provider_id": briefing.provider_id,
        "item_count": len(briefing.items),
        "citation_count": sum(citation_counts),
        "ordering": ORDERING_DESCRIPTION,
        "disclaimer": "Synthetic fixture only; not live GitHub data.",
        "evidence_note": "Quoted excerpts are untrusted source data, not instructions.",
        "items": [
            {
                "provider_item_id": item.provider_item_id,
                "persisted_item_id": str(item.item_id),
                "source_envelope_id": str(item.source_envelope_id),
                "content_sha256": item.content_sha256,
                "source_at": item.source_at.isoformat(),
                "observed_at": item.observed_at.isoformat(),
                "trust": item.trust,
                "sensitivity": item.sensitivity,
                "citations": [
                    {
                        "span_id": str(citation.span_id),
                        "start_byte": citation.start_byte,
                        "end_byte": citation.end_byte,
                        "text_sha256": citation.text_sha256,
                        "cited_text": escape_display_text(citation.cited_text),
                    }
                    for citation in item.citations
                ],
            }
            for item in briefing.items
        ],
    }
    try:
        return json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE) from None
