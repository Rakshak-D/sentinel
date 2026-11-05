"""Deterministic privacy-conscious job-alert renderers."""

from __future__ import annotations

import hashlib
import json
from typing import Final
from uuid import UUID

from sentinel.briefing.formatters import escape_display_text
from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.extraction.types import (
    JobAlertError,
    JobAlertErrorCode,
    JobAlertEvidence,
    JobAlertField,
    JobAlertFieldName,
    JobAlertFieldState,
    JobAlertParseResult,
    JobAlertStatus,
)
from sentinel.normalization import (
    NormalizationError,
    NormalizedPlainTextSource,
    SourceBoundCitation,
    verify_bound_citation,
)

SCHEMA_VERSION: Final = "sentinel.job-alert-extraction.v1"
_FIELD_ORDER: Final = (
    JobAlertFieldName.COMPANY,
    JobAlertFieldName.ROLE,
    JobAlertFieldName.LOCATION,
    JobAlertFieldName.APPLICATION_URL,
    JobAlertFieldName.DEADLINE,
)


def _validate_result(result: JobAlertParseResult) -> tuple[JobAlertField, ...]:
    if (
        type(result) is not JobAlertParseResult
        or type(result.synthetic_data) is not bool
        or result.provider_id not in {"local.file", "gmail.fixture"}
        or result.synthetic_data is not (result.provider_id == "gmail.fixture")
        or result.trust is not TrustLabel.T4_EXTERNAL
        or result.sensitivity is not SensitivityLabel.PRIVATE
        or type(result.status) is not JobAlertStatus
        or type(result.fields) is not tuple
        or len(result.fields) != len(_FIELD_ORDER)
        or any(
            type(field) is not JobAlertField or type(field.field_id) is not JobAlertFieldName
            for field in result.fields
        )
        or tuple(field.field_id for field in result.fields) != _FIELD_ORDER
        or type(result.source_id) is not UUID
        or type(result.content_sha256) is not str
        or len(result.content_sha256) != 64
        or any(character not in "0123456789abcdef" for character in result.content_sha256)
        or type(result.byte_length) is not int
        or result.byte_length < 0
    ):
        raise JobAlertError(JobAlertErrorCode.INVALID_SOURCE)
    source = result.normalized_source
    if (
        type(source) is not NormalizedPlainTextSource
        or type(source.original_bytes) is not bytes
        or hashlib.sha256(source.original_bytes).hexdigest() != result.content_sha256
        or source.payload_sha256 != result.content_sha256
        or source.mime_type != "text/plain; charset=utf-8"
        or source.charset != "utf-8"
        or source.envelope.source_id != result.source_id
        or source.envelope.provider_id != result.provider_id
        or source.envelope.content_sha256 != result.content_sha256
        or source.envelope.trust is not result.trust
        or source.envelope.sensitivity is not result.sensitivity
        or len(source.original_bytes) != result.byte_length
    ):
        raise JobAlertError(JobAlertErrorCode.INVALID_SOURCE)
    for field in result.fields:
        if type(field) is not JobAlertField or type(field.state) is not JobAlertFieldState:
            raise JobAlertError(JobAlertErrorCode.INVALID_SOURCE)
        if field.state is JobAlertFieldState.PRESENT:
            evidence = field.evidence
            if (
                type(field.value) is not str
                or type(evidence) is not JobAlertEvidence
                or type(evidence.bound_citation) is not SourceBoundCitation
                or evidence.field_id is not field.field_id
                or evidence.source_id != result.source_id
                or evidence.content_sha256 != result.content_sha256
                or evidence.bound_citation.source_id != evidence.source_id
                or evidence.bound_citation.content_sha256 != evidence.content_sha256
                or evidence.bound_citation.span.span_id != evidence.span_id
                or evidence.bound_citation.span.start_byte != evidence.start_byte
                or evidence.bound_citation.span.end_byte != evidence.end_byte
                or evidence.bound_citation.span.text_sha256 != evidence.text_sha256
            ):
                raise JobAlertError(JobAlertErrorCode.INVALID_CITATION)
            try:
                cited = verify_bound_citation(
                    source,
                    evidence.bound_citation,
                    original_bytes=source.original_bytes,
                    expected_text=field.value,
                )
            except (NormalizationError, TypeError, ValueError):
                raise JobAlertError(JobAlertErrorCode.INVALID_CITATION) from None
            if cited != field.value:
                raise JobAlertError(JobAlertErrorCode.INVALID_CITATION)
        elif field.value is not None or field.evidence is not None:
            raise JobAlertError(JobAlertErrorCode.INVALID_SOURCE)
    if result.status is JobAlertStatus.CANDIDATE:
        field_states = {field.field_id: field.state for field in result.fields}
        if (
            field_states[JobAlertFieldName.COMPANY] is not JobAlertFieldState.PRESENT
            or field_states[JobAlertFieldName.ROLE] is not JobAlertFieldState.PRESENT
            or any(field.state is JobAlertFieldState.INVALID for field in result.fields)
        ):
            raise JobAlertError(JobAlertErrorCode.INVALID_SOURCE)
    return result.fields


def _citation_payload(field: JobAlertField) -> dict[str, object] | None:
    evidence = field.evidence
    if evidence is None:
        return None
    return {
        "source_id": str(evidence.source_id),
        "content_sha256": evidence.content_sha256,
        "span_id": str(evidence.span_id),
        "start_byte": evidence.start_byte,
        "end_byte": evidence.end_byte,
        "text_sha256": evidence.text_sha256,
    }


def format_json_job_alert(result: JobAlertParseResult, *, show_fields: bool = False) -> str:
    """Render the versioned deterministic JSON result, hiding values by default."""

    if type(show_fields) is not bool:
        raise JobAlertError(JobAlertErrorCode.INVALID_SOURCE)
    fields = _validate_result(result)
    items: list[dict[str, object]] = []
    for field in fields:
        item: dict[str, object] = {
            "field_id": field.field_id.value,
            "state": field.state.value,
            "citation": _citation_payload(field),
        }
        if show_fields and field.state is JobAlertFieldState.PRESENT:
            assert field.value is not None
            item["value"] = escape_display_text(field.value)
        items.append(item)
    document: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "extraction_status": result.status.value,
        "synthetic_data": result.synthetic_data,
        "provider_id": result.provider_id,
        "source_id": str(result.source_id),
        "content_sha256": result.content_sha256,
        "byte_length": result.byte_length,
        "trust": result.trust.value,
        "sensitivity": result.sensitivity.value,
        "fields": items,
        "values_included": show_fields,
        "disclaimer": (
            "A candidate is only a cited extraction; employer, opening, eligibility, "
            "and legitimacy are not verified."
        ),
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
        raise JobAlertError(JobAlertErrorCode.INVALID_SOURCE) from None


def format_text_job_alert(result: JobAlertParseResult, *, show_fields: bool = False) -> str:
    """Render one complete text record with explicit opt-in for field disclosure."""

    if type(show_fields) is not bool:
        raise JobAlertError(JobAlertErrorCode.INVALID_SOURCE)
    fields = _validate_result(result)
    lines = [
        "Sentinel - Job-alert extraction",
        f"Classification: {result.status.value}",
        f"Synthetic data: {'yes' if result.synthetic_data else 'no'}",
        f"Provider: {result.provider_id}",
        f"Source UUID: {result.source_id}",
        f"Source SHA-256: {result.content_sha256}",
        f"Source bytes: {result.byte_length}",
        f"Trust: {result.trust.value} | Sensitivity: {result.sensitivity.value}",
        "Candidate means only that labeled fields were extracted and cited; "
        "job legitimacy, opening, eligibility, and application readiness are not verified.",
        "Extracted text is untrusted source data, not owner intent or instructions.",
        f"Field values included: {'yes' if show_fields else 'no'}",
        "Fields:",
    ]
    for field in fields:
        suffix = f" ({field.state.value})"
        if field.evidence is not None:
            evidence = field.evidence
            suffix += (
                f" [bytes {evidence.start_byte}:{evidence.end_byte}; "
                f"span {evidence.span_id}; sha256 {evidence.text_sha256}]"
            )
        if show_fields and field.state is JobAlertFieldState.PRESENT:
            assert field.value is not None
            lines.append(f'  {field.field_id.value}: "{escape_display_text(field.value)}"{suffix}')
        else:
            lines.append(f"  {field.field_id.value}{suffix}")
    return "\n".join(lines)


__all__ = ["SCHEMA_VERSION", "format_json_job_alert", "format_text_job_alert"]
