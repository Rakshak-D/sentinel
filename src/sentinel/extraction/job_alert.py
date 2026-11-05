"""Strict, deterministic extraction from explicitly selected untrusted text."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Final, NoReturn
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import ValidationError

from sentinel.contracts.envelopes import ByteSpan, SourceEnvelope
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
    add_citation,
    bind_citation,
    verify_bound_citation,
    verify_citation,
)
from sentinel.readers.local_text import read_allowlisted_local_text, verify_local_text_span
from sentinel.readers.local_text_types import LocalFileMetadata, LocalTextFormat, LocalTextRead
from sentinel.readers.types import GmailFixtureMessage

MAX_JOB_ALERT_SOURCE_BYTES: Final = 64 * 1024
MAX_JOB_ALERT_LINES: Final = 256
MAX_JOB_ALERT_LINE_BYTES: Final = 1024
MAX_JOB_ALERT_FIELDS: Final = 12
MAX_COMPANY_BYTES: Final = 160
MAX_ROLE_BYTES: Final = 200
MAX_LOCATION_BYTES: Final = 200
MAX_APPLICATION_URL_BYTES: Final = 1024
MAX_DEADLINE_BYTES: Final = 64

_FIELDS: Final = (
    JobAlertFieldName.COMPANY,
    JobAlertFieldName.ROLE,
    JobAlertFieldName.LOCATION,
    JobAlertFieldName.APPLICATION_URL,
    JobAlertFieldName.DEADLINE,
)
_LABELS: Final = {
    "company": JobAlertFieldName.COMPANY,
    "employer": JobAlertFieldName.COMPANY,
    "role": JobAlertFieldName.ROLE,
    "position": JobAlertFieldName.ROLE,
    "location": JobAlertFieldName.LOCATION,
    "apply url": JobAlertFieldName.APPLICATION_URL,
    "application url": JobAlertFieldName.APPLICATION_URL,
    "deadline": JobAlertFieldName.DEADLINE,
}
_VALUE_LIMITS: Final = {
    JobAlertFieldName.COMPANY: MAX_COMPANY_BYTES,
    JobAlertFieldName.ROLE: MAX_ROLE_BYTES,
    JobAlertFieldName.LOCATION: MAX_LOCATION_BYTES,
    JobAlertFieldName.APPLICATION_URL: MAX_APPLICATION_URL_BYTES,
    JobAlertFieldName.DEADLINE: MAX_DEADLINE_BYTES,
}
_MAILBOX_ALIAS = re.compile(r"[a-z][a-z0-9-]{1,62}[a-z0-9]\Z")
_OPAQUE_MESSAGE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_UNKNOWN_LABEL = re.compile(rb"[A-Za-z][A-Za-z0-9 -]{0,40}:\Z")
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


@dataclass(frozen=True, slots=True)
class _Occurrence:
    field_id: JobAlertFieldName
    value_bytes: bytes
    start_byte: int
    end_byte: int


def _raise(code: JobAlertErrorCode) -> NoReturn:
    raise JobAlertError(code) from None


def _validate_normalized_source(
    normalized: NormalizedPlainTextSource,
    *,
    expected_provider: str,
) -> tuple[bytes, str, UUID]:
    if type(normalized) is not NormalizedPlainTextSource:
        _raise(JobAlertErrorCode.INVALID_SOURCE)
    try:
        raw = normalized.original_bytes
        text = normalized.text
        envelope = normalized.envelope
        if type(raw) is not bytes or type(text) is not str:
            _raise(JobAlertErrorCode.INVALID_SOURCE)
        if len(raw) > MAX_JOB_ALERT_SOURCE_BYTES:
            _raise(JobAlertErrorCode.SOURCE_TOO_LARGE)
        decoded = raw.decode("utf-8", errors="strict")
        if decoded != text:
            _raise(JobAlertErrorCode.INVALID_SOURCE)
        digest = hashlib.sha256(raw).hexdigest()
        if (
            type(envelope) is not SourceEnvelope
            or type(normalized.payload_sha256) is not str
            or normalized.payload_sha256 != digest
            or envelope.content_sha256 != digest
            or envelope.provider_id != expected_provider
            or envelope.trust is not TrustLabel.T4_EXTERNAL
            or envelope.sensitivity is not SensitivityLabel.PRIVATE
            or normalized.declared_mime_type != "text/plain; charset=utf-8"
            or normalized.mime_type != "text/plain; charset=utf-8"
            or normalized.charset != "utf-8"
            or type(envelope.source_id) is not UUID
        ):
            _raise(JobAlertErrorCode.INVALID_SOURCE)
        SourceEnvelope.model_validate(envelope.model_dump(mode="python"))
        for span in normalized.citations:
            if type(span) is not ByteSpan:
                _raise(JobAlertErrorCode.INVALID_SOURCE)
            verify_citation(normalized, span, original_bytes=raw)
        return raw, digest, envelope.source_id
    except JobAlertError:
        raise
    except (UnicodeDecodeError, NormalizationError, TypeError, ValueError, ValidationError):
        _raise(JobAlertErrorCode.INVALID_SOURCE)
    except Exception:
        _raise(JobAlertErrorCode.INVALID_SOURCE)


def _validate_gmail_message(message: GmailFixtureMessage) -> NormalizedPlainTextSource:
    if type(message) is not GmailFixtureMessage:
        _raise(JobAlertErrorCode.INVALID_SOURCE)
    if (
        type(message.mailbox_alias) is not str
        or _MAILBOX_ALIAS.fullmatch(message.mailbox_alias) is None
        or type(message.message_id) is not str
        or _OPAQUE_MESSAGE_ID.fullmatch(message.message_id) is None
        or type(message.thread_id) is not str
        or _OPAQUE_MESSAGE_ID.fullmatch(message.thread_id) is None
        or type(message.internal_date) is not datetime
        or message.internal_date.tzinfo is None
        or message.internal_date.utcoffset() is None
        or type(message.citations) is not tuple
    ):
        _raise(JobAlertErrorCode.INVALID_SOURCE)
    normalized = message.normalized_source
    _, _, source_id = _validate_normalized_source(normalized, expected_provider="gmail.fixture")
    expected_id = uuid5(
        NAMESPACE_URL,
        f"sentinel:gmail.fixture:{message.mailbox_alias}#{message.message_id}",
    )
    if source_id != expected_id:
        _raise(JobAlertErrorCode.INVALID_SOURCE)
    for citation in message.citations:
        try:
            verify_bound_citation(normalized, citation, original_bytes=normalized.original_bytes)
        except (NormalizationError, TypeError, ValueError):
            _raise(JobAlertErrorCode.INVALID_SOURCE)
    return normalized


def _value_is_safe(value: str, raw: bytes, field_id: JobAlertFieldName) -> bool:
    if not value or len(raw) > _VALUE_LIMITS[field_id]:
        return False
    if value != value.strip(" \t"):
        return False
    for character in value:
        codepoint = ord(character)
        category = unicodedata.category(character)
        if (
            category in {"Cc", "Cs", "Zl", "Zp"}
            or (category == "Cf" and codepoint not in {0x200C, 0x200D})
            or codepoint in _BIDI_CONTROLS
        ):
            return False
    if field_id is JobAlertFieldName.APPLICATION_URL:
        return _valid_application_url(value)
    if field_id is JobAlertFieldName.DEADLINE:
        if _DATE.fullmatch(value) is None:
            return False
        try:
            date.fromisoformat(value)
        except ValueError:
            return False
    return True


def _valid_application_url(value: str) -> bool:
    try:
        encoded = value.encode("ascii", errors="strict")
        if (
            len(encoded) > MAX_APPLICATION_URL_BYTES
            or any(character.isspace() for character in value)
            or "\\" in value
            or "#" in value
            or re.search(r"%(?![0-9A-Fa-f]{2})", value) is not None
        ):
            return False
        parsed = urlsplit(value)
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            return False
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            return False
        if "[" in parsed.netloc or "]" in parsed.netloc or parsed.netloc.endswith(":"):
            return False
        host = parsed.hostname
        if host is None or len(host) > 253 or host.endswith("."):
            return False
        lowered = host.lower()
        if (
            lowered == "localhost"
            or lowered.endswith((".localhost", ".local", ".internal", ".lan"))
            or re.fullmatch(r"[0-9.]+", lowered) is not None
        ):
            return False
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            pass
        labels = host.split(".")
        if len(labels) < 2 or any(_DNS_LABEL.fullmatch(label) is None for label in labels):
            return False
        port = parsed.port
        if port is not None and not (1 <= port <= 65535):
            return False
        return True
    except (UnicodeEncodeError, ValueError, TypeError):
        return False


def _split_lines(raw: bytes) -> tuple[tuple[bytes, int], ...]:
    pieces = raw.split(b"\n")
    has_trailing_newline = raw.endswith(b"\n")
    line_count = len(pieces) - 1 if has_trailing_newline else len(pieces)
    if line_count > MAX_JOB_ALERT_LINES:
        _raise(JobAlertErrorCode.INPUT_TOO_COMPLEX)
    physical_pieces = pieces[:-1] if has_trailing_newline else pieces
    lines: list[tuple[bytes, int]] = []
    offset = 0
    for index, piece in enumerate(physical_pieces):
        has_newline = index < len(pieces) - 1
        line = piece[:-1] if has_newline and piece.endswith(b"\r") else piece
        if len(line) > MAX_JOB_ALERT_LINE_BYTES:
            _raise(JobAlertErrorCode.INPUT_TOO_COMPLEX)
        lines.append((line, offset))
        offset += len(piece) + (1 if has_newline else 0)
    return tuple(lines)


def _parse_occurrences(raw: bytes) -> tuple[tuple[tuple[_Occurrence, ...], ...], int]:
    groups: list[tuple[_Occurrence, ...]] = []
    current: list[_Occurrence] = []
    marker_count = 0
    recognized_count = 0

    def close_group() -> None:
        nonlocal current
        if current:
            groups.append(tuple(current))
            current = []

    for line, line_offset in _split_lines(raw):
        if line.lower() == b"job opportunity":
            marker_count += 1
            close_group()
            continue
        if not line.strip(b" \t"):
            close_group()
            continue
        colon = line.find(b":")
        label: str | None = None
        if colon >= 0:
            try:
                label = line[:colon].decode("ascii", errors="strict").lower()
            except UnicodeDecodeError:
                label = None
        field_id = None if label is None else _LABELS.get(label)
        if field_id is not None:
            recognized_count += 1
            if recognized_count > MAX_JOB_ALERT_FIELDS:
                _raise(JobAlertErrorCode.INPUT_TOO_COMPLEX)
            value_start = colon + 1
            while value_start < len(line) and line[value_start] in b" \t":
                value_start += 1
            current.append(
                _Occurrence(
                    field_id=field_id,
                    value_bytes=line[value_start:],
                    start_byte=line_offset + value_start,
                    end_byte=line_offset + len(line),
                )
            )
            continue
        if colon >= 0 and _UNKNOWN_LABEL.fullmatch(line[: colon + 1]) is not None:
            close_group()
            continue
        close_group()
    close_group()
    return tuple(groups), marker_count


def _empty_fields(state: JobAlertFieldState) -> tuple[JobAlertField, ...]:
    return tuple(JobAlertField(field_id=field_id, state=state) for field_id in _FIELDS)


def _add_field_evidence(
    normalized: NormalizedPlainTextSource,
    occurrence: _Occurrence,
    *,
    local_source: LocalTextRead | None,
) -> tuple[NormalizedPlainTextSource, JobAlertField]:
    try:
        value = occurrence.value_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return normalized, JobAlertField(
            field_id=occurrence.field_id, state=JobAlertFieldState.INVALID
        )
    if not _value_is_safe(value, occurrence.value_bytes, occurrence.field_id):
        return normalized, JobAlertField(
            field_id=occurrence.field_id, state=JobAlertFieldState.INVALID
        )
    try:
        if local_source is not None:
            verify_local_text_span(
                local_source,
                start_byte=occurrence.start_byte,
                end_byte=occurrence.end_byte,
                expected_text=value,
            )
        source_id = normalized.envelope.source_id
        span_id = uuid5(
            NAMESPACE_URL,
            "sentinel:job-alert-field:v1:"
            f"{source_id}:{occurrence.field_id.value}:{occurrence.start_byte}:{occurrence.end_byte}",
        )
        updated = add_citation(
            normalized,
            span_id=span_id,
            start_byte=occurrence.start_byte,
            end_byte=occurrence.end_byte,
            expected_text=value,
        )
        span = next(span for span in updated.citations if span.span_id == span_id)
        bound = bind_citation(updated, span)
        verified = verify_bound_citation(
            updated,
            bound,
            original_bytes=normalized.original_bytes,
            expected_text=value,
        )
        if verified != value:
            _raise(JobAlertErrorCode.INVALID_CITATION)
        evidence = JobAlertEvidence(
            field_id=occurrence.field_id,
            source_id=bound.source_id,
            content_sha256=bound.content_sha256,
            span_id=bound.span.span_id,
            start_byte=bound.span.start_byte,
            end_byte=bound.span.end_byte,
            text_sha256=bound.span.text_sha256,
            bound_citation=bound,
        )
        return updated, JobAlertField(
            field_id=occurrence.field_id,
            state=JobAlertFieldState.PRESENT,
            value=value,
            evidence=evidence,
        )
    except JobAlertError:
        raise
    except (NormalizationError, StopIteration, TypeError, ValueError):
        _raise(JobAlertErrorCode.INVALID_CITATION)


def _parse_validated_source(
    normalized: NormalizedPlainTextSource,
    *,
    provider_id: str,
    synthetic_data: bool,
    local_source: LocalTextRead | None = None,
) -> JobAlertParseResult:
    raw, digest, source_id = _validate_normalized_source(
        normalized,
        expected_provider=provider_id,
    )
    groups, marker_count = _parse_occurrences(raw)
    all_occurrences = tuple(occurrence for group in groups for occurrence in group)
    counts: dict[JobAlertFieldName, int] = {field_id: 0 for field_id in _FIELDS}
    for occurrence in all_occurrences:
        counts[occurrence.field_id] += 1
    ambiguous = marker_count > 1 or len(groups) > 1 or any(count > 1 for count in counts.values())
    if ambiguous:
        fields = tuple(
            JobAlertField(
                field_id=field_id,
                state=(
                    JobAlertFieldState.AMBIGUOUS
                    if counts[field_id] > 0
                    else JobAlertFieldState.MISSING
                ),
            )
            for field_id in _FIELDS
        )
        status = JobAlertStatus.AMBIGUOUS
    elif not all_occurrences:
        fields = _empty_fields(JobAlertFieldState.MISSING)
        status = JobAlertStatus.INCOMPLETE if marker_count else JobAlertStatus.NO_MATCH
    else:
        occurrences = {occurrence.field_id: occurrence for occurrence in all_occurrences}
        output_fields: list[JobAlertField] = []
        augmented = normalized
        for field_id in _FIELDS:
            selected_occurrence = occurrences.get(field_id)
            if selected_occurrence is None:
                output_fields.append(
                    JobAlertField(field_id=field_id, state=JobAlertFieldState.MISSING)
                )
                continue
            augmented, parsed_field = _add_field_evidence(
                augmented,
                selected_occurrence,
                local_source=local_source,
            )
            output_fields.append(parsed_field)
        fields = tuple(output_fields)
        states = {field.field_id: field.state for field in fields}
        status = (
            JobAlertStatus.CANDIDATE
            if states[JobAlertFieldName.COMPANY] is JobAlertFieldState.PRESENT
            and states[JobAlertFieldName.ROLE] is JobAlertFieldState.PRESENT
            and all(field.state is not JobAlertFieldState.INVALID for field in fields)
            else JobAlertStatus.INCOMPLETE
        )
        normalized = augmented
    return JobAlertParseResult(
        status=status,
        synthetic_data=synthetic_data,
        provider_id=provider_id,
        source_id=source_id,
        content_sha256=digest,
        byte_length=len(raw),
        trust=TrustLabel.T4_EXTERNAL,
        sensitivity=SensitivityLabel.PRIVATE,
        fields=fields,
        normalized_source=normalized,
    )


def parse_local_job_alert(
    *,
    allowed_root: str | Path,
    file_path: str | Path,
) -> JobAlertParseResult:
    """Parse one explicitly selected .txt/.md file through the CR1-M reader."""

    local_source = read_allowlisted_local_text(allowed_root=allowed_root, file_path=file_path)
    if type(local_source) is not LocalTextRead:
        _raise(JobAlertErrorCode.INVALID_SOURCE)
    relative_identity = local_source._relative_identity
    if (
        local_source.provider_id != "local.file"
        or local_source.trust is not TrustLabel.T4_EXTERNAL
        or local_source.sensitivity is not SensitivityLabel.PRIVATE
        or type(local_source.source_id) is not UUID
        or type(local_source.source_format) is not LocalTextFormat
        or type(relative_identity) is not str
        or not relative_identity
        or local_source.byte_length != len(local_source.normalized_source.original_bytes)
        or local_source.content_sha256 != local_source.normalized_source.envelope.content_sha256
        or local_source.normalized_source.envelope.source_id != local_source.source_id
        or local_source.source_id
        != uuid5(
            NAMESPACE_URL,
            f"sentinel:local-text:v1:{relative_identity}:{local_source.content_sha256}",
        )
        or type(local_source.file_metadata) is not LocalFileMetadata
        or type(local_source.file_metadata.byte_length) is not int
        or local_source.file_metadata.byte_length != local_source.byte_length
        or local_source.file_metadata.source_format is not local_source.source_format
    ):
        _raise(JobAlertErrorCode.INVALID_SOURCE)
    return _parse_validated_source(
        local_source.normalized_source,
        provider_id="local.file",
        synthetic_data=False,
        local_source=local_source,
    )


def parse_gmail_fixture_job_alert(message: GmailFixtureMessage) -> JobAlertParseResult:
    """Parse one in-memory synthetic Gmail message body; never loads a mailbox."""

    normalized = _validate_gmail_message(message)
    return _parse_validated_source(
        normalized,
        provider_id="gmail.fixture",
        synthetic_data=True,
    )


__all__ = [
    "MAX_APPLICATION_URL_BYTES",
    "MAX_COMPANY_BYTES",
    "MAX_DEADLINE_BYTES",
    "MAX_JOB_ALERT_FIELDS",
    "MAX_JOB_ALERT_LINE_BYTES",
    "MAX_JOB_ALERT_LINES",
    "MAX_JOB_ALERT_SOURCE_BYTES",
    "MAX_LOCATION_BYTES",
    "MAX_ROLE_BYTES",
    "parse_gmail_fixture_job_alert",
    "parse_local_job_alert",
]
