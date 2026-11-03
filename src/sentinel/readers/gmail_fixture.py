"""Strict, credential-free reader for a fixed fictional Gmail fixture."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from typing import Annotated, Final, Literal, NoReturn
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization import (
    NormalizationError,
    PlainTextSourceDescriptor,
    add_citation,
    bind_citation,
    normalize_plain_text,
    verify_bound_citation,
)
from sentinel.readers.types import (
    GmailFixtureError,
    GmailFixtureErrorCode,
    GmailFixtureMessage,
    GmailFixtureRead,
)

GMAIL_FIXTURE_SCHEMA_VERSION: Final = "sentinel.gmail-messages-fixture.v1"
GMAIL_FIXTURE_OBSERVED_AT: Final = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)
GMAIL_FIXTURE_SHA256: Final = "781112d5b62439e833f33040f0e4f67c4adafa86d2f94e1b137fa09d52fa8b57"
GMAIL_FIXTURE_NAMESPACE: Final = NAMESPACE_URL

MAX_GMAIL_FIXTURE_BYTES: Final = 64 * 1024
MAX_GMAIL_MESSAGES: Final = 8
MAX_GMAIL_BODY_BYTES: Final = 16 * 1024
MAX_GMAIL_ENCODED_BODY_CHARS: Final = ((MAX_GMAIL_BODY_BYTES + 2) // 3) * 4
MAX_GMAIL_MESSAGE_ID_BYTES: Final = 128
MAX_GMAIL_MAILBOX_ALIAS_BYTES: Final = 64
MAX_GMAIL_SUBJECT_BYTES: Final = 1024
MAX_GMAIL_HEADER_COUNT: Final = 8
MAX_GMAIL_HEADER_NAME_BYTES: Final = 128
MAX_GMAIL_HEADER_VALUE_BYTES: Final = 2048
MAX_GMAIL_SPANS_PER_MESSAGE: Final = 32
MAX_GMAIL_EXPECTED_TEXT_BYTES: Final = 4096
MAX_GMAIL_INTERNAL_DATE_MS: Final = 4_102_444_799_999  # 2099-12-31T23:59:59.999Z

_MAILBOX_ALIAS_PATTERN: Final = re.compile(r"[a-z][a-z0-9-]{1,62}[a-z0-9]")
_OPAQUE_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9_-]{1,128}")
_HEADER_NAME_PATTERN: Final = re.compile(r"[A-Za-z0-9-]{1,128}")
_BASE64URL_PATTERN: Final = re.compile(r"[A-Za-z0-9_-]*")
_CONTENT_TYPE_PATTERN: Final = re.compile(
    r"text/plain\s*;\s*charset\s*=\s*(?:utf-8|\"utf-8\")",
    re.IGNORECASE,
)
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class _FrozenStrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class _Header(_FrozenStrictModel):
    name: Annotated[StrictStr, Field(min_length=1, max_length=MAX_GMAIL_HEADER_NAME_BYTES)]
    value: Annotated[StrictStr, Field(max_length=MAX_GMAIL_HEADER_VALUE_BYTES)]

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if _HEADER_NAME_PATTERN.fullmatch(value) is None:
            raise ValueError("invalid header name")
        if value.lower() not in {"subject", "content-type"}:
            raise ValueError("unsupported fixture header")
        return value

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ValueError("invalid header value") from None
        if len(encoded) > MAX_GMAIL_HEADER_VALUE_BYTES:
            raise ValueError("header value too large")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("control character in header")
        return value


class _EvidenceSpan(_FrozenStrictModel):
    span_id: UUID
    start_byte: Annotated[StrictInt, Field(ge=0)]
    end_byte: Annotated[StrictInt, Field(gt=0)]
    expected_text: Annotated[
        StrictStr,
        Field(min_length=1, max_length=MAX_GMAIL_EXPECTED_TEXT_BYTES),
    ]

    @model_validator(mode="after")
    def validate_ordered_range(self) -> _EvidenceSpan:
        if self.end_byte <= self.start_byte:
            raise ValueError("invalid evidence range")
        return self


class _MessageBody(_FrozenStrictModel):
    size: Annotated[StrictInt, Field(ge=0, le=MAX_GMAIL_BODY_BYTES)]
    data: Annotated[StrictStr, Field(max_length=MAX_GMAIL_ENCODED_BODY_CHARS)]


class _Payload(_FrozenStrictModel):
    mimeType: Literal["text/plain"]
    filename: Literal[""]
    headers: tuple[_Header, ...] = Field(min_length=1, max_length=MAX_GMAIL_HEADER_COUNT)
    body: _MessageBody

    @model_validator(mode="after")
    def validate_fixture_headers(self) -> _Payload:
        names = [header.name.lower() for header in self.headers]
        if names.count("subject") != 1 or names.count("content-type") > 1:
            raise ValueError("invalid fixture headers")
        if len(set(names)) != len(names):
            raise ValueError("duplicate fixture headers")
        subjects = [header for header in self.headers if header.name.lower() == "subject"]
        if len(subjects[0].value.encode("utf-8", errors="strict")) > MAX_GMAIL_SUBJECT_BYTES:
            raise ValueError("fixture subject too large")
        content_types = [
            header.value
            for header in self.headers
            if header.name.lower() == "content-type"
        ]
        if content_types and _CONTENT_TYPE_PATTERN.fullmatch(content_types[0].strip()) is None:
            raise ValueError("unsupported fixture content type")
        return self


class _GmailMessage(_FrozenStrictModel):
    id: Annotated[StrictStr, Field(min_length=1, max_length=MAX_GMAIL_MESSAGE_ID_BYTES)]
    threadId: Annotated[StrictStr, Field(min_length=1, max_length=MAX_GMAIL_MESSAGE_ID_BYTES)]
    internalDate: Annotated[StrictStr, Field(min_length=1, max_length=13)]
    payload: _Payload

    @field_validator("id", "threadId")
    @classmethod
    def validate_opaque_id(cls, value: str) -> str:
        if _OPAQUE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("invalid opaque message identifier")
        return value

    @field_validator("internalDate")
    @classmethod
    def validate_internal_date(cls, value: str) -> str:
        if not value.isascii() or not value.isdecimal():
            raise ValueError("invalid epoch millisecond string")
        if len(value) > 1 and value.startswith("0"):
            raise ValueError("non-canonical epoch millisecond string")
        if int(value) > MAX_GMAIL_INTERNAL_DATE_MS:
            raise ValueError("epoch millisecond value outside fixture bounds")
        return value


class _FixtureMessage(_FrozenStrictModel):
    message: _GmailMessage
    evidence_spans: tuple[_EvidenceSpan, ...] = Field(max_length=MAX_GMAIL_SPANS_PER_MESSAGE)

    @model_validator(mode="after")
    def validate_unique_span_ids(self) -> _FixtureMessage:
        ids = [span.span_id for span in self.evidence_spans]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate evidence span identifier")
        return self


class _FixtureDocument(_FrozenStrictModel):
    fixture_version: Literal["sentinel.gmail-messages-fixture.v1"]
    mailbox_alias: Annotated[
        StrictStr,
        Field(min_length=3, max_length=MAX_GMAIL_MAILBOX_ALIAS_BYTES),
    ]
    messages: tuple[_FixtureMessage, ...] = Field(min_length=1, max_length=MAX_GMAIL_MESSAGES)

    @field_validator("mailbox_alias")
    @classmethod
    def validate_mailbox_alias(cls, value: str) -> str:
        if _MAILBOX_ALIAS_PATTERN.fullmatch(value) is None:
            raise ValueError("invalid synthetic mailbox alias")
        return value

    @model_validator(mode="after")
    def reject_duplicate_messages(self) -> _FixtureDocument:
        ids = [item.message.id for item in self.messages]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate message identity")
        return self


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> NoReturn:
    raise ValueError("non-standard JSON constant")


def _read_gmail_fixture_resource() -> bytes:
    """Read the fixed packaged resource; no caller-selected path is accepted."""

    return files("sentinel.readers").joinpath(
        "fixtures", "gmail-messages-v1.json"
    ).read_bytes()


def _decode_canonical_base64url(encoded: str) -> bytes:
    if type(encoded) is not str or len(encoded) > MAX_GMAIL_ENCODED_BODY_CHARS:
        raise GmailFixtureError(GmailFixtureErrorCode.INVALID_BASE64URL)
    if _BASE64URL_PATTERN.fullmatch(encoded) is None or len(encoded) % 4 == 1:
        raise GmailFixtureError(GmailFixtureErrorCode.INVALID_BASE64URL)
    try:
        ascii_data = encoded.encode("ascii", errors="strict")
        decoded = base64.b64decode(
            ascii_data + b"=" * (-len(ascii_data) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise GmailFixtureError(GmailFixtureErrorCode.INVALID_BASE64URL) from None
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=")
    if canonical != ascii_data:
        raise GmailFixtureError(GmailFixtureErrorCode.INVALID_BASE64URL)
    if len(decoded) > MAX_GMAIL_BODY_BYTES:
        raise GmailFixtureError(GmailFixtureErrorCode.INVALID_BODY)
    return decoded


def _mailbox_message_source_id(mailbox_alias: str, message_id: str) -> UUID:
    return uuid5(
        GMAIL_FIXTURE_NAMESPACE,
        f"sentinel:gmail.fixture:{mailbox_alias}#{message_id}",
    )


def _to_internal_date(epoch_milliseconds: str) -> datetime:
    return _EPOCH + timedelta(milliseconds=int(epoch_milliseconds))


def _parse_fixture_bytes(
    raw_json: bytes,
    *,
    observed_at: datetime = GMAIL_FIXTURE_OBSERVED_AT,
) -> GmailFixtureRead:
    """Strictly validate bytes and create normalized, source-bound message records."""

    if type(raw_json) is not bytes or len(raw_json) > MAX_GMAIL_FIXTURE_BYTES:
        raise GmailFixtureError(GmailFixtureErrorCode.INVALID_FIXTURE)
    if (
        type(observed_at) is not datetime
        or observed_at.tzinfo is None
        or observed_at.utcoffset() is None
    ):
        raise GmailFixtureError(GmailFixtureErrorCode.INVALID_OBSERVED_AT)

    try:
        decoded_json = raw_json.decode("utf-8", errors="strict")
        json.loads(
            decoded_json,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
        document = _FixtureDocument.model_validate_json(raw_json, strict=True)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
        ValidationError,
    ):
        raise GmailFixtureError(GmailFixtureErrorCode.INVALID_FIXTURE) from None

    messages: list[GmailFixtureMessage] = []
    for fixture_message in document.messages:
        message = fixture_message.message
        payload = message.payload
        try:
            subject = next(
                header.value for header in payload.headers if header.name.lower() == "subject"
            )
            subject.encode("utf-8", errors="strict")
        except (StopIteration, UnicodeEncodeError):
            raise GmailFixtureError(GmailFixtureErrorCode.INVALID_FIXTURE) from None

        body_bytes = _decode_canonical_base64url(payload.body.data)
        if len(body_bytes) != payload.body.size:
            raise GmailFixtureError(GmailFixtureErrorCode.INVALID_BODY)
        try:
            body_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise GmailFixtureError(GmailFixtureErrorCode.INVALID_BODY) from None

        descriptor = PlainTextSourceDescriptor(
            source_id=_mailbox_message_source_id(document.mailbox_alias, message.id),
            provider_id="gmail.fixture",
            observed_at=observed_at,
            trust=TrustLabel.T4_EXTERNAL,
            sensitivity=SensitivityLabel.PRIVATE,
        )
        try:
            normalized = normalize_plain_text(
                descriptor,
                body_bytes,
                "text/plain; charset=utf-8",
            )
        except NormalizationError:
            raise GmailFixtureError(GmailFixtureErrorCode.INVALID_BODY) from None

        try:
            for evidence in fixture_message.evidence_spans:
                normalized = add_citation(
                    normalized,
                    span_id=evidence.span_id,
                    start_byte=evidence.start_byte,
                    end_byte=evidence.end_byte,
                    expected_text=evidence.expected_text,
                )
            citations = tuple(bind_citation(normalized, span) for span in normalized.citations)
            for evidence, citation in zip(
                fixture_message.evidence_spans,
                citations,
                strict=True,
            ):
                verify_bound_citation(
                    normalized,
                    citation,
                    expected_text=evidence.expected_text,
                )
        except (NormalizationError, ValueError):
            raise GmailFixtureError(GmailFixtureErrorCode.INVALID_CITATION) from None

        messages.append(
            GmailFixtureMessage(
                mailbox_alias=document.mailbox_alias,
                message_id=message.id,
                thread_id=message.threadId,
                internal_date=_to_internal_date(message.internalDate),
                subject=subject,
                normalized_source=normalized,
                citations=citations,
            )
        )

    return GmailFixtureRead(
        mailbox_alias=document.mailbox_alias,
        fixture_version=document.fixture_version,
        fixture_sha256=hashlib.sha256(raw_json).hexdigest(),
        messages=tuple(messages),
    )


def read_packaged_gmail_fixture() -> GmailFixtureRead:
    """Read one pinned package resource and return validated in-memory messages."""

    try:
        raw_json = _read_gmail_fixture_resource()
    except Exception:
        raise GmailFixtureError(GmailFixtureErrorCode.FIXTURE_UNAVAILABLE) from None
    if type(raw_json) is not bytes or len(raw_json) > MAX_GMAIL_FIXTURE_BYTES:
        raise GmailFixtureError(GmailFixtureErrorCode.INVALID_FIXTURE)
    if hashlib.sha256(raw_json).hexdigest() != GMAIL_FIXTURE_SHA256:
        raise GmailFixtureError(GmailFixtureErrorCode.FIXTURE_HASH_MISMATCH)
    return _parse_fixture_bytes(raw_json, observed_at=GMAIL_FIXTURE_OBSERVED_AT)


__all__ = [
    "GMAIL_FIXTURE_OBSERVED_AT",
    "GMAIL_FIXTURE_SCHEMA_VERSION",
    "GMAIL_FIXTURE_SHA256",
    "MAX_GMAIL_BODY_BYTES",
    "MAX_GMAIL_FIXTURE_BYTES",
    "GmailFixtureError",
    "GmailFixtureErrorCode",
    "GmailFixtureMessage",
    "GmailFixtureRead",
    "read_packaged_gmail_fixture",
]
