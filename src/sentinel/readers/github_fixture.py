"""Strict reader for one pinned, fictional GitHub-style issue collection."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from importlib.resources import files
from typing import Annotated, Final, Literal, NoReturn
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import (
    AwareDatetime,
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
    GithubFixtureError,
    GithubFixtureErrorCode,
    GithubFixtureIssue,
    GithubFixtureRead,
)

FIXTURE_SCHEMA_VERSION: Final = "sentinel.github-issues-fixture.v1"
FIXTURE_OBSERVED_AT: Final = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)
FIXTURE_SHA256: Final = "7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1"
GITHUB_FIXTURE_NAMESPACE: Final = NAMESPACE_URL

MAX_FIXTURE_BYTES: Final = 64 * 1024
MAX_ISSUES: Final = 16
MAX_TITLE_BYTES: Final = 1024
MAX_BODY_BYTES: Final = 32 * 1024
MAX_SPANS_PER_ISSUE: Final = 32
MAX_EXPECTED_TEXT_BYTES: Final = 4096

_REPOSITORY_PATTERN: Final = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?/"
    r"[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?$"
)


class _FrozenStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _EvidenceSpan(_FrozenStrictModel):
    span_id: UUID
    start_byte: Annotated[StrictInt, Field(ge=0)]
    end_byte: Annotated[StrictInt, Field(gt=0)]
    expected_text: Annotated[StrictStr, Field(min_length=1, max_length=MAX_EXPECTED_TEXT_BYTES)]

    @model_validator(mode="after")
    def validate_ordered_range(self) -> _EvidenceSpan:
        if self.end_byte <= self.start_byte:
            raise ValueError("invalid evidence range")
        return self


class _IssueDocument(_FrozenStrictModel):
    repository: Annotated[StrictStr, Field(min_length=3, max_length=140)]
    issue_number: Annotated[StrictInt, Field(gt=0)]
    updated_at: AwareDatetime
    title: Annotated[StrictStr, Field(min_length=1, max_length=MAX_TITLE_BYTES)]
    body: Annotated[StrictStr, Field(min_length=1, max_length=MAX_BODY_BYTES)]
    evidence_spans: tuple[_EvidenceSpan, ...] = Field(max_length=MAX_SPANS_PER_ISSUE)

    @field_validator("repository")
    @classmethod
    def validate_repository(cls, value: str) -> str:
        if _REPOSITORY_PATTERN.fullmatch(value) is None:
            raise ValueError("invalid repository identifier")
        return value

    @model_validator(mode="after")
    def validate_span_ids(self) -> _IssueDocument:
        if len({span.span_id for span in self.evidence_spans}) != len(self.evidence_spans):
            raise ValueError("duplicate span identifier")
        return self


class _FixtureDocument(_FrozenStrictModel):
    fixture_version: Literal["sentinel.github-issues-fixture.v1"]
    issues: tuple[_IssueDocument, ...] = Field(min_length=1, max_length=MAX_ISSUES)

    @model_validator(mode="after")
    def validate_unique_issue_ids(self) -> _FixtureDocument:
        identities = [(issue.repository, issue.issue_number) for issue in self.issues]
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate issue identity")
        return self


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("non-standard JSON constant")


def _read_fixture_resource() -> bytes:
    """Read only the fixed packaged resource, never a caller-selected path."""

    return files("sentinel.readers").joinpath("fixtures", "github-issues-v1.json").read_bytes()


def _parse_fixture_bytes(
    raw_json: bytes,
    *,
    observed_at: datetime = FIXTURE_OBSERVED_AT,
) -> GithubFixtureRead:
    """Strict schema conversion helper; the public reader pins bytes before calling it."""

    if type(raw_json) is not bytes or len(raw_json) > MAX_FIXTURE_BYTES:
        raise GithubFixtureError(GithubFixtureErrorCode.INVALID_FIXTURE)
    if (
        type(observed_at) is not datetime
        or observed_at.tzinfo is None
        or observed_at.utcoffset() is None
    ):
        raise GithubFixtureError(GithubFixtureErrorCode.INVALID_OBSERVED_AT)

    try:
        text = raw_json.decode("utf-8", errors="strict")
        json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
        document = _FixtureDocument.model_validate_json(raw_json, strict=True)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, ValidationError):
        raise GithubFixtureError(GithubFixtureErrorCode.INVALID_FIXTURE) from None

    for issue in document.issues:
        try:
            title_bytes = issue.title.encode("utf-8", errors="strict")
            body_bytes = issue.body.encode("utf-8", errors="strict")
            evidence_byte_lengths = [
                len(span.expected_text.encode("utf-8", errors="strict"))
                for span in issue.evidence_spans
            ]
        except UnicodeEncodeError:
            raise GithubFixtureError(GithubFixtureErrorCode.INVALID_FIXTURE) from None
        if (
            len(title_bytes) > MAX_TITLE_BYTES
            or len(body_bytes) > MAX_BODY_BYTES
            or any(length > MAX_EXPECTED_TEXT_BYTES for length in evidence_byte_lengths)
        ):
            raise GithubFixtureError(GithubFixtureErrorCode.INVALID_FIXTURE)

    output: list[GithubFixtureIssue] = []
    for issue in document.issues:
        source_id = uuid5(
            GITHUB_FIXTURE_NAMESPACE,
            f"sentinel:github.fixture:{issue.repository}#{issue.issue_number}",
        )
        descriptor = PlainTextSourceDescriptor(
            source_id=source_id,
            provider_id="github.fixture",
            observed_at=observed_at,
            trust=TrustLabel.T4_EXTERNAL,
            sensitivity=SensitivityLabel.PUBLIC,
        )
        try:
            normalized = normalize_plain_text(
                descriptor,
                issue.body.encode("utf-8", errors="strict"),
                "text/plain; charset=utf-8",
            )
        except NormalizationError:
            raise GithubFixtureError(GithubFixtureErrorCode.INVALID_SOURCE) from None

        try:
            for evidence in issue.evidence_spans:
                normalized = add_citation(
                    normalized,
                    span_id=evidence.span_id,
                    start_byte=evidence.start_byte,
                    end_byte=evidence.end_byte,
                    expected_text=evidence.expected_text,
                )
            citations = tuple(bind_citation(normalized, span) for span in normalized.citations)
            for evidence, citation in zip(issue.evidence_spans, citations, strict=True):
                verify_bound_citation(
                    normalized,
                    citation,
                    expected_text=evidence.expected_text,
                )
        except (NormalizationError, ValueError):
            raise GithubFixtureError(GithubFixtureErrorCode.INVALID_CITATION) from None

        output.append(
            GithubFixtureIssue(
                repository=issue.repository,
                issue_number=issue.issue_number,
                updated_at=issue.updated_at,
                title=issue.title,
                normalized_source=normalized,
                citations=citations,
            )
        )

    return GithubFixtureRead(
        fixture_version=document.fixture_version,
        fixture_sha256=hashlib.sha256(raw_json).hexdigest(),
        issues=tuple(output),
    )


def read_packaged_github_fixture() -> GithubFixtureRead:
    """Load the pinned fixture and return immutable normalized issues and bound citations."""

    try:
        raw_json = _read_fixture_resource()
    except Exception:
        raise GithubFixtureError(GithubFixtureErrorCode.FIXTURE_UNAVAILABLE) from None
    if type(raw_json) is not bytes or len(raw_json) > MAX_FIXTURE_BYTES:
        raise GithubFixtureError(GithubFixtureErrorCode.INVALID_FIXTURE)
    if hashlib.sha256(raw_json).hexdigest() != FIXTURE_SHA256:
        raise GithubFixtureError(GithubFixtureErrorCode.FIXTURE_HASH_MISMATCH)
    return _parse_fixture_bytes(raw_json, observed_at=FIXTURE_OBSERVED_AT)


__all__ = [
    "FIXTURE_OBSERVED_AT",
    "FIXTURE_SCHEMA_VERSION",
    "FIXTURE_SHA256",
    "GITHUB_FIXTURE_NAMESPACE",
    "MAX_BODY_BYTES",
    "MAX_FIXTURE_BYTES",
    "GithubFixtureError",
    "GithubFixtureErrorCode",
    "GithubFixtureIssue",
    "GithubFixtureRead",
    "read_packaged_github_fixture",
]
