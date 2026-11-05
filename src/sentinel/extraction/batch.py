"""Bounded batch review of explicitly selected local job-alert sources."""

from __future__ import annotations

import ntpath
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Final, cast
from uuid import UUID

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.extraction.batch_types import (
    JobAlertBatchReview,
    JobAlertClassificationCounts,
    JobAlertCorrelationGroup,
    JobAlertCorrelationKind,
    JobAlertReviewedFile,
    JobAlertReviewError,
    JobAlertReviewErrorCode,
)
from sentinel.extraction.formatters import format_json_job_alert
from sentinel.extraction.job_alert import parse_local_job_alert
from sentinel.extraction.types import (
    JobAlertError,
    JobAlertField,
    JobAlertFieldName,
    JobAlertFieldState,
    JobAlertParseResult,
    JobAlertStatus,
)
from sentinel.readers.local_text import read_allowlisted_local_text
from sentinel.readers.local_text_types import LocalTextError, LocalTextRead

MAX_SELECTED_FILES: Final = 8
MAX_SOURCE_BYTES: Final = 64 * 1024
MAX_TOTAL_SOURCE_BYTES: Final = MAX_SELECTED_FILES * MAX_SOURCE_BYTES


def _fail(code: JobAlertReviewErrorCode) -> None:
    raise JobAlertReviewError(code) from None


def _selection(value: object) -> tuple[str | Path, ...]:
    if type(value) not in (list, tuple):
        _fail(JobAlertReviewErrorCode.INVALID_SELECTION)
    paths = cast(Sequence[object], value)
    if not paths:
        _fail(JobAlertReviewErrorCode.INVALID_SELECTION)
    if len(paths) > MAX_SELECTED_FILES:
        _fail(JobAlertReviewErrorCode.TOO_MANY_FILES)
    if any(type(path) is not str and not isinstance(path, Path) for path in paths):
        _fail(JobAlertReviewErrorCode.INVALID_SELECTION)
    return cast(tuple[str | Path, ...], tuple(paths))


def _validate_local_read(value: object) -> LocalTextRead:
    if type(value) is not LocalTextRead:
        _fail(JobAlertReviewErrorCode.SOURCE_INVALID)
    source = cast(LocalTextRead, value)
    if (
        type(source._relative_identity) is not str
        or not source._relative_identity
        or type(source.normalized_source.original_bytes) is not bytes
        or type(source.source_id) is not UUID
        or source.provider_id != "local.file"
        or source.trust is not TrustLabel.T4_EXTERNAL
        or source.sensitivity is not SensitivityLabel.PRIVATE
        or source.byte_length != len(source.normalized_source.original_bytes)
        or source.normalized_source.envelope.source_id != source.source_id
        or source.normalized_source.envelope.content_sha256 != source.content_sha256
    ):
        _fail(JobAlertReviewErrorCode.SOURCE_INVALID)
    raw = source.normalized_source.original_bytes
    if len(raw) > MAX_SOURCE_BYTES:
        _fail(JobAlertReviewErrorCode.SOURCE_INVALID)
    try:
        if raw.decode("utf-8", errors="strict") != source.normalized_source.text:
            _fail(JobAlertReviewErrorCode.SOURCE_INVALID)
    except UnicodeError:
        _fail(JobAlertReviewErrorCode.SOURCE_INVALID)
    return source


def _validate_parse_result(value: object, source: LocalTextRead) -> JobAlertParseResult:
    if type(value) is not JobAlertParseResult:
        _fail(JobAlertReviewErrorCode.SOURCE_CHANGED)
    result = cast(JobAlertParseResult, value)
    if (
        result.provider_id != "local.file"
        or result.synthetic_data is not False
        or result.trust is not TrustLabel.T4_EXTERNAL
        or result.sensitivity is not SensitivityLabel.PRIVATE
        or result.source_id != source.source_id
        or result.content_sha256 != source.content_sha256
        or result.byte_length != source.byte_length
        or result.normalized_source.original_bytes != source.normalized_source.original_bytes
        or result.normalized_source.envelope.source_id != source.source_id
    ):
        _fail(JobAlertReviewErrorCode.SOURCE_CHANGED)
    try:
        # The accepted CR1-O formatter validates every PRESENT field citation
        # against the exact source bytes. Do not duplicate that verifier here.
        format_json_job_alert(result, show_fields=False)
    except JobAlertError:
        _fail(JobAlertReviewErrorCode.SOURCE_INVALID)
    return result


def _same_source(before: LocalTextRead, after_value: object) -> bool:
    if type(after_value) is not LocalTextRead:
        return False
    after = after_value
    return (
        ntpath.normcase(before._relative_identity) == ntpath.normcase(after._relative_identity)
        and before.source_id == after.source_id
        and before.content_sha256 == after.content_sha256
        and before.byte_length == after.byte_length
        and before.normalized_source.original_bytes == after.normalized_source.original_bytes
    )


def _field(result: JobAlertParseResult, name: JobAlertFieldName) -> JobAlertField | None:
    return next((item for item in result.fields if item.field_id is name), None)


def _correlation_groups(
    files: tuple[JobAlertReviewedFile, ...],
) -> tuple[JobAlertCorrelationGroup, ...]:
    by_content: dict[tuple[str, bytes], list[JobAlertReviewedFile]] = defaultdict(list)
    by_url: dict[str, list[JobAlertReviewedFile]] = defaultdict(list)
    for item in files:
        raw = item.result.normalized_source.original_bytes
        by_content[(item.content_sha256, raw)].append(item)
        if item.status is JobAlertStatus.CANDIDATE:
            url = _field(item.result, JobAlertFieldName.APPLICATION_URL)
            if (
                url is not None
                and url.state is JobAlertFieldState.PRESENT
                and url.value is not None
            ):
                by_url[url.value].append(item)

    groups: list[JobAlertCorrelationGroup] = []
    content_sets = sorted(
        (members for members in by_content.values() if len(members) > 1),
        key=lambda members: min(member.ordinal for member in members),
    )
    for index, members in enumerate(content_sets, start=1):
        groups.append(
            JobAlertCorrelationGroup(
                group_id=f"source-content-{index:03d}",
                kind=JobAlertCorrelationKind.EXACT_SOURCE_CONTENT,
                member_file_ordinals=tuple(member.ordinal for member in members),
                member_source_ids=tuple(str(member.source_id) for member in members),
                member_count=len(members),
                content_sha256=members[0].content_sha256,
            )
        )

    url_sets = sorted(
        (members for members in by_url.values() if len(members) > 1),
        key=lambda members: min(member.ordinal for member in members),
    )
    for index, members in enumerate(url_sets, start=1):
        groups.append(
            JobAlertCorrelationGroup(
                group_id=f"application-url-{index:03d}",
                kind=JobAlertCorrelationKind.SHARED_APPLICATION_URL,
                member_file_ordinals=tuple(member.ordinal for member in members),
                member_source_ids=tuple(str(member.source_id) for member in members),
                member_count=len(members),
            )
        )
    return tuple(groups)


def review_selected_job_alerts(
    *,
    allowed_root: str | Path,
    file_paths: Sequence[str | Path],
) -> JobAlertBatchReview:
    """Review 1–8 explicitly selected files without merging or persisting records.

    Every file goes through CR1-M path validation and CR1-O parsing/citation
    validation. A final bounded read detects many changes during assembly, but
    this is not an atomic multi-file snapshot or an ABA defense.
    """
    selected = _selection(file_paths)
    if type(allowed_root) is not str and not isinstance(allowed_root, Path):
        _fail(JobAlertReviewErrorCode.INVALID_SELECTION)

    sources: list[LocalTextRead] = []
    reviewed: list[JobAlertReviewedFile] = []
    identities: set[str] = set()
    total_bytes = 0
    try:
        for ordinal, path in enumerate(selected, start=1):
            source = _validate_local_read(
                read_allowlisted_local_text(allowed_root=allowed_root, file_path=path)
            )
            identity = ntpath.normcase(source._relative_identity)
            if identity in identities:
                _fail(JobAlertReviewErrorCode.DUPLICATE_FILE)
            identities.add(identity)
            total_bytes += source.byte_length
            if total_bytes > MAX_TOTAL_SOURCE_BYTES:
                _fail(JobAlertReviewErrorCode.SOURCE_INVALID)
            try:
                parsed = parse_local_job_alert(allowed_root=allowed_root, file_path=path)
            except (JobAlertError, LocalTextError, OSError):
                _fail(JobAlertReviewErrorCode.SOURCE_INVALID)
            result = _validate_parse_result(parsed, source)
            sources.append(source)
            reviewed.append(JobAlertReviewedFile(ordinal=ordinal, result=result))
    except JobAlertReviewError:
        raise
    except Exception:
        _fail(JobAlertReviewErrorCode.SOURCE_INVALID)

    files = tuple(reviewed)
    counts = {status: 0 for status in JobAlertStatus}
    verified_fields = 0
    files_with_url = 0
    files_with_deadline = 0
    for item in files:
        counts[item.status] += 1
        present = [
            field for field in item.result.fields if field.state is JobAlertFieldState.PRESENT
        ]
        verified_fields += len(present)
        url = _field(item.result, JobAlertFieldName.APPLICATION_URL)
        deadline = _field(item.result, JobAlertFieldName.DEADLINE)
        files_with_url += int(url is not None and url.state is JobAlertFieldState.PRESENT)
        files_with_deadline += int(
            deadline is not None and deadline.state is JobAlertFieldState.PRESENT
        )
    groups = _correlation_groups(files)

    # CR1-M reread per selected file rejects detectable identity, digest,
    # length, and byte changes; it makes no single-snapshot claim.
    for path, original in zip(selected, sources, strict=True):
        try:
            current = read_allowlisted_local_text(allowed_root=allowed_root, file_path=path)
        except Exception:
            _fail(JobAlertReviewErrorCode.SOURCE_CHANGED)
        try:
            unchanged = _same_source(original, current)
        except Exception:
            unchanged = False
        if not unchanged:
            _fail(JobAlertReviewErrorCode.SOURCE_CHANGED)

    return JobAlertBatchReview(
        schema_version="sentinel.job-alert-batch-review.v1",
        review_mode="explicit_local_job_alert_batch",
        synthetic_data=False,
        trust=TrustLabel.T4_EXTERNAL,
        sensitivity=SensitivityLabel.PRIVATE,
        selected_file_count=len(files),
        classification_counts=JobAlertClassificationCounts(
            candidate=counts[JobAlertStatus.CANDIDATE],
            incomplete=counts[JobAlertStatus.INCOMPLETE],
            ambiguous=counts[JobAlertStatus.AMBIGUOUS],
            no_match=counts[JobAlertStatus.NO_MATCH],
        ),
        verified_field_count=verified_fields,
        citation_count=verified_fields,
        files_with_application_url=files_with_url,
        files_with_explicit_deadline=files_with_deadline,
        files=files,
        correlation_groups=groups,
    )


__all__ = ["review_selected_job_alerts"]
