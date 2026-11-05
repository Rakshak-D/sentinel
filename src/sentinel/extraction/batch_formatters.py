"""Deterministic, citation-validating formatters for job-alert batches."""

from __future__ import annotations

import json
from typing import Final, cast

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.extraction.batch import _correlation_groups
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
from sentinel.extraction.types import JobAlertFieldState, JobAlertStatus

MAX_RENDERED_OUTPUT_BYTES: Final = 128 * 1024
_STATUS_KEYS: Final = {
    JobAlertStatus.CANDIDATE: "candidate",
    JobAlertStatus.INCOMPLETE: "incomplete",
    JobAlertStatus.AMBIGUOUS: "ambiguous",
    JobAlertStatus.NO_MATCH: "no_match",
}


def _fail() -> None:
    raise JobAlertReviewError(JobAlertReviewErrorCode.SOURCE_INVALID) from None


def _document(review: JobAlertBatchReview, *, show_fields: bool) -> dict[str, object]:
    if (
        type(review) is not JobAlertBatchReview
        or type(show_fields) is not bool
        or review.schema_version != "sentinel.job-alert-batch-review.v1"
        or review.review_mode != "explicit_local_job_alert_batch"
        or review.synthetic_data is not False
        or review.trust is not TrustLabel.T4_EXTERNAL
        or review.sensitivity is not SensitivityLabel.PRIVATE
        or type(review.files) is not tuple
        or not 1 <= len(review.files) <= 8
        or review.selected_file_count != len(review.files)
        or type(review.classification_counts) is not JobAlertClassificationCounts
        or type(review.correlation_groups) is not tuple
    ):
        _fail()

    statuses = {key: 0 for key in _STATUS_KEYS.values()}
    file_documents: list[dict[str, object]] = []
    verified_fields = 0
    files_with_url = 0
    files_with_deadline = 0
    ordinals: set[int] = set()
    for expected_ordinal, reviewed_file in enumerate(review.files, start=1):
        if (
            type(reviewed_file) is not JobAlertReviewedFile
            or type(reviewed_file.ordinal) is not int
            or reviewed_file.ordinal != expected_ordinal
        ):
            _fail()
        if expected_ordinal in ordinals:
            _fail()
        ordinals.add(expected_ordinal)
        try:
            parsed = json.loads(
                format_json_job_alert(reviewed_file.result, show_fields=show_fields)
            )
        except Exception:
            _fail()
        if type(parsed) is not dict or parsed.get("source_id") != str(reviewed_file.source_id):
            _fail()
        status = reviewed_file.status
        if status not in _STATUS_KEYS:
            _fail()
        statuses[_STATUS_KEYS[status]] += 1
        parsed_fields = parsed.get("fields")
        if type(parsed_fields) is not list or len(parsed_fields) != 5:
            _fail()
        for field_document in parsed_fields:
            if type(field_document) is not dict:
                _fail()
            if field_document.get("state") == JobAlertFieldState.PRESENT.value:
                verified_fields += 1
                if field_document.get("field_id") == "application_url":
                    files_with_url += 1
                if field_document.get("field_id") == "deadline":
                    files_with_deadline += 1
        file_documents.append(
            {
                "file_ordinal": expected_ordinal,
                "source_id": str(reviewed_file.source_id),
                "content_sha256": reviewed_file.content_sha256,
                "byte_length": reviewed_file.byte_length,
                "classification": status.value,
                "fields": parsed_fields,
            }
        )

    actual_counts = review.classification_counts
    if (
        type(actual_counts.candidate) is not int
        or type(actual_counts.incomplete) is not int
        or type(actual_counts.ambiguous) is not int
        or type(actual_counts.no_match) is not int
        or actual_counts.candidate != statuses["candidate"]
        or actual_counts.incomplete != statuses["incomplete"]
        or actual_counts.ambiguous != statuses["ambiguous"]
        or actual_counts.no_match != statuses["no_match"]
        or review.verified_field_count != verified_fields
        or review.citation_count != verified_fields
        or review.files_with_application_url != files_with_url
        or review.files_with_explicit_deadline != files_with_deadline
    ):
        _fail()

    groups: list[dict[str, object]] = []
    try:
        expected_groups = _correlation_groups(review.files)
    except Exception:
        _fail()
    if review.correlation_groups != expected_groups:
        _fail()
    for group in review.correlation_groups:
        if (
            type(group) is not JobAlertCorrelationGroup
            or type(group.member_file_ordinals) is not tuple
            or type(group.member_source_ids) is not tuple
            or group.member_count != len(group.member_file_ordinals)
            or group.member_count < 2
            or len(group.member_source_ids) != group.member_count
            or any(
                type(ordinal) is not int or ordinal not in ordinals
                for ordinal in group.member_file_ordinals
            )
            or type(group.kind) is not JobAlertCorrelationKind
        ):
            _fail()
        payload: dict[str, object] = {
            "group_id": group.group_id,
            "kind": group.kind.value,
            "member_file_ordinals": list(group.member_file_ordinals),
            "member_source_ids": list(group.member_source_ids),
            "member_count": group.member_count,
        }
        if group.kind is JobAlertCorrelationKind.EXACT_SOURCE_CONTENT:
            if type(group.content_sha256) is not str or len(group.content_sha256) != 64:
                _fail()
            payload["content_sha256"] = group.content_sha256
        elif group.content_sha256 is not None:
            _fail()
        groups.append(payload)

    return {
        "schema_version": "sentinel.job-alert-batch-review.v1",
        "review_mode": "explicit_local_job_alert_batch",
        "synthetic_data": False,
        "trust": TrustLabel.T4_EXTERNAL.value,
        "sensitivity": SensitivityLabel.PRIVATE.value,
        "selected_file_count": len(file_documents),
        "classification_counts": statuses,
        "verified_field_count": verified_fields,
        "citation_count": verified_fields,
        "files_with_application_url": files_with_url,
        "files_with_explicit_deadline": files_with_deadline,
        "values_included": show_fields,
        "files": file_documents,
        "correlation_groups": groups,
        "disclaimer": (
            "Classifications are bounded extraction results, not verified vacancies, "
            "eligibility, legitimacy, or application readiness. "
            "Correlation groups do not merge records."
        ),
    }


def _bounded_output(value: str) -> str:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail()
    if len(encoded) > MAX_RENDERED_OUTPUT_BYTES:
        raise JobAlertReviewError(JobAlertReviewErrorCode.OUTPUT_TOO_LARGE) from None
    return value


def format_json_job_alert_batch(
    review: JobAlertBatchReview,
    *,
    show_fields: bool = False,
) -> str:
    """Render all records as versioned deterministic JSON after citation checks."""
    payload = _document(review, show_fields=show_fields)
    try:
        encoded = json.dumps(
            payload, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        )
    except (TypeError, ValueError):
        _fail()
    return _bounded_output(encoded)


def format_text_job_alert_batch(
    review: JobAlertBatchReview,
    *,
    show_fields: bool = False,
) -> str:
    """Render a compact body-free review; values require explicit opt-in."""
    payload = _document(review, show_fields=show_fields)
    counts = cast(dict[str, int], payload["classification_counts"])
    lines = [
        "Sentinel - Local job-alert batch review",
        "Source: explicitly selected local files | Trust: T4_EXTERNAL | Sensitivity: PRIVATE",
        "This is cited extraction only; vacancies, legitimacy, eligibility and readiness "
        "are unverified.",
        f"Files: {payload['selected_file_count']} | Candidate: {counts['candidate']} | "
        f"Incomplete: {counts['incomplete']} | Ambiguous: {counts['ambiguous']} | "
        f"No match: {counts['no_match']}",
        f"Present fields: {payload['verified_field_count']} | "
        f"Verified citations: {payload['citation_count']} | "
        f"Values included: {'yes' if show_fields else 'no'}",
    ]
    for item in cast(list[dict[str, object]], payload["files"]):
        lines.extend(
            [
                "",
                f"File {item['file_ordinal']} | {item['classification']} | "
                f"Source {item['source_id']} | SHA-256 {item['content_sha256']} | "
                f"{item['byte_length']} bytes",
            ]
        )
        for field_document in cast(list[dict[str, object]], item["fields"]):
            line = f"  {field_document['field_id']}: {field_document['state']}"
            citation = field_document.get("citation")
            if citation is not None:
                citation_doc = cast(dict[str, object], citation)
                line += (
                    f" [bytes {citation_doc['start_byte']}:{citation_doc['end_byte']}; "
                    f"span {citation_doc['span_id']}; sha256 {citation_doc['text_sha256']}]"
                )
            if show_fields and "value" in field_document:
                line += f' = "{field_document["value"]}"'
            lines.append(line)
    groups = cast(list[dict[str, object]], payload["correlation_groups"])
    if groups:
        lines.extend(["", "Correlation signals (records are not merged):"])
        for group in groups:
            member_ordinals = cast(list[object], group["member_file_ordinals"])
            members = ", ".join(str(item) for item in member_ordinals)
            lines.append(
                f"  {group['group_id']} | {group['kind']} | members {members} | "
                f"count {group['member_count']}"
            )
    return _bounded_output("\n".join(lines))


__all__ = [
    "MAX_RENDERED_OUTPUT_BYTES",
    "format_json_job_alert_batch",
    "format_text_job_alert_batch",
]
