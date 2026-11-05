"""Bounded deterministic renderers for private, cited job-alert triage."""

from __future__ import annotations

import json
from typing import Final, cast

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.extraction import format_json_job_alert
from sentinel.extraction.types import JobAlertFieldState
from sentinel.triage.job_alert import validate_job_alert_triage
from sentinel.triage.types import (
    JobAlertSignalKind,
    JobAlertTriage,
    JobAlertTriageError,
    JobAlertTriageErrorCode,
)

MAX_TRIAGE_OUTPUT_BYTES: Final = 128 * 1024
_SIGNAL_ORDER: Final = (
    JobAlertSignalKind.JOB_ALERT_CANDIDATE,
    JobAlertSignalKind.APPLICATION_URL_DECLARED,
    JobAlertSignalKind.DEADLINE_DATE_DECLARED,
)


def _fail(code: JobAlertTriageErrorCode = JobAlertTriageErrorCode.INVALID_RESULT) -> None:
    raise JobAlertTriageError(code) from None


def _document(triage: JobAlertTriage, *, show_fields: object) -> dict[str, object]:
    if type(show_fields) is not bool:
        _fail()
    show_values = show_fields is True
    verified = validate_job_alert_triage(triage)
    source_items: list[dict[str, object]] = []
    signal_items: list[dict[str, object]] = []
    for item in verified.items:
        try:
            parsed = json.loads(format_json_job_alert(item.result, show_fields=show_values))
        except Exception:
            _fail()
        if type(parsed) is not dict or type(parsed.get("fields")) is not list:
            _fail()
        fields: list[dict[str, object]] = []
        for field_doc in parsed["fields"]:
            if type(field_doc) is not dict:
                _fail()
            field_record: dict[str, object] = {
                "field_id": field_doc.get("field_id"),
                "state": field_doc.get("state"),
                "citation": field_doc.get("citation"),
            }
            if show_values and field_doc.get("state") == JobAlertFieldState.PRESENT.value:
                if type(field_doc.get("value")) is not str:
                    _fail()
                field_record["value"] = field_doc["value"]
            fields.append(field_record)
        source_items.append(
            {
                "file_ordinal": item.ordinal,
                "source_id": str(item.source_id),
                "content_sha256": item.content_sha256,
                "byte_length": item.byte_length,
                "classification": item.classification.value,
                "outcome": item.outcome.value,
                "review_reason": item.review_reason.value if item.review_reason else None,
                "field_issues": [
                    {"field_id": issue.field_id.value, "state": issue.state.value}
                    for issue in item.field_issues
                ],
                "fields": fields,
            }
        )
        for signal in item.signals:
            signal_items.append(
                {
                    "file_ordinal": item.ordinal,
                    "signal_id": str(signal.signal_id),
                    "kind": signal.kind.value,
                    "source_id": str(signal.source_id),
                    "content_sha256": signal.content_sha256,
                    "trust": signal.trust.value,
                    "sensitivity": signal.sensitivity.value,
                    "evidence": [
                        {
                            "field_id": evidence.field_id.value,
                            "source_id": str(evidence.source_id),
                            "content_sha256": evidence.content_sha256,
                            "span_id": str(evidence.span_id),
                            "start_byte": evidence.start_byte,
                            "end_byte": evidence.end_byte,
                            "text_sha256": evidence.text_sha256,
                            "source_trust": evidence.source_trust.value,
                            "source_sensitivity": evidence.source_sensitivity.value,
                        }
                        for evidence in signal.evidence
                    ],
                }
            )

    signal_items.sort(
        key=lambda entry: (
            cast(int, entry["file_ordinal"]),
            _SIGNAL_ORDER.index(JobAlertSignalKind(cast(str, entry["kind"]))),
        )
    )
    return {
        "schema_version": "sentinel.job-alert-triage.v1",
        "triage_mode": "deterministic_cited_field_projection",
        "selected_file_count": verified.selected_file_count,
        "classification_counts": {
            "candidate": verified.classification_counts.candidate,
            "incomplete": verified.classification_counts.incomplete,
            "ambiguous": verified.classification_counts.ambiguous,
            "no_match": verified.classification_counts.no_match,
        },
        "outcome_counts": {
            "evidence_present": verified.outcome_counts.evidence_present,
            "review_required": verified.outcome_counts.review_required,
            "no_signal": verified.outcome_counts.no_signal,
        },
        "signal_counts": {
            "job_alert_candidate": verified.signal_counts.job_alert_candidate,
            "application_url_declared": verified.signal_counts.application_url_declared,
            "deadline_date_declared": verified.signal_counts.deadline_date_declared,
        },
        "signals": signal_items,
        "sources": source_items,
        "values_included": show_values,
        "trust": TrustLabel.T4_EXTERNAL.value,
        "sensitivity": SensitivityLabel.PRIVATE.value,
        "signal_trust": TrustLabel.T3_DERIVED.value,
        "disclaimer": (
            "Signals are deterministic projections of cited external fields. They do not verify "
            "employers, openings, eligibility, deadlines, suitability, owner intent, or actions."
        ),
    }


def _bounded(text: str) -> str:
    try:
        size = len(text.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        _fail()
    if size > MAX_TRIAGE_OUTPUT_BYTES:
        _fail(JobAlertTriageErrorCode.OUTPUT_TOO_LARGE)
    return text


def format_json_job_alert_triage(triage: JobAlertTriage, *, show_fields: bool = False) -> str:
    """Render complete deterministic JSON, optionally disclosing cited field values."""
    document = _document(triage, show_fields=show_fields)
    try:
        text = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        _fail()
    return _bounded(text)


def format_text_job_alert_triage(triage: JobAlertTriage, *, show_fields: bool = False) -> str:
    """Render a compact ordinal-based report without names or values by default."""
    document = _document(triage, show_fields=show_fields)
    classes = cast(dict[str, int], document["classification_counts"])
    outcomes = cast(dict[str, int], document["outcome_counts"])
    lines = [
        "Sentinel - Local job-alert triage",
        "Mode: deterministic cited-field projection | Source: T4_EXTERNAL / PRIVATE",
        "Signals: T3_DERIVED / PRIVATE; no model, employer, eligibility, or opening verification.",
        f"Files: {document['selected_file_count']} | Candidate: {classes['candidate']} | "
        f"Incomplete: {classes['incomplete']} | Ambiguous: {classes['ambiguous']} | "
        f"No match: {classes['no_match']}",
        f"Evidence present: {outcomes['evidence_present']} | "
        f"Review required: {outcomes['review_required']} | No signal: {outcomes['no_signal']}",
        f"Field values included: {'yes' if show_fields else 'no'}",
    ]
    for source in cast(list[dict[str, object]], document["sources"]):
        lines.extend(
            [
                f"File {source['file_ordinal']}: {source['classification']} -> {source['outcome']}",
                f"  Source UUID: {source['source_id']} | SHA-256: {source['content_sha256']}",
            ]
        )
        if source["review_reason"] is not None:
            lines.append(f"  Review reason: {source['review_reason']}")
        for issue in cast(list[dict[str, str]], source["field_issues"]):
            lines.append(f"  Field {issue['field_id']}: {issue['state']}")
        for field_doc in cast(list[dict[str, object]], source["fields"]):
            citation = field_doc["citation"]
            suffix = f" ({field_doc['state']})"
            if type(citation) is dict:
                suffix += (
                    f" [bytes {citation['start_byte']}:{citation['end_byte']}; "
                    f"span {citation['span_id']}; sha256 {citation['text_sha256']}]"
                )
            if show_fields and type(field_doc.get("value")) is str:
                lines.append(f'  {field_doc["field_id"]}: "{field_doc["value"]}"{suffix}')
            else:
                lines.append(f"  Field {field_doc['field_id']}{suffix}")
        for signal in cast(list[dict[str, object]], document["signals"]):
            if signal["file_ordinal"] != source["file_ordinal"]:
                continue
            evidence = cast(list[dict[str, object]], signal["evidence"])
            references = ", ".join(
                f"{item['field_id']}:{item['span_id']}@{item['start_byte']}:{item['end_byte']}"
                for item in evidence
            )
            lines.append(f"  Signal {signal['kind']} {signal['signal_id']} | evidence {references}")
    return _bounded("\n".join(lines))


__all__ = [
    "MAX_TRIAGE_OUTPUT_BYTES",
    "format_json_job_alert_triage",
    "format_text_job_alert_triage",
]
