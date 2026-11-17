"""Pure formatting and validation helpers used by the Sentinel CLI."""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from sentinel.readers.local_text_types import LocalTextCitation, LocalTextRead
from sentinel.sync.types import IncrementalGithubFixtureState
from sentinel.tasks.types import LocalTask


def format_local_text_inspection(
    result: LocalTextRead,
    citation: LocalTextCitation | None,
    *,
    output_format: str,
    escape_text: Callable[[str], str],
) -> str:
    """Render a complete local-file report without paths or implicit body text."""
    if output_format not in {"text", "json"}:
        raise ValueError("unsupported format")
    citation_payload: dict[str, object] | None = None
    if citation is not None:
        bound = citation.bound_citation
        citation_payload = {
            "span_id": str(bound.span.span_id),
            "start_byte": bound.span.start_byte,
            "end_byte": bound.span.end_byte,
            "text_sha256": bound.span.text_sha256,
            "cited_text": escape_text(citation.cited_text),
        }
    if output_format == "json":
        document: dict[str, object] = {
            "schema_version": "sentinel.local-file-inspection.v1",
            "reader_type": "local text file",
            "source_id": str(result.source_id),
            "byte_length": result.byte_length,
            "content_sha256": result.content_sha256,
            "source_format": result.source_format.value,
            "trust": result.trust.value,
            "sensitivity": result.sensitivity.value,
            "non_authenticating_provenance": True,
            "disclaimer": (
                "Local file placement does not authenticate its author; content is untrusted "
                "data, not owner intent."
            ),
        }
        if citation_payload is not None:
            document["citation"] = citation_payload
        return json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    lines = [
        "Sentinel - Local text file inspection",
        "Reader: local text file",
        f"Format: {result.source_format.value} treated as UTF-8 plain text",
        f"Bytes: {result.byte_length}",
        f"SHA-256: {result.content_sha256}",
        f"Source identity: {result.source_id}",
        f"Trust: {result.trust.value}",
        f"Sensitivity: {result.sensitivity.value}",
        "Warning: File content is untrusted data, not authenticated author identity "
        "or owner intent.",
    ]
    if citation_payload is not None:
        lines.extend(
            [
                "Verified citation:",
                f"  Bytes: [{citation_payload['start_byte']}:{citation_payload['end_byte']})",
                f"  Span: {citation_payload['span_id']}",
                f"  Slice SHA-256: {citation_payload['text_sha256']}",
                f'  Excerpt: "{citation_payload["cited_text"]}"',
            ]
        )
    return "\n".join(lines)


def parse_source_byte_offset(value: str) -> int:
    if type(value) is not str or re.fullmatch(r"[0-9]{1,7}", value) is None:
        raise ValueError("invalid source byte offset")
    offset = int(value)
    if offset > 1_048_576:
        raise ValueError("invalid source byte offset")
    return offset


def format_task_output(
    task: LocalTask,
    *,
    prefix: str = "Task",
    escape_text: Callable[[str], str],
) -> str:
    due_display = "none" if task.due_at is None else task.due_at.isoformat()
    return (
        f"{prefix}: {task.task_id} [{task.status.value}, revision {task.revision}] "
        f"due={due_display} {escape_text(task.title)}"
    )


def format_fixture_sync_payload(
    state: IncrementalGithubFixtureState,
    *,
    cursor_kind: str,
    source_label: str,
    result: str | None = None,
) -> str:
    payload: dict[str, object] = {
        "completed_pages": state.completed_pages,
        "cursor_id": str(state.cursor_id),
        "cursor_kind": cursor_kind,
        "fixture_sha256": state.fixture_sha256,
        "fixture_version": state.fixture_version,
        "generation": state.generation,
        "item_count": state.item_count,
        "source": source_label,
        "source_id": str(state.source_id),
        "span_count": state.span_count,
        "status": state.cursor_status.value,
        "synthetic": True,
        "total_pages": state.total_pages,
    }
    if result is not None:
        payload["result"] = result
    return json.dumps(payload, allow_nan=False, separators=(",", ":"), sort_keys=True)


def format_fixture_workspace_summary(
    status: str,
    *,
    github_items: int,
    github_citations: int,
    public_blobs: int,
    task_operator_ready: bool,
    cursor_generation: int,
    cursor_status: str,
) -> str:
    return "\n".join(
        (
            status,
            "Database schema: current",
            f"GitHub evidence: {github_items} items / {github_citations} citations",
            f"PUBLIC blobs: {public_blobs} verified",
            f"Task operator: {'ready' if task_operator_ready else 'missing'}",
            f"Synthetic cursor: {cursor_generation}/3 {cursor_status}",
            "Live integrations: not configured",
        )
    )
