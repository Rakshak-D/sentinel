"""Minimal command-line entry point for the Sentinel package."""

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID, uuid4

import typer

from sentinel import __version__
from sentinel.bootstrap.doctor import DoctorReport, run_doctor
from sentinel.bootstrap.init import BootstrapInitError, initialize_new_database
from sentinel.briefing import build_github_fixture_brief, format_json_brief, format_text_brief
from sentinel.briefing.formatters import escape_display_text
from sentinel.briefing.types import BriefingError
from sentinel.demo import run_demo
from sentinel.extraction import JobAlertError, parse_local_job_alert
from sentinel.extraction.formatters import format_json_job_alert, format_text_job_alert
from sentinel.ingestion.types import GithubBlobIntegrationError
from sentinel.overview import (
    OverviewError,
    build_local_overview,
    format_json_local_overview,
    format_text_local_overview,
)
from sentinel.overview.assembly import parse_as_of_timestamp
from sentinel.readers.local_search import (
    format_json_local_file_search,
    format_text_local_file_search,
    search_selected_local_text_files,
)
from sentinel.readers.local_search_types import LocalSearchError
from sentinel.readers.local_text import read_allowlisted_local_text, verify_local_text_span
from sentinel.readers.local_text_types import LocalTextCitation, LocalTextError, LocalTextRead
from sentinel.sync import (
    FixtureSyncAdvanceReport,
    FixtureSyncError,
    IncrementalGithubFixtureState,
    advance_incremental_github_fixture,
    read_incremental_github_fixture_state,
    setup_incremental_github_fixture,
)
from sentinel.sync.github_fixture import INCREMENTAL_CURSOR_KIND, INCREMENTAL_SOURCE_LABEL
from sentinel.tasks import (
    UNCHANGED,
    TaskStatus,
    TaskStoreError,
    complete_local_task,
    create_local_task,
    edit_local_task,
    list_local_tasks,
    reopen_local_task,
    setup_local_task_operator,
)
from sentinel.tasks.types import LocalTask

app = typer.Typer(no_args_is_help=True, help="Sentinel local-first automation CLI.")
brief_app = typer.Typer(no_args_is_help=True, help="Read verified, source-cited evidence.")
task_app = typer.Typer(no_args_is_help=True, help="Manage manually entered local tasks.")
fixture_sync_app = typer.Typer(
    no_args_is_help=True,
    help="Replay the fixed synthetic GitHub issue fixture one page at a time.",
)
source_app = typer.Typer(
    no_args_is_help=True,
    help="Inspect or search explicitly allowlisted local text files.",
)


def _write_brief_stdout(output: str) -> None:
    """Write one complete UTF-8 record after evidence and rendering succeed."""

    payload = (output + "\n").encode("utf-8", errors="strict")
    stream_buffer = getattr(sys.stdout, "buffer", None)
    if stream_buffer is not None:
        stream_buffer.write(payload)
        stream_buffer.flush()
    else:
        typer.echo(output)


@app.callback()
def main(ctx: typer.Context) -> None:
    """Show command help when no subcommand is selected."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


@app.command()
def version() -> None:
    """Print the installed Sentinel package version."""
    typer.echo(__version__)


@app.command()
def init(
    database: Annotated[
        Path,
        typer.Option(
            "--database",
            help="Absolute path for a new database; existing paths are refused.",
        ),
    ],
) -> None:
    """Initialize one new database at the explicitly selected path."""
    try:
        initialize_new_database(database)
    except BootstrapInitError as exc:
        typer.echo(f"Initialization failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo("Initialized new Sentinel database; migration and integrity checks passed.")


@app.command()
def doctor(
    database: Annotated[
        Path,
        typer.Option(
            "--database",
            help="Absolute path to an existing Sentinel database; never created or modified.",
        ),
    ],
) -> None:
    """Run read-only diagnostics on one explicitly selected existing database."""
    try:
        report: DoctorReport = run_doctor(database)
    except Exception:
        typer.echo("Doctor failed: diagnostic execution failed.", err=True)
        raise typer.Exit(code=1) from None

    typer.echo("A passing Sentinel diagnostic is not a production readiness result.")
    for check in report.checks:
        typer.echo(f"{check.status.value} {check.check_id.value}: {check.message}")
    if not report.successful:
        raise typer.Exit(code=1)


@app.command()
def demo() -> None:
    """Run the deterministic credential-free synthetic DEMO flow."""
    try:
        report = run_demo()
        output = report.to_json_bytes().decode("utf-8", errors="strict")
    except Exception:
        typer.echo("Demo failed: synthetic execution could not be verified.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(output)


@brief_app.command("github-fixture")
def github_fixture_brief(
    database: Annotated[
        Path,
        typer.Option("--database", help="Existing current Sentinel database."),
    ],
    store_root: Annotated[
        Path,
        typer.Option("--store-root", help="Initialized PUBLIC blob store."),
    ],
    output_format: Annotated[
        Literal["text", "json"],
        typer.Option("--format", help="Output format: text or json."),
    ] = "text",
) -> None:
    """Display verified evidence from the fixed synthetic GitHub fixture."""

    try:
        briefing = build_github_fixture_brief(database, store_root=store_root)
        output = (
            format_text_brief(briefing) if output_format == "text" else format_json_brief(briefing)
        )
    except (BriefingError, GithubBlobIntegrationError):
        typer.echo("Brief failed: verified synthetic evidence is unavailable.", err=True)
        raise typer.Exit(code=1) from None
    except Exception:
        typer.echo("Brief failed: verified synthetic evidence is unavailable.", err=True)
        raise typer.Exit(code=1) from None
    _write_brief_stdout(output)


@brief_app.command("local-overview")
def local_overview_brief(
    database: Annotated[
        Path,
        typer.Option("--database", help="Existing current Sentinel database."),
    ],
    store_root: Annotated[
        Path,
        typer.Option("--store-root", help="Initialized PUBLIC blob store."),
    ],
    as_of: Annotated[
        str,
        typer.Option("--as-of", help="ISO-8601 timestamp with an explicit UTC offset."),
    ],
    output_format: Annotated[
        Literal["text", "json"],
        typer.Option("--format", help="Output format: text or json."),
    ] = "text",
) -> None:
    """Show verified local tasks, synthetic evidence, and replay status for one selected day."""

    try:
        selected_time = parse_as_of_timestamp(as_of)
        overview = build_local_overview(database, store_root=store_root, as_of=selected_time)
        output = (
            format_text_local_overview(overview)
            if output_format == "text"
            else format_json_local_overview(overview)
        )
    except OverviewError as exc:
        typer.echo(f"Local overview failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    except Exception:
        typer.echo("Local overview failed: required local state could not be verified.", err=True)
        raise typer.Exit(code=1) from None
    _write_brief_stdout(output)


app.add_typer(brief_app, name="brief")


def _format_local_text_inspection(
    result: LocalTextRead,
    citation: LocalTextCitation | None,
    *,
    output_format: str,
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
            "cited_text": escape_display_text(citation.cited_text),
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


def _parse_source_byte_offset(value: str) -> int:
    if type(value) is not str or re.fullmatch(r"[0-9]{1,7}", value) is None:
        raise ValueError("invalid source byte offset")
    offset = int(value)
    if offset > 1_048_576:
        raise ValueError("invalid source byte offset")
    return offset


@source_app.command("inspect-file")
def source_inspect_file(
    allow_root: Annotated[
        Path,
        typer.Option(
            "--allow-root",
            help="Explicit absolute allowlisted directory on a local Windows fixed volume.",
        ),
    ],
    file: Annotated[
        Path,
        typer.Option("--file", help="One existing .txt or .md file beneath --allow-root."),
    ],
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: text or json."),
    ] = "text",
    start_byte: Annotated[
        str | None,
        typer.Option("--start-byte", help="Optional first byte of one citation range."),
    ] = None,
    end_byte: Annotated[
        str | None,
        typer.Option("--end-byte", help="Optional exclusive end byte of one citation range."),
    ] = None,
) -> None:
    """Inspect metadata or one explicitly selected verified byte excerpt."""
    if output_format not in {"text", "json"}:
        typer.echo("Source inspection failed: output format must be text or json.", err=True)
        raise typer.Exit(code=1)
    if (start_byte is None) != (end_byte is None):
        typer.echo(
            "Source inspection failed: both citation byte offsets are required together.", err=True
        )
        raise typer.Exit(code=1)
    try:
        parsed_start = None if start_byte is None else _parse_source_byte_offset(start_byte)
        parsed_end = None if end_byte is None else _parse_source_byte_offset(end_byte)
        result = read_allowlisted_local_text(allowed_root=allow_root, file_path=file)
        citation = (
            None
            if parsed_start is None or parsed_end is None
            else verify_local_text_span(result, start_byte=parsed_start, end_byte=parsed_end)
        )
        output = _format_local_text_inspection(
            result,
            citation,
            output_format=output_format,
        )
    except LocalTextError as exc:
        typer.echo(f"Source inspection failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    except Exception:
        typer.echo(
            "Source inspection failed: the selected local source could not be verified.", err=True
        )
        raise typer.Exit(code=1) from None
    _write_brief_stdout(output)


@source_app.command("search-files")
def source_search_files(
    allow_root: Annotated[
        Path,
        typer.Option(
            "--allow-root",
            help="Explicit absolute allowlisted directory on a local Windows fixed volume.",
        ),
    ],
    files: Annotated[
        list[Path],
        typer.Option(
            "--file", help="One explicitly selected .txt or .md file; repeat up to eight."
        ),
    ],
    query: Annotated[
        str,
        typer.Option("--query", help="One literal case-sensitive UTF-8 query (not logged)."),
    ],
    show_snippets: Annotated[
        bool,
        typer.Option(
            "--show-snippets",
            help="Explicitly disclose bounded verified context in terminal/JSON output.",
        ),
    ] = False,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: text or json."),
    ] = "text",
) -> None:
    """Search only the explicitly selected local files for a literal phrase."""
    if output_format not in {"text", "json"}:
        typer.echo("File search failed: output format must be text or json.", err=True)
        raise typer.Exit(code=1)
    try:
        result = search_selected_local_text_files(
            allowed_root=allow_root,
            file_paths=files,
            query=query,
            show_snippets=show_snippets,
        )
        output = (
            format_text_local_file_search(result)
            if output_format == "text"
            else format_json_local_file_search(result)
        )
    except (LocalSearchError, LocalTextError) as exc:
        typer.echo(f"File search failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    except Exception:
        typer.echo("File search failed: selected local sources could not be verified.", err=True)
        raise typer.Exit(code=1) from None
    _write_brief_stdout(output)


@source_app.command("parse-job-alert")
def source_parse_job_alert(
    allow_root: Annotated[
        Path,
        typer.Option(
            "--allow-root",
            help="Explicit absolute allowlisted directory on a local Windows fixed volume.",
        ),
    ],
    file: Annotated[
        Path,
        typer.Option("--file", help="One explicitly selected .txt or .md message body."),
    ],
    show_fields: Annotated[
        bool,
        typer.Option("--show-fields", help="Explicitly disclose accepted cited field values."),
    ] = False,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: text or json."),
    ] = "text",
) -> None:
    """Extract only explicitly labeled fields from one selected local message body."""
    if output_format not in {"text", "json"}:
        typer.echo("Job-alert extraction failed: output format must be text or json.", err=True)
        raise typer.Exit(code=1)
    try:
        result = parse_local_job_alert(allowed_root=allow_root, file_path=file)
        output = (
            format_text_job_alert(result, show_fields=show_fields)
            if output_format == "text"
            else format_json_job_alert(result, show_fields=show_fields)
        )
    except LocalTextError as exc:
        typer.echo(f"Job-alert extraction failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    except JobAlertError as exc:
        typer.echo(f"Job-alert extraction failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    except Exception:
        typer.echo(
            "Job-alert extraction failed: the selected source could not be verified.", err=True
        )
        raise typer.Exit(code=1) from None
    _write_brief_stdout(output)


app.add_typer(source_app, name="source")


def _parse_cli_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed
    except (OverflowError, ValueError):
        typer.echo(
            "Task operation failed: due-at must be an ISO-8601 timestamp with an offset.", err=True
        )
        raise typer.Exit(code=1) from None


def _parse_cli_uuid(value: str, *, field_name: str) -> UUID:
    try:
        return UUID(value)
    except (ValueError, TypeError, AttributeError):
        typer.echo(f"Task operation failed: {field_name} must be a UUID.", err=True)
        raise typer.Exit(code=1) from None


def _task_output(task: LocalTask, *, prefix: str = "Task") -> str:
    due_display = "none" if task.due_at is None else task.due_at.isoformat()
    return (
        f"{prefix}: {task.task_id} [{task.status.value}, revision {task.revision}] "
        f"due={due_display} {escape_display_text(task.title)}"
    )


@task_app.command("setup")
def task_setup(
    database: Annotated[
        Path, typer.Option("--database", help="Existing current Sentinel database.")
    ],
) -> None:
    """Initialize the dedicated unauthenticated local task operator."""
    try:
        operator = setup_local_task_operator(database)
    except TaskStoreError as exc:
        typer.echo(f"Task setup failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Local task operator initialized (unauthenticated): {operator.principal_id}")


@task_app.command("add")
def task_add(
    database: Annotated[
        Path, typer.Option("--database", help="Existing current Sentinel database.")
    ],
    title: Annotated[str, typer.Option("--title", help="Non-sensitive manual task title.")],
    due_at: Annotated[
        str | None,
        typer.Option("--due-at", help="Optional ISO-8601 timestamp with an explicit UTC offset."),
    ] = None,
    request_id: Annotated[
        str | None,
        typer.Option(
            "--request-id", help="Optional UUID for an explicitly identified create request."
        ),
    ] = None,
) -> None:
    """Add one manually entered local task."""
    request_uuid = (
        uuid4() if request_id is None else _parse_cli_uuid(request_id, field_name="request-id")
    )
    try:
        result = create_local_task(
            database,
            request_id=request_uuid,
            title=title,
            due_at=_parse_cli_datetime(due_at),
        )
    except TaskStoreError as exc:
        typer.echo(f"Task creation failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    prefix = "Task created" if result.created else "Task already exists for request"
    typer.echo(
        f"{prefix}: {result.task.task_id} request={result.request_id} "
        f"revision={result.task.revision}"
    )


@task_app.command("list")
def task_list(
    database: Annotated[
        Path, typer.Option("--database", help="Existing current Sentinel database.")
    ],
    status: Annotated[
        Literal["OPEN", "COMPLETED"] | None,
        typer.Option("--status", help="Optional task status filter."),
    ] = None,
) -> None:
    """List local tasks in deterministic due/creation/ID order."""
    try:
        task_status = None if status is None else TaskStatus(status)
        tasks = list_local_tasks(database, status=task_status)
    except TaskStoreError as exc:
        typer.echo(f"Task listing failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    if not tasks:
        typer.echo("No tasks.")
        return
    for task in tasks:
        typer.echo(_task_output(task))


@task_app.command("edit")
def task_edit(
    database: Annotated[
        Path, typer.Option("--database", help="Existing current Sentinel database.")
    ],
    task_id: Annotated[str, typer.Option("--task-id", help="Task UUID from task list/add.")],
    expected_revision: Annotated[int, typer.Option("--expected-revision", min=1)],
    title: Annotated[
        str | None, typer.Option("--title", help="Replacement non-sensitive title.")
    ] = None,
    due_at: Annotated[
        str | None,
        typer.Option("--due-at", help="Replacement ISO-8601 timestamp with explicit offset."),
    ] = None,
    clear_due_at: Annotated[
        bool,
        typer.Option("--clear-due-at", help="Clear the current due date."),
    ] = False,
) -> None:
    """Edit the title and/or due date with an expected revision."""
    task_uuid = _parse_cli_uuid(task_id, field_name="task-id")
    if clear_due_at and due_at is not None:
        typer.echo("Task edit failed: choose either --due-at or --clear-due-at.", err=True)
        raise typer.Exit(code=1)
    try:
        updated = edit_local_task(
            database,
            task_id=task_uuid,
            expected_revision=expected_revision,
            title=UNCHANGED if title is None else title,
            due_at=(None if clear_due_at else _parse_cli_datetime(due_at))
            if clear_due_at or due_at is not None
            else UNCHANGED,
        )
    except TaskStoreError as exc:
        typer.echo(f"Task edit failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(_task_output(updated, prefix="Task updated"))


@task_app.command("complete")
def task_complete(
    database: Annotated[
        Path, typer.Option("--database", help="Existing current Sentinel database.")
    ],
    task_id: Annotated[str, typer.Option("--task-id", help="Task UUID from task list/add.")],
    expected_revision: Annotated[int, typer.Option("--expected-revision", min=1)],
) -> None:
    """Complete one OPEN task at the expected revision."""
    try:
        task = complete_local_task(
            database,
            task_id=_parse_cli_uuid(task_id, field_name="task-id"),
            expected_revision=expected_revision,
        )
    except TaskStoreError as exc:
        typer.echo(f"Task completion failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(_task_output(task, prefix="Task completed"))


@task_app.command("reopen")
def task_reopen(
    database: Annotated[
        Path, typer.Option("--database", help="Existing current Sentinel database.")
    ],
    task_id: Annotated[str, typer.Option("--task-id", help="Task UUID from task list/add.")],
    expected_revision: Annotated[int, typer.Option("--expected-revision", min=1)],
) -> None:
    """Reopen one COMPLETED task at the expected revision."""
    try:
        task = reopen_local_task(
            database,
            task_id=_parse_cli_uuid(task_id, field_name="task-id"),
            expected_revision=expected_revision,
        )
    except TaskStoreError as exc:
        typer.echo(f"Task reopening failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(_task_output(task, prefix="Task reopened"))


app.add_typer(task_app, name="task")


def _fixture_sync_payload(
    state: IncrementalGithubFixtureState,
    *,
    result: str | None = None,
) -> str:
    payload: dict[str, object] = {
        "completed_pages": state.completed_pages,
        "cursor_id": str(state.cursor_id),
        "cursor_kind": INCREMENTAL_CURSOR_KIND,
        "fixture_sha256": state.fixture_sha256,
        "fixture_version": state.fixture_version,
        "generation": state.generation,
        "item_count": state.item_count,
        "source": INCREMENTAL_SOURCE_LABEL,
        "source_id": str(state.source_id),
        "span_count": state.span_count,
        "status": state.cursor_status.value,
        "synthetic": True,
        "total_pages": state.total_pages,
    }
    if result is not None:
        payload["result"] = result
    return json.dumps(payload, allow_nan=False, separators=(",", ":"), sort_keys=True)


@fixture_sync_app.command("setup")
def fixture_sync_setup(
    database: Annotated[
        Path, typer.Option("--database", help="Existing current Sentinel database.")
    ],
    store_root: Annotated[
        Path, typer.Option("--store-root", help="Initialized PUBLIC blob store.")
    ],
) -> None:
    """Register the isolated synthetic incremental source and generation-zero cursor."""
    try:
        state = setup_incremental_github_fixture(database, store_root=store_root)
    except FixtureSyncError as exc:
        typer.echo(f"Fixture sync setup failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(_fixture_sync_payload(state))


@fixture_sync_app.command("advance")
def fixture_sync_advance(
    database: Annotated[
        Path, typer.Option("--database", help="Existing current Sentinel database.")
    ],
    store_root: Annotated[
        Path, typer.Option("--store-root", help="Initialized PUBLIC blob store.")
    ],
    expected_generation: Annotated[
        int,
        typer.Option(
            "--expected-generation", min=0, max=3, help="Generation observed before this call."
        ),
    ],
) -> None:
    """Atomically apply at most the next fixed synthetic issue page."""
    try:
        report: FixtureSyncAdvanceReport = advance_incremental_github_fixture(
            database,
            store_root=store_root,
            expected_generation=expected_generation,
        )
    except FixtureSyncError as exc:
        typer.echo(f"Fixture sync advance failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(_fixture_sync_payload(report.state, result=report.result.value))


@fixture_sync_app.command("status")
def fixture_sync_status(
    database: Annotated[
        Path, typer.Option("--database", help="Existing current Sentinel database.")
    ],
    store_root: Annotated[
        Path, typer.Option("--store-root", help="Initialized PUBLIC blob store.")
    ],
) -> None:
    """Read and fully verify the synthetic cursor, items, spans and blobs."""
    try:
        state = read_incremental_github_fixture_state(database, store_root=store_root)
    except FixtureSyncError as exc:
        typer.echo(f"Fixture sync status failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(_fixture_sync_payload(state))


app.add_typer(fixture_sync_app, name="fixture-sync")


if __name__ == "__main__":
    app()
